// Package broker 实现用钥调度：把已认证会话、登记 Binding、交付模式与许可期限
// 组合成一次 UseLease，并且先授权后取值。
package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

// Source 在受信内存中解出指定完整凭证版本。它由 vault 实现；P0 原型使用内存实现。
// Materialize 必须在授权检查之后调用。
type Source interface {
	Materialize(ctx context.Context, credentialID string, version int) (model.CredentialVersion, error)
	// Locked 报告当前是否处于锁定状态。
	Locked() bool
}

// UseQuery 是一次用钥申请中交给外部中心裁定的内容。中心按实际主体、绑定、方式
// 与凭证版本裁定，Broker 再以裁定结果约束最终取值。
type UseQuery struct {
	PrincipalID       string
	BindingID         string
	Mode              model.DeliveryMode
	CredentialID      string
	CredentialVersion int
}

// Permit 是中心对一次用钥的完整裁定。主体、绑定、方式和版本必须与最终取值精确一致；
// 缺字段不会被解释为通配，避免旧响应或兼容 JSON 意外放宽权限。
type Permit struct {
	PrincipalID       string
	BindingID         string
	CredentialID      string
	Mode              model.DeliveryMode
	CredentialVersion int
	// MaxLeaseDuration 非零时收紧许可上限。
	MaxLeaseDuration time.Duration
	// LeaseID 是中心签发的许可标识，仅用于审计。
	LeaseID string
	// ExpiresAt caps execution at the center’s original absolute deadline.
	ExpiresAt time.Time
}

// Gate 是可选的中心许可检查。启用时每次用钥前必须先通过中心或短期许可。
type Gate interface {
	// CheckUse 以实际主体、绑定、方式和凭证版本校验该次用钥是否被中心允许，
	// 并返回对最终取值的约束。
	CheckUse(ctx context.Context, q UseQuery) (Permit, error)
}

// enforce 校验中心裁定是否允许本次主体、目标与版本取值。
func (p Permit) enforce(q UseQuery, cred model.Credential) error {
	if p.PrincipalID != q.PrincipalID {
		return model.NewError(model.CodeUseNotAllowed,
			"center permit principal %q does not match requesting principal %q", p.PrincipalID, q.PrincipalID)
	}
	if p.BindingID != q.BindingID {
		return model.NewError(model.CodeUseNotAllowed,
			"center permit binding %q does not match requested binding %q", p.BindingID, q.BindingID)
	}
	if p.Mode != q.Mode {
		return model.NewError(model.CodeUseNotAllowed, "center permits %s only, request is %s", p.Mode, q.Mode)
	}
	// 中心的 credential_id 是中心侧的逻辑引用：多设备部署里各设备可以有各自的
	// 本地凭证 ID，因此这里只把它当审计信息，不用它拒绝用钥。
	//
	// 版本则参与裁定：本机版本领先于中心许可时说明本机轮换没有同步到中心，
	// 这时拒绝用钥，避免本机轮换绕过中心策略。中心记录的版本比本机新时可能
	// 只是尚未下发，不阻塞本次用钥（旧许可仍会按 /v1/check 的版本漂移失效）。
	if p.CredentialVersion != 0 && cred.CurrentVersion > p.CredentialVersion {
		return model.NewError(model.CodeControlUnavailable,
			"credential %s is at local version %d but the center authorizes version %d; synchronize the center policy first",
			cred.ID, cred.CurrentVersion, p.CredentialVersion)
	}
	if p.CredentialVersion != 0 && q.CredentialVersion != 0 && q.CredentialVersion > p.CredentialVersion {
		return model.NewError(model.CodeControlUnavailable,
			"requested credential version %d is newer than the center authorization %d", q.CredentialVersion, p.CredentialVersion)
	}
	return nil
}

// Options 配置 Broker 的运行参数。
type Options struct {
	// SessionTTL 是默认会话有效期。
	SessionTTL time.Duration
	// MaxLeaseDuration 是缺省许可上限；单个 Grant 可以更短。
	MaxLeaseDuration time.Duration
	// CacheDuration 是内存凭证缓存上限，不超过许可与原凭证到期。
	CacheDuration time.Duration
	// CleanupInterval 是独立过期清扫周期；默认 30 秒，测试可注入更短周期。
	CleanupInterval time.Duration
	// Now 便于测试注入时钟。
	Now func() time.Time
	// Gate 为空表示单机模式；非空时先过中心许可检查。
	Gate Gate
	// Auth 按 Grant 的验证策略决定是否需要 Touch ID 等额外验证。daemon 总会注入；
	// 为空时 Broker 不评估策略（库内策略仍按 once 迁移），注入但没有 verifier
	// 时一律以 AUTH_UNAVAILABLE 拒绝，绝不静默放行。
	Auth *Authenticator
	// LocalPrincipalID is the account whose grants also cover recognized local agents.
	LocalPrincipalID string
}

func (o *Options) normalize() {
	if o.SessionTTL <= 0 {
		o.SessionTTL = 12 * time.Hour
	}
	if o.MaxLeaseDuration <= 0 {
		o.MaxLeaseDuration = 10 * time.Minute
	}
	if o.CacheDuration <= 0 {
		o.CacheDuration = 5 * time.Minute
	}
	if o.CleanupInterval <= 0 {
		o.CleanupInterval = 30 * time.Second
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
}

// Authorization 是一次通过校验的用钥结果：许可与同版本完整凭证。
type Authorization struct {
	// Execution is canceled when the broker revokes a proxy use.
	Execution context.Context
	Lease     model.UseLease
	Version   model.CredentialVersion
	Session   model.Session
	// Binding 是已校验的登记 Binding，供交付通道读取认证方案与目标。
	Binding *model.Binding
}

// ExecutionContext links an operation to its original lease, caller, and expiry.
func (a *Authorization) ExecutionContext(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithDeadline(parent, a.Lease.UseLeaseExpiresAt)
	if a.Execution == nil {
		return ctx, cancel
	}
	stop := context.AfterFunc(a.Execution, cancel)
	if a.Execution.Err() != nil {
		cancel()
	}
	return ctx, func() {
		stop()
		cancel()
	}
}

type liveLease struct {
	model.UseLease
	permit Permit
	cancel context.CancelFunc
}

// Request 描述一次用钥申请。
type Request struct {
	// Token 是中介会话令牌原文；只在受信通道内传递。
	Token secret.Value
	// Route 或 BindingID 二选一；Route 用于网关按已登记路由查找。
	Route     string
	BindingID string
	Mode      model.DeliveryMode
	Purpose   string
}

// Broker 持有运行时会话与许可。持久数据走 store，运行时状态只驻留内存。
type Broker struct {
	store  store.Store
	source Source
	opts   Options

	mu       sync.Mutex
	sessions map[string]*model.Session
	// tokenIndex 以令牌哈希索引会话，不保存令牌原文。
	tokenIndex map[string]string
	leases     map[string]*liveLease
	epoch      string
	locked     bool

	cleanupStop chan struct{}
	cleanupDone chan struct{}
	closeOnce   sync.Once
}

// New 构造 Broker。
func New(st store.Store, src Source, opts Options) *Broker {
	opts.normalize()
	b := &Broker{
		store:       st,
		source:      src,
		opts:        opts,
		sessions:    map[string]*model.Session{},
		tokenIndex:  map[string]string{},
		leases:      map[string]*liveLease{},
		epoch:       randomID(),
		cleanupStop: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	go b.runCleanup()
	return b
}

// Epoch 返回当前授权代次。
func (b *Broker) Epoch() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.epoch
}

// Locked 报告 Broker 是否拒绝新的用钥。
func (b *Broker) Locked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.locked || b.source.Locked()
}

// Lock 停止接受新的用钥并失效全部会话与许可，同时更换授权代次。
// 运行中的任务取消由调用方（runner）负责。
func (b *Broker) Lock(ctx context.Context) {
	b.mu.Lock()
	b.locked = true
	b.epoch = randomID()
	for id, s := range b.sessions {
		s.Status = model.StatusRevoked
		delete(b.tokenIndex, s.TokenHash)
		_ = id
	}
	for id := range b.leases {
		b.removeLease(id)
	}
	b.mu.Unlock()
	b.clearAuth("lock")
	b.audit(ctx, store.AuditEvent{Mode: "control", Result: "lock", Detail: "vault locked; sessions and leases revoked"})
}

// Unlock 允许新的用钥请求；它不恢复旧会话或许可。
func (b *Broker) Unlock() {
	b.mu.Lock()
	b.locked = false
	b.epoch = randomID()
	b.mu.Unlock()
	// 解锁不恢复任何旧验证结果。
	b.clearAuth("unlock")
}

// CreateSession 使用默认有效期建立会话。
func (b *Broker) CreateSession(ctx context.Context, principalID, purpose string) (model.Session, secret.Value, error) {
	return b.CreateSessionTTL(ctx, principalID, purpose, 0)
}

// CreateSessionTTL 为已认证主体建立会话并返回中介令牌。
// 令牌只在受信通道交付，存储中仅保留哈希；ttl 为 0 时使用默认有效期，上限 24 小时。
func (b *Broker) CreateSessionTTL(ctx context.Context, principalID, purpose string, ttl time.Duration) (model.Session, secret.Value, error) {
	if b.Locked() {
		return model.Session{}, secret.Empty, model.NewError(model.CodeVaultLocked, "vault is locked")
	}
	p, err := b.store.GetPrincipal(ctx, principalID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return model.Session{}, secret.Empty, model.NewError(model.CodeSessionInvalid, "unknown principal")
		}
		return model.Session{}, secret.Empty, err
	}
	if p.Status != model.StatusActive {
		return model.Session{}, secret.Empty, model.NewError(model.CodeSessionInvalid, "principal %s is %s", principalID, p.Status)
	}
	token := randomToken()
	sum := sha256.Sum256([]byte(token))
	now := b.opts.Now()
	if ttl <= 0 {
		ttl = b.opts.SessionTTL
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	s := &model.Session{
		ID:                 randomID(),
		PrincipalID:        principalID,
		IdentityType:       p.IdentityType,
		AuthenticatedAt:    now,
		ExpiresAt:          now.Add(ttl),
		AuthorizationEpoch: b.Epoch(),
		Status:             model.StatusActive,
		TokenHash:          base64.RawStdEncoding.EncodeToString(sum[:]),
	}
	b.mu.Lock()
	b.sessions[s.ID] = s
	b.tokenIndex[s.TokenHash] = s.ID
	cp := *s
	b.mu.Unlock()
	b.audit(ctx, store.AuditEvent{SessionID: s.ID, PrincipalID: principalID, Mode: "session", Result: "created", Detail: purpose})
	return cp, secret.New(token), nil
}

// SessionByToken 返回令牌对应会话；不匹配或过期返回稳定错误。
func (b *Broker) SessionByToken(token secret.Value) (model.Session, error) {
	if token.IsEmpty() {
		return model.Session{}, model.NewError(model.CodeSessionInvalid, "missing session token")
	}
	sum := sha256.Sum256(token.Reveal())
	hash := base64.RawStdEncoding.EncodeToString(sum[:])
	b.mu.Lock()
	defer b.mu.Unlock()
	id, ok := b.tokenIndex[hash]
	if !ok {
		// 常量时间比较防止通过时序判断令牌是否存在。
		subtle.ConstantTimeCompare([]byte(hash), []byte(hash))
		return model.Session{}, model.NewError(model.CodeSessionInvalid, "unknown session token")
	}
	s, ok := b.sessions[id]
	if !ok {
		return model.Session{}, model.NewError(model.CodeSessionInvalid, "session not found")
	}
	if s.Status != model.StatusActive {
		delete(b.sessions, id)
		if s.TokenHash != "" {
			delete(b.tokenIndex, s.TokenHash)
		}
		return model.Session{}, model.NewError(model.CodeSessionInvalid, "session is %s", s.Status)
	}
	if !b.opts.Now().Before(s.ExpiresAt) {
		// 过期会话当场删除，不再占用内存。
		delete(b.sessions, id)
		delete(b.tokenIndex, s.TokenHash)
		return model.Session{}, model.NewError(model.CodeSessionInvalid, "session expired")
	}
	if s.AuthorizationEpoch != b.epoch {
		return model.Session{}, model.NewError(model.CodeSessionInvalid, "session epoch is stale")
	}
	cp := *s
	return cp, nil
}

// RequireAdmin 校验令牌所属主体拥有管理权。普通用钥会话的管理请求被拒绝。
func (b *Broker) RequireAdmin(ctx context.Context, token secret.Value) (model.Session, error) {
	s, err := b.SessionByToken(token)
	if err != nil {
		return model.Session{}, err
	}
	p, err := b.store.GetPrincipal(ctx, s.PrincipalID)
	if err != nil {
		return model.Session{}, model.NewError(model.CodeSessionInvalid, "unknown principal")
	}
	if !p.Admin {
		b.audit(ctx, store.AuditEvent{SessionID: s.ID, PrincipalID: s.PrincipalID, Mode: "admin", Result: "denied", ErrorCode: string(model.CodeSessionInvalid)})
		return model.Session{}, model.NewError(model.CodeSessionInvalid, "principal is not permitted to manage KeyKoi")
	}
	return s, nil
}

// CloseSession 撤销会话及其许可。
func (b *Broker) CloseSession(ctx context.Context, sessionID string) error {
	return b.CloseSessionForPrincipal(ctx, sessionID, "")
}

// CloseSessionForPrincipal limits closure to an owner, or permits any owner when principalID is empty.
func (b *Broker) CloseSessionForPrincipal(ctx context.Context, sessionID, principalID string) error {
	b.mu.Lock()
	s, ok := b.sessions[sessionID]
	if !ok || (principalID != "" && s.PrincipalID != principalID) {
		b.mu.Unlock()
		return store.ErrNotFound
	}
	s.Status = model.StatusRevoked
	delete(b.tokenIndex, s.TokenHash)
	// 结束的会话不再保留运行时记录，只留审计。
	delete(b.sessions, sessionID)
	for id, l := range b.leases {
		if l.SessionID == sessionID {
			l.Status = model.StatusRevoked
			b.removeLease(id)
		}
	}
	b.mu.Unlock()
	b.clearAuthForSession(sessionID)
	b.audit(ctx, store.AuditEvent{SessionID: sessionID, PrincipalID: s.PrincipalID, Mode: "session", Result: "revoked"})
	return nil
}

// CheckLease checks the original execution decision without loading credentials or renewing it.
func (b *Broker) CheckLease(ctx context.Context, token secret.Value, original model.UseLease) error {
	sess, err := b.SessionByToken(token)
	if err != nil {
		return err
	}
	b.mu.Lock()
	lease := b.leases[original.ID]
	if lease == nil || lease.SessionID != sess.ID {
		b.mu.Unlock()
		return model.NewError(model.CodeLeaseExpired, "use lease is no longer active")
	}
	err = b.revalidateDelivery(ctx, &lease.UseLease, sess,
		&model.Binding{ID: lease.BindingID}, &model.Credential{ID: lease.CredentialID},
		&model.Grant{ID: lease.GrantID})
	permit := lease.permit
	b.mu.Unlock()
	if err != nil {
		return err
	}
	if verifier, ok := b.opts.Gate.(interface {
		CheckExecution(context.Context, Permit) error
	}); ok && permit.LeaseID != "" {
		return verifier.CheckExecution(ctx, permit)
	}
	return nil
}

// RevokeLease 撤销单个许可。
func (b *Broker) RevokeLease(ctx context.Context, leaseID string) error {
	return b.RevokeLeaseForPrincipal(ctx, leaseID, "")
}

// RevokeLeaseForPrincipal limits revocation to an owner, or permits any owner when principalID is empty.
func (b *Broker) RevokeLeaseForPrincipal(ctx context.Context, leaseID, principalID string) error {
	b.mu.Lock()
	l, ok := b.leases[leaseID]
	if !ok {
		b.mu.Unlock()
		return store.ErrNotFound
	}
	var owner string
	if s := b.sessions[l.SessionID]; s != nil {
		owner = s.PrincipalID
	}
	if principalID != "" && owner != principalID {
		b.mu.Unlock()
		return store.ErrNotFound
	}
	l.Status = model.StatusRevoked
	b.removeLease(leaseID)
	b.mu.Unlock()
	b.clearAuthForSession(l.SessionID)
	b.audit(ctx, store.AuditEvent{PrincipalID: owner, SessionID: l.SessionID, BindingID: l.BindingID, Mode: string(l.DeliveryMode), Result: "revoked"})
	return nil
}

// RevokeForCredential 在凭证版本切换后失效关联许可，阻止旧授权路径继续用钥。
func (b *Broker) RevokeForCredential(ctx context.Context, credentialID string) int {
	b.mu.Lock()
	n := 0
	for id, l := range b.leases {
		if l.CredentialID == credentialID {
			l.Status = model.StatusRevoked
			b.removeLease(id)
			n++
		}
	}
	b.mu.Unlock()
	// 凭证轮换使旧验证结果一并失效，避免用旧策略继续放行新版本。
	b.clearAuth("credential_rotation")
	if n > 0 {
		b.audit(ctx, store.AuditEvent{CredentialID: credentialID, Mode: "control", Result: "rotation_revoked_leases", Detail: fmt.Sprintf("%d leases revoked", n)})
	}
	return n
}

// Authorize 按会话、Binding、交付模式与期限校验一次用钥，并返回同版本完整凭证。
// 授权先于取值：任何一项不满足都不会读取凭证。
func (b *Broker) Authorize(ctx context.Context, req Request) (*Authorization, error) {
	return b.authorize(ctx, req, true)
}

// AuthorizeMetadata exercises the same policy without reading a credential.
func (b *Broker) AuthorizeMetadata(ctx context.Context, req Request) (model.UseLease, error) {
	authz, err := b.authorize(ctx, req, false)
	if err != nil {
		return model.UseLease{}, err
	}
	b.ReleaseLease(authz.Lease.ID)
	return authz.Lease, nil
}

func (b *Broker) authorize(ctx context.Context, req Request, materialize bool) (*Authorization, error) {
	start := b.opts.Now()
	// 顺手清理已过期或已撤销的运行时记录，避免只增不减。
	b.pruneExpired(start)
	if !req.Mode.Valid() {
		return nil, model.NewError(model.CodeUseNotAllowed, "invalid delivery mode %q", req.Mode)
	}
	if b.Locked() {
		b.audit(ctx, store.AuditEvent{Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeVaultLocked)})
		return nil, model.NewError(model.CodeVaultLocked, "vault is locked")
	}
	sess, err := b.SessionByToken(req.Token)
	if err != nil {
		b.audit(ctx, store.AuditEvent{Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeSessionInvalid)})
		return nil, err
	}
	var binding *model.Binding
	if req.BindingID != "" {
		binding, err = b.store.GetBinding(ctx, req.BindingID)
	} else {
		binding, err = b.store.GetBindingByRoute(ctx, req.Route)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			b.audit(ctx, store.AuditEvent{PrincipalID: sess.PrincipalID, SessionID: sess.ID, Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeBindingDisabled)})
			return nil, model.NewError(model.CodeBindingDisabled, "binding is not registered")
		}
		return nil, err
	}
	if binding.Status != model.StatusActive {
		b.audit(ctx, store.AuditEvent{PrincipalID: sess.PrincipalID, SessionID: sess.ID, BindingID: binding.ID, Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeBindingDisabled)})
		return nil, model.NewError(model.CodeBindingDisabled, "binding %s is %s", binding.ID, binding.Status)
	}
	cred, err := b.store.GetCredential(ctx, binding.CredentialID)
	if err != nil || cred.Status != model.StatusActive {
		b.audit(ctx, store.AuditEvent{PrincipalID: sess.PrincipalID, SessionID: sess.ID, BindingID: binding.ID, Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeCredentialUnavailable)})
		return nil, model.NewError(model.CodeCredentialUnavailable, "credential for binding %s is unavailable", binding.ID)
	}
	grant, err := b.findGrant(ctx, sess.PrincipalID, binding.ID, req.Mode)
	if model.CodeOf(err) == model.CodeUseNotAllowed && sess.IdentityType == "local_agent" && b.opts.LocalPrincipalID != "" {
		grant, err = b.findGrant(ctx, b.opts.LocalPrincipalID, binding.ID, req.Mode)
	}
	if err != nil {
		b.audit(ctx, store.AuditEvent{SessionID: sess.ID, PrincipalID: sess.PrincipalID, BindingID: binding.ID, Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeUseNotAllowed), AuthResult: "not_required"})
		return nil, err
	}
	// 额外验证策略：per_use/window/once 在放行前判定，permanent 直接跳过。
	// 验证结果先挂在 decision 上、暂不写入缓存；交付前重校验通过后才提交，
	// 避免验证期间发生撤销、停用或轮换后仍留下可复用的旧决定。
	authMethod, authResult := "none", "not_required"
	var decision AuthDecision
	if b.opts.Auth != nil {
		d, aerr := b.opts.Auth.Require(ctx, VerifyRequest{
			PrincipalID:       grant.PrincipalID,
			SessionID:         sess.ID,
			GrantID:           grant.ID,
			BindingID:         binding.ID,
			Mode:              req.Mode,
			Policy:            grant.AuthPolicy(),
			CredentialVersion: cred.CurrentVersion,
			BindingRevision:   binding.Revision,
		})
		decision = d
		authMethod, authResult = d.Method, d.Result
		if aerr != nil {
			b.audit(ctx, store.AuditEvent{
				SessionID: sess.ID, PrincipalID: sess.PrincipalID, BindingID: binding.ID,
				Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeOf(aerr)),
				AuthMethod: authMethod, AuthResult: authResult,
				Detail: "auth policy " + d.Policy,
			})
			return nil, aerr
		}
	}
	var permit Permit
	if b.opts.Gate != nil {
		// 中心模式：以实际主体、方式和本机当前版本申请许可，再以完整裁定约束最终取值。
		query := UseQuery{
			PrincipalID:       sess.PrincipalID,
			BindingID:         binding.ID,
			Mode:              req.Mode,
			CredentialID:      cred.ID,
			CredentialVersion: cred.CurrentVersion,
		}
		p, gerr := b.opts.Gate.CheckUse(ctx, query)
		if gerr != nil {
			b.audit(ctx, store.AuditEvent{SessionID: sess.ID, PrincipalID: sess.PrincipalID, BindingID: binding.ID, Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeOf(gerr))})
			return nil, gerr
		}
		if perr := p.enforce(query, *cred); perr != nil {
			b.audit(ctx, store.AuditEvent{SessionID: sess.ID, PrincipalID: sess.PrincipalID, BindingID: binding.ID, Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeOf(perr))})
			return nil, perr
		}
		permit = p
	}
	now := b.opts.Now()
	expires := now.Add(grant.MaxLeaseDuration)
	if grant.MaxLeaseDuration <= 0 || expires.After(now.Add(b.opts.MaxLeaseDuration)) {
		expires = now.Add(b.opts.MaxLeaseDuration)
	}
	if permit.MaxLeaseDuration > 0 && now.Add(permit.MaxLeaseDuration).Before(expires) {
		// 中心许可比本机上限更短时收紧。
		expires = now.Add(permit.MaxLeaseDuration)
	}
	if !permit.ExpiresAt.IsZero() && permit.ExpiresAt.Before(expires) {
		expires = permit.ExpiresAt
	}
	if sess.ExpiresAt.Before(expires) {
		expires = sess.ExpiresAt
	}
	if cred.ProviderExpiresAt != nil && cred.ProviderExpiresAt.Before(expires) {
		expires = *cred.ProviderExpiresAt
	}
	if !expires.After(now) {
		b.audit(ctx, store.AuditEvent{PrincipalID: sess.PrincipalID, SessionID: sess.ID, BindingID: binding.ID, Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeLeaseExpired)})
		return nil, model.NewError(model.CodeLeaseExpired, "no usable lease time remains for credential %s", cred.ID)
	}
	lease := &model.UseLease{
		ID:                          randomID(),
		SessionID:                   sess.ID,
		AuthorizationEpoch:          sess.AuthorizationEpoch,
		BindingID:                   binding.ID,
		CredentialID:                cred.ID,
		CredentialVersion:           cred.CurrentVersion,
		GrantID:                     grant.ID,
		GrantRevision:               grant.Revision,
		Target:                      binding.UpstreamOrigin,
		BindingRevision:             binding.Revision,
		DeliveryMode:                req.Mode,
		UseLeaseExpiresAt:           expires,
		CacheExpiresAt:              minTime(now.Add(b.opts.CacheDuration), expires),
		ProviderCredentialExpiresAt: cred.ProviderExpiresAt,
		Status:                      model.StatusActive,
	}
	var version model.CredentialVersion
	if materialize {
		version, err = b.source.Materialize(ctx, lease.CredentialID, lease.CredentialVersion)
		if err != nil {
			b.audit(ctx, store.AuditEvent{PrincipalID: sess.PrincipalID, SessionID: sess.ID, BindingID: binding.ID, CredentialID: cred.ID, CredentialVersion: lease.CredentialVersion, Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeCredentialUnavailable)})
			return nil, err
		}
	}
	// 交付前重校验：验证、中心裁定与取值之间可能发生撤销、停用或轮换。
	// 只有仍与这次决定一致的授权状态才允许交付，并以此阻止旧用钥决定继续生效。
	b.mu.Lock()
	if ferr := b.revalidateDelivery(ctx, lease, sess, binding, cred, grant); ferr != nil {
		b.mu.Unlock()
		b.audit(ctx, store.AuditEvent{
			PrincipalID: sess.PrincipalID, SessionID: sess.ID, BindingID: binding.ID,
			CredentialID: cred.ID, CredentialVersion: lease.CredentialVersion,
			Mode: string(req.Mode), Result: "denied", ErrorCode: string(model.CodeOf(ferr)),
			AuthMethod: authMethod, AuthResult: authResult, Detail: "delivery revalidation failed",
		})
		return nil, ferr
	}
	if b.opts.Auth != nil {
		// 校验通过后才提交验证状态，下一次用钥才能复用。
		b.opts.Auth.Commit(decision)
	}
	var execution context.Context
	entry := &liveLease{UseLease: *lease, permit: permit}
	if materialize && req.Mode == model.ModeProxy {
		execution, entry.cancel = context.WithCancel(context.Background())
	}
	b.leases[lease.ID] = entry
	leaseCopy := *lease
	b.mu.Unlock()
	b.audit(ctx, store.AuditEvent{
		SessionID: sess.ID, PrincipalID: sess.PrincipalID, BindingID: binding.ID,
		CredentialID: cred.ID, CredentialVersion: lease.CredentialVersion,
		Mode: string(req.Mode), Result: "allowed",
		DurationMS: time.Since(start).Milliseconds(), Detail: req.Purpose,
		AuthMethod: authMethod, AuthResult: authResult,
	})
	return &Authorization{Execution: execution, Lease: leaseCopy, Version: version, Session: sess, Binding: binding}, nil
}

// revalidateDelivery 在取到同版本材料之后、登记许可之前重新核对这次用钥决定的前提。
// 调用者持有 b.mu，保证锁库和会话关闭与许可提交有序。
func (b *Broker) revalidateDelivery(ctx context.Context, lease *model.UseLease, sess model.Session, binding *model.Binding, cred *model.Credential, grant *model.Grant) error {
	live, ok := b.sessions[sess.ID]
	if b.locked || b.source.Locked() {
		return model.NewError(model.CodeVaultLocked, "vault was locked while the use was being authorized")
	}
	if !ok {
		return model.NewError(model.CodeSessionInvalid, "session was closed while the use was being authorized")
	}
	if live.Status != model.StatusActive {
		return model.NewError(model.CodeSessionInvalid, "session is %s", live.Status)
	}
	if b.epoch != lease.AuthorizationEpoch {
		return model.NewError(model.CodeSessionInvalid, "authorization epoch changed while the use was being authorized")
	}
	if !b.opts.Now().Before(sess.ExpiresAt) {
		return model.NewError(model.CodeSessionInvalid, "session expired while the use was being authorized")
	}
	freshBinding, err := b.store.GetBinding(ctx, binding.ID)
	if err != nil {
		return model.NewError(model.CodeBindingDisabled, "binding %s is no longer registered", binding.ID)
	}
	if freshBinding.Status != model.StatusActive || freshBinding.Revision != lease.BindingRevision || freshBinding.UpstreamOrigin != lease.Target {
		return model.NewError(model.CodeBindingDisabled, "binding %s changed while the use was being authorized", binding.ID)
	}
	freshGrant, err := b.store.GetGrant(ctx, grant.ID)
	if err != nil {
		return model.NewError(model.CodeUseNotAllowed, "grant %s is no longer registered", grant.ID)
	}
	if freshGrant.Status != model.StatusActive || freshGrant.Revision != lease.GrantRevision {
		return model.NewError(model.CodeUseNotAllowed, "grant %s changed while the use was being authorized", grant.ID)
	}
	freshCred, err := b.store.GetCredential(ctx, cred.ID)
	if err != nil || freshCred.Status != model.StatusActive {
		return model.NewError(model.CodeCredentialUnavailable, "credential %s is no longer available", cred.ID)
	}
	if freshCred.CurrentVersion != lease.CredentialVersion {
		return model.NewError(model.CodeCredentialUnavailable,
			"credential %s was rotated to version %d while the use was being authorized", cred.ID, freshCred.CurrentVersion)
	}
	if b.source.Locked() {
		return model.NewError(model.CodeVaultLocked, "vault was locked while the use was being authorized")
	}
	if !b.opts.Now().Before(lease.UseLeaseExpiresAt) {
		return model.NewError(model.CodeLeaseExpired, "authorization expired before delivery")
	}
	return nil
}

// runCleanup 以单一带周期 goroutine 独立清理过期记录；CloseAll 会停止并等待它退出。
func (b *Broker) runCleanup() {
	defer close(b.cleanupDone)
	ticker := time.NewTicker(b.opts.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.pruneExpired(b.opts.Now())
		case <-b.cleanupStop:
			return
		}
	}
}

// pruneExpired 清理已过期或已撤销的会话与许可。长期运行的守护进程不能只增不减。
func (b *Broker) pruneExpired(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, s := range b.sessions {
		if s.Status != model.StatusActive || !now.Before(s.ExpiresAt) {
			delete(b.sessions, id)
			if s.TokenHash != "" {
				delete(b.tokenIndex, s.TokenHash)
			}
		}
	}
	for id, l := range b.leases {
		if l.Status != model.StatusActive || !now.Before(l.UseLeaseExpiresAt) {
			b.removeLease(id)
		}
	}
}

// PruneExpired 清理已过期或已撤销的会话与许可。
// 守护进程用固定间隔调用它，长期运行时不依赖下一次用钥触发清理。
func (b *Broker) PruneExpired() {
	b.pruneExpired(b.opts.Now())
}

// Lease 返回当前有效的许可。
func (b *Broker) Lease(id string) (model.UseLease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l, ok := b.leases[id]
	if !ok {
		return model.UseLease{}, store.ErrNotFound
	}
	return l.UseLease, nil
}

// removeLease is called under b.mu and wakes local executors before returning.
func (b *Broker) removeLease(leaseID string) {
	if lease := b.leases[leaseID]; lease != nil && lease.cancel != nil {
		lease.cancel()
	}
	delete(b.leases, leaseID)
}

// ReleaseLease 在调用方用完一次许可后立即释放。
// 网关为每个请求申请一次许可，不能等到会话关闭才清理；这里不额外写审计，
// 该次用钥已经由授权事件记录。
func (b *Broker) ReleaseLease(leaseID string) {
	if leaseID == "" {
		return
	}
	b.mu.Lock()
	b.removeLease(leaseID)
	b.mu.Unlock()
}

// ActiveLeaseCount 供诊断与测试使用。
func (b *Broker) ActiveLeaseCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.leases)
}

// CloseAll 停止后台清扫并撤销全部会话与许可。服务关闭或重启前调用，可重复调用。
func (b *Broker) CloseAll(ctx context.Context) {
	b.closeOnce.Do(func() {
		close(b.cleanupStop)
		<-b.cleanupDone
	})
	b.mu.Lock()
	for id := range b.sessions {
		delete(b.sessions, id)
	}
	b.tokenIndex = map[string]string{}
	for id := range b.leases {
		b.removeLease(id)
	}
	b.mu.Unlock()
	b.clearAuth("shutdown")
	b.audit(ctx, store.AuditEvent{Mode: "control", Result: "shutdown", Detail: "runtime sessions cleared"})
}

// findGrant 在同一主体、绑定与方式下选择唯一的有效授权。
// 存储层不保证唯一，这里以确定规则收敛：先看 revision 更高的，再按 ID 排序，
// 让「新增更严格策略」总是取代旧策略，而不是取决于返回顺序。
func (b *Broker) findGrant(ctx context.Context, principalID, bindingID string, mode model.DeliveryMode) (*model.Grant, error) {
	grants, err := b.store.ListGrants(ctx, principalID)
	if err != nil {
		return nil, err
	}
	var chosen *model.Grant
	for _, g := range grants {
		if g.BindingID != bindingID {
			continue
		}
		if g.Status != model.StatusActive {
			continue
		}
		if g.DeliveryMode != mode {
			continue
		}
		if chosen == nil || g.Revision > chosen.Revision || (g.Revision == chosen.Revision && g.ID < chosen.ID) {
			chosen = g
		}
	}
	if chosen == nil {
		return nil, model.NewError(model.CodeUseNotAllowed, "no %s grant for binding %s", mode, bindingID)
	}
	return chosen, nil
}

func (b *Broker) audit(ctx context.Context, e store.AuditEvent) {
	e.ID = randomID()
	e.Time = b.opts.Now()
	_ = b.store.AppendAudit(ctx, &e)
}

func randomID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return "id_" + base64.RawURLEncoding.EncodeToString(buf)
}

func randomToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return "kks_" + base64.RawURLEncoding.EncodeToString(buf)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// SetAuth 替换验证策略执行器并丢弃既有验证结果。daemon 在构造时注入，
// 测试与诊断可在运行期替换。
func (b *Broker) SetAuth(a *Authenticator) {
	b.mu.Lock()
	b.opts.Auth = a
	b.mu.Unlock()
}

// AuthCache 暴露内存验证状态，供 daemon 显式验证与诊断使用。
func (b *Broker) AuthCache() *AuthCache {
	if b.opts.Auth == nil {
		return nil
	}
	return b.opts.Auth.Cache()
}

// clearAuth 清空全部验证状态并记录审计。
func (b *Broker) clearAuth(reason string) {
	if b.opts.Auth == nil {
		return
	}
	if n := b.opts.Auth.Cache().Clear(); n > 0 {
		b.audit(context.Background(), store.AuditEvent{Mode: "control", Result: "auth_cache_cleared", AuthResult: "not_required", Detail: fmt.Sprintf("%s: %d verifications dropped", reason, n)})
	}
}

// clearAuthForSession 清空某个会话的验证状态。
func (b *Broker) clearAuthForSession(sessionID string) {
	if b.opts.Auth == nil {
		return
	}
	if n := b.opts.Auth.Cache().ClearForSession(sessionID); n > 0 {
		b.audit(context.Background(), store.AuditEvent{SessionID: sessionID, Mode: "control", Result: "auth_cache_cleared", AuthResult: "not_required", Detail: fmt.Sprintf("%d verifications dropped with session", n)})
	}
}

// InvalidateGrant ends committed uses and cached verification for a changed grant.
func (b *Broker) InvalidateGrant(ctx context.Context, grantID, reason string) {
	b.mu.Lock()
	for id, lease := range b.leases {
		if lease.GrantID == grantID {
			b.removeLease(id)
		}
	}
	var cleared int
	if b.opts.Auth != nil {
		cleared = b.opts.Auth.Cache().ClearForGrant(grantID)
	}
	b.mu.Unlock()
	if cleared > 0 {
		b.audit(ctx, store.AuditEvent{Mode: "control", Result: "auth_cache_cleared", AuthResult: "not_required", Detail: fmt.Sprintf("grant %s %s: %d verifications dropped", grantID, reason, cleared)})
	}
}

// Record 写入一条审计事件，供网关与运行器记录使用元数据。
func (b *Broker) Record(ctx context.Context, e store.AuditEvent) {
	b.audit(ctx, e)
}
