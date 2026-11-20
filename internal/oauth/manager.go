package oauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"keykoi/internal/model"
)

// Store 是 Manager 需要的凭证边界：读取当前组合、原子提交新组合、标记状态、
// 失效旧许可。生产实现由 daemon 适配 keykoi 的 store / backend / broker。
type Store interface {
	// Load 返回凭证索引与当前完整版本（秘密只在受信内存中）。
	Load(ctx context.Context, credentialID string) (model.Credential, model.CredentialVersion, error)
	// Commit 原子写入新版本并切换当前版本，且必须递增凭证记录的 revision：
	// 未提供 CommitCASer 时，Manager 用该增量核对提交窗口内是否发生过并行写。
	Commit(ctx context.Context, credentialID string, version model.CredentialVersion) (*model.Credential, error)
	// MarkStatus 仅在 revision 仍匹配时更新状态；0 表示调用方没有版本预期。
	MarkStatus(ctx context.Context, credentialID string, status model.EntityStatus, expectedRevision int64) error
	// RevokeLeases 使该凭证关联的既有许可失效，返回失效数量。
	RevokeLeases(ctx context.Context, credentialID string) int
}

// CommitCASer 是 Store 可选的“带预期版本的提交”能力。Manager 写入新版本时优先
// 使用它，把“确认记录未变”与“写入新版本”合并为一次原子提交。
//
// 契约：
//   - revision 必须随凭证记录的任意改动递增（切换当前版本、修改状态、同步到期时间），
//     这样管理员停用与并行轮换都会让 expectedRevision 失效；
//   - expectedRevision 必须精确匹配（0 也是有效预期，不表示“没有预期”）；
//     不匹配时不写入任何内容，返回包装了 ErrCommitConflict 的错误；
//   - 成功时返回写入后的凭证记录，且 revision 恰好比 expectedRevision 大 1。
//
// Store 实现者未提供该能力时，Manager 退回现有流程：写前再读一次记录、Commit、
// 写后核对 revision 增量。回退流程同样不会重新激活管理员停用的凭证，但在提交
// 窗口内无法阻止版本被写入，只能把结果报告为冲突。
type CommitCASer interface {
	CommitCAS(ctx context.Context, credentialID string, expectedRevision int64, version model.CredentialVersion) (*model.Credential, error)
}

// ErrCommitConflict 由 CommitCAS 实现返回（可包装），表示预期 revision 已经失效、
// 本次没有写入任何内容。
var ErrCommitConflict = errors.New("oauth: credential revision changed before the commit")

// RefreshOptions 控制一次刷新是否被强制以及调用方观察到的版本。
type RefreshOptions struct {
	// Force 忽略缓存有效期，仍然只在同一 Credential 的一次推进内执行。
	Force bool
	// ExpectVersion 是调用方发起请求时看到的当前版本。取得串行锁后若版本已经
	// 推进，说明另一个轮换已完成，本次不调用上游、不写入，并返回冲突错误
	// （ClassConflict，Code=version_conflict）。
	ExpectVersion int
}

// Result 是登录/刷新/状态查询的元数据结果，永远不含 token 原文。
type Result struct {
	CredentialID   string             `json:"credential_id"`
	Version        int                `json:"version"`
	Status         model.EntityStatus `json:"status"`
	ExpiresAt      *time.Time         `json:"provider_expires_at,omitempty"`
	CacheExpiresAt *time.Time         `json:"cache_expires_at,omitempty"`
	Expired        bool               `json:"expired"`
	TokenType      string             `json:"token_type,omitempty"`
	// Refreshed 报告本次调用是否真的推进了上游刷新或登录。
	Refreshed bool `json:"refreshed"`
	// Rotated 报告本次是否轮换了 refresh_token。
	Rotated bool `json:"refresh_token_rotated"`
	// RevokedLeases 是版本切换后失效的既有许可数量。
	RevokedLeases int `json:"revoked_leases"`
	// RecoveryRequired / NextAction 让失败状态可见：
	// none / refresh / reauth。
	RecoveryRequired bool   `json:"recovery_required"`
	NextAction       string `json:"next_action"`
	// Provider 是本次使用的提供方形态标识。
	Provider string `json:"provider"`
}

// ProviderKind 是本次实现选定的提供方形态。
const ProviderKind = "oauth2_authorization_code_pkce"

// Manager 把串行刷新、版本提交与失败恢复组合成一次受信操作。
type Manager struct {
	// Service 执行上游协议交互。
	Service *Service
	// Store 是凭证边界。
	Store Store
	// LockFn 返回 Credential 级互斥锁；daemon 传入 d.oauth.Lock。
	LockFn func(credentialID string) *sync.Mutex
	// States 是跨请求的运行时状态（恢复标记）。
	States *StateStore
	// Now 便于测试注入时钟。
	Now func() time.Time
	// Skew 是缓存有效期余量，缺省 30s。
	Skew time.Duration

	fallbackMu sync.Mutex
	fallback   map[string]*sync.Mutex
}

func (m *Manager) service() *Service {
	if m.Service == nil {
		m.Service = NewService()
	}
	return m.Service
}

func (m *Manager) states() *StateStore {
	if m.States == nil {
		m.States = NewStateStore()
	}
	return m.States
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) skew() time.Duration {
	if m.Skew > 0 {
		return m.Skew
	}
	return DefaultSkew
}

// lock 取得 Credential 级串行锁。
func (m *Manager) lock(credentialID string) func() {
	var mu *sync.Mutex
	if m.LockFn != nil {
		mu = m.LockFn(credentialID)
	} else {
		m.fallbackMu.Lock()
		if m.fallback == nil {
			m.fallback = map[string]*sync.Mutex{}
		}
		l, ok := m.fallback[credentialID]
		if !ok {
			l = &sync.Mutex{}
			m.fallback[credentialID] = l
		}
		mu = l
		m.fallbackMu.Unlock()
	}
	mu.Lock()
	return mu.Unlock
}

func (m *Manager) metadata(cred model.Credential, version model.CredentialVersion) Result {
	res := Result{
		CredentialID:   cred.ID,
		Version:        cred.CurrentVersion,
		Status:         cred.Status,
		ExpiresAt:      version.ProviderExpiresAt,
		CacheExpiresAt: CacheExpiry(version.ProviderExpiresAt, m.skew()),
		Provider:       ProviderKind,
	}
	if raw, err := version.Field(FieldTokenType); err == nil {
		res.TokenType = raw.RevealString()
	}
	res.Expired = m.stale(version.ProviderExpiresAt)
	if _, ok := m.states().Recovery(cred.ID); ok || cred.Status == model.StatusRecovery {
		res.RecoveryRequired = true
	}
	switch {
	case res.RecoveryRequired, cred.Status == model.StatusRevoked:
		res.NextAction = "reauth"
	case res.Expired:
		res.NextAction = "refresh"
	default:
		res.NextAction = "none"
	}
	return res
}

// stale 报告凭证是否已到需要刷新的时刻（真实到期减时钟余量）。
func (m *Manager) stale(expiresAt *time.Time) bool {
	if expiresAt == nil {
		return false
	}
	return !m.now().Add(m.skew()).Before(*expiresAt)
}

// Status 返回当前元数据，不访问上游、不写任何状态。
func (m *Manager) Status(ctx context.Context, credentialID string) (Result, error) {
	cred, version, err := m.Store.Load(ctx, credentialID)
	if err != nil {
		return Result{CredentialID: credentialID, Provider: ProviderKind}, err
	}
	if cred.Kind != model.KindOAuth {
		return m.metadata(cred, version), configError("credential %s is kind %q, not %q", cred.ID, cred.Kind, model.KindOAuth)
	}
	return m.metadata(cred, version), nil
}

// BeginAuthorization 生成受信授权入口，PKCE verifier 留在中介内存。
func (m *Manager) BeginAuthorization(ctx context.Context, credentialID string) (Authorization, error) {
	cred, version, err := m.Store.Load(ctx, credentialID)
	if err != nil {
		return Authorization{}, err
	}
	if cred.Kind != model.KindOAuth {
		return Authorization{}, configError("credential %s is kind %q, not %q", cred.ID, cred.Kind, model.KindOAuth)
	}
	cfg, err := ConfigFromVersion(version)
	if err != nil {
		return Authorization{}, err
	}
	// 把发起时刻的记录版本与状态登记进待完成授权：回调提交时据此拒绝
	// 覆盖等待期间的管理员停用或并行轮换。
	return m.service().Begin(cfg, credentialID, BeginBinding{
		Version:  cred.CurrentVersion,
		Revision: cred.Revision,
		Status:   cred.Status,
	})
}

// CompleteAuthorization 用回调代码完成交换、原子写入新版本并失效旧许可。
// 成功即清除恢复标记；只有发起登录时的记录状态未被改动过，才把 revoked /
// recovery_required 拉回 active。
func (m *Manager) CompleteAuthorization(ctx context.Context, credentialID, state, code string) (Result, error) {
	release := m.lock(credentialID)
	defer release()

	empty := Result{CredentialID: credentialID, Provider: ProviderKind}
	cred, version, err := m.Store.Load(ctx, credentialID)
	if err != nil {
		return empty, err
	}
	res := m.metadata(cred, version)
	if cred.Kind != model.KindOAuth {
		return res, configError("credential %s is kind %q, not %q", cred.ID, cred.Kind, model.KindOAuth)
	}
	pending, ok := m.service().Pending.Take(state)
	if !ok {
		return res, reauthError("exchange", "state is unknown, already used, or expired; restart the login flow")
	}
	if !EqualState(pending.State, state) {
		return res, reauthError("exchange", "state does not match the pending authorization")
	}
	if pending.CredentialID != credentialID {
		return res, reauthError("exchange", "state belongs to a different credential")
	}
	// 回调绑定校验必须在读取当前版本配置与交换代码之前完成：记录已被管理员
	// 停用或被并行轮换改过时，本次登录作废，不再向上游换取 token。
	if err := pendingBindingError(cred, pending); err != nil {
		res.NextAction = "reauth"
		return res, err
	}
	cfg, err := ConfigFromVersion(version)
	if err != nil {
		return res, err
	}
	tokens, err := m.service().Exchange(ctx, cfg, code, pending.CodeVerifier, pending.RedirectURI)
	if err != nil {
		return res, err
	}
	// 绑定校验已确认状态未被改动，重新登录可以把 revoked / recovery_required
	// 拉回 active；管理员在等待期间的停用不会走到这里。
	return m.commitTokens(ctx, cred, version, tokens, "login", res, true)
}

// pendingBindingError 校验发起登录时登记的记录状态是否仍然成立。
// 等待回调期间管理员停用凭证、手工轮换推进版本或有并行登录提交时，
// 返回冲突错误并放弃本次更新，保留管理员写入的停用状态。
func pendingBindingError(cred model.Credential, pending Pending) error {
	if pending.Version == 0 {
		// 没有登记绑定的待完成授权（旧调用点）：保持原有行为。
		return nil
	}
	if pending.Version != cred.CurrentVersion || pending.Revision != cred.Revision {
		return conflictError("exchange", CodeCredentialChanged,
			"credential %s changed while the authorization was in flight (version %d→%d, revision %d→%d); the in-flight login was discarded and the current record kept",
			cred.ID, pending.Version, cred.CurrentVersion, pending.Revision, cred.Revision)
	}
	if pending.Status != "" && pending.Status != cred.Status {
		return conflictError("exchange", CodeCredentialChanged,
			"credential %s status changed from %q to %q while the authorization was in flight; the in-flight login will not override it",
			cred.ID, pending.Status, cred.Status)
	}
	return nil
}

// Refresh 串行刷新同一 Credential：
//  1. 取得凭证级锁，重新读取当前版本（不信任调用方拿到的旧版本）；
//  2. 预期版本已推进时返回冲突，缓存仍新鲜时直接返回元数据，都不调用上游；
//  3. 调用上游刷新，成功后原子写入完整新组合；
//  4. 本地提交失败时标记 recovery_required，并让错误携带该状态。
func (m *Manager) Refresh(ctx context.Context, credentialID string, opts RefreshOptions) (Result, error) {
	release := m.lock(credentialID)
	defer release()

	empty := Result{CredentialID: credentialID, Provider: ProviderKind}
	cred, version, err := m.Store.Load(ctx, credentialID)
	if err != nil {
		return empty, err
	}
	res := m.metadata(cred, version)
	if cred.Kind != model.KindOAuth {
		return res, configError("credential %s is kind %q, not %q", cred.ID, cred.Kind, model.KindOAuth)
	}
	if mark, ok := m.states().Recovery(cred.ID); ok {
		// 运行时标记优先：即使状态写入失败，恢复要求也必须可见且阻止继续刷新。
		res.RecoveryRequired = true
		res.Status = model.StatusRecovery
		res.NextAction = "reauth"
		return res, newError(ClassRecovery, "refresh", "", 0, nil,
			"credential %s is recovery_required (%s at version %d); re-authorize", cred.ID, mark.Reason, mark.Version)
	}
	switch cred.Status {
	case model.StatusActive:
	case model.StatusRecovery:
		return res, newError(ClassRecovery, "refresh", "", 0, nil,
			"credential %s is recovery_required: the previous refresh rotated upstream tokens but the local commit failed; re-authorize", cred.ID)
	case model.StatusRevoked:
		return res, reauthError("refresh", "credential "+cred.ID+" is revoked; re-authorization is required")
	default:
		return res, configError("credential %s is %s and cannot be refreshed", cred.ID, cred.Status)
	}
	if opts.ExpectVersion > 0 && opts.ExpectVersion != cred.CurrentVersion {
		// 排队期间版本已被推进。当前版本仍新鲜时（典型情况是另一次刷新刚完成），
		// 本次本来就没有可做的工作：按成功返回元数据，不写任何东西。
		if !m.stale(version.ProviderExpiresAt) {
			res.NextAction = "none"
			return res, nil
		}
		// 推进后仍然过期或不可用：不能判断推进方做了什么（例如手工轮换），
		// 以冲突结果要求调用方重新读取后再决定。
		res.NextAction = nextActionFor(res, true)
		return res, conflictError("refresh", CodeVersionConflict,
			"credential %s advanced to version %d while the refresh was queued (expected %d); re-read the credential before retrying",
			cred.ID, cred.CurrentVersion, opts.ExpectVersion)
	}
	if !opts.Force && !m.stale(version.ProviderExpiresAt) {
		return res, nil
	}
	cfg, err := ConfigFromVersion(version)
	if err != nil {
		return res, err
	}
	refreshToken, err := version.Field(FieldRefreshToken)
	if err != nil {
		return res, reauthError("refresh", "credential "+cred.ID+" has no refresh_token; re-authorization is required")
	}
	tokens, err := m.service().Refresh(ctx, cfg, refreshToken)
	if err != nil {
		// 撤销是持久事实：标记 revoked，让后续使用与状态查询都能看到。
		if NeedsReauth(err) {
			if markErr := m.Store.MarkStatus(ctx, credentialID, model.StatusRevoked, cred.Revision); markErr == nil {
				res.Status = model.StatusRevoked
				res.NextAction = "reauth"
			}
		}
		return res, err
	}
	return m.commitTokens(ctx, cred, version, tokens, "refresh", res, false)
}

func nextActionFor(res Result, stale bool) string {
	switch {
	case res.RecoveryRequired, res.Status == model.StatusRevoked:
		return "reauth"
	case stale:
		return "refresh"
	default:
		return "none"
	}
}

// commitTokens 把上游成功的结果原子写入新版本；提交失败即进入可见恢复状态。
// reactivate 只在发起登录时的记录状态未被改动（由回调绑定校验保证）时为 true。
//
// 提交顺序：
//  1. 写前再读一次记录，读取失败即中止（不写版本、不回退状态）；
//  2. 版本、修订号或状态已变即冲突，不写入；
//  3. 带预期 revision 的 CAS 提交（Store 提供 CommitCASer 时）；CAS 拒绝即
//     不写入、不激活；未提供时退回 Commit，并在写后核对 revision 增量；
//  4. 只有提交窗口内没有并行写、且发起时观察到的状态仍是当前状态，才允许重新激活。
func (m *Manager) commitTokens(ctx context.Context, cred model.Credential, version model.CredentialVersion, tokens TokenSet, op string, res Result, reactivate bool) (Result, error) {
	now := m.now()
	// 写前再读一次记录：版本、修订号或状态已经变化说明有并行轮换或管理员
	// 更新，此时放弃写入，避免用旧快照覆盖对方的结果。读取失败同样中止。
	current, _, loadErr := m.Store.Load(ctx, cred.ID)
	if loadErr != nil {
		return m.commitFailure(ctx, cred, op, res, now, loadErr)
	}
	if current.CurrentVersion != cred.CurrentVersion || current.Revision != cred.Revision || current.Status != cred.Status {
		res.NextAction = nextActionFor(res, m.stale(version.ProviderExpiresAt))
		return res, conflictError(op+" commit", CodeCredentialChanged,
			"credential %s changed during %s (version %d→%d, revision %d→%d, status %q→%q); the stale update was discarded",
			cred.ID, op, cred.CurrentVersion, current.CurrentVersion,
			cred.Revision, current.Revision, cred.Status, current.Status)
	}
	expiresAt := tokens.ExpiresAt(now)
	next := model.CredentialVersion{
		CredentialID:      cred.ID,
		Version:           cred.CurrentVersion + 1,
		Fields:            versionFields(version.Fields, tokens),
		ProviderExpiresAt: expiresAt,
	}
	// 提交与“记录未被改动”的核对必须在一次原子操作内完成：检查与写入之间不再
	// 留窗口，管理员在这个窗口里的停用不会被覆盖。
	updated, atomic, commitErr := m.commitVersion(ctx, cred, next)
	if commitErr != nil {
		// CAS 明确拒绝，或写入失败后记录已被并行改动：都以冲突收尾，不激活。
		if errors.Is(commitErr, ErrCommitConflict) || m.recordChanged(ctx, cred) {
			return m.conflictAfterChange(ctx, cred, res, op+" commit", CodeCredentialChanged,
				"credential %s changed while %s was committing (expected revision %d); the update was discarded",
				cred.ID, op, cred.Revision)
		}
		return m.commitFailure(ctx, cred, op, res, now, commitErr)
	}
	if updated == nil {
		return m.commitFailure(ctx, cred, op, res, now, errors.New("commit returned no credential record"))
	}

	revoked := m.Store.RevokeLeases(ctx, cred.ID)
	m.states().Clear(cred.ID)
	m.states().NoteFresh(cred.ID, updated.CurrentVersion)

	res.Version = updated.CurrentVersion
	res.Status = updated.Status
	res.ExpiresAt = expiresAt
	res.CacheExpiresAt = CacheExpiry(expiresAt, m.skew())
	res.Expired = m.stale(expiresAt)
	res.Refreshed = true
	res.Rotated = tokens.Rotated && !tokens.RefreshToken.IsEmpty()
	res.RevokedLeases = revoked
	res.RecoveryRequired = false
	if tokens.TokenType != "" {
		res.TokenType = tokens.TokenType
	}
	res.NextAction = "none"

	// 回退流程（Store 未提供 CAS）无法原子拒绝窗口内的并行写：提交后用 revision
	// 增量核对，发现并行写就以冲突收尾，并且不再重新激活。
	if !atomic && (updated.Revision != cred.Revision+1 || updated.CurrentVersion != next.Version) {
		res.NextAction = "reauth"
		return m.conflictAfterChange(ctx, cred, res, op+" commit", CodeCredentialChanged,
			"credential %s changed during the non-atomic commit (revision %d→%d); the concurrent writer's status was preserved",
			cred.ID, cred.Revision, updated.Revision)
	}

	if reactivate && res.Status != model.StatusActive && res.Status != "" {
		// 只有“本次登录开始时观察到的状态”仍是当前状态才允许激活：管理员在
		// 检查/提交窗口内改成 disabled / revoked 时保留管理员状态。
		if updated.Status != cred.Status {
			res.NextAction = "reauth"
			return m.conflictAfterChange(ctx, cred, res, op+" reactivate", CodeCredentialChanged,
				"credential %s status changed from %q to %q before reactivation; the newer status was preserved",
				cred.ID, cred.Status, updated.Status)
		}
		// 只有提交产生的 revision 仍未变化才能重新激活；管理员随后的停用优先，
		// 这里不重试，直接把更晚的状态报告给调用方。
		if markErr := m.Store.MarkStatus(ctx, cred.ID, model.StatusActive, updated.Revision); markErr != nil {
			res.NextAction = "reauth"
			if current, _, currentErr := m.Store.Load(ctx, cred.ID); currentErr == nil {
				res.Status = current.Status
				res.Version = current.CurrentVersion
			}
			return res, conflictError(op+" reactivate", CodeCredentialChanged,
				"credential %s changed after the token commit; the newer credential status was preserved", cred.ID)
		}
		res.Status = model.StatusActive
	}
	if res.Status != model.StatusActive && res.Status != "" {
		// 没有重新激活的调用（例如刷新）不应把停用记录描述成可继续使用。
		res.NextAction = "reauth"
	}
	return res, nil
}

// commitVersion 提交新版本，优先使用 Store 可选的 CAS 能力。
// atomic 报告本次提交是否由“带 revision 预期”的实现保证；未提供 CAS 时退回
// Commit，由调用方在写后核对 revision 增量。
func (m *Manager) commitVersion(ctx context.Context, cred model.Credential, next model.CredentialVersion) (*model.Credential, bool, error) {
	if cas, ok := m.Store.(CommitCASer); ok {
		updated, err := cas.CommitCAS(ctx, cred.ID, cred.Revision, next)
		return updated, true, err
	}
	updated, err := m.Store.Commit(ctx, cred.ID, next)
	return updated, false, err
}

// recordChanged 重新读取记录，报告它是否已偏离本次操作的快照。
func (m *Manager) recordChanged(ctx context.Context, cred model.Credential) bool {
	latest, _, err := m.Store.Load(ctx, cred.ID)
	if err != nil {
		return false
	}
	return latest.CurrentVersion != cred.CurrentVersion || latest.Revision != cred.Revision || latest.Status != cred.Status
}

// conflictAfterChange 用当前记录刷新结果并返回冲突错误：写入被放弃或与并行写
// 相撞时，调用方必须看到真实的版本与状态，而不是自己的旧快照。
func (m *Manager) conflictAfterChange(ctx context.Context, cred model.Credential, res Result, op, code, format string, args ...any) (Result, error) {
	if latest, latestVersion, err := m.Store.Load(ctx, cred.ID); err == nil {
		res.Version = latest.CurrentVersion
		res.Status = latest.Status
		res.ExpiresAt = latestVersion.ProviderExpiresAt
		res.CacheExpiresAt = CacheExpiry(latestVersion.ProviderExpiresAt, m.skew())
		res.Expired = m.stale(latestVersion.ProviderExpiresAt)
	}
	res.NextAction = nextActionFor(res, res.Expired)
	return res, conflictError(op, code, format, args...)
}

func (m *Manager) commitFailure(ctx context.Context, cred model.Credential, op string, res Result, now time.Time, cause error) (Result, error) {
	m.states().MarkRecovery(cred.ID, RecoveryMark{
		At: now, Reason: "commit_failed", Version: cred.CurrentVersion, NextAction: "reauth",
		Detail: "upstream rotated tokens but the new credential version could not be persisted",
	})
	_ = m.Store.MarkStatus(ctx, cred.ID, model.StatusRecovery, cred.Revision)
	res.RecoveryRequired = true
	res.Status = model.StatusRecovery
	res.NextAction = "reauth"
	oauthErr := newError(ClassRecovery, op+" commit", "", 0, cause,
		"upstream %s succeeded but the local version commit failed; credential is recovery_required", op)
	oauthErr.Version = cred.CurrentVersion
	return res, oauthErr
}

// Describe 返回不含秘密的实现摘要。
func (m *Manager) Describe() string {
	// 提交路径影响并发语义，诊断时需要能看出当前 Store 是否提供 CAS。
	commitPath := "fallback"
	if _, ok := m.Store.(CommitCASer); ok {
		commitPath = "cas"
	}
	return fmt.Sprintf("oauth manager: provider=%s skew=%s serialized_by_credential=true commit=%s", ProviderKind, m.skew(), commitPath)
}
