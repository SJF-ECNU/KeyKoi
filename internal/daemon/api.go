package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

// Version 是当前构建版本标识。
const Version = "0.1.0"

func cryptoRand(b []byte) (int, error) { return rand.Read(b) }

// bootstrapPrincipals 建立本机管理主体与普通用钥主体。二者权限分开评估。
func (d *Daemon) bootstrapPrincipals(ctx context.Context) error {
	uid := os.Getuid()
	adminID := fmt.Sprintf("principal_admin_local_%d", uid)
	localID := localPrincipalID()
	if _, err := d.store.GetPrincipal(ctx, adminID); err != nil {
		if err := d.store.PutPrincipal(ctx, &store.Principal{
			ID: adminID, IdentityType: "local_user",
			IdentityReference: fmt.Sprintf("macos-uid:%d", uid), Status: model.StatusActive, Admin: true,
		}); err != nil {
			return err
		}
	}
	if _, err := d.store.GetPrincipal(ctx, localID); err != nil {
		if err := d.store.PutPrincipal(ctx, &store.Principal{
			ID: localID, IdentityType: "local_user",
			IdentityReference: fmt.Sprintf("macos-uid:%d", uid), Status: model.StatusActive, Admin: false,
		}); err != nil {
			return err
		}
	}
	for _, subject := range d.builtinSubjects()[1:] {
		if _, err := d.store.GetPrincipal(ctx, subject.ID); err != nil {
			if err := d.store.PutPrincipal(ctx, &store.Principal{
				ID: subject.ID, IdentityType: "local_agent", IdentityReference: subject.Key, Status: model.StatusActive,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Daemon) adminPrincipalID() string {
	return fmt.Sprintf("principal_admin_local_%d", os.Getuid())
}

func localPrincipalID() string {
	return fmt.Sprintf("principal_local_%d", os.Getuid())
}

// requireAdmin 校验调用方拥有本机管理权：0600 管理令牌或管理员会话。
func (d *Daemon) requireAdmin(r *http.Request) (string, error) {
	if tok := r.Header.Get("X-KeyKoi-Admin"); tok != "" && subtleEqual(tok, d.adminToken) {
		return d.adminPrincipalID(), nil
	}
	if s := bearerToken(r); s != "" {
		sess, err := d.broker.RequireAdmin(r.Context(), secret.New(s))
		if err != nil {
			return "", err
		}
		return sess.PrincipalID, nil
	}
	return "", model.NewError(model.CodeSessionInvalid, "management requests require local administrator authentication")
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.Header.Get("X-KeyKoi-Session")
}

// controlPrincipal returns an empty scope only for authenticated administrative requests.
func (d *Daemon) controlPrincipal(r *http.Request) (string, error) {
	if r.Header.Get("X-KeyKoi-Admin") != "" || bearerToken(r) != "" {
		_, err := d.requireAdmin(r)
		return "", err
	}
	subject, err := d.currentSubject(r)
	return subject.ID, err
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return model.NewError("", "invalid JSON body")
	}
	return nil
}

func (d *Daemon) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	var body struct {
		Purpose    string `json:"purpose"`
		AdminProof string `json:"admin_proof"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	principal := d.adminPrincipalID()
	if body.AdminProof != "" {
		if !subtleEqual(body.AdminProof, d.adminToken) {
			writeAPIError(w, model.NewError(model.CodeSessionInvalid, "administrator proof did not match"))
			return
		}
	} else {
		subject, err := d.currentSubject(r)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		principal = subject.ID
	}
	ttl := time.Duration(body.TTLSeconds) * time.Second
	sess, token, err := d.broker.CreateSessionTTL(r.Context(), principal, body.Purpose, ttl)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"session": sess,
		"token":   token.RevealString(),
	})
}

func (d *Daemon) handleSessionClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	principal, err := d.controlPrincipal(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		SessionID string `json:"session_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := d.broker.CloseSessionForPrincipal(r.Context(), body.SessionID, principal); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"closed": body.SessionID})
}

// handleResolve 交付一次完整凭证版本。它只服务 runtime_delivery：
// 签名模式需要的是协议结果或单类密钥材料，不得通过通用解析取得整组字段。
func (d *Daemon) handleResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	var body struct {
		Token     string `json:"token"`
		BindingID string `json:"binding_id"`
		Route     string `json:"route"`
		Mode      string `json:"mode"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	mode := model.DeliveryMode(body.Mode)
	if mode == "" {
		mode = model.ModeRuntimeDelivery
	}
	if mode != model.ModeRuntimeDelivery {
		// 拒绝也要留审计：这条路径上的尝试说明有人想用签名许可换取原始字段，
		// 只记方式与错误码，不记请求内容。
		d.broker.Record(r.Context(), store.AuditEvent{
			Mode: string(mode), Result: "denied", ErrorCode: string(model.CodeUseNotAllowed),
			Detail: "raw delivery refused: only runtime_delivery may use the generic resolve endpoint",
		})
		writeAPIError(w, model.NewError(model.CodeUseNotAllowed,
			"raw credential delivery is limited to runtime_delivery; sign grants are delivered by their protocol or key-material endpoints"))
		return
	}
	authz, err := d.broker.Authorize(r.Context(), brokerRequest(body.Token, body.BindingID, body.Route, mode, "ipc resolve"))
	if err != nil {
		writeAPIError(w, err)
		return
	}
	fields := map[string]string{}
	if allowed := authz.Binding.RuntimeFields; allowed != nil {
		for _, name := range allowed {
			if value, ok := authz.Version.Fields[name]; ok {
				fields[name] = value.RevealString()
			}
		}
	} else {
		for name, value := range authz.Version.Fields {
			fields[name] = value.RevealString()
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"lease":               authz.Lease,
		"credential_id":       authz.Lease.CredentialID,
		"credential_version":  authz.Lease.CredentialVersion,
		"fields":              fields,
		"binding":             authz.Binding,
		"provider_expires_at": authz.Lease.ProviderCredentialExpiresAt,
	})
}

func (d *Daemon) handleUseLeases(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token     string `json:"token"`
		BindingID string `json:"binding_id"`
		Route     string `json:"route"`
		Mode      string `json:"mode"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	mode := model.DeliveryMode(body.Mode)
	lease, err := d.broker.AuthorizeMetadata(r.Context(), brokerRequest(body.Token, body.BindingID, body.Route, mode, "lease metadata"))
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lease": lease})
}

func (d *Daemon) handleUseLeaseRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	principal, err := d.controlPrincipal(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		LeaseID string `json:"lease_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := d.broker.RevokeLeaseForPrincipal(r.Context(), body.LeaseID, principal); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": body.LeaseID})
}

type credentialCreateRequest struct {
	Kind              string            `json:"kind"`
	Label             string            `json:"label"`
	Fields            map[string]string `json:"fields"`
	ProviderExpiresAt *time.Time        `json:"provider_expires_at"`
}

func (d *Daemon) handleCredentials(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		creds, err := d.store.ListCredentials(r.Context())
		if err != nil {
			writeAPIError(w, err)
			return
		}
		out := make([]map[string]any, 0, len(creds))
		for _, c := range creds {
			out = append(out, credentialMetadata(c))
		}
		writeJSON(w, http.StatusOK, map[string]any{"credentials": out})
	case http.MethodPost:
		if _, err := d.requireAdmin(r); err != nil {
			writeAPIError(w, err)
			return
		}
		var body credentialCreateRequest
		if err := decodeJSON(r, &body); err != nil {
			writeAPIError(w, err)
			return
		}
		if body.Kind == "" || body.Label == "" || len(body.Fields) == 0 {
			writeAPIError(w, model.NewError("", "kind, label and fields are required"))
			return
		}
		fields := map[string]secret.Value{}
		for k, v := range body.Fields {
			fields[k] = secret.New(v)
		}
		meta := model.Credential{
			ID:                "cred_" + randomSuffix(),
			Kind:              model.CredentialKind(body.Kind),
			Label:             body.Label,
			CurrentVersion:    1,
			Status:            model.StatusActive,
			ProviderExpiresAt: body.ProviderExpiresAt,
		}
		version := model.CredentialVersion{
			CredentialID: meta.ID, Version: 1, Fields: fields, ProviderExpiresAt: body.ProviderExpiresAt,
		}
		created, err := d.backend.CreateCredential(r.Context(), meta, version)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, credentialMetadata(created))
	default:
		writeAPIError(w, model.NewError("", "method not allowed"))
	}
}

func (d *Daemon) handleCredentialItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/credentials/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" {
		writeAPIError(w, model.NewError("", "credential id is required"))
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		c, err := d.store.GetCredential(r.Context(), id)
		if err != nil {
			writeAPIError(w, model.NewError(model.CodeCredentialUnavailable, "credential not found"))
			return
		}
		writeJSON(w, http.StatusOK, credentialMetadata(c))
		return
	}
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	if len(parts) == 2 && parts[1] == "versions" && r.Method == http.MethodPost {
		var body credentialCreateRequest
		if err := decodeJSON(r, &body); err != nil {
			writeAPIError(w, err)
			return
		}
		fields := map[string]secret.Value{}
		for k, v := range body.Fields {
			fields[k] = secret.New(v)
		}
		c, err := d.store.GetCredential(r.Context(), id)
		if err != nil {
			writeAPIError(w, model.NewError(model.CodeCredentialUnavailable, "credential not found"))
			return
		}
		version := model.CredentialVersion{
			CredentialID: id, Version: c.CurrentVersion + 1, Fields: fields, ProviderExpiresAt: body.ProviderExpiresAt,
		}
		// OAuth 凭证的轮换与刷新/回调共用同一把凭证级锁：否则管理员的轮换
		// 会插进回调的「检查—提交」窗口，被回调的旧快照覆盖。
		unlock := d.lockOAuthCredential(id, c.Kind)
		updated, err := d.backend.AddVersion(r.Context(), id, version)
		unlock()
		if err != nil {
			writeAPIError(w, err)
			return
		}
		// 版本切换使旧许可失效。
		d.broker.RevokeForCredential(r.Context(), id)
		writeJSON(w, http.StatusOK, credentialMetadata(updated))
		return
	}
	if len(parts) == 2 && parts[1] == "disable" && r.Method == http.MethodPost {
		// 停用同样在 OAuth 凭证锁内完成，回调不会把管理员的停用改回 active。
		kind := model.CredentialKind("")
		if existing, err := d.store.GetCredential(r.Context(), id); err == nil {
			kind = existing.Kind
		}
		unlock := d.lockOAuthCredential(id, kind)
		err := d.store.UpdateCredentialStatus(r.Context(), id, model.StatusDisabled, 0)
		unlock()
		if err != nil {
			writeAPIError(w, err)
			return
		}
		d.broker.RevokeForCredential(r.Context(), id)
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": model.StatusDisabled})
		return
	}
	writeAPIError(w, model.NewError("", "unsupported credential operation"))
}

// lockOAuthCredential 对 OAuth 凭证取得与刷新/回调同一把凭证级锁，返回解锁函数。
// 其他类型的凭证没有并发窗口，直接返回空操作。
func (d *Daemon) lockOAuthCredential(credentialID string, kind model.CredentialKind) func() {
	if kind != model.KindOAuth || d.oauth == nil {
		return func() {}
	}
	lock := d.oauth.Lock(credentialID)
	lock.Lock()
	return lock.Unlock
}

func credentialMetadata(c *model.Credential) map[string]any {
	fields := model.FieldSpecs(c.Kind)
	out := map[string]any{
		"id":                             c.ID,
		"kind":                           c.Kind,
		"label":                          c.Label,
		"current_version":                c.CurrentVersion,
		"status":                         c.Status,
		"revision":                       c.Revision,
		"fields":                         fields,
		"provider_credential_expires_at": c.ProviderExpiresAt,
	}
	return out
}

func (d *Daemon) handleBindings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		bs, err := d.store.ListBindings(r.Context())
		if err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"bindings": bs})
	case http.MethodPost:
		if _, err := d.requireAdmin(r); err != nil {
			writeAPIError(w, err)
			return
		}
		var b model.Binding
		if err := decodeJSON(r, &b); err != nil {
			writeAPIError(w, err)
			return
		}
		if b.ID == "" || b.CredentialID == "" || b.UpstreamOrigin == "" || !b.AuthScheme.Valid() {
			writeAPIError(w, model.NewError("", "id, credential_id, upstream_origin and valid auth_scheme are required"))
			return
		}
		if b.Status == "" {
			b.Status = model.StatusActive
		}
		if _, err := b.Target(); err != nil {
			writeAPIError(w, model.NewError("", "%v", err))
			return
		}
		// 路由必须唯一：两条有效绑定共用同一路由时，按路由查找的结果取决于存储顺序。
		if b.Route != "" {
			if existing, err := d.store.GetBindingByRoute(r.Context(), b.Route); err == nil && existing != nil && existing.ID != b.ID {
				if existing.Status == model.StatusActive {
					writeAPIError(w, model.NewError(model.CodeConfigDrift,
						"route %q is already served by active binding %s", b.Route, existing.ID))
					return
				}
			}
		}
		if err := d.store.PutBinding(r.Context(), &b); err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, b)
	default:
		writeAPIError(w, model.NewError("", "method not allowed"))
	}
}

// handleBindingItem 返回单个登记绑定的元数据。
//
// 代理在既有连接的整个生命周期里要能廉价地发现改绑：它只需要 revision 与
// status，不应为了这个目的重复列出全部绑定或重新取值。
func (d *Daemon) handleBindingItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/bindings/")
	if id == "" || strings.Contains(id, "/") {
		writeAPIError(w, model.NewError("", "binding id is required"))
		return
	}
	b, err := d.store.GetBinding(r.Context(), id)
	if err != nil {
		writeAPIError(w, model.NewError(model.CodeBindingDisabled, "binding %s is not registered", id))
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (d *Daemon) handleGrants(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		principal := r.URL.Query().Get("principal_id")
		gs, err := d.store.ListGrants(r.Context(), principal)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"grants": gs})
	case http.MethodPost:
		if _, err := d.requireAdmin(r); err != nil {
			writeAPIError(w, err)
			return
		}
		var body struct {
			PrincipalID     string `json:"principal_id"`
			BindingID       string `json:"binding_id"`
			DeliveryMode    string `json:"delivery_mode"`
			MaxLeaseSeconds int64  `json:"max_lease_seconds"`
			AuthRequirement string `json:"auth_requirement"`
			Admin           bool   `json:"admin"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeAPIError(w, err)
			return
		}
		if !strings.HasPrefix(body.PrincipalID, "principal_") {
			subjects, err := d.subjects(r.Context())
			if err != nil {
				writeAPIError(w, err)
				return
			}
			for _, subject := range subjects {
				if strings.EqualFold(body.PrincipalID, subject.Key) {
					body.PrincipalID = subject.ID
					break
				}
			}
		}
		if _, err := d.store.GetPrincipal(r.Context(), body.PrincipalID); err != nil {
			writeAPIError(w, model.NewError("", "unknown authorization subject"))
			return
		}
		if binding, err := d.store.GetBinding(r.Context(), body.BindingID); err != nil || binding.Status != model.StatusActive {
			writeAPIError(w, model.NewError(model.CodeBindingDisabled, "binding is not active"))
			return
		}
		mode := model.DeliveryMode(body.DeliveryMode)
		if !mode.Valid() {
			writeAPIError(w, model.NewError("", "invalid delivery_mode"))
			return
		}
		max := time.Duration(body.MaxLeaseSeconds) * time.Second
		if max <= 0 {
			max = 10 * time.Minute
		}
		policy, err := model.ParseAuthPolicy(body.AuthRequirement)
		if err != nil {
			writeAPIError(w, model.NewError("", "%v", err))
			return
		}
		// 存储在同一事务/临界区内取代旧授权；这里的预读只用于提交后的缓存与审计清理。
		var superseded []*model.Grant
		if existing, err := d.store.ListGrants(r.Context(), body.PrincipalID); err == nil {
			for _, old := range existing {
				if old.Status == model.StatusActive && old.BindingID == body.BindingID && old.DeliveryMode == mode {
					superseded = append(superseded, old)
				}
			}
		}
		g := &model.Grant{
			ID:               "grant_" + randomSuffix(),
			PrincipalID:      body.PrincipalID,
			BindingID:        body.BindingID,
			DeliveryMode:     mode,
			MaxLeaseDuration: max,
			AuthRequirement:  policy.String(),
			Status:           model.StatusActive,
		}
		if err := d.store.PutGrant(r.Context(), g); err != nil {
			writeAPIError(w, err)
			return
		}
		for _, old := range superseded {
			d.broker.InvalidateGrant(r.Context(), old.ID, "superseded")
			d.broker.Record(r.Context(), store.AuditEvent{
				Mode: "control", Result: "grant_superseded", BindingID: body.BindingID,
				Detail: "grant " + old.ID + " replaced by a new " + string(mode) + " grant",
			})
		}
		writeJSON(w, http.StatusCreated, g)
	default:
		writeAPIError(w, model.NewError("", "method not allowed"))
	}
}

func (d *Daemon) handleGrantItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/grants/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		writeAPIError(w, model.NewError("", "unsupported grant operation"))
		return
	}
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	switch parts[1] {
	case "revoke":
		if err := d.store.UpdateGrantStatus(r.Context(), parts[0], model.StatusRevoked, 0); err != nil {
			writeAPIError(w, err)
			return
		}
		// 撤销授权同时丢弃该授权的验证结果。
		d.broker.InvalidateGrant(r.Context(), parts[0], "revoked")
		writeJSON(w, http.StatusOK, map[string]any{"id": parts[0], "status": model.StatusRevoked})
	case "approve":
		// approve 只服务恢复后待复核的授权。已撤销或被新授权取代的记录不能借此复活，
		// 否则会绕过「同一主体、绑定与方式只有一个有效授权」的约束。
		grant, err := d.store.GetGrant(r.Context(), parts[0])
		if err != nil {
			writeAPIError(w, model.NewError(model.CodeUseNotAllowed, "unknown grant %q", parts[0]))
			return
		}
		if grant.Status != model.StatusPending {
			writeAPIError(w, model.NewError(model.CodeConfigDrift,
				"grant %s is %s; only grants pending review can be approved", parts[0], grant.Status))
			return
		}
		if err := d.store.UpdateGrantStatus(r.Context(), parts[0], model.StatusActive, grant.Revision); err != nil {
			writeAPIError(w, grantApprovalError(parts[0], err))
			return
		}
		d.broker.InvalidateGrant(r.Context(), parts[0], "approved")
		writeJSON(w, http.StatusOK, map[string]any{"id": parts[0], "status": model.StatusActive})
	default:
		writeAPIError(w, model.NewError("", "unsupported grant operation"))
	}
}

// grantApprovalError 把批准失败的两种原因收敛为可区分的配置冲突：
// 同一范围已有有效授权（唯一索引拒绝），或记录在读取后被并发修改。
func grantApprovalError(grantID string, err error) error {
	msg := err.Error()
	if errors.Is(err, store.ErrConflict) || strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "constraint") {
		return model.NewError(model.CodeConfigDrift,
			"grant %s cannot be approved: another authorization is already active for the same principal, binding and mode", grantID)
	}
	return err
}

func (d *Daemon) handleLock(w http.ResponseWriter, r *http.Request) {
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := d.backend.Lock(r.Context()); err != nil {
		writeAPIError(w, err)
		return
	}
	d.broker.Lock(r.Context())
	d.passwordProof.clear()
	d.runners.KillAll()
	writeJSON(w, http.StatusOK, map[string]any{"locked": true, "epoch": d.broker.Epoch()})
}

func (d *Daemon) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := d.backend.Unlock(r.Context(), []byte(body.Password)); err != nil {
		writeAPIError(w, err)
		return
	}
	d.broker.Unlock()
	d.passwordProof.clear()
	d.recordAuthAudit(r.Context(), store.AuditEvent{Mode: "control", Result: "unlock", AuthMethod: "password", AuthResult: "verified", Detail: "vault unlocked with master password"})
	writeJSON(w, http.StatusOK, map[string]any{"locked": false, "epoch": d.broker.Epoch(), "auth_method": "password"})
}

func (d *Daemon) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	events, err := d.store.ListAudit(r.Context(), limit)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

// handleClientAudit 接受本机同用户进程上报的使用结果，让代理也能把本地决定写进
// 同一份审计。它只接受字段白名单，不接受主体、会话或凭证标识，代理无法借此伪装身份。
func (d *Daemon) handleClientAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	var body struct {
		Mode       string `json:"mode"`
		Result     string `json:"result"`
		Detail     string `json:"detail"`
		ErrorCode  string `json:"error_code"`
		BindingID  string `json:"binding_id"`
		DurationMS int64  `json:"duration_ms"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Mode == "" || body.Result == "" {
		writeAPIError(w, model.NewError("", "mode and result are required"))
		return
	}
	if body.DurationMS < 0 {
		body.DurationMS = 0
	}
	d.broker.Record(r.Context(), store.AuditEvent{
		Mode:       truncateField(body.Mode, 32),
		Result:     truncateField(body.Result, 32),
		Detail:     truncateField(body.Detail, 200),
		ErrorCode:  truncateField(body.ErrorCode, 32),
		BindingID:  truncateField(body.BindingID, 128),
		DurationMS: body.DurationMS,
	})
	writeJSON(w, http.StatusOK, map[string]any{"recorded": true})
}

// truncateField 限制上报字段长度，避免代理把审计写成无界文本。
func truncateField(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func brokerRequest(token, bindingID, route string, mode model.DeliveryMode, purpose string) broker.Request {
	return broker.Request{Token: secret.New(token), BindingID: bindingID, Route: route, Mode: mode, Purpose: purpose}
}

// supportView 描述一种交付模式的展示文案。
type supportView struct {
	Mode           string `json:"mode"`
	Label          string `json:"label"`
	Status         string `json:"status"`
	ToolSeesSecret bool   `json:"tool_sees_real_value"`
	Summary        string `json:"summary"`
}

// SupportMatrix 返回交付模式与验证状态的展示文案。真实值是否到达工具必须显式说明。
func SupportMatrix() []supportView {
	return []supportView{
		{
			Mode: "proxy", Label: "显式 HTTP 网关", Status: string(model.SupportVerified),
			ToolSeesSecret: false,
			Summary:        "工具把 endpoint 指向本机网关并使用中介会话令牌；真实凭证只在上游请求注入，工具与 Agent 不取得真实值。",
		},
		{
			Mode: "runtime_delivery", Label: "Helper 与子进程环境", Status: string(model.SupportExperimental),
			ToolSeesSecret: true,
			Summary:        "真实值按工具原生协议或子进程环境交付；工具进程及其后代可以看到真实值，只在声明通道输出。",
		},
		{
			Mode: "sign", Label: "注册协议签名", Status: string(model.SupportExperimental),
			ToolSeesSecret: false,
			Summary:        "中介用托管密钥在已登记协议内签名；私钥不离开中介，签名材料不写入日志。",
		},
	}
}

func (d *Daemon) handleSupport(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"support": SupportMatrix()})
}

func randomSuffix() string {
	b := make([]byte, 9)
	if _, err := cryptoRand(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

var _ = context.Background
var _ = sort.Strings
