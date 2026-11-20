package daemon

import (
	"context"
	"net/http"
	"sync"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/store"
)

// BiometricVault 由支持系统生物识别（Touch ID）的密钥库实现。
type BiometricVault interface {
	// EnrollBiometric 把根密钥写入系统保护存储。
	EnrollBiometric(ctx context.Context) error
	// UnlockBiometric 通过系统验证取出根密钥并解锁。
	UnlockBiometric(ctx context.Context) error
	// VerifyBiometric 只做一次系统验证，不改变解锁状态。
	VerifyBiometric(ctx context.Context) error
	// DeleteBiometricEnrollment 删除已登记的根密钥条目。
	DeleteBiometricEnrollment(ctx context.Context) error
	// BiometricStatus 返回不含秘密的可用性与登记状态。
	BiometricStatus(ctx context.Context) map[string]any
}

// PasswordVerifier 由加密密钥库实现「只验密码、不解锁」。
type PasswordVerifier interface {
	VerifyPassword(ctx context.Context, password []byte) error
}

// defaultPasswordFallback 是主密码验证证明的有效期。它只影响「生物识别不可用」
// 时的一次性回退，不是持久授权。
const defaultPasswordFallback = 5 * time.Minute

// passwordProof 保存「刚刚用主密码证明过身份」的主体，证明只能被消费一次。
type passwordProof struct {
	mu  sync.Mutex
	ttl time.Duration
	now func() time.Time
	exp map[string]time.Time
}

func newPasswordProof(ttl time.Duration, now func() time.Time) *passwordProof {
	if ttl <= 0 {
		ttl = defaultPasswordFallback
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &passwordProof{ttl: ttl, now: now, exp: map[string]time.Time{}}
}

func (p *passwordProof) grant(principalID string) {
	if principalID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exp[principalID] = p.now().Add(p.ttl)
}

// consume 取用一次证明；过期或不存在的证明返回 false。
func (p *passwordProof) consume(principalID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	expiry, ok := p.exp[principalID]
	if !ok {
		return false
	}
	delete(p.exp, principalID)
	return p.now().Before(expiry)
}

func (p *passwordProof) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exp = map[string]time.Time{}
}

// noteAuthProblem 记录最近一次无法完成验证的原因，供状态接口展示。
func (d *Daemon) noteAuthProblem(err error) {
	if err == nil {
		return
	}
	d.authMu.Lock()
	d.authProblem = err.Error()
	d.authMu.Unlock()
}

func (d *Daemon) lastAuthProblem() string {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.authProblem
}

// verifyAuth 实现 broker.Verifier：先试系统生物识别，不可用时回退一次性主密码证明，
// 两者都不行就返回 AUTH_UNAVAILABLE 让调用方明确失败，而不是静默放行。
func (d *Daemon) verifyAuth(ctx context.Context, req broker.VerifyRequest) (string, error) {
	bv, ok := d.backend.(BiometricVault)
	if !ok {
		d.noteAuthProblem(model.NewError(model.CodeAuthUnavailable, "this backend has no biometric unlock"))
	} else if err := bv.VerifyBiometric(ctx); err == nil {
		return "biometric", nil
	} else if model.CodeOf(err) == model.CodeAuthUnavailable {
		// 无生物识别、非 GUI 会话或未登记：允许回退主密码证明。
		d.noteAuthProblem(err)
	} else {
		// 用户取消或验证失败：不再回退，交由调用方决定是否重新发起。
		return "none", err
	}
	if d.passwordProof.consume(req.PrincipalID) {
		return "password", nil
	}
	reason := d.lastAuthProblem()
	if reason == "" {
		reason = "no verification provider is available"
	}
	return "none", model.NewError(model.CodeAuthUnavailable,
		"Touch ID verification is unavailable (%s); run 'keykoi auth verify --method password --grant %s --mode %s' to authorize one use with the master password",
		reason, req.GrantID, req.Mode)
}

// handleVaultUnlockBiometric 用 Touch ID 解锁密钥库。无生物识别或非 GUI 会话时
// 返回 AUTH_UNAVAILABLE，调用方应回退主密码。
func (d *Daemon) handleVaultUnlockBiometric(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	principal, err := d.requireAdmin(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	bv, ok := d.backend.(BiometricVault)
	if !ok {
		writeAPIError(w, model.NewError(model.CodeAuthUnavailable, "this backend has no biometric unlock"))
		return
	}
	if err := bv.UnlockBiometric(r.Context()); err != nil {
		d.recordAuthAudit(r.Context(), store.AuditEvent{
			PrincipalID: principal, Mode: "control", Result: "denied",
			ErrorCode: string(model.CodeOf(err)), AuthMethod: "biometric", AuthResult: "failed",
			Detail: "biometric unlock failed",
		})
		writeAPIError(w, err)
		return
	}
	d.broker.Unlock()
	d.passwordProof.clear()
	d.recordAuthAudit(r.Context(), store.AuditEvent{
		PrincipalID: principal, Mode: "control", Result: "unlock",
		AuthMethod: "biometric", AuthResult: "verified", Detail: "vault unlocked with Touch ID",
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"locked": false, "state": d.backend.State(), "epoch": d.broker.Epoch(), "auth_method": "biometric",
	})
}

// handleVaultEnrollBiometric 登记（或重新登记）由系统保护存储守护的根密钥。
func (d *Daemon) handleVaultEnrollBiometric(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	principal, err := d.requireAdmin(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	bv, ok := d.backend.(BiometricVault)
	if !ok {
		writeAPIError(w, model.NewError(model.CodeAuthUnavailable, "this backend has no biometric enrollment"))
		return
	}
	if err := bv.EnrollBiometric(r.Context()); err != nil {
		d.recordAuthAudit(r.Context(), store.AuditEvent{
			PrincipalID: principal, Mode: "control", Result: "denied",
			ErrorCode: string(model.CodeOf(err)), AuthMethod: "biometric", AuthResult: "failed",
			Detail: "biometric enrollment failed",
		})
		writeAPIError(w, err)
		return
	}
	d.recordAuthAudit(r.Context(), store.AuditEvent{
		PrincipalID: principal, Mode: "control", Result: "enroll_biometric",
		AuthMethod: "biometric", AuthResult: "verified", Detail: "root key stored under Touch ID protection",
	})
	writeJSON(w, http.StatusOK, map[string]any{"enrolled": true, "biometric": bv.BiometricStatus(r.Context())})
}

// handleAuthStatus 返回生物识别可用性、登记状态与授权策略概览。
func (d *Daemon) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	biometric := map[string]any{
		"configured": false, "available": false, "enrolled": false,
		"reason": "this backend has no biometric support", "account": "",
	}
	if bv, ok := d.backend.(BiometricVault); ok {
		if status := bv.BiometricStatus(r.Context()); status != nil {
			biometric = status
		}
	}
	grants, _ := d.store.ListGrants(r.Context(), "")
	policyRows := make([]map[string]any, 0, len(grants))
	for _, g := range grants {
		if g.Status != model.StatusActive {
			continue
		}
		policy := g.AuthPolicy()
		policyRows = append(policyRows, map[string]any{
			"grant_id": g.ID, "principal_id": g.PrincipalID, "binding_id": g.BindingID,
			"delivery_mode": g.DeliveryMode, "auth_requirement": policy.String(),
			"auth_policy": policy.Describe(),
		})
	}
	cached := 0
	if cache := d.broker.AuthCache(); cache != nil {
		cached = cache.Len()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"biometric": biometric,
		"auth": map[string]any{
			"default_policy":        model.DefaultAuthRequirement,
			"password_fallback":     true,
			"password_fallback_ttl": int64(d.passwordProof.ttl / time.Second),
			"cached_verifications":  cached,
			"last_problem":          d.lastAuthProblem(),
		},
		"grants": policyRows,
	})
}

// handleAuthVerify 是显式验证入口，供 CLI 在不触发用钥的情况下证明身份，
// 或为一次 per_use 授权预先准备验证结果。
func (d *Daemon) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	principal, err := d.requireAdmin(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		Method    string `json:"method"`
		Password  string `json:"password"`
		GrantID   string `json:"grant_id"`
		Mode      string `json:"mode"`
		SessionID string `json:"session_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	mode := model.DeliveryMode(body.Mode)
	if mode != "" && !mode.Valid() {
		writeAPIError(w, model.NewError(model.CodeUseNotAllowed, "invalid delivery mode %q", body.Mode))
		return
	}
	var grant *model.Grant
	if body.GrantID != "" {
		grant, err = d.store.GetGrant(r.Context(), body.GrantID)
		if err != nil {
			writeAPIError(w, model.NewError(model.CodeUseNotAllowed, "unknown grant %q", body.GrantID))
			return
		}
		if grant.Status != model.StatusActive {
			writeAPIError(w, model.NewError(model.CodeUseNotAllowed, "grant %s is %s", grant.ID, grant.Status))
			return
		}
	}
	method := body.Method
	if method == "" {
		method = "biometric"
	}
	authReq := broker.VerifyRequest{
		PrincipalID: principal, SessionID: body.SessionID, GrantID: body.GrantID,
		Mode: mode, Policy: model.AuthPolicy{Kind: model.AuthOnce},
	}
	if grant != nil {
		authReq.PrincipalID = grant.PrincipalID
		authReq.BindingID = grant.BindingID
		authReq.Policy = grant.AuthPolicy()
	}
	decision := broker.AuthDecision{Policy: authReq.Policy.String(), Method: method}
	switch method {
	case "biometric":
		bv, ok := d.backend.(BiometricVault)
		if !ok {
			writeAPIError(w, model.NewError(model.CodeAuthUnavailable, "this backend has no biometric support"))
			return
		}
		if err := bv.VerifyBiometric(r.Context()); err != nil {
			d.recordAuthAudit(r.Context(), store.AuditEvent{
				PrincipalID: principal, BindingID: authReq.BindingID, Mode: "auth", Result: "denied",
				ErrorCode: string(model.CodeOf(err)), AuthMethod: "biometric", AuthResult: "failed",
				Detail: "explicit biometric verification failed",
			})
			writeAPIError(w, err)
			return
		}
	case "password":
		pv, ok := d.backend.(PasswordVerifier)
		if !ok {
			writeAPIError(w, model.NewError(model.CodeAuthUnavailable, "this backend cannot verify the master password"))
			return
		}
		if err := pv.VerifyPassword(r.Context(), []byte(body.Password)); err != nil {
			d.recordAuthAudit(r.Context(), store.AuditEvent{
				PrincipalID: principal, BindingID: authReq.BindingID, Mode: "auth", Result: "denied",
				ErrorCode: string(model.CodeOf(err)), AuthMethod: "password", AuthResult: "failed",
				Detail: "explicit password verification failed",
			})
			writeAPIError(w, err)
			return
		}
		if grant == nil {
			// 没有指定授权时，这是一次主体级的一次性回退证明。
			d.passwordProof.grant(principal)
		}
	default:
		writeAPIError(w, model.NewError("", "unsupported verification method %q", method))
		return
	}
	if grant != nil && d.authn != nil {
		recorded, derr := d.authn.RecordVerification(authReq, method)
		if derr != nil {
			// 例如 once 策略没有指定会话：不能退化成全局通配证明。
			d.recordAuthAudit(r.Context(), store.AuditEvent{
				PrincipalID: principal, BindingID: authReq.BindingID, Mode: "auth", Result: "denied",
				ErrorCode: string(model.CodeOf(derr)), AuthMethod: method, AuthResult: "failed",
				Detail: "explicit verification cannot be recorded: " + derr.Error(),
			})
			writeAPIError(w, derr)
			return
		}
		decision = recorded
	}
	d.recordAuthAudit(r.Context(), store.AuditEvent{
		PrincipalID: principal, BindingID: authReq.BindingID, Mode: "auth", Result: "verify",
		AuthMethod: method, AuthResult: "verified",
		Detail: "explicit verification; grant=" + body.GrantID,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"verified": true, "method": method, "grant_id": body.GrantID,
		"delivery_mode": string(mode), "auth_requirement": decision.Policy,
		"verified_at": decision.VerifiedAt,
	})
}

// recordAuthAudit 写入一条验证相关审计；失败不影响主流程。
func (d *Daemon) recordAuthAudit(ctx context.Context, e store.AuditEvent) {
	if e.AuthResult == "" {
		e.AuthResult = "not_required"
	}
	if e.AuthMethod == "" {
		e.AuthMethod = "none"
	}
	d.broker.Record(ctx, e)
}
