package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"keykoi/internal/model"
	"keykoi/internal/oauth"
	"keykoi/internal/store"
)

// 选定的提供方形态：标准 OAuth 2.0 authorization code + PKCE，token 端点支持
// refresh_token 轮换与 invalid_grant 撤销语义。客户端信息只来自凭证字段。
//
// 路由 /v1/oauth/begin|callback|refresh 由 daemon.go 注册；三个入口都要求本机管理权。
//
// 运行时状态（待完成授权、恢复标记）必须跨请求存活，所以在包级持有；
// 凭证级刷新的串行锁复用 d.oauth.Lock。

var oauthRuntime = struct {
	service *oauth.Service
	states  *oauth.StateStore
}{
	service: oauth.NewService(),
	states:  oauth.NewStateStore(),
}

var oauthSkewOnce = sync.Once{}

var oauthSkewValue = oauth.DefaultSkew

// oauthClockSkew 返回缓存有效期余量。验收脚本可用 KEYKOI_OAUTH_CLOCK_SKEW 缩短余量，
// 生产默认 30s，不允许配置为负值。
func oauthClockSkew() time.Duration {
	oauthSkewOnce.Do(func() {
		raw := os.Getenv("KEYKOI_OAUTH_CLOCK_SKEW")
		if raw == "" {
			return
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d < 0 {
			return
		}
		oauthSkewValue = d
	})
	return oauthSkewValue
}

// oauthStore 把 daemon 的 store / backend / broker 适配成 oauth.Store。
type oauthStore struct{ d *Daemon }

// Load 读取凭证索引与当前完整版本。
func (s oauthStore) Load(ctx context.Context, credentialID string) (model.Credential, model.CredentialVersion, error) {
	cred, err := s.d.store.GetCredential(ctx, credentialID)
	if err != nil {
		return model.Credential{}, model.CredentialVersion{},
			model.NewError(model.CodeCredentialUnavailable, "credential %s is unavailable", credentialID)
	}
	version, err := s.d.backend.Materialize(ctx, credentialID, cred.CurrentVersion)
	if err != nil {
		return model.Credential{}, model.CredentialVersion{}, err
	}
	return *cred, version, nil
}

// Commit 原子写入新版本并切换当前版本。
func (s oauthStore) Commit(ctx context.Context, credentialID string, version model.CredentialVersion) (*model.Credential, error) {
	return s.d.backend.AddVersion(ctx, credentialID, version)
}

// CommitCAS 实现 oauth.CommitCASer：只有凭证 revision 仍是调用方观察到的值时
// 才写入新版本，把「检查记录未变」与「提交」压成一次原子决定。
func (s oauthStore) CommitCAS(ctx context.Context, credentialID string, expectedRevision int64, version model.CredentialVersion) (*model.Credential, error) {
	updated, err := s.d.backend.ActivateVersionCAS(ctx, credentialID, version, expectedRevision)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, fmt.Errorf("%w: credential %s revision %d is no longer current", oauth.ErrCommitConflict, credentialID, expectedRevision)
		}
		return nil, err
	}
	return updated, nil
}

// MarkStatus 按预期 revision 更新状态，避免覆盖并行管理写入。
func (s oauthStore) MarkStatus(ctx context.Context, credentialID string, status model.EntityStatus, expectedRevision int64) error {
	return s.d.store.UpdateCredentialStatus(ctx, credentialID, status, expectedRevision)
}

// RevokeLeases 在版本切换后失效该凭证的既有许可。
func (s oauthStore) RevokeLeases(ctx context.Context, credentialID string) int {
	return s.d.broker.RevokeForCredential(ctx, credentialID)
}

// oauthManager 构造一次操作所需的 Manager，串行锁复用 d.oauth.Lock。
func (d *Daemon) oauthManager() *oauth.Manager {
	return &oauth.Manager{
		Service: oauthRuntime.service,
		Store:   oauthStore{d: d},
		LockFn:  d.oauth.Lock,
		States:  oauthRuntime.states,
		Now:     func() time.Time { return time.Now().UTC() },
		Skew:    oauthClockSkew(),
	}
}

type oauthBeginRequest struct {
	CredentialID string `json:"credential_id"`
}

type oauthCallbackRequest struct {
	CredentialID string `json:"credential_id"`
	Code         string `json:"code"`
	State        string `json:"state"`
}

type oauthRefreshRequest struct {
	CredentialID string `json:"credential_id"`
	// Force 忽略缓存有效期；仍然只在同一凭证的一次推进内执行。
	Force bool `json:"force"`
	// DryRun 只返回元数据，不访问上游、不写任何状态（keykoi oauth status 使用）。
	DryRun bool `json:"dry_run"`
}

func (d *Daemon) requireAdminPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return false
	}
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return false
	}
	return true
}

// handleOAuthBegin 生成 PKCE + state 并返回受信授权入口。响应只含 URL 与 state。
func (d *Daemon) handleOAuthBegin(w http.ResponseWriter, r *http.Request) {
	if !d.requireAdminPost(w, r) {
		return
	}
	var body oauthBeginRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.CredentialID == "" {
		writeAPIError(w, model.NewError("", "credential_id is required"))
		return
	}
	auth, err := d.oauthManager().BeginAuthorization(r.Context(), body.CredentialID)
	if err != nil {
		writeOAuthError(w, body.CredentialID, err, nil)
		return
	}
	d.broker.Record(r.Context(), auditOAuth("begin", body.CredentialID, 0, "allowed", "authorization url issued"))
	writeJSON(w, http.StatusOK, map[string]any{
		"credential_id":     body.CredentialID,
		"authorization_url": auth.URL,
		"state":             auth.State,
		"redirect_uri":      auth.RedirectRI,
		"expires_at":        auth.ExpiresAt,
		"provider":          oauth.ProviderKind,
	})
}

// handleOAuthCallback 用 code 完成交换并原子写入新版本；成功后失效旧许可。
func (d *Daemon) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if !d.requireAdminPost(w, r) {
		return
	}
	var body oauthCallbackRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.CredentialID == "" || body.Code == "" || body.State == "" {
		writeAPIError(w, model.NewError("", "credential_id, code and state are required"))
		return
	}
	res, err := d.oauthManager().CompleteAuthorization(r.Context(), body.CredentialID, body.State, body.Code)
	if err != nil {
		writeOAuthError(w, body.CredentialID, err, &res)
		return
	}
	d.broker.Record(r.Context(), auditOAuth("callback", body.CredentialID, res.Version, "allowed", "authorization completed"))
	writeJSON(w, http.StatusOK, res)
}

// handleOAuthRefresh 执行串行刷新并只返回元数据；dry_run 返回当前状态快照。
func (d *Daemon) handleOAuthRefresh(w http.ResponseWriter, r *http.Request) {
	if !d.requireAdminPost(w, r) {
		return
	}
	var body oauthRefreshRequest
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.CredentialID == "" {
		writeAPIError(w, model.NewError("", "credential_id is required"))
		return
	}
	mgr := d.oauthManager()
	dryRun := body.DryRun || r.URL.Query().Get("dry_run") == "1" || r.URL.Query().Get("dry_run") == "true"
	if dryRun {
		res, err := mgr.Status(r.Context(), body.CredentialID)
		if err != nil {
			writeOAuthError(w, body.CredentialID, err, &res)
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}
	// 取得锁之前的版本作为“排队时观察到的版本”：排队期间若已推进，本次不重复刷新。
	expect := 0
	if cred, err := d.store.GetCredential(r.Context(), body.CredentialID); err == nil {
		expect = cred.CurrentVersion
	}
	res, err := mgr.Refresh(r.Context(), body.CredentialID, oauth.RefreshOptions{Force: body.Force, ExpectVersion: expect})
	if err != nil {
		result := "denied"
		if oauth.RecoveryRequired(err) {
			result = "recovery_required"
		}
		d.broker.Record(r.Context(), auditOAuth("refresh", body.CredentialID, res.Version, result, string(oauth.ClassOf(err))))
		writeOAuthError(w, body.CredentialID, err, &res)
		return
	}
	if res.Refreshed {
		d.broker.Record(r.Context(), auditOAuth("refresh", body.CredentialID, res.Version, "allowed", "refresh advanced"))
	}
	writeJSON(w, http.StatusOK, res)
}

// auditOAuth 记录不含秘密的审计事件。
func auditOAuth(op, credentialID string, version int, result, detail string) store.AuditEvent {
	return store.AuditEvent{
		CredentialID:      credentialID,
		CredentialVersion: version,
		Mode:              "oauth_" + op,
		Result:            result,
		Detail:            detail,
	}
}

// writeOAuthError 把 oauth 错误映射成稳定错误码与 HTTP 状态。
// 已撤销/需重新登录/恢复要求返回 409，可重试的上游故障返回 503，上游拒绝返回 502。
func writeOAuthError(w http.ResponseWriter, credentialID string, err error, res *oauth.Result) {
	if code := model.CodeOf(err); code != "" {
		// 密钥库锁定、凭证缺失等沿用统一映射。
		writeAPIError(w, err)
		return
	}
	class := oauth.ClassOf(err)
	status := http.StatusInternalServerError
	apiCode := "OAUTH_LOCAL_ERROR"
	switch class {
	case oauth.ClassRetryable:
		status, apiCode = http.StatusServiceUnavailable, "OAUTH_UPSTREAM_UNAVAILABLE"
	case oauth.ClassRevoked, oauth.ClassReauth:
		status, apiCode = http.StatusConflict, "OAUTH_REAUTH_REQUIRED"
	case oauth.ClassRecovery:
		status, apiCode = http.StatusConflict, "OAUTH_RECOVERY_REQUIRED"
	case oauth.ClassConflict:
		// 并发轮换或回调与管理员停用冲突：调用方需要重新发起，而不是当成本地故障。
		status, apiCode = http.StatusConflict, "OAUTH_CONFLICT"
	case oauth.ClassConfig:
		status, apiCode = http.StatusBadRequest, "OAUTH_CONFIG_INVALID"
	case oauth.ClassRejected, oauth.ClassMalformed:
		status, apiCode = http.StatusBadGateway, "OAUTH_UPSTREAM_REJECTED"
	}
	body := map[string]any{
		"error": map[string]any{
			"code":              apiCode,
			"class":             string(class),
			"message":           err.Error(),
			"credential_id":     credentialID,
			"retryable":         oauth.IsRetryable(err),
			"recovery_required": oauth.RecoveryRequired(err),
			"next_action":       nextActionForClass(class),
		},
	}
	if res != nil {
		body["metadata"] = *res
	}
	writeJSON(w, status, body)
}

func nextActionForClass(class oauth.Class) string {
	switch class {
	case oauth.ClassRetryable, oauth.ClassConflict:
		return "retry"
	case oauth.ClassReauth, oauth.ClassRevoked, oauth.ClassRecovery:
		return "reauth"
	default:
		return "none"
	}
}
