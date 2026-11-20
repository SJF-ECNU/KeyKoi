// Package remoteauth 让代理进程把用钥决定交给本机主服务。
//
// 代理不再自行解锁密钥库、也不再建立独立 Broker：锁定状态、逐次验证和中心策略
// 都由 keykoid 在受信进程内统一执行，代理只拿到一次授权的绑定快照与凭证版本。
// 这样「主库已锁定」和「需要 Touch ID」不会因为换了一个入口而失效。
package remoteauth

import (
	"context"
	"errors"
	"sync"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

// Authorizer 是代理侧的授权入口，实现各代理包定义的授权接口。
type Authorizer struct {
	client  *ipcclient.Client
	purpose string
	now     func() time.Time

	mu      sync.Mutex
	session *ipcclient.Session
}

// New 构造代理授权器。purpose 写入会话审计，便于区分哪个入口在用钥。
func New(c *ipcclient.Client, purpose string) *Authorizer {
	return &Authorizer{client: c, purpose: purpose, now: func() time.Time { return time.Now().UTC() }}
}

// Authorize 通过主服务完成一次授权，并返回同一次授权建立的许可、绑定与凭证版本。
// 调用方只能使用这里返回的快照，不得再单独读取目标或版本。
func (a *Authorizer) Authorize(ctx context.Context, req broker.Request) (*broker.Authorization, error) {
	if req.Mode != model.ModeRuntimeDelivery {
		// 代理只做运行时交付；签名与协议签名各有专用入口。
		return nil, model.NewError(model.CodeUseNotAllowed,
			"proxies use runtime_delivery only, request is %s", req.Mode)
	}
	if req.BindingID == "" {
		return nil, model.NewError(model.CodeBindingDisabled, "binding id is required")
	}
	token, err := a.sessionToken(ctx)
	if err != nil {
		return nil, err
	}
	resolved, err := a.client.ResolveContext(ctx, token, req.BindingID, string(req.Mode))
	if err != nil {
		if !isStaleSession(err) {
			return nil, err
		}
		// 会话过期或被主服务重启清空：重建一次会话后重试，仍然失败就报原错误。
		if rerr := a.resetSession(); rerr != nil {
			return nil, err
		}
		token, terr := a.sessionToken(ctx)
		if terr != nil {
			return nil, err
		}
		resolved, err = a.client.ResolveContext(ctx, token, req.BindingID, string(req.Mode))
		if err != nil {
			return nil, err
		}
	}
	if resolved.Binding == nil {
		return nil, model.NewError(model.CodeBindingDisabled,
			"keykoid did not return binding %s with the authorization", req.BindingID)
	}
	fields := make(map[string]secret.Value, len(resolved.Fields))
	for name, value := range resolved.Fields {
		fields[name] = secret.New(value)
	}
	return &broker.Authorization{
		Lease: resolved.Lease,
		Version: model.CredentialVersion{
			CredentialID:      resolved.CredentialID,
			Version:           resolved.CredentialVersion,
			Fields:            fields,
			ProviderExpiresAt: resolved.ProviderExpiresAt,
		},
		Binding: resolved.Binding,
	}, nil
}

// RevokeLease 结束一次许可，用于代理在请求结束后立即释放。
func (a *Authorizer) RevokeLease(_ context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}
	return a.client.RevokeLease(leaseID)
}

// Record 把代理侧的判定结果写进主服务审计。上报失败不影响用钥结果。
func (a *Authorizer) Record(ctx context.Context, event store.AuditEvent) {
	_ = a.client.RecordAudit(ctx, ipcclient.AuditEvent{
		Mode:       event.Mode,
		Result:     event.Result,
		Detail:     event.Detail,
		ErrorCode:  event.ErrorCode,
		BindingID:  event.BindingID,
		DurationMS: event.DurationMS,
	})
}

// Close 关闭代理会话，避免长期运行留下无用会话。
func (a *Authorizer) Close(ctx context.Context) {
	a.mu.Lock()
	session := a.session
	a.session = nil
	a.mu.Unlock()
	if session == nil {
		return
	}
	_ = a.client.PostContext(ctx, "/v1/sessions/close", map[string]any{"session_id": session.ID}, nil)
}

// sessionToken 返回可用的会话令牌；缺失或临近过期时重建。
func (a *Authorizer) sessionToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	session := a.session
	a.mu.Unlock()
	if session != nil && a.now().Before(session.ExpiresAt.Add(-time.Minute)) {
		return session.Token, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session != nil && a.now().Before(a.session.ExpiresAt.Add(-time.Minute)) {
		return a.session.Token, nil
	}
	created, err := a.client.CreateSessionContext(ctx, a.purpose, false, 12*time.Hour)
	if err != nil {
		return "", err
	}
	a.session = created
	return created.Token, nil
}

// resetSession 丢弃本地会话记录，让下一次调用重新申请。
func (a *Authorizer) resetSession() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.session = nil
	return nil
}

// isStaleSession 报告错误是否只是会话失效，可安全重建后重试。
func isStaleSession(err error) bool {
	var apiErr *ipcclient.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == string(model.CodeSessionInvalid)
	}
	return model.CodeOf(err) == model.CodeSessionInvalid
}
