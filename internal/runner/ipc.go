package runner

import (
	"context"
	"time"

	"keykoi/internal/ipcclient"
)

// IPCResolver 用本机受认证 IPC 实现 Resolver。
type IPCResolver struct {
	Client *ipcclient.Client
}

// CreateSession 建立普通用钥会话，返回令牌与会话 ID。
func (r IPCResolver) CreateSession(ctx context.Context, purpose string, ttl time.Duration) (string, string, error) {
	s, err := r.Client.CreateSessionTTL(purpose, false, ttl)
	if err != nil {
		return "", "", err
	}
	return s.Token, s.ID, nil
}

// CloseSession 结束会话。
func (r IPCResolver) CloseSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	return r.Client.Post("/v1/sessions/close", map[string]any{"session_id": sessionID}, nil)
}

// Resolve 按 runtime_delivery 许可取得完整版本。
func (r IPCResolver) Resolve(ctx context.Context, token, bindingID, mode string) (Resolved, error) {
	res, err := r.Client.Resolve(token, bindingID, mode)
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{LeaseID: res.Lease.ID, Fields: res.Fields, ProviderExpiresAt: res.ProviderExpiresAt}, nil
}

// RevokeLease 在运行结束后撤销许可。
func (r IPCResolver) RevokeLease(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}
	return r.Client.Post("/v1/use-leases/revoke", map[string]any{"lease_id": leaseID}, nil)
}

// GatewayBase 返回本机网关基址。
func (r IPCResolver) GatewayBase(ctx context.Context) (string, error) {
	st, err := r.Client.Status()
	if err != nil {
		return "", err
	}
	gw, _ := st["gateway"].(string)
	if gw == "" {
		return "", nil
	}
	return "http://" + gw, nil
}
