package ssha

import (
	"context"
	"errors"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
)

// IPCProvider lists public keys and requests signatures from keykoid.
type IPCProvider struct {
	Client *ipcclient.Client
	Token  string
	// Renew 在会话过期或被后台重启清空时重建会话并返回新令牌。
	// 为空时 Agent 只使用启动时建立的会话。Agent 会长时间驻留，后台重启或
	// 默认期限过去后必须能续期，否则监听仍在但无法签名。
	Renew func(ctx context.Context) (string, error)

	mu sync.Mutex
}

var _ Provider = (*IPCProvider)(nil)

// NewIPCProvider 构造 IPC 提供者。
func NewIPCProvider(c *ipcclient.Client, sessionToken string) *IPCProvider {
	return &IPCProvider{Client: c, Token: sessionToken}
}

// ListKeys 返回该会话持有 sign 许可的 ssh_key 元数据。响应里没有私钥。
func (p *IPCProvider) ListKeys(ctx context.Context) ([]KeyInfo, error) {
	var out struct {
		Keys []KeyInfo `json:"keys"`
	}
	err := p.withSession(ctx, func(token string) error {
		return p.Client.Post("/v1/ssh-keys", map[string]string{"token": token}, &out)
	})
	if err != nil {
		return nil, err
	}
	return out.Keys, nil
}

// Sign asks keykoid to sign with a key it keeps inside the daemon.
func (p *IPCProvider) Sign(ctx context.Context, bindingID string, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	var out ssh.Signature
	err := p.withSession(ctx, func(token string) error {
		return p.Client.Post("/v1/ssh-sign", map[string]any{
			"token": token, "binding_id": bindingID, "data": data, "flags": flags,
		}, &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// withSession 用当前会话执行一次调用；会话失效时重建一次会话再重试。
// 撤销、锁定和权限变化不会被这里掩盖：它们返回的是别的错误码。
func (p *IPCProvider) withSession(ctx context.Context, call func(token string) error) error {
	p.mu.Lock()
	token := p.Token
	p.mu.Unlock()
	err := call(token)
	if err == nil || !isSessionExpired(err) || p.Renew == nil {
		return err
	}
	fresh, rerr := p.Renew(ctx)
	if rerr != nil || fresh == "" {
		return err
	}
	p.mu.Lock()
	p.Token = fresh
	p.mu.Unlock()
	return call(fresh)
}

// isSessionExpired 报告错误是否只是会话失效（可安全续期）。
func isSessionExpired(err error) bool {
	var apiErr *ipcclient.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == string(model.CodeSessionInvalid)
	}
	return model.CodeOf(err) == model.CodeSessionInvalid
}
