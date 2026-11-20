package ssha

import (
	"context"
	"errors"
	"sync"

	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
)

// IPCProvider 通过本机受认证 IPC 向 keykoid 申请密钥元数据与一次性签名材料。
//
// 它只携带非管理员会话令牌：枚举走 /v1/ssh-keys，签名材料走 /v1/ssh-sign-material。
// 两条路径都由后台按 sign 许可重新授权，撤销后立即失效。签名材料接口只返回
// 私钥与可选口令，因此签名权限不会顺带取得整组原始凭证字段。
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

// ResolveMaterial 取得一次签名材料。返回错误时材料已被清除。
func (p *IPCProvider) ResolveMaterial(ctx context.Context, bindingID string) (*Material, error) {
	var res struct {
		CredentialID string            `json:"credential_id"`
		Fields       map[string]string `json:"fields"`
	}
	err := p.withSession(ctx, func(token string) error {
		return p.Client.Post("/v1/ssh-sign-material", map[string]string{
			"token": token, "binding_id": bindingID,
		}, &res)
	})
	if err != nil {
		return nil, err
	}
	m := &Material{}
	if v := res.Fields["private_key"]; v != "" {
		m.PrivateKeyPEM = []byte(v)
	}
	if v := res.Fields["private_key_passphrase"]; v != "" {
		m.Passphrase = []byte(v)
	}
	// 交付结果里的字符串副本不可清除，至少立刻断开映射引用。
	for k := range res.Fields {
		res.Fields[k] = ""
	}
	if len(m.PrivateKeyPEM) == 0 {
		m.Wipe()
		return nil, model.NewError(model.CodeCredentialUnavailable,
			"binding %s did not return a private_key field", bindingID)
	}
	return m, nil
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
	err = call(fresh)
	if err == nil || !isSessionExpired(err) {
		return err
	}
	return err
}

// isSessionExpired 报告错误是否只是会话失效（可安全续期）。
func isSessionExpired(err error) bool {
	var apiErr *ipcclient.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == string(model.CodeSessionInvalid)
	}
	return model.CodeOf(err) == model.CodeSessionInvalid
}
