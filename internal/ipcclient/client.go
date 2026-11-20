// Package ipcclient 是 CLI、Helper 与运行器访问后台本机 IPC 的客户端。
// 它只连接 Unix socket，不暴露普通 TCP 端口。
package ipcclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"keykoi/internal/model"
)

// Client 是后台 IPC 客户端。
type Client struct {
	socket     string
	adminToken string
	http       *http.Client
}

// New 构造客户端。adminToken 为空时只能发起普通会话与用钥请求。
func New(socket, adminToken string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &Client{
		socket:     socket,
		adminToken: adminToken,
		http:       &http.Client{Transport: tr, Timeout: 30 * time.Second},
	}
}

// APIError 是后台返回的稳定错误。
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

func (c *Client) do(method, path string, body, out any) error {
	return c.doContext(context.Background(), method, path, body, out)
}

// doContext 是带上下文的一次请求；代理用它在连接关闭时取消授权往返。
func (c *Client) doContext(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://keykoi.local"+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.adminToken != "" {
		req.Header.Set("X-KeyKoi-Admin", c.adminToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("connect to keykoid: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var wrapper struct {
			Error APIError `json:"error"`
		}
		if json.Unmarshal(data, &wrapper) == nil && wrapper.Error.Code != "" {
			return &wrapper.Error
		}
		return fmt.Errorf("keykoid returned HTTP %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode keykoid response: %w", err)
		}
	}
	return nil
}

// OpenStream decodes the initial reply and keeps an IPC-owned operation alive
// until the caller closes the response body or cancels the context.
func (c *Client) OpenStream(ctx context.Context, path string, body, initial any) (io.ReadCloser, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://keykoi.local"+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KeyKoi-Admin", c.adminToken)
	transport := c.http.Transport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.DisableKeepAlives = true
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		var wrapper struct {
			Error APIError `json:"error"`
		}
		if dec.Decode(&wrapper) == nil && wrapper.Error.Message != "" {
			return nil, &wrapper.Error
		}
		return nil, fmt.Errorf("keykoid returned HTTP %d", resp.StatusCode)
	}
	if err := dec.Decode(initial); err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("decode keykoid stream: %w", err)
	}
	return resp.Body, nil
}

// Status 返回后台状态。
func (c *Client) Status() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/v1/status", nil, &out)
	return out, err
}

// Session 是创建会话的结果。
type Session struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"token"`
}

// CreateSession 建立会话；admin 为 true 时附带本机管理令牌。
func (c *Client) CreateSession(purpose string, admin bool) (*Session, error) {
	return c.CreateSessionTTL(purpose, admin, 0)
}

// CreateSessionTTL 建立指定有效期的会话（上限由后台限制为 24 小时）。
func (c *Client) CreateSessionTTL(purpose string, admin bool, ttl time.Duration) (*Session, error) {
	return c.CreateSessionContext(context.Background(), purpose, admin, ttl)
}

// Resolved 是原始值交付结果，只在受信通道内使用。
type Resolved struct {
	CredentialID      string            `json:"credential_id"`
	CredentialVersion int               `json:"credential_version"`
	Fields            map[string]string `json:"fields"`
	ProviderExpiresAt *time.Time        `json:"provider_expires_at"`
	// Lease 是同一次授权建立的许可，代理按它登记期限与撤销。
	Lease model.UseLease `json:"lease"`
	// Binding 是同一次授权校验过的登记绑定快照。调用方必须使用它，而不是另取目标。
	Binding *model.Binding `json:"binding"`
}

// Resolve 按 runtime_delivery 许可获取完整凭证版本。
func (c *Client) Resolve(token, bindingID, mode string) (*Resolved, error) {
	return c.ResolveContext(context.Background(), token, bindingID, mode)
}

// ResolveContext 是带上下文的解析请求。
func (c *Client) ResolveContext(ctx context.Context, token, bindingID, mode string) (*Resolved, error) {
	var out Resolved
	err := c.doContext(ctx, http.MethodPost, "/v1/resolve", map[string]any{
		"token": token, "binding_id": bindingID, "mode": mode,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Get 是通用 GET。
func (c *Client) Get(path string, out any) error { return c.do(http.MethodGet, path, nil, out) }

// Post 是通用 POST。
func (c *Client) Post(path string, body, out any) error {
	return c.do(http.MethodPost, path, body, out)
}

// PostContext 是带上下文的通用 POST。
func (c *Client) PostContext(ctx context.Context, path string, body, out any) error {
	return c.doContext(ctx, http.MethodPost, path, body, out)
}

// CreateSessionContext 是带上下文的会话创建。
func (c *Client) CreateSessionContext(ctx context.Context, purpose string, admin bool, ttl time.Duration) (*Session, error) {
	body := map[string]any{"purpose": purpose}
	if ttl > 0 {
		body["ttl_seconds"] = int64(ttl.Seconds())
	}
	if admin {
		if c.adminToken == "" {
			return nil, fmt.Errorf("administrator token is not available")
		}
		body["admin_proof"] = c.adminToken
	}
	var out struct {
		Session json.RawMessage `json:"session"`
		Token   string          `json:"token"`
	}
	if err := c.doContext(ctx, http.MethodPost, "/v1/sessions", body, &out); err != nil {
		return nil, err
	}
	var meta struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(out.Session, &meta); err != nil {
		return nil, err
	}
	return &Session{ID: meta.ID, ExpiresAt: meta.ExpiresAt, Token: out.Token}, nil
}

// RecordAudit 上报一条不含秘密的使用结果，供代理把本地决定写入主服务审计。
func (c *Client) RecordAudit(ctx context.Context, event AuditEvent) error {
	return c.doContext(ctx, http.MethodPost, "/v1/client-audit", event, nil)
}

// AuditEvent 是代理向主服务上报的使用结果字段白名单。
type AuditEvent struct {
	Mode       string `json:"mode"`
	Result     string `json:"result"`
	Detail     string `json:"detail,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
	BindingID  string `json:"binding_id,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

// Socket 返回客户端使用的 socket 路径。
func (c *Client) Socket() string { return c.socket }
