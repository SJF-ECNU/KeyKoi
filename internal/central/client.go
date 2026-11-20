package central

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
)

// Client 是本机设备访问中心的客户端，同时实现 broker.Gate。
type Client struct {
	BaseURL  string
	DeviceID string
	// Secret 是注册时一次性下发的设备秘密；只在本地 0600 状态文件与内存中保存。
	Secret string
	// Mode 是 online（每次用钥向中心确认）或 short_term（期限内离线可用）。
	Mode string
	HTTP *http.Client
	Now  func() time.Time

	mu     sync.Mutex
	epoch  string
	leases map[leaseKey]Lease
}

// leaseKey 区分同一设备上不同主体、方式与版本的许可，避免相互覆盖。
type leaseKey struct {
	BindingID         string
	PrincipalID       string
	Mode              string
	CredentialVersion int
}

// DeviceState 是本地设备身份文件内容。
type DeviceState struct {
	DeviceID string `json:"device_id"`
	Secret   string `json:"device_secret"`
	Central  string `json:"central_url"`
	Name     string `json:"name"`
}

// LoadOrRegister 读取本地设备状态；缺失时用 bootstrap 令牌注册并写入 0600 文件。
func LoadOrRegister(ctx context.Context, statePath, baseURL, bootstrap, name, mode string) (*Client, error) {
	c := &Client{BaseURL: baseURL, Mode: mode, HTTP: &http.Client{Timeout: 10 * time.Second}, Now: func() time.Time { return time.Now().UTC() }, leases: map[leaseKey]Lease{}}
	if mode == "" {
		c.Mode = "online"
	}
	if data, err := os.ReadFile(statePath); err == nil {
		var st DeviceState
		if json.Unmarshal(data, &st) == nil && st.DeviceID != "" {
			if st.Central != baseURL {
				return nil, fmt.Errorf("device state belongs to a different center %q", st.Central)
			}
			c.DeviceID, c.Secret = st.DeviceID, st.Secret
			return c, nil
		}
	}
	if bootstrap == "" {
		return nil, fmt.Errorf("device is not registered and no bootstrap credential was provided")
	}
	body, _ := json.Marshal(map[string]string{"name": name})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/devices/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Central-Bootstrap", bootstrap)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("register device failed: %s", APIError(data))
	}
	var out struct {
		DeviceID     string `json:"device_id"`
		DeviceSecret string `json:"device_secret"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	c.DeviceID, c.Secret = out.DeviceID, out.DeviceSecret
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return nil, err
	}
	st := DeviceState{DeviceID: c.DeviceID, Secret: c.Secret, Central: baseURL, Name: name}
	raw, _ := json.MarshalIndent(st, "", "  ")
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		return nil, err
	}
	return c, nil
}

// APIError 提取中心返回的错误说明。
func APIError(data []byte) string {
	var wrapper struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &wrapper) == nil && wrapper.Error.Code != "" {
		return wrapper.Error.Code + ": " + wrapper.Error.Message
	}
	return string(data)
}

// errorCode 提取中心返回的稳定错误码。
func errorCode(data []byte) string {
	var wrapper struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &wrapper) == nil {
		return wrapper.Error.Code
	}
	return ""
}

func (c *Client) sign(payload string) string {
	sum := sha256.Sum256([]byte(c.Secret))
	key := hex.EncodeToString(sum[:])
	return hmacSHA256([]byte(key), []byte(payload))
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

// fetchLease 按主体、方式与版本向中心申请许可。请求携带本机版本时，若中心
// 已切换版本会返回 LEASE_STALE；此时去掉版本再申请一次，由中心给出权威版本，
// 再由 Broker 的许可约束拒绝过期版本。
func (c *Client) fetchLease(ctx context.Context, q broker.UseQuery, mode string) (Lease, error) {
	lease, code, err := c.requestLease(ctx, q, mode, true)
	if code == codeLeaseStale && q.CredentialVersion != 0 {
		c.invalidate(leaseKeyFor(q, mode))
		lease, _, err = c.requestLease(ctx, q, mode, false)
	}
	return lease, err
}

// requestLease 发一次许可申请；withVersion 控制是否携带本机凭证版本。
func (c *Client) requestLease(ctx context.Context, q broker.UseQuery, mode string, withVersion bool) (Lease, string, error) {
	nonceBytes := make([]byte, 12)
	_, _ = rand.Read(nonceBytes)
	reqBody := leaseRequestBody{
		BindingID: q.BindingID, PrincipalID: q.PrincipalID, Mode: mode, Nonce: hex.EncodeToString(nonceBytes),
	}
	if withVersion {
		reqBody.CredentialID = q.CredentialID
		reqBody.CredentialVersion = q.CredentialVersion
	}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/leases", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Device-ID", c.DeviceID)
	req.Header.Set("X-Device-Signature", c.sign(leaseSignaturePayload(reqBody)))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Lease{}, "", model.WrapError(model.CodeControlUnavailable, err, "center is unreachable")
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Lease{}, errorCode(data), model.NewError(model.CodeControlUnavailable, "%s", APIError(data))
	}
	var out struct {
		Lease        Lease  `json:"lease"`
		Epoch        string `json:"epoch"`
		CredentialID string `json:"credential_id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return Lease{}, "", err
	}
	// 旧中心只在顶层返回 credential_id；保留该兼容读取，缺失时由 Broker 拒绝不完整裁定。
	if out.Lease.CredentialID == "" {
		out.Lease.CredentialID = out.CredentialID
	}
	c.mu.Lock()
	c.epoch = out.Epoch
	c.leases[leaseKeyFor(q, mode)] = out.Lease
	c.mu.Unlock()
	return out.Lease, "", nil
}

func leaseKeyFor(q broker.UseQuery, mode string) leaseKey {
	return leaseKey{BindingID: q.BindingID, PrincipalID: q.PrincipalID, Mode: mode, CredentialVersion: q.CredentialVersion}
}

func (c *Client) cached(key leaseKey) (Lease, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	lease, ok := c.leases[key]
	return lease, ok
}

func (c *Client) invalidate(key leaseKey) {
	c.mu.Lock()
	delete(c.leases, key)
	c.mu.Unlock()
}

// confirmLease 向中心确认某一许可仍然有效。
func (c *Client) confirmLease(ctx context.Context, lease Lease) (broker.Permit, error) {
	body, _ := json.Marshal(map[string]string{"lease_id": lease.ID, "device_id": c.DeviceID})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return broker.Permit{}, model.WrapError(model.CodeControlUnavailable, err, "center confirmation failed; new use is stopped")
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return broker.Permit{}, &checkError{code: errorCode(data), message: APIError(data)}
	}
	var out struct {
		Valid             bool       `json:"valid"`
		PrincipalID       *string    `json:"principal_id"`
		BindingID         *string    `json:"binding_id"`
		CredentialID      *string    `json:"credential_id"`
		CredentialVersion *int       `json:"credential_version"`
		Mode              *string    `json:"mode"`
		ExpiresAt         *time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &out); err != nil || !out.Valid {
		return broker.Permit{}, model.NewError(model.CodeControlUnavailable, "center returned an invalid lease confirmation")
	}
	// 老中心可能只返回 valid/epoch：缺失字段沿用签发许可中的已绑定值；若中心明确
	// 返回不同值则保留该值，让 Broker 的精确约束拒绝本次取值。
	confirmed := lease
	if out.PrincipalID != nil {
		confirmed.PrincipalID = *out.PrincipalID
	}
	if out.BindingID != nil {
		confirmed.BindingID = *out.BindingID
	}
	if out.CredentialID != nil {
		confirmed.CredentialID = *out.CredentialID
	}
	if out.CredentialVersion != nil {
		confirmed.CredentialVersion = *out.CredentialVersion
	}
	if out.Mode != nil {
		confirmed.Mode = *out.Mode
	}
	if out.ExpiresAt != nil {
		confirmed.ExpiresAt = *out.ExpiresAt
	}
	return c.permitFor(confirmed), nil
}

// checkError 是中心确认返回的稳定错误码，用于区分可安全重新申请与真正撤销。
type checkError struct {
	code    string
	message string
}

func (e *checkError) Error() string { return e.code + ": " + e.message }

// CheckUse 在每次用钥前执行中心校验或短期许可期限校验，并返回中心对取值的约束。
// 它按实际主体、方式和凭证版本申请许可，不再固定按 proxy 方式申请。
func (c *Client) CheckUse(ctx context.Context, q broker.UseQuery) (broker.Permit, error) {
	mode := string(q.Mode)
	if mode == "" {
		mode = string(model.ModeProxy)
	}
	key := leaseKeyFor(q, mode)
	lease, ok := c.cached(key)
	if !ok || c.now().After(lease.ExpiresAt.Add(-2*time.Second)) {
		fetched, err := c.fetchLease(ctx, q, mode)
		if err != nil {
			return broker.Permit{}, err
		}
		lease = fetched
	}
	if c.Mode == "short_term" {
		// 离线可用，但不超过中心签发的绝对截止。
		if c.now().After(lease.ExpiresAt) {
			return broker.Permit{}, model.NewError(model.CodeLeaseExpired, "center-issued lease expired at %s", lease.ExpiresAt.Format(time.RFC3339))
		}
		return c.permitFor(lease), nil
	}
	// 在线模式：向中心确认，撤销立即生效。
	permit, err := c.confirmLease(ctx, lease)
	if err == nil {
		return permit, nil
	}
	// 只有「可以安全重新申请」的许可失效才重试：版本冲突与代次过期。
	// 真正撤销（CONTROL_UNAVAILABLE）立即拒绝，不重试。
	var ce *checkError
	if !errors.As(err, &ce) || !retryableCheckCode(ce.code) {
		return broker.Permit{}, model.NewError(model.CodeControlUnavailable, "%s", err.Error())
	}
	c.invalidate(key)
	fresh, ferr := c.fetchLease(ctx, q, mode)
	if ferr != nil {
		return broker.Permit{}, ferr
	}
	permit, err = c.confirmLease(ctx, fresh)
	if err != nil {
		return broker.Permit{}, model.NewError(model.CodeControlUnavailable, "center confirmation failed after reissuing the lease: %s", err.Error())
	}
	return permit, nil
}

// retryableCheckCode 判断该错误码是否表示「许可需要重新签发」而不是撤销。
func retryableCheckCode(code string) bool {
	return code == codeLeaseStale || code == codeLeaseEpochStale
}

// permitFor 把中心许可转换成 Broker 的取值约束。
func (c *Client) permitFor(lease Lease) broker.Permit {
	permit := broker.Permit{
		PrincipalID:       lease.PrincipalID,
		BindingID:         lease.BindingID,
		CredentialID:      lease.CredentialID,
		Mode:              model.DeliveryMode(lease.Mode),
		CredentialVersion: lease.CredentialVersion,
		LeaseID:           lease.ID,
	}
	if remaining := lease.ExpiresAt.Sub(c.now()); remaining > 0 {
		permit.MaxLeaseDuration = remaining
	}
	return permit
}

// Epoch 返回最近一次租约携带的授权代次。
func (c *Client) Epoch() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch
}
