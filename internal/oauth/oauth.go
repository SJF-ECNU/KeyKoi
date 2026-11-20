// Package oauth 实现 KeyKoi 托管的 OAuth 2.0 授权码 + PKCE 登录与串行刷新。
//
// 支持范围（选定提供方形态：标准 OAuth 2.0 authorization code + refresh_token 轮换）：
//   - Begin：生成 PKCE(S256) 与 state，产出受信授权入口 URL；verifier 只留在中介内存。
//   - Exchange：用 authorization code 换取完整 token 组合，校验 code_verifier。
//   - Refresh：串行刷新并原子保存完整新组合（access_token + 轮换后的 refresh_token +
//     真实到期时间），缓存有效期不超过真实到期减时钟余量。
//
// 失败语义按可操作性分类：可重试网络/上游临时错误、已撤销（invalid_grant，需重新登录）、
// 上游拒绝（配置或请求问题）、响应不合规，以及“上游已轮换但本地提交失败”
// （recovery_required，可见且可诊断）。任何错误正文都不含 token 原文。
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"keykoi/internal/model"
	"keykoi/internal/secret"
)

// 字段名称。前五个与 model.FieldSpecs(KindOAuth) 一致；其余是提供方入口与客户端
// 认证方式，仍然只存在于凭证字段中，不写入工具普通配置。
const (
	FieldAccessToken       = "access_token"
	FieldRefreshToken      = "refresh_token"
	FieldClientID          = "client_id"
	FieldClientSecret      = "client_secret"
	FieldTokenEndpoint     = "token_endpoint"
	FieldAuthorizeEndpoint = "authorize_endpoint"
	FieldRedirectURI       = "redirect_uri"
	FieldScope             = "scope"
	FieldTokenType         = "token_type"
)

// AuthMethod 是客户端在 token 端点的认证方式。
type AuthMethod string

const (
	// AuthClientSecretBasic 使用 HTTP Basic（RFC 6749 §2.3.1）。
	AuthClientSecretBasic AuthMethod = "client_secret_basic"
	// AuthClientSecretPost 把 client_secret 放进表单体。
	AuthClientSecretPost AuthMethod = "client_secret_post"
	// AuthNone 用于公开客户端，仅依赖 PKCE。
	AuthNone AuthMethod = "none"
)

// DefaultSkew 是缓存有效期的时钟余量：缓存到期 = 真实到期 - 余量。
const DefaultSkew = 30 * time.Second

// ProviderConfig 是令牌端点所需的最少客户端信息，全部来自凭证字段。
type ProviderConfig struct {
	ClientID          string
	ClientSecret      secret.Value
	TokenEndpoint     string
	AuthorizeEndpoint string
	RedirectURI       string
	Scopes            []string
	// AuthMethod 缺省按是否配置 client_secret 推断。
	AuthMethod AuthMethod
}

// ConfigFromVersion 从 oauth 凭证版本读取客户端信息；缺失关键字段明确失败。
func ConfigFromVersion(v model.CredentialVersion) (ProviderConfig, error) {
	cfg := ProviderConfig{}
	if raw, err := v.Field(FieldClientID); err == nil {
		cfg.ClientID = strings.TrimSpace(raw.RevealString())
	}
	if raw, err := v.Field(FieldClientSecret); err == nil {
		cfg.ClientSecret = raw
	}
	if raw, err := v.Field(FieldTokenEndpoint); err == nil {
		cfg.TokenEndpoint = strings.TrimSpace(raw.RevealString())
	}
	if raw, err := v.Field(FieldAuthorizeEndpoint); err == nil {
		cfg.AuthorizeEndpoint = strings.TrimSpace(raw.RevealString())
	}
	if raw, err := v.Field(FieldRedirectURI); err == nil {
		cfg.RedirectURI = strings.TrimSpace(raw.RevealString())
	}
	if raw, err := v.Field(FieldScope); err == nil {
		cfg.Scopes = strings.Fields(raw.RevealString())
	}
	if cfg.ClientID == "" {
		return ProviderConfig{}, configError("credential %s: field %q is required", v.CredentialID, FieldClientID)
	}
	if cfg.TokenEndpoint == "" {
		return ProviderConfig{}, configError("credential %s: field %q is required", v.CredentialID, FieldTokenEndpoint)
	}
	if err := validateEndpoint(FieldTokenEndpoint, cfg.TokenEndpoint); err != nil {
		return ProviderConfig{}, err
	}
	if cfg.RedirectURI != "" {
		if err := validateEndpoint(FieldRedirectURI, cfg.RedirectURI); err != nil {
			return ProviderConfig{}, err
		}
	}
	if cfg.AuthMethod == "" {
		if cfg.ClientSecret.IsEmpty() {
			cfg.AuthMethod = AuthNone
		} else {
			cfg.AuthMethod = AuthClientSecretBasic
		}
	}
	return cfg, nil
}

func validateEndpoint(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return configError("%s %q is not an absolute URL", name, raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return configError("%s %q must use http or https", name, raw)
	}
	return nil
}

// TokenSet 是一次交换或刷新得到的完整 token 组合。
type TokenSet struct {
	AccessToken  secret.Value
	RefreshToken secret.Value
	TokenType    string
	ExpiresIn    time.Duration
	Scope        string
	// Rotated 报告上游是否下发了新的 refresh_token。
	Rotated bool
}

// ExpiresAt 返回真实到期时间；上游未给 expires_in 时返回 nil（不伪造到期）。
func (t TokenSet) ExpiresAt(now time.Time) *time.Time {
	if t.ExpiresIn <= 0 {
		return nil
	}
	exp := now.Add(t.ExpiresIn)
	return &exp
}

// Authorization 是一次待完成授权的受信入口。
type Authorization struct {
	URL        string `json:"authorization_url"`
	State      string `json:"state"`
	RedirectRI string `json:"redirect_uri"`
	ExpiresAt  time.Time
}

// Service 执行上游 OAuth 协议交互。它不持有凭证存储，也不做版本提交。
type Service struct {
	// HTTP 用于访问 token 端点；默认 15s 超时。服务会复制它并强制
	// CheckRedirect 拒绝一切跳转，这里的 CheckRedirect 不生效。
	HTTP *http.Client
	// Now 便于测试注入时钟。
	Now func() time.Time
	// Pending 保存待完成授权的 PKCE verifier 与 state。
	Pending *PendingStore
	// AllowLoopbackHTTP 显式允许回环地址（127.0.0.1、localhost、::1）
	// 的明文 http。默认 false：令牌端点与授权入口只接受 https，证书由
	// 默认传输层校验。只有自动化测试与受控本地上游才打开。
	AllowLoopbackHTTP bool
}

// LoopbackHTTPEnv 是回环明文放行开关的环境变量名。只有取值为 1 或 true 时
// 才打开，用于自动化验收与受控本地上游；生产环境不应设置。
const LoopbackHTTPEnv = "KEYKOI_OAUTH_ALLOW_LOOPBACK_HTTP"

// NewService 构造服务。回环明文放行只跟随显式开关，默认关闭。
func NewService() *Service {
	return &Service{
		HTTP:              &http.Client{Timeout: 15 * time.Second},
		Now:               func() time.Time { return time.Now().UTC() },
		Pending:           NewPendingStore(10 * time.Minute),
		AllowLoopbackHTTP: loopbackHTTPFromEnv(),
	}
}

// loopbackHTTPFromEnv 读取显式开关；未设置或取值不明确时保持关闭。
func loopbackHTTPFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(LoopbackHTTPEnv))) {
	case "1", "true":
		return true
	}
	return false
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// refuseRedirect 让令牌请求一律不跟随跳转，重定向响应原样交回调用方判断。
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// tokenHTTPClient 返回用于令牌请求的客户端：复制调用方提供的客户端，
// 覆盖 CheckRedirect 为拒绝跳转，并拒绝任何关闭证书校验的传输层。
// 这样令牌表单不会随 307/308 之类的跳转离开登记的令牌端点。
func (s *Service) tokenHTTPClient() (*http.Client, error) {
	base := s.HTTP
	if base == nil {
		base = &http.Client{Timeout: 15 * time.Second}
	}
	if tr, ok := base.Transport.(*http.Transport); ok && tr != nil &&
		tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		return nil, configError("oauth token endpoint certificate verification must not be disabled")
	}
	client := *base
	if client.Timeout <= 0 {
		client.Timeout = 15 * time.Second
	}
	client.CheckRedirect = refuseRedirect
	return &client, nil
}

// endpointURL 解析并校验中介实际请求或引导的端点。
//   - https：允许，证书由传输层校验；
//   - 明文 http：只有显式打开 AllowLoopbackHTTP 且主机是回环地址时允许；
//   - 其他 scheme 与缺少主机的 URL 一律拒绝。
func (s *Service) endpointURL(field, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil, configError("%s %q is not an absolute URL", field, raw)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if !s.AllowLoopbackHTTP {
			return nil, configError("%s %q must use https; plaintext http requires an explicit loopback opt-in", field, raw)
		}
		if !isLoopbackHost(u.Hostname()) {
			return nil, configError("%s %q must use https; plaintext http is only allowed for loopback hosts", field, raw)
		}
		return u, nil
	default:
		return nil, configError("%s %q must use https", field, raw)
	}
}

// isLoopbackHost 报告主机名是否为本机回环地址（localhost 或任意回环 IP）。
func isLoopbackHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// sameOrigin 比较两个 URL 的 scheme 与 host:port，缺省端口按 scheme 归一。
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(originOf(a), originOf(b))
}

func originOf(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

// PKCE 生成 code_verifier 与 S256 code_challenge。
func PKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// BeginBinding 是发起登录时观察到的凭证记录状态。回调提交时用它判断管理员
// 或并行轮换是否在等待期间改动过记录：版本、修订号或状态不一致就不覆盖。
type BeginBinding struct {
	Version  int
	Revision int64
	Status   model.EntityStatus
}

// Begin 生成 PKCE + state 并返回受信授权入口。verifier 只在 Pending 中驻留。
// binding 可选：传入时把发起时刻的记录版本与状态登记进 Pending，供回调校验。
func (s *Service) Begin(cfg ProviderConfig, credentialID string, binding ...BeginBinding) (Authorization, error) {
	var bound BeginBinding
	if len(binding) > 0 {
		bound = binding[0]
	}
	if cfg.AuthorizeEndpoint == "" {
		return Authorization{}, configError("credential %s: field %q is required for login", credentialID, FieldAuthorizeEndpoint)
	}
	authorizeURL, err := s.endpointURL(FieldAuthorizeEndpoint, cfg.AuthorizeEndpoint)
	if err != nil {
		return Authorization{}, err
	}
	if cfg.RedirectURI == "" {
		return Authorization{}, configError("credential %s: field %q is required for login", credentialID, FieldRedirectURI)
	}
	verifier, challenge, err := PKCE()
	if err != nil {
		return Authorization{}, localError("generate pkce", err)
	}
	stateBuf := make([]byte, 32)
	if _, err := rand.Read(stateBuf); err != nil {
		return Authorization{}, localError("generate state", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBuf)

	u := authorizeURL
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	if len(cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	u.RawQuery = q.Encode()

	if s.Pending == nil {
		s.Pending = NewPendingStore(10 * time.Minute)
	}
	expires := s.Pending.Put(Pending{
		State:        state,
		CredentialID: credentialID,
		CodeVerifier: verifier,
		RedirectURI:  cfg.RedirectURI,
		CreatedAt:    s.now(),
		Version:      bound.Version,
		Revision:     bound.Revision,
		Status:       bound.Status,
	})
	return Authorization{URL: u.String(), State: state, RedirectRI: cfg.RedirectURI, ExpiresAt: expires}, nil
}

// Exchange 用 authorization code 换取 token 组合，并提交 PKCE verifier。
func (s *Service) Exchange(ctx context.Context, cfg ProviderConfig, code, codeVerifier, redirectURI string) (TokenSet, error) {
	if strings.TrimSpace(code) == "" {
		return TokenSet{}, reauthError("exchange", "authorization code is empty")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}
	return s.tokenRequest(ctx, cfg, "exchange", form)
}

// Refresh 用 refresh_token 换取新的完整组合；上游可能轮换 refresh_token。
// 返回的 TokenSet.Rotated 表示上游是否下发了新值。
func (s *Service) Refresh(ctx context.Context, cfg ProviderConfig, refreshToken secret.Value) (TokenSet, error) {
	if refreshToken.IsEmpty() {
		return TokenSet{}, reauthError("refresh", "credential has no refresh_token; re-authorization is required")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken.RevealString())
	if len(cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	return s.tokenRequest(ctx, cfg, "refresh", form)
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (s *Service) tokenRequest(ctx context.Context, cfg ProviderConfig, op string, form url.Values) (TokenSet, error) {
	endpoint, err := s.endpointURL(FieldTokenEndpoint, cfg.TokenEndpoint)
	if err != nil {
		return TokenSet{}, err
	}
	client, err := s.tokenHTTPClient()
	if err != nil {
		return TokenSet{}, err
	}
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(body))
	if err != nil {
		return TokenSet{}, configError("token_endpoint %q is invalid", cfg.TokenEndpoint)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	switch cfg.AuthMethod {
	case AuthClientSecretPost:
		form.Set("client_id", cfg.ClientID)
		form.Set("client_secret", cfg.ClientSecret.RevealString())
		body = form.Encode()
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
	case AuthNone:
		form.Set("client_id", cfg.ClientID)
		body = form.Encode()
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
	default:
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret.RevealString())
	}

	resp, err := client.Do(req)
	if err != nil {
		return TokenSet{}, networkError(op, err)
	}
	defer resp.Body.Close()
	// 请求必须仍然落在登记的令牌端点上；被改写到其他 origin 的响应不能当成功。
	if resp.Request != nil && resp.Request.URL != nil && !sameOrigin(resp.Request.URL, endpoint) {
		return TokenSet{}, configError("token request reached %s instead of the registered token endpoint", resp.Request.URL.Redacted())
	}
	// 跳转响应不跟随、也不视为成功：令牌表单绝不离开登记的令牌端点。
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return TokenSet{}, redirectError(op, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return TokenSet{}, networkError(op, err)
	}
	var tr tokenResponse
	decoded := json.Unmarshal(raw, &tr) == nil

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return TokenSet{}, upstreamStatusError(op, resp.StatusCode, tr.Error, tr.ErrorDescription)
	}
	if !decoded {
		return TokenSet{}, malformedError(op, "token endpoint returned a non-JSON body")
	}
	if tr.Error != "" {
		return TokenSet{}, upstreamStatusError(op, resp.StatusCode, tr.Error, tr.ErrorDescription)
	}
	if tr.AccessToken == "" {
		return TokenSet{}, malformedError(op, "token endpoint returned no access_token")
	}
	ts := TokenSet{
		AccessToken:  secret.New(tr.AccessToken),
		RefreshToken: secret.New(tr.RefreshToken),
		TokenType:    strings.TrimSpace(tr.TokenType),
		Scope:        tr.Scope,
		Rotated:      tr.RefreshToken != "",
	}
	if tr.ExpiresIn > 0 {
		ts.ExpiresIn = time.Duration(tr.ExpiresIn) * time.Second
	}
	return ts, nil
}

// EqualState 用常量时间比较 state。
func EqualState(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// CacheExpiry 返回缓存到期：真实到期减时钟余量；没有真实到期时返回 nil。
func CacheExpiry(expiresAt *time.Time, skew time.Duration) *time.Time {
	if expiresAt == nil {
		return nil
	}
	if skew <= 0 {
		skew = DefaultSkew
	}
	out := expiresAt.Add(-skew)
	return &out
}

// versionFields 把新 token 组合合并进原字段：access_token 一定替换，
// refresh_token 只有在上游轮换时才替换，客户端信息保持不变。
func versionFields(base map[string]secret.Value, ts TokenSet) map[string]secret.Value {
	out := make(map[string]secret.Value, len(base)+3)
	for k, v := range base {
		out[k] = v
	}
	out[FieldAccessToken] = ts.AccessToken
	if !ts.RefreshToken.IsEmpty() {
		out[FieldRefreshToken] = ts.RefreshToken
	}
	if ts.TokenType != "" {
		out[FieldTokenType] = secret.New(ts.TokenType)
	}
	return out
}
