package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"keykoi/internal/model"
	"keykoi/internal/oauth"
	"keykoi/internal/secret"
)

// OAuth token 相关字段名。它们都来自凭证版本，只有 token_endpoint 可能是非敏感值。
const (
	fieldTokenEndpoint = "token_endpoint"
	fieldClientID      = "client_id"
	fieldClientSecret  = "client_secret"
	fieldScope         = "scope"
	fieldAudience      = "audience"
	fieldClientAuth    = "client_auth"
	fieldClientEmail   = "client_email"
	fieldPrivateKey    = "private_key"
	fieldTokenURI      = "token_uri"
)

// 授予类型。
const (
	grantClientCredentials = "client_credentials"
	grantJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

const (
	// tokenClockSkew 是缓存到期相对上游 expires_in 的时间余量。
	tokenClockSkew = 60 * time.Second
	// tokenRequestTimeout 限制单次 token 交换，避免网关请求被上游拖住。
	tokenRequestTimeout = 15 * time.Second
	// maxTokenResponseBytes 限制 token 端点响应体大小。
	maxTokenResponseBytes = 1 << 20
)

// clientAuthMode 是 client_credentials 在 token 端点的客户端认证方式。
type clientAuthMode string

const (
	clientAuthBasic clientAuthMode = "basic"
	clientAuthPost  clientAuthMode = "post"
)

// tokenSourceConfig 是一次 token 交换所需的全部输入，值只来自当前凭证版本。
// 它不包含会话令牌，也不包含任何上游返回的 token。
type tokenSourceConfig struct {
	Scheme model.AuthScheme

	// Endpoint 是实际请求的 token 端点（JWT bearer 时等于 TokenURI）。
	Endpoint     string
	ClientID     string
	ClientSecret secret.Value
	Scope        string
	Audience     string
	ClientAuth   clientAuthMode

	// 服务账号形态。
	ClientEmail string
	PrivateKey  secret.Value
	TokenURI    string

	// assertion 是本次请求签出的 JWT，只用于在错误正文里做替换，不参与缓存。
	assertion secret.Value
}

// oauthAccessToken 返回可注入的 access token：命中内存缓存时直接复用，
// 否则按凭证 ID + 版本 + scope 做一次 single-flight 换取。
func (g *Gateway) oauthAccessToken(ctx context.Context, version model.CredentialVersion, scheme model.AuthScheme) (secret.Value, error) {
	cfg, err := tokenConfigFromVersion(scheme, version)
	if err != nil {
		return secret.Empty, err
	}
	key := tokenCacheKey(scheme, version, cfg.Scope)
	return g.tokens.get(ctx, key, func(fctx context.Context) (secret.Value, time.Time, error) {
		return g.exchangeToken(fctx, cfg)
	})
}

// exchangeToken 向上游 token 端点换取一次 access token。
// 返回零值到期时间表示上游未给 expires_in，调用方不得缓存该 token。
func (g *Gateway) exchangeToken(ctx context.Context, cfg tokenSourceConfig) (secret.Value, time.Time, error) {
	form := url.Values{}
	switch cfg.Scheme {
	case model.AuthOAuthClientCredentials:
		form.Set("grant_type", grantClientCredentials)
		if cfg.Scope != "" {
			form.Set("scope", cfg.Scope)
		}
		if cfg.Audience != "" {
			form.Set("audience", cfg.Audience)
		}
	case model.AuthOAuthJWTBearer:
		signed, err := oauth.SignJWTAssertion(oauth.Assertion{
			Issuer:     cfg.ClientEmail,
			PrivateKey: cfg.PrivateKey,
			Scope:      cfg.Scope,
			Audience:   cfg.Audience,
			IssuedAt:   g.now(),
			Lifetime:   oauth.MaxAssertionLifetime,
		})
		if err != nil {
			return secret.Empty, time.Time{}, mapOAuthError(err, cfg)
		}
		cfg.assertion = secret.New(signed)
		form.Set("grant_type", grantJWTBearer)
		form.Set("assertion", signed)
	default:
		// buildAuthHeader 只把两种 OAuth 方案送到这里；其它值属于适配缺口。
		return secret.Empty, time.Time{}, model.NewError(model.CodeAdapterUnsupported, "auth scheme %q has no OAuth token flow", cfg.Scheme)
	}

	if cfg.Scheme == model.AuthOAuthClientCredentials && cfg.ClientAuth == clientAuthPost {
		// client_secret_post：客户端凭据放在表单体里。
		form.Set("client_id", cfg.ClientID)
		form.Set("client_secret", cfg.ClientSecret.RevealString())
	}

	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, strings.NewReader(body))
	if err != nil {
		return secret.Empty, time.Time{}, model.NewError(model.CodeCredentialUnavailable, "token endpoint is not a usable URL")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "KeyKoi/1 oauth-token")
	if cfg.Scheme == model.AuthOAuthClientCredentials && cfg.ClientAuth != clientAuthPost {
		// client_secret_basic：按 RFC 6749 §2.3.1 用 HTTP Basic 提交客户端凭据。
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret.RevealString())
	}

	resp, err := g.tokenHTTP.Do(req)
	if err != nil {
		return secret.Empty, time.Time{}, mapOAuthError(err, cfg)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return secret.Empty, time.Time{}, mapOAuthError(err, cfg)
	}
	var tr tokenResponse
	decoded := json.Unmarshal(raw, &tr) == nil

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return secret.Empty, time.Time{}, tokenStatusError(cfg, resp.StatusCode, tr.Error, tr.ErrorDescription)
	}
	if !decoded {
		return secret.Empty, time.Time{}, tokenMalformed(cfg, "token endpoint returned a non-JSON body (HTTP %d)", resp.StatusCode)
	}
	if tr.Error != "" {
		return secret.Empty, time.Time{}, tokenStatusError(cfg, resp.StatusCode, tr.Error, tr.ErrorDescription)
	}
	if strings.TrimSpace(tr.AccessToken) == "" {
		return secret.Empty, time.Time{}, tokenMalformed(cfg, "token endpoint returned no access_token (HTTP %d)", resp.StatusCode)
	}
	expiresAt := tokenExpiry(g.now(), time.Duration(tr.ExpiresIn)*time.Second)
	return secret.New(tr.AccessToken), expiresAt, nil
}

// tokenResponse 只保留交换所需字段；响应体其余内容一律丢弃。
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// tokenExpiry 计算缓存到期：上游到期时间减去 60s 余量。
//   - expires_in 缺失（<=0）：不缓存，返回零值。
//   - expires_in 小于余量：取一半有效期，避免“刚取到就过期”仍然落缓存。
func tokenExpiry(now time.Time, expiresIn time.Duration) time.Time {
	if expiresIn <= 0 {
		return time.Time{}
	}
	if ttl := expiresIn - tokenClockSkew; ttl > 0 {
		return now.Add(ttl)
	}
	return now.Add(expiresIn / 2)
}

// tokenConfigFromVersion 从凭证版本读取并校验 OAuth 交换配置。
// 缺失或非法字段是凭证问题（CREDENTIAL_UNAVAILABLE）；
// 客户端认证方式不认识是不支持的适配形态（ADAPTER_UNSUPPORTED）。
func tokenConfigFromVersion(scheme model.AuthScheme, version model.CredentialVersion) (tokenSourceConfig, error) {
	cfg := tokenSourceConfig{Scheme: scheme}
	get := func(name string) secret.Value {
		value, err := version.Field(name)
		if err != nil {
			return secret.Empty
		}
		return value
	}
	text := func(name string) string { return strings.TrimSpace(get(name).RevealString()) }

	missing := func(field, scheme string) error {
		return model.NewError(model.CodeCredentialUnavailable,
			"credential %s version %d: field %q is required for %s",
			version.CredentialID, version.Version, field, scheme)
	}

	switch scheme {
	case model.AuthOAuthClientCredentials:
		cfg.Endpoint = text(fieldTokenEndpoint)
		cfg.ClientID = text(fieldClientID)
		cfg.ClientSecret = get(fieldClientSecret)
		cfg.Scope = text(fieldScope)
		cfg.Audience = text(fieldAudience)
		cfg.ClientAuth = clientAuthBasic
		switch mode := strings.ToLower(text(fieldClientAuth)); mode {
		case "", "basic", "client_secret_basic":
			cfg.ClientAuth = clientAuthBasic
		case "post", "client_secret_post":
			cfg.ClientAuth = clientAuthPost
		default:
			return cfg, model.NewError(model.CodeAdapterUnsupported,
				"credential %s version %d: unsupported client_auth mode %q (want basic or post)",
				version.CredentialID, version.Version, mode)
		}
		if cfg.Endpoint == "" {
			return cfg, missing(fieldTokenEndpoint, string(scheme))
		}
		if cfg.ClientID == "" {
			return cfg, missing(fieldClientID, string(scheme))
		}
		if cfg.ClientSecret.IsEmpty() {
			return cfg, missing(fieldClientSecret, string(scheme))
		}

	case model.AuthOAuthJWTBearer:
		cfg.TokenURI = text(fieldTokenURI)
		cfg.ClientEmail = text(fieldClientEmail)
		cfg.PrivateKey = get(fieldPrivateKey)
		cfg.Scope = text(fieldScope)
		cfg.Audience = text(fieldAudience)
		if cfg.TokenURI == "" {
			return cfg, missing(fieldTokenURI, string(scheme))
		}
		if cfg.ClientEmail == "" {
			return cfg, missing(fieldClientEmail, string(scheme))
		}
		if cfg.PrivateKey.IsEmpty() {
			return cfg, missing(fieldPrivateKey, string(scheme))
		}
		// 断言默认以 token_uri 为目标；显式 audience 覆盖它。
		cfg.Endpoint = cfg.TokenURI
		if cfg.Audience == "" {
			cfg.Audience = cfg.TokenURI
		}

	default:
		return cfg, model.NewError(model.CodeAdapterUnsupported,
			"auth scheme %q is not an OAuth token scheme", scheme)
	}

	if err := oauth.ValidateTokenEndpoint(cfg.Endpoint); err != nil {
		return cfg, model.WrapError(model.CodeCredentialUnavailable, err,
			"credential %s version %d: %s requires a valid HTTPS endpoint",
			version.CredentialID, version.Version, fieldNameForEndpoint(scheme))
	}
	return cfg, nil
}

func fieldNameForEndpoint(scheme model.AuthScheme) string {
	if scheme == model.AuthOAuthJWTBearer {
		return fieldTokenURI
	}
	return fieldTokenEndpoint
}

// tokenStatusError 把 token 端点的非 2xx 响应分类：
// 网络/5xx/429/408 视为上游不可用，其余 4xx 视为上游认证失败。
// 错误正文只含状态码、OAuth error 代码与截断后的描述，并对已知秘密做替换。
func tokenStatusError(cfg tokenSourceConfig, status int, code, description string) error {
	detail := ""
	if c := sanitizeTokenText(code); c != "" {
		detail = " " + c
	}
	desc := sanitizeTokenText(description)
	if desc != "" {
		desc = ": " + desc
	}
	switch {
	case status >= 500 || status == http.StatusTooManyRequests || status == http.StatusRequestTimeout:
		return tokenError(cfg, model.CodeUpstreamUnavailable,
			"token endpoint temporary failure (HTTP %d)%s%s", status, detail, desc)
	default:
		return tokenError(cfg, model.CodeUpstreamAuthFailed,
			"token endpoint rejected the request (HTTP %d%s)%s", status, detail, desc)
	}
}

func tokenMalformed(cfg tokenSourceConfig, format string, args ...any) error {
	return tokenError(cfg, model.CodeUpstreamAuthFailed, format, args...)
}

// tokenError 构造不含秘密的错误：消息里出现的 client_secret 或断言会被替换。
func tokenError(cfg tokenSourceConfig, code model.Code, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	msg = redactSecrets(msg, cfg.ClientSecret, cfg.PrivateKey, cfg.assertion)
	return model.NewError(code, "%s", msg)
}

// redactSecrets 把消息中出现的秘密原文替换为占位符。
// 上游可以把任意内容放进 error_description，这一步防止它把凭据反射回错误正文。
func redactSecrets(msg string, values ...secret.Value) string {
	for _, value := range values {
		raw := value.RevealString()
		if len(raw) < 4 {
			continue
		}
		if strings.Contains(msg, raw) {
			msg = strings.ReplaceAll(msg, raw, "<redacted>")
		}
	}
	return msg
}

// sanitizeTokenText 截断上游文本，避免把大块响应写进错误或日志。
func sanitizeTokenText(s string) string {
	s = strings.ToValidUTF8(strings.TrimSpace(s), "")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// mapOAuthError 把网络错误与 oauth 包的结构化错误翻译成网关错误码。
func mapOAuthError(err error, cfg tokenSourceConfig) error {
	var oe *oauth.Error
	if errors.As(err, &oe) {
		msg := redactSecrets(oe.Error(), cfg.ClientSecret, cfg.PrivateKey, cfg.assertion)
		switch oe.Class {
		case oauth.ClassConfig:
			return model.NewError(model.CodeCredentialUnavailable, "%s", msg)
		case oauth.ClassRetryable:
			return model.WrapError(model.CodeUpstreamUnavailable, err, "%s", msg)
		default:
			return model.WrapError(model.CodeUpstreamAuthFailed, err, "%s", msg)
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return model.WrapError(model.CodeUpstreamUnavailable, err, "token exchange canceled")
	}
	// 其它错误来自 DNS/TCP/TLS 层：上游不可达，不把底层正文透给工具。
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return model.WrapError(model.CodeUpstreamUnavailable, err, "token endpoint timed out")
	}
	if strings.Contains(err.Error(), "token endpoint redirect") {
		return model.WrapError(model.CodeUpstreamUnavailable, err, "token endpoint returned a redirect, which is not followed")
	}
	return model.WrapError(model.CodeUpstreamUnavailable, err, "token endpoint is unreachable")
}
