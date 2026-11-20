// Package gateway 实现显式 HTTP 网关：只向已登记的 Binding 注入认证信息，
// 移除中介令牌与内部控制头，保留原路径、查询、状态码与流式响应。
package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/httpforward"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

// Options 配置网关。
type Options struct {
	// Transport 允许测试注入受控传输；默认使用校验上游证书的 http.Transport。
	Transport http.RoundTripper
	// Now 便于测试注入时钟。
	Now func() time.Time
	// MaxBodyBytes 限制请求体大小；0 表示不限制（仍需显式设置）。
	MaxBodyBytes int64
}

// Gateway 是网关入口。
type Gateway struct {
	broker    *broker.Broker
	transport http.RoundTripper
	// tokenHTTP 只用于访问 OAuth token 端点；它不跟随重定向。
	tokenHTTP *http.Client
	now       func() time.Time
	maxBody   int64
	// tokens 是 OAuth access token 的内存缓存（按凭证 ID + 版本 + scope）。
	tokens *tokenCache
}

// New 构造网关。
func New(b *broker.Broker, opts Options) *Gateway {
	if opts.Transport == nil {
		opts.Transport = DefaultTransport()
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Gateway{
		broker:    b,
		transport: opts.Transport,
		tokenHTTP: &http.Client{
			Transport: opts.Transport,
			Timeout:   tokenRequestTimeout,
			// token 端点重定向不跟随：否则客户端凭据可能被带到未登记的主机。
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("token endpoint redirect is not followed")
			},
		},
		now:     opts.Now,
		maxBody: opts.MaxBodyBytes,
		tokens:  newTokenCache(opts.Now),
	}
}

// DefaultTransport 返回校验上游证书、限制连接阶段的传输。
// 它不关闭 TLS 校验，也不使用环境代理，避免把业务请求转发到意外第三方。
func DefaultTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// ServeHTTP 处理 /gateway/{route}/... 请求。
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := g.now()
	base := r.URL.Path
	if !strings.HasPrefix(base, "/gateway/") {
		writeError(w, model.NewError(model.CodeSessionInvalid, "gateway path must start with /gateway/"))
		return
	}
	rest := strings.TrimPrefix(base, "/gateway/")
	route := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		route = rest[:i]
	}
	if route == "" {
		writeError(w, model.NewError(model.CodeSessionInvalid, "gateway route is missing"))
		return
	}
	if isUpgrade(r) {
		writeError(w, model.NewError(model.CodeUpstreamUnavailable, "HTTP upgrade, WebSocket and gRPC are not supported by this gateway"))
		return
	}
	token, err := sessionToken(r)
	if err != nil {
		writeError(w, err)
		return
	}
	authz, err := g.broker.Authorize(r.Context(), broker.Request{
		Token:   token,
		Route:   route,
		Mode:    model.ModeProxy,
		Purpose: "http gateway route=" + route,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	// 一次请求用一次许可：响应结束即释放，不把短期许可留到会话关闭。
	defer g.broker.ReleaseLease(authz.Lease.ID)
	ctx, cancel := authz.ExecutionContext(r.Context())
	defer cancel()
	controller := http.NewResponseController(w)
	if controller.SetWriteDeadline(authz.Lease.UseLeaseExpiresAt) == nil {
		defer controller.SetWriteDeadline(time.Time{})
	}
	r = r.WithContext(ctx)
	binding := bindingFor(authz, route)
	upstream, err := g.buildUpstreamURL(binding, route, r)
	if err != nil {
		writeError(w, err)
		return
	}
	// 判定范围与实际转发的路径必须是同一形式：upstream.Path 已是规范化结果，
	// EscapedPath 是真正写进请求行的形式。两种解释都落在前缀内才放行。
	sentPath := upstream.EscapedPath()
	if !binding.PathAllowed(upstream.Path) || !binding.PathAllowed(sentPath) {
		writeError(w, model.NewError(model.CodeBindingDisabled, "request path is not allowed for route %s", route))
		return
	}
	headerName, headerValue, err := g.buildAuthHeader(r.Context(), binding, authz.Version)
	if err != nil {
		// 认证失败也要留审计：只记录错误码与状态，不记录任何凭据值。
		g.record(r.Context(), authz, binding, statusForError(err), string(model.CodeOf(err)), start)
		writeError(w, err)
		return
	}
	body := r.Body
	if body != nil && g.maxBody > 0 {
		body = http.MaxBytesReader(w, r.Body, g.maxBody)
	}
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstream.String(), body)
	if err != nil {
		writeError(w, model.NewError(model.CodeUpstreamUnavailable, "cannot build upstream request"))
		return
	}
	outReq.URL = upstream
	outReq.Host = bindingHost(binding)
	outReq.ContentLength = r.ContentLength
	httpforward.CopyHeaders(outReq.Header, r.Header)
	removeInternalHeaders(outReq.Header)
	outReq.Header.Del("Authorization")
	outReq.Header.Del(strings.ToLower(binding.AuthHeader))
	outReq.Header.Del("X-Api-Key")
	outReq.Header.Set(headerName, headerValue)

	resp, err := g.transport.RoundTrip(outReq)
	if err != nil {
		// 只记录连接层原因，不含请求头或凭证。
		log.Printf("gateway: upstream request failed: binding=%s host=%s err=%v", binding.ID, bindingHost(binding), err)
		g.record(r.Context(), authz, binding, http.StatusBadGateway, string(model.CodeUpstreamUnavailable), start)
		writeError(w, model.NewError(model.CodeUpstreamUnavailable, "upstream %s request failed", bindingHost(binding)))
		return
	}
	defer resp.Body.Close()
	httpforward.CopyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	// 跳转不跟随：网关只把上游的回答交回调用方，自身绝不再发一次带凭证的请求。
	// 但跳转不是一次完成的交换，按非成功记账，避免审计把它当成功。
	resultCode := ""
	if isRedirect(resp.StatusCode) {
		resultCode = codeUpstreamRedirect
	}
	readErr, writeErr := httpforward.StreamBody(w, resp.Body)
	if writeErr != nil {
		g.record(r.Context(), authz, binding, resp.StatusCode, codeClientWriteFailed, start)
		return
	}
	if readErr != nil {
		log.Printf("gateway: upstream response interrupted: binding=%s host=%s status=%d err=%v",
			binding.ID, bindingHost(binding), resp.StatusCode, readErr)
		g.record(r.Context(), authz, binding, resp.StatusCode, codeResponseInterrupted, start)
		panic(http.ErrAbortHandler)
	}
	g.record(r.Context(), authz, binding, resp.StatusCode, resultCode, start)
}

// 网关审计里单独标记的未完成交换。它们都不是成功。
const (
	// codeResponseInterrupted 表示上游响应体读取中断，客户端只拿到部分数据。
	codeResponseInterrupted = "upstream_response_interrupted"
	// codeUpstreamRedirect 表示上游返回跳转；网关不跟随，也不把它当成功。
	codeUpstreamRedirect = "upstream_redirect_not_followed"
	// codeClientWriteFailed 表示写回调用方失败，交换没有完成。
	codeClientWriteFailed = "client_write_failed"
)

// isRedirect 报告状态码是否为需要跟随的跳转。
func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

func (g *Gateway) record(ctx context.Context, authz *broker.Authorization, binding *model.Binding, status int, code string, start time.Time) {
	g.broker.Record(ctx, store.AuditEvent{
		SessionID:         authz.Session.ID,
		PrincipalID:       authz.Session.PrincipalID,
		BindingID:         binding.ID,
		CredentialID:      authz.Lease.CredentialID,
		CredentialVersion: authz.Lease.CredentialVersion,
		Mode:              string(model.ModeProxy),
		Result:            "http_" + strconv.Itoa(status),
		ErrorCode:         code,
		DurationMS:        g.now().Sub(start).Milliseconds(),
	})
}

// bindingFor 从授权结果恢复 Binding 的登记路由信息。
// Broker 已校验 Binding，此处只读取随许可固定的 ID 与路由。
func bindingFor(authz *broker.Authorization, route string) *model.Binding {
	b := authz.Binding
	if b == nil {
		b = &model.Binding{ID: authz.Lease.BindingID, Route: route, Status: model.StatusActive}
	}
	return b
}

func (g *Gateway) buildUpstreamURL(binding *model.Binding, route string, r *http.Request) (*url.URL, error) {
	origin, err := binding.Origin()
	if err != nil {
		return nil, model.NewError(model.CodeBindingDisabled, "binding origin is invalid")
	}
	prefix := "/gateway/" + route
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	if rest == "" {
		rest = "/"
	}
	// 转发路径与 PathAllowed 用同一规范化：判定过的路径就是发出去的路径，
	// 会自行规范化路径的上游也无法把请求带到登记前缀之外。
	normalized, err := model.NormalizePath(rest)
	if err != nil {
		return nil, model.NewError(model.CodeBindingDisabled, "request path cannot be normalized")
	}
	rawRest := ""
	if r.URL.RawPath != "" {
		rawRest = strings.TrimPrefix(r.URL.RawPath, prefix)
	}
	u := &url.URL{
		Scheme:   origin.Scheme,
		Host:     origin.Host,
		Path:     normalized,
		RawQuery: r.URL.RawQuery,
	}
	// 只有在原始编码与规范化后的路径语义一致时保留原始编码；规范化改写了路径
	// 时丢弃 RawPath，避免上游按旧的编码形式解析出与判定不同的路径。
	if rawRest != "" {
		if decoded, err := url.PathUnescape(rawRest); err == nil && decoded == normalized {
			u.RawPath = rawRest
		}
	}
	return u, nil
}

func bindingHost(binding *model.Binding) string {
	u, err := url.Parse(binding.UpstreamOrigin)
	if err != nil {
		return ""
	}
	return u.Host
}

// buildAuthHeader 生成注入上游的认证头。静态方案直接读字段；
// OAuth 方案先经缓存/换取拿到 access token，再以 Bearer 注入。
func (g *Gateway) buildAuthHeader(ctx context.Context, binding *model.Binding, version model.CredentialVersion) (string, string, error) {
	switch binding.AuthScheme {
	case model.AuthOAuthClientCredentials, model.AuthOAuthJWTBearer:
		token, err := g.oauthAccessToken(ctx, version, binding.AuthScheme)
		if err != nil {
			return "", "", err
		}
		return "Authorization", "Bearer " + token.RevealString(), nil
	}
	return staticAuthHeader(binding, version)
}

// staticAuthHeader 覆盖不需要上游换取的方案。
func staticAuthHeader(binding *model.Binding, version model.CredentialVersion) (string, string, error) {
	switch binding.AuthScheme {
	case model.AuthBearer:
		field := defaultString(binding.TokenField, "token")
		v, err := version.Field(field)
		if err != nil {
			return "", "", model.WrapError(model.CodeCredentialUnavailable, err, "credential field for bearer injection is missing")
		}
		return "Authorization", "Bearer " + v.RevealString(), nil
	case model.AuthAPIKey:
		field := defaultString(binding.TokenField, "token")
		v, err := version.Field(field)
		if err != nil {
			return "", "", model.WrapError(model.CodeCredentialUnavailable, err, "credential field for API key injection is missing")
		}
		return defaultString(binding.AuthHeader, "X-Api-Key"), v.RevealString(), nil
	case model.AuthBasic:
		user, err := version.Field(defaultString(binding.UsernameField, "username"))
		if err != nil {
			return "", "", model.WrapError(model.CodeCredentialUnavailable, err, "credential field for basic auth user is missing")
		}
		pw, err := version.Field(defaultString(binding.PasswordField, "password"))
		if err != nil {
			return "", "", model.WrapError(model.CodeCredentialUnavailable, err, "credential field for basic auth password is missing")
		}
		creds := user.RevealString() + ":" + pw.RevealString()
		return "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(creds)), nil
	}
	return "", "", model.NewError(model.CodeAdapterUnsupported, "unsupported auth scheme %q", binding.AuthScheme)
}

func sessionToken(r *http.Request) (secret.Value, error) {
	if v := r.Header.Get("X-KeyKoi-Session"); v != "" {
		return secret.New(v), nil
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		tok := strings.TrimPrefix(auth, "Bearer ")
		if strings.HasPrefix(tok, "kks_") {
			return secret.New(tok), nil
		}
	}
	// git 等客户端只会用 Basic；把密码位当作中介令牌即可，真实凭据由网关注入。
	if strings.HasPrefix(auth, "Basic ") {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic ")); err == nil {
			if _, pass, ok := strings.Cut(string(raw), ":"); ok && strings.HasPrefix(pass, "kks_") {
				return secret.New(pass), nil
			}
		}
	}
	// 通用 API 客户端可在原生 Key 头中提交会话令牌。
	for _, name := range []string{"X-Api-Key", "Api-Key"} {
		if v := r.Header.Get(name); strings.HasPrefix(v, "kks_") {
			return secret.New(v), nil
		}
	}
	return secret.Empty, model.NewError(model.CodeSessionInvalid, "missing intermediary session token")
}

func isUpgrade(r *http.Request) bool {
	if r.Header.Get("Upgrade") != "" {
		return true
	}
	for _, v := range r.Header.Values("Connection") {
		if strings.Contains(strings.ToLower(v), "upgrade") {
			return true
		}
	}
	return false
}

// removeInternalHeaders 移除中介自己的令牌与控制头，避免泄露给上游。
func removeInternalHeaders(h http.Header) {
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-keykoi-") {
			h.Del(name)
		}
	}
	// Preserve outbound stripping for the retired session header.
	for _, name := range []string{"X-Api-Key", "X-Goog-Api-Key", "Api-Key", "Authorization"} {
		h.Del(name)
	}
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// ErrorBody 是稳定错误封装，只含错误码与说明。
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, err error) {
	code := model.CodeOf(err)
	status := statusForError(err)
	if code == model.CodeSessionInvalid {
		// 让 git 等客户端知道可以走凭据助手重试。
		w.Header().Set("WWW-Authenticate", `Basic realm="KeyKoi"`)
	}
	body := ErrorBody{}
	body.Error.Code = string(code)
	if code == "" {
		body.Error.Code = "INTERNAL"
	}
	body.Error.Message = err.Error()
	if code == "" {
		// 不把未分类的内部错误原文返回给工具。
		body.Error.Message = "internal error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, encodeJSON(body))
}

// statusForError 把稳定错误码映射为 HTTP 状态码，供响应与审计共用。
//
// 验证类失败必须给出可处理的状态，不能落成 500：AUTH_REQUIRED 是“还差一次
// 验证”（401，验证后可重试），AUTH_UNAVAILABLE 是“当前环境无法完成验证”
// （403，重试无用，需先补齐验证手段）。两类都保留稳定错误码在响应体里。
func statusForError(err error) int {
	code := model.CodeOf(err)
	status := http.StatusInternalServerError
	switch code {
	case model.CodeVaultLocked:
		status = http.StatusServiceUnavailable
	case model.CodeVaultUnlockFailed:
		status = http.StatusUnauthorized
	case model.CodeSessionInvalid, model.CodeAuthRequired:
		status = http.StatusUnauthorized
	case model.CodeAuthUnavailable:
		status = http.StatusForbidden
	case model.CodeUseNotAllowed, model.CodeLeaseExpired:
		status = http.StatusForbidden
	case model.CodeBindingDisabled:
		status = http.StatusNotFound
	case model.CodeCredentialUnavailable:
		status = http.StatusServiceUnavailable
	case model.CodeAdapterUnsupported:
		status = http.StatusNotImplemented
	case model.CodeUpstreamUnavailable:
		status = http.StatusBadGateway
	case model.CodeControlUnavailable:
		status = http.StatusServiceUnavailable
	case model.CodeUpstreamAuthFailed:
		status = http.StatusUnauthorized
	default:
		if errors.Is(err, context.Canceled) {
			status = http.StatusRequestTimeout
		}
	}
	return status
}

func encodeJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":{"code":"INTERNAL","message":"internal error"}}`
	}
	return string(b)
}
