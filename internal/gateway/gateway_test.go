package gateway_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/gateway"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

type stack struct {
	store    *store.Memory
	source   *broker.MemorySource
	broker   *broker.Broker
	gw       *gateway.Gateway
	server   *httptest.Server
	upstream *httptest.Server
	clock    *fakeClock
	token    secret.Value
	credID   string
	binding  string
	route    string
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// stackOptions 允许单个用例在默认测试栈上注入验证器或受控传输。
type stackOptions struct {
	broker  func(*broker.Options)
	gateway func(*gateway.Options)
}

func newStack(t *testing.T, expectedToken string, authMode model.AuthScheme) *stack {
	t.Helper()
	return newStackWith(t, expectedToken, authMode, stackOptions{})
}

func newStackWith(t *testing.T, expectedToken string, authMode model.AuthScheme, opts stackOptions) *stack {
	t.Helper()
	st := store.NewMemory()
	src := broker.NewMemorySource()
	clock := &fakeClock{t: time.Now().UTC()}

	// 受控上游：只回报是否收到预期认证字段。
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/stream":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(200)
			fl := w.(http.Flusher)
			for i := 0; i < 4; i++ {
				fmt.Fprintf(w, "chunk-%d\n", i)
				fl.Flush()
				time.Sleep(100 * time.Millisecond)
			}
		case r.URL.Path == "/redirect":
			http.Redirect(w, r, "http://127.0.0.1:9/elsewhere", http.StatusFound)
		default:
			matched := false
			switch authMode {
			case model.AuthBearer:
				matched = r.Header.Get("Authorization") == "Bearer "+expectedToken
			case model.AuthAPIKey:
				matched = r.Header.Get("X-Custom-Key") == expectedToken
			case model.AuthBasic:
				matched = strings.HasPrefix(r.Header.Get("Authorization"), "Basic ")
			}
			resp := map[string]any{
				"matched":           matched,
				"path":              r.URL.EscapedPath(),
				"query":             r.URL.RawQuery,
				"keykoi_headers":    countKeyKoiHeaders(r),
				"authorization_set": r.Header.Get("Authorization") != "",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	t.Cleanup(upstream.Close)

	ctx := context.Background()
	principal := &store.Principal{ID: "principal_local_test", IdentityType: "local_user", IdentityReference: "uid:501", Status: model.StatusActive}
	if err := st.PutPrincipal(ctx, principal); err != nil {
		t.Fatal(err)
	}
	credID := "cred_test"
	fields := map[string]secret.Value{"token": secret.New(expectedToken), "username": secret.New("user"), "password": secret.New("pw")}
	// 让 basic 模式的期望值可比较。
	if authMode == model.AuthBasic {
		fields["password"] = secret.New("pw")
	}
	src.Put(model.CredentialVersion{CredentialID: credID, Version: 1, Fields: fields})
	if err := st.CreateCredential(ctx, &model.Credential{ID: credID, Kind: model.KindAPIKey, Label: "test", CurrentVersion: 1, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	b := &model.Binding{
		ID: "binding_test", CredentialID: credID, UpstreamOrigin: upstream.URL,
		AuthScheme: authMode, AuthHeader: "X-Custom-Key", Route: "svc", Status: model.StatusActive,
	}
	if err := st.PutBinding(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(ctx, &model.Grant{ID: "grant_proxy", PrincipalID: principal.ID, BindingID: b.ID,
		DeliveryMode: model.ModeProxy, MaxLeaseDuration: 10 * time.Minute, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}

	bopts := broker.Options{SessionTTL: time.Hour, MaxLeaseDuration: 10 * time.Minute, Now: clock.now}
	if opts.broker != nil {
		opts.broker(&bopts)
	}
	br := broker.New(st, src, bopts)
	sess, token, err := br.CreateSession(ctx, principal.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	_ = sess
	gopts := gateway.Options{Now: clock.now}
	if opts.gateway != nil {
		opts.gateway(&gopts)
	}
	gw := gateway.New(br, gopts)
	server := httptest.NewServer(gw)
	t.Cleanup(server.Close)
	return &stack{store: st, source: src, broker: br, gw: gw, server: server, upstream: upstream,
		clock: clock, token: token, credID: credID, binding: b.ID, route: "svc"}
}

func countKeyKoiHeaders(r *http.Request) int {
	n := 0
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-keykoi-") {
			n++
		}
	}
	return n
}

func (s *stack) do(t *testing.T, method, path string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, s.server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func TestProxyInjectionRemovesIntermediaryToken(t *testing.T) {
	secretToken := randomString("secret-access-key")
	s := newStack(t, secretToken, model.AuthBearer)
	resp, body := s.do(t, http.MethodGet, "/gateway/svc/echo?a=1&a=2", map[string]string{
		"X-KeyKoi-Session": s.token.RevealString(),
		"X-KeyKoi-Caller":  "test-tool",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out["matched"] != true {
		t.Fatalf("upstream did not receive injected credential: %v", out)
	}
	if out["keykoi_headers"] != float64(0) {
		t.Fatalf("internal headers leaked upstream: %v", out)
	}
	if out["query"] != "a=1&a=2" {
		t.Fatalf("query not preserved: %v", out["query"])
	}
}

func TestAPIKeyHeaderInjection(t *testing.T) {
	key := randomString("apikey")
	s := newStack(t, key, model.AuthAPIKey)
	resp, body := s.do(t, http.MethodGet, "/gateway/svc/echo", map[string]string{"Authorization": "Bearer " + s.token.RevealString()})
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"matched":true`) {
		t.Fatalf("api key injection failed: %d %s", resp.StatusCode, body)
	}
}

func TestBasicInjection(t *testing.T) {
	s := newStack(t, "ignored", model.AuthBasic)
	resp, body := s.do(t, http.MethodGet, "/gateway/svc/echo", map[string]string{"X-KeyKoi-Session": s.token.RevealString()})
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"authorization_set":true`) {
		t.Fatalf("basic injection failed: %d %s", resp.StatusCode, body)
	}
}

func TestRejections(t *testing.T) {
	secretToken := randomString("secret")
	s := newStack(t, secretToken, model.AuthBearer)
	valid := map[string]string{"X-KeyKoi-Session": s.token.RevealString()}

	// 无会话
	if resp, _ := s.do(t, http.MethodGet, "/gateway/svc/echo", nil); resp.StatusCode != 401 {
		t.Fatalf("missing token: want 401 got %d", resp.StatusCode)
	}
	// 未登记路由
	if resp, _ := s.do(t, http.MethodGet, "/gateway/unknown/echo", valid); resp.StatusCode != 404 {
		t.Fatalf("unknown route: want 404 got %d", resp.StatusCode)
	}
	// 越模式：仅 proxy 许可，要求 runtime_delivery 必须拒绝。
	_, err := s.broker.Authorize(context.Background(), broker.Request{Token: s.token, BindingID: s.binding, Mode: model.ModeRuntimeDelivery})
	if err == nil || model.CodeOf(err) != model.CodeUseNotAllowed {
		t.Fatalf("mode escalation must be rejected, got %v", err)
	}
	// 会话过期
	s.clock.advance(2 * time.Hour)
	if resp, _ := s.do(t, http.MethodGet, "/gateway/svc/echo", valid); resp.StatusCode != 401 {
		t.Fatalf("expired session: want 401 got %d", resp.StatusCode)
	}
}

func TestPathRestriction(t *testing.T) {
	secretToken := randomString("secret")
	s := newStack(t, secretToken, model.AuthBearer)
	ctx := context.Background()
	b, err := s.store.GetBinding(ctx, s.binding)
	if err != nil {
		t.Fatal(err)
	}
	b.AllowedPaths = []string{"/echo"}
	if err := s.store.PutBinding(ctx, b); err != nil {
		t.Fatal(err)
	}
	valid := map[string]string{"X-KeyKoi-Session": s.token.RevealString()}
	if resp, _ := s.do(t, http.MethodGet, "/gateway/svc/other", valid); resp.StatusCode != 404 {
		t.Fatalf("path outside binding: want 404 got %d", resp.StatusCode)
	}
	if resp, _ := s.do(t, http.MethodGet, "/gateway/svc/echo", valid); resp.StatusCode != 200 {
		t.Fatalf("allowed path: want 200 got %d", resp.StatusCode)
	}
}

func TestStreamingFirstChunkBeforeEnd(t *testing.T) {
	secretToken := randomString("secret")
	s := newStack(t, secretToken, model.AuthBearer)
	start := time.Now()
	req, _ := http.NewRequest(http.MethodGet, s.server.URL+"/gateway/svc/stream", nil)
	req.Header.Set("X-KeyKoi-Session", s.token.RevealString())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 8)
	n, err := resp.Body.Read(buf)
	firstAt := time.Since(start)
	if err != nil || n == 0 {
		t.Fatalf("no first chunk: %v", err)
	}
	rest, _ := io.ReadAll(resp.Body)
	total := time.Since(start)
	if !strings.HasPrefix(string(buf[:n])+string(rest), "chunk-0") {
		t.Fatalf("unexpected stream content")
	}
	if total-firstAt < 200*time.Millisecond {
		t.Fatalf("stream did not span expected time: first=%v total=%v", firstAt, total)
	}
	if firstAt > total/2 {
		t.Fatalf("first chunk arrived too late: first=%v total=%v", firstAt, total)
	}
}

func TestCrossOriginRedirectNotFollowed(t *testing.T) {
	var hits int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(200)
	}))
	defer other.Close()
	secretToken := randomString("secret")
	s := newStack(t, secretToken, model.AuthBearer)
	ctx := context.Background()
	b, _ := s.store.GetBinding(ctx, s.binding)
	b.UpstreamOrigin = s.upstream.URL
	if err := s.store.PutBinding(ctx, b); err != nil {
		t.Fatal(err)
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, s.server.URL+"/gateway/svc/redirect", nil)
	req.Header.Set("X-KeyKoi-Session", s.token.RevealString())
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect status should pass through unchanged, got %d", resp.StatusCode)
	}
	if atomic.LoadInt64(&hits) != 0 {
		t.Fatal("gateway followed cross-origin redirect and leaked request")
	}
	// 跳转不是一次完成的交换：审计必须单独标记，不能当成成功。
	ev := s.findAudit(t, "upstream_redirect_not_followed")
	if ev.Result != "http_302" {
		t.Fatalf("redirect audit result = %q, want http_302", ev.Result)
	}
}

func TestLockedVaultRejects(t *testing.T) {
	secretToken := randomString("secret")
	s := newStack(t, secretToken, model.AuthBearer)
	s.broker.Lock(context.Background())
	resp, body := s.do(t, http.MethodGet, "/gateway/svc/echo", map[string]string{"X-KeyKoi-Session": s.token.RevealString()})
	if resp.StatusCode != 503 || !strings.Contains(string(body), "VAULT_LOCKED") {
		t.Fatalf("locked vault: got %d %s", resp.StatusCode, body)
	}
}

func TestUpgradeRejected(t *testing.T) {
	secretToken := randomString("secret")
	s := newStack(t, secretToken, model.AuthBearer)
	req, _ := http.NewRequest(http.MethodGet, s.server.URL+"/gateway/svc/echo", nil)
	req.Header.Set("X-KeyKoi-Session", s.token.RevealString())
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("upgrade must be rejected, got %d", resp.StatusCode)
	}
}

func TestPathEncodingPreserved(t *testing.T) {
	secretToken := randomString("secret")
	s := newStack(t, secretToken, model.AuthBearer)
	resp, body := s.do(t, http.MethodGet, "/gateway/svc/echo/a%2Fb?x=%2F", map[string]string{"X-KeyKoi-Session": s.token.RevealString()})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"path":"/echo/a%2Fb"`) {
		t.Fatalf("encoded path not preserved: %s", body)
	}
	if !strings.Contains(string(body), `"query":"x=%2F"`) {
		t.Fatalf("encoded query not preserved: %s", body)
	}
}

func TestInvalidSessionToken(t *testing.T) {
	s := newStack(t, "x", model.AuthBearer)
	// 形如令牌但不存在：必须 401 且不读取凭证。
	resp, body := s.do(t, http.MethodGet, "/gateway/svc/echo", map[string]string{"X-KeyKoi-Session": "kks_" + randomString("bogus")})
	if resp.StatusCode != 401 || !strings.Contains(string(body), "SESSION_INVALID") {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
}

func randomString(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + "-" + base64.RawURLEncoding.EncodeToString(b)
}

var _ = url.Parse

func TestBasicCarriesIntermediaryToken(t *testing.T) {
	secretToken := randomString("secret")
	s := newStack(t, secretToken, model.AuthBasic)
	basic := base64.StdEncoding.EncodeToString([]byte("git:" + s.token.RevealString()))
	resp, body := s.do(t, http.MethodGet, "/gateway/svc/echo", map[string]string{"Authorization": "Basic " + basic})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out["authorization_set"] != true {
		t.Fatalf("upstream did not receive injected auth: %v", out)
	}
}

// findAudit 返回最近一条带指定错误码的审计记录。
func (s *stack) findAudit(t *testing.T, code string) *store.AuditEvent {
	t.Helper()
	events, err := s.store.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].ErrorCode == code {
			return events[i]
		}
	}
	t.Fatalf("no audit event with error code %q", code)
	return nil
}

// TestAuthUnavailableReturns403 覆盖 27：需要验证但当前环境无法验证时，
// 网关必须给出可处理的状态与稳定错误码，而不是 500。
func TestAuthUnavailableReturns403(t *testing.T) {
	s := newStackWith(t, randomString("secret"), model.AuthBearer, stackOptions{
		// 没有 verifier 的 Authenticator 对需要验证的策略一律返回 AUTH_UNAVAILABLE。
		broker: func(o *broker.Options) { o.Auth = broker.NewAuthenticator(nil, o.Now) },
	})
	resp, body := s.do(t, http.MethodGet, "/gateway/svc/echo", map[string]string{"X-KeyKoi-Session": s.token.RevealString()})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("auth unavailable: want 403, got %d %s", resp.StatusCode, body)
	}
	assertErrorCode(t, body, string(model.CodeAuthUnavailable))
	ev := s.findAudit(t, string(model.CodeAuthUnavailable))
	if ev.Result != "denied" {
		t.Fatalf("auth unavailable audit result = %q, want denied", ev.Result)
	}
}

// TestAuthRequiredReturns401 覆盖 27：用户取消或验证失败应提示可重试的 401。
func TestAuthRequiredReturns401(t *testing.T) {
	s := newStackWith(t, randomString("secret"), model.AuthBearer, stackOptions{
		broker: func(o *broker.Options) {
			o.Auth = broker.NewAuthenticator(broker.VerifierFunc(
				func(context.Context, broker.VerifyRequest) (string, error) {
					return "", model.NewError(model.CodeAuthRequired, "user cancelled the verification prompt")
				}), o.Now)
		},
	})
	resp, body := s.do(t, http.MethodGet, "/gateway/svc/echo", map[string]string{"X-KeyKoi-Session": s.token.RevealString()})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("auth required: want 401, got %d %s", resp.StatusCode, body)
	}
	assertErrorCode(t, body, string(model.CodeAuthRequired))
}

// TestDisabledGrantReturns403 覆盖 27 的权限类失败：许可被停用后应是 403。
func TestDisabledGrantReturns403(t *testing.T) {
	s := newStack(t, randomString("secret"), model.AuthBearer)
	ctx := context.Background()
	grant, err := s.store.GetGrant(ctx, "grant_proxy")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpdateGrantStatus(ctx, grant.ID, model.StatusDisabled, grant.Revision); err != nil {
		t.Fatal(err)
	}
	resp, body := s.do(t, http.MethodGet, "/gateway/svc/echo", map[string]string{"X-KeyKoi-Session": s.token.RevealString()})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled grant: want 403, got %d %s", resp.StatusCode, body)
	}
	assertErrorCode(t, body, string(model.CodeUseNotAllowed))
}

// TestPathEscapesRejectedAfterNormalization 覆盖 31：判定与转发都按规范化路径，
// 会自行规范化路径的上游不能把请求带出登记前缀。
func TestPathEscapesRejectedAfterNormalization(t *testing.T) {
	s := newStack(t, randomString("secret"), model.AuthBearer)
	ctx := context.Background()
	b, err := s.store.GetBinding(ctx, s.binding)
	if err != nil {
		t.Fatal(err)
	}
	b.AllowedPaths = []string{"/echo"}
	if err := s.store.PutBinding(ctx, b); err != nil {
		t.Fatal(err)
	}
	valid := map[string]string{"X-KeyKoi-Session": s.token.RevealString()}

	escapes := []string{
		"/gateway/svc/echo/../admin",
		"/gateway/svc/echo/%2e%2e/admin",
		"/gateway/svc/echo/..%2fadmin",
		"/gateway/svc/echo/%2E%2E%2Fadmin",
		"/gateway/svc/echo/a/../../admin",
	}
	for _, path := range escapes {
		resp, body := s.do(t, http.MethodGet, path, valid)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("escape %q: want 404, got %d %s", path, resp.StatusCode, body)
		}
		if !strings.Contains(string(body), string(model.CodeBindingDisabled)) {
			t.Fatalf("escape %q: stable code missing: %s", path, body)
		}
	}

	// 规范化后仍在前缀内的路径必须放行。
	inside := []string{
		"/gateway/svc/echo",
		"/gateway/svc/echo/deep/path",
		"/gateway/svc/echo/./deep",
		"/gateway/svc/echo/a/../b",
		"/gateway/svc//echo//double",
		"/gateway/svc/echo/a%2Fb",
	}
	for _, path := range inside {
		resp, body := s.do(t, http.MethodGet, path, valid)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("inside %q: want 200, got %d %s", path, resp.StatusCode, body)
		}
	}

	// 判定与实际转发必须是同一形式：上游收到的是规范化后的路径。
	_, body := s.do(t, http.MethodGet, "/gateway/svc/echo/a/../b", valid)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out["path"] != "/echo/b" {
		t.Fatalf("forwarded path = %v, want the normalized /echo/b", out["path"])
	}
}

// roundTripperFunc 让测试用例直接返回受控响应。
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// flakyBody 先给出部分数据，再返回非 EOF 错误，模拟被截断的上游响应。
type flakyBody struct{ sent bool }

func (b *flakyBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, "partial-body"), nil
	}
	return 0, errors.New("connection reset by peer")
}

func (b *flakyBody) Close() error { return nil }

// TestUpstreamResponseInterruptionRecordedAsFailure 覆盖 31：非 EOF 的读取错误是
// 传输中断，必须记为失败并让调用方看到截断，而不是当作正常结束。
func TestUpstreamResponseInterruptionRecordedAsFailure(t *testing.T) {
	s := newStackWith(t, randomString("secret"), model.AuthBearer, stackOptions{
		gateway: func(o *gateway.Options) {
			o.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"text/plain"}},
					Body:       &flakyBody{},
				}, nil
			})
		},
	})
	req, err := http.NewRequest(http.MethodGet, s.server.URL+"/gateway/svc/echo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-KeyKoi-Session", s.token.RevealString())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("response header should still arrive: %v", err)
	}
	defer resp.Body.Close()
	if _, readErr := io.ReadAll(resp.Body); readErr == nil {
		t.Fatal("truncated upstream response was handed to the client as a complete body")
	}
	ev := s.findAudit(t, "upstream_response_interrupted")
	if ev.Result != "http_200" || ev.ErrorCode != "upstream_response_interrupted" {
		t.Fatalf("interruption audit = %q/%q", ev.Result, ev.ErrorCode)
	}
}

// assertErrorCode 断言 JSON 错误体仍保持 {"error":{"code","message"}} 结构。
func assertErrorCode(t *testing.T, body []byte, want string) {
	t.Helper()
	var out struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, body)
	}
	if out.Error.Code != want {
		t.Fatalf("error code = %q, want %q (%s)", out.Error.Code, want, body)
	}
	if out.Error.Message == "" {
		t.Fatalf("error message is empty: %s", body)
	}
}
