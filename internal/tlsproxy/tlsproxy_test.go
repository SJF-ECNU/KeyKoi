package tlsproxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
	"keykoi/internal/tlsproxy"
)

// upstream 记录收到的请求头，用于验证注入与不泄露。
type upstream struct {
	mu       sync.Mutex
	requests int
	headers  []http.Header
	server   *httptest.Server
}

func newUpstream(t *testing.T, scheme model.AuthScheme, expected string) *upstream {
	t.Helper()
	u := &upstream{}
	u.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.requests++
		u.headers = append(u.headers, r.Header.Clone())
		u.mu.Unlock()
		keykoiHeaders := 0
		sessionTokens := 0
		for name, vals := range r.Header {
			if strings.HasPrefix(strings.ToLower(name), "x-keykoi-") {
				keykoiHeaders++
			}
			for _, v := range vals {
				if strings.Contains(v, "kks_") {
					sessionTokens++
				}
			}
		}
		matched := false
		switch scheme {
		case model.AuthBearer:
			matched = r.Header.Get("Authorization") == "Bearer "+expected
		case model.AuthAPIKey:
			matched = r.Header.Get("X-Api-Key") == expected
		case model.AuthBasic:
			matched = r.Header.Get("Authorization") == "Basic "+base64.StdEncoding.EncodeToString([]byte("tool:tool-pw"))
		}
		if r.URL.Path == "/partial" {
			w.Header().Set("Content-Length", "20")
			_, _ = io.WriteString(w, "partial")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"matched":         matched,
			"path":            r.URL.Path,
			"query":           r.URL.RawQuery,
			"keykoi_headers":  keykoiHeaders,
			"session_tokens":  sessionTokens,
			"auth_header_set": r.Header.Get("Authorization") != "",
		})
	}))
	u.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	u.server.StartTLS()
	t.Cleanup(u.server.Close)
	return u
}

func (u *upstream) snapshot() (int, []http.Header) {
	u.mu.Lock()
	defer u.mu.Unlock()
	cp := make([]http.Header, len(u.headers))
	for i, h := range u.headers {
		cp[i] = h.Clone()
	}
	return u.requests, cp
}

// stack 是本进程内的代理测试栈。
type stack struct {
	proxy    *tlsproxy.Proxy
	server   *httptest.Server
	client   *http.Client
	upstream *upstream
	caDir    string
	secret   string
	auth     *scriptedAuth
	binding  *model.Binding
	credID   string
	token    string
}

// scriptedAuth 包装内存 Broker，用来模拟主服务返回的绑定快照、revision 与错误。
// 生产路径直接使用 daemon 内的 Broker。
type scriptedAuth struct {
	inner tlsproxy.Authorizer

	mu       sync.Mutex
	binding  *model.Binding
	revDelta int64
	err      error
	records  []store.AuditEvent
}

func (s *scriptedAuth) setBinding(b *model.Binding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.binding = b
}

func (s *scriptedAuth) setRevisionDelta(d int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revDelta = d
}

func (s *scriptedAuth) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *scriptedAuth) Authorize(ctx context.Context, req broker.Request) (*broker.Authorization, error) {
	s.mu.Lock()
	err := s.err
	override := s.binding
	delta := s.revDelta
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	authz, aerr := s.inner.Authorize(ctx, req)
	if aerr != nil {
		return nil, aerr
	}
	if override != nil {
		cp := *override
		authz.Binding = &cp
	}
	authz.Lease.BindingRevision += delta
	return authz, nil
}

func (s *scriptedAuth) ReleaseLease(leaseID string) {
	s.inner.ReleaseLease(leaseID)
}

func (s *scriptedAuth) SessionByToken(token secret.Value) (model.Session, error) {
	return s.inner.SessionByToken(token)
}

func (s *scriptedAuth) Record(ctx context.Context, e store.AuditEvent) {
	s.mu.Lock()
	s.records = append(s.records, e)
	s.mu.Unlock()
	s.inner.Record(ctx, e)
}

func (s *scriptedAuth) recorded() []store.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.AuditEvent(nil), s.records...)
}

// stackOptions 配置测试栈。
type stackOptions struct {
	trustUpstream bool
	scheme        model.AuthScheme
	// credentialValue 固定凭证值，便于让第二台上游期望同一份凭证。
	credentialValue string
	// extraUpstreamCerts 追加信任的上游证书，用于模拟改绑到另一台目标。
	extraUpstreamCerts []*x509.Certificate
}

func newStack(t *testing.T, trustUpstream bool) *stack {
	t.Helper()
	return newStackAuth(t, trustUpstream, model.AuthBearer)
}

func newStackAuth(t *testing.T, trustUpstream bool, scheme model.AuthScheme) *stack {
	t.Helper()
	return newStackWith(t, stackOptions{trustUpstream: trustUpstream, scheme: scheme})
}

// newStackWith 按选项搭建代理、内存存储与授权来源。
func newStackWith(t *testing.T, opts stackOptions) *stack {
	t.Helper()
	ctx := context.Background()
	credentialValue := opts.credentialValue
	if credentialValue == "" {
		credentialValue = "kk_tls_test_" + base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))[:16]
	}
	up := newUpstream(t, opts.scheme, credentialValue)

	st := store.NewMemory()
	src := broker.NewMemorySource()
	principal := &store.Principal{ID: "principal_local_test", IdentityType: "local_user", IdentityReference: "macos-uid:501", Status: model.StatusActive}
	if err := st.PutPrincipal(ctx, principal); err != nil {
		t.Fatal(err)
	}
	credID := "cred_tls_test"
	src.Put(model.CredentialVersion{CredentialID: credID, Version: 1, Fields: map[string]secret.Value{
		"token":    secret.New(credentialValue),
		"username": secret.New("tool"),
		"password": secret.New("tool-pw"),
	}})
	if err := st.CreateCredential(ctx, &model.Credential{ID: credID, Kind: model.KindAPIKey, Label: "tls test", CurrentVersion: 1, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	binding := &model.Binding{
		ID: "binding_tls_test", CredentialID: credID, UpstreamOrigin: up.server.URL,
		AuthScheme: opts.scheme, Route: "tls-svc", Status: model.StatusActive,
	}
	if opts.scheme == model.AuthBasic {
		binding.UsernameField = "username"
		binding.PasswordField = "password"
	}
	if err := st.PutBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(ctx, &model.Grant{ID: "grant_tls_runtime", PrincipalID: principal.ID, BindingID: binding.ID,
		DeliveryMode: model.ModeProxy, MaxLeaseDuration: 10 * time.Minute, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	br := broker.New(st, src, broker.Options{SessionTTL: time.Hour, MaxLeaseDuration: 10 * time.Minute})
	_, token, err := br.CreateSession(ctx, principal.ID, "tlsproxy test")
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	if opts.trustUpstream {
		roots.AddCert(up.server.Certificate())
	}
	for _, cert := range opts.extraUpstreamCerts {
		roots.AddCert(cert)
	}
	auth := &scriptedAuth{inner: br}
	caDir := t.TempDir()
	proxy, err := tlsproxy.New(tlsproxy.Options{
		Authorizer: auth, Store: st,
		BindingIDs: []string{binding.ID}, UpstreamRoots: roots, CADir: caDir,
		Logger: testLogger{t},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = proxy.Close() })

	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("keykoi", token.RevealString())
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: proxy.CA().Pool(), MinVersion: tls.VersionTLS12},
		},
	}
	stored, err := st.GetBinding(ctx, binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	return &stack{proxy: proxy, server: server, client: client, upstream: up, caDir: caDir, secret: credentialValue,
		auth: auth, binding: stored, credID: credID, token: token.RevealString()}
}

type testLogger struct{ t *testing.T }

func (l testLogger) Printf(format string, args ...any) { l.t.Logf(format, args...) }

func TestConnectRequiresInstanceToken(t *testing.T) {
	s := newStack(t, true)
	target, err := url.Parse(s.upstream.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, auth := range []string{"", "Basic " + base64.StdEncoding.EncodeToString([]byte("keykoi:wrong-token"))} {
		req := httptest.NewRequest(http.MethodConnect, target.Host, nil)
		req.Header.Set("Proxy-Authorization", auth)
		res := httptest.NewRecorder()
		s.proxy.ServeHTTP(res, req)
		if res.Code != http.StatusProxyAuthRequired || res.Header().Get("Proxy-Authenticate") == "" {
			t.Fatalf("CONNECT must ask for proxy authentication, got %d", res.Code)
		}
	}
}

func TestInterruptedUpstreamResponseIsAudited(t *testing.T) {
	s := newStack(t, true)
	resp, err := s.client.Get(s.upstream.server.URL + "/partial")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("expected a read error for the interrupted response")
	}
	events := s.auth.recorded()
	if len(events) == 0 || events[len(events)-1].ErrorCode != "upstream_response_interrupted" {
		t.Fatalf("interrupted response must be audited as a failure: %+v", events)
	}
}

func TestInjectsCredentialForRegisteredTarget(t *testing.T) {
	s := newStack(t, true)
	resp, err := s.client.Get(s.upstream.server.URL + "/echo?a=1&a=2")
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out["matched"] != true {
		t.Fatalf("upstream did not receive injected bearer credential: %v", out)
	}
	if out["query"] != "a=1&a=2" {
		t.Fatalf("query not preserved: %v", out["query"])
	}
	if out["keykoi_headers"] != float64(0) {
		t.Fatalf("internal KeyKoi headers reached upstream: %v", out["keykoi_headers"])
	}
	if out["session_tokens"] != float64(0) {
		t.Fatalf("intermediary session token reached upstream: %v", out["session_tokens"])
	}
	stats := s.proxy.Stats()
	if stats.RequestsInjected != 1 || stats.RequestsForwarded != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestAPIKeyAndBasicInjection(t *testing.T) {
	for _, scheme := range []model.AuthScheme{model.AuthAPIKey, model.AuthBasic} {
		scheme := scheme
		t.Run(string(scheme), func(t *testing.T) {
			s := newStackAuth(t, true, scheme)
			resp, err := s.client.Get(s.upstream.server.URL + "/echo")
			if err != nil {
				t.Fatalf("request through proxy failed: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d body %s", resp.StatusCode, body)
			}
			var out map[string]any
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatal(err)
			}
			if out["matched"] != true {
				t.Fatalf("%s injection failed: %v", scheme, out)
			}
		})
	}
}

func TestSessionTokenAndControlHeadersNeverReachUpstream(t *testing.T) {
	s := newStack(t, true)
	resp, err := s.client.Get(s.upstream.server.URL + "/echo")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	_, headers := s.upstream.snapshot()
	if len(headers) != 1 {
		t.Fatalf("expected one upstream request, got %d", len(headers))
	}
	for name, vals := range headers[0] {
		if strings.HasPrefix(strings.ToLower(name), "x-keykoi-") {
			t.Fatalf("internal header %q leaked to upstream", name)
		}
		for _, v := range vals {
			if strings.Contains(v, "kks_") {
				t.Fatalf("session token leaked in header %q", name)
			}
			if strings.Contains(v, s.secret) && !strings.EqualFold(name, "Authorization") {
				t.Fatalf("credential leaked in non-auth header %q", name)
			}
		}
	}
	if got := headers[0].Get("Authorization"); got != "Bearer "+s.secret {
		t.Fatalf("authorization header is not the injected one: %q", got)
	}
}

func TestUnregisteredDomainRejectedAtConnect(t *testing.T) {
	s := newStack(t, true)
	_, err := s.client.Get("https://unregistered.keykoi.test/echo")
	if err == nil {
		t.Fatal("unregistered domain must be rejected")
	}
	if !strings.Contains(err.Error(), "403") && !strings.Contains(strings.ToLower(err.Error()), "forbidden") {
		t.Fatalf("rejection is not identifiable: %v", err)
	}
	if requests, _ := s.upstream.snapshot(); requests != 0 {
		t.Fatalf("unregistered target reached upstream %d times", requests)
	}
	if s.proxy.Stats().RequestsInjected != 0 {
		t.Fatalf("proxy injected a credential for an unregistered target: %+v", s.proxy.Stats())
	}
}

func TestUpstreamCertificateErrorTerminates(t *testing.T) {
	s := newStack(t, false) // 信任池为空：上游证书无法验证。
	_, err := s.client.Get(s.upstream.server.URL + "/echo")
	if err == nil {
		t.Fatal("invalid upstream certificate must terminate the tunnel")
	}
	if !strings.Contains(err.Error(), "502") && !strings.Contains(strings.ToLower(err.Error()), "bad gateway") {
		t.Fatalf("upstream certificate error is not identifiable: %v", err)
	}
	if requests, _ := s.upstream.snapshot(); requests != 0 {
		t.Fatalf("request was delivered despite invalid upstream certificate (%d requests)", requests)
	}
	stats := s.proxy.Stats()
	if stats.UpstreamTLSInvalid != 1 {
		t.Fatalf("upstream TLS failure was not recorded: %+v", stats)
	}
	if stats.RequestsInjected != 0 {
		t.Fatalf("credential was injected despite invalid upstream certificate: %+v", stats)
	}
}

func TestClientThatDoesNotTrustProxyCAIsRecordedUnsupported(t *testing.T) {
	s := newStack(t, true)
	proxyURL, _ := url.Parse(s.server.URL)
	proxyURL.User = url.UserPassword("keykoi", s.token)
	untrusting := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := untrusting.Get(s.upstream.server.URL + "/echo")
	if err == nil {
		resp.Body.Close()
		t.Fatal("client that does not trust the proxy CA must fail verification")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("unexpected client verification failure: %v", err)
	}
	// 记录为不支持：客户端验证失败，不能完成注入。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.proxy.Stats().ClientTLSFailures >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.proxy.Stats().ClientTLSFailures < 1 {
		t.Fatalf("client TLS failure was not recorded as unsupported: %+v", s.proxy.Stats())
	}
	if requests, _ := s.upstream.snapshot(); requests != 0 {
		t.Fatalf("upstream was reached despite untrusted proxy CA (%d requests)", requests)
	}
}

func TestCAFilesAreRestricted(t *testing.T) {
	s := newStack(t, true)
	certPath := s.proxy.CA().CertPath()
	if filepath.Base(certPath) != "ca.pem" {
		t.Fatalf("unexpected CA certificate path %s", certPath)
	}
	keyInfo, err := os.Stat(filepath.Join(s.caDir, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("CA private key must be 0600, got %o", keyInfo.Mode().Perm())
	}
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if certInfo.Mode().Perm() != 0o644 {
		t.Fatalf("CA certificate must be 0644, got %o", certInfo.Mode().Perm())
	}
	dirInfo, err := os.Stat(s.caDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("CA directory must be 0700, got %o", dirInfo.Mode().Perm())
	}
}

// proxyResultCode 返回代理写回的稳定错误码。
func proxyResultCode(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	return resp.Header.Get("X-KeyKoi-Proxy-Result")
}

// TestForwardTargetComesFromAuthorizedBinding 确认转发目标是当次授权返回的绑定快照，
// 而不是建连时另行读取的目标：授权把目标指向别处时，请求必须去快照里的目标。
func TestForwardTargetComesFromAuthorizedBinding(t *testing.T) {
	value := "kk_tls_binding_" + base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))[:16]
	second := newUpstream(t, model.AuthBearer, value)
	s := newStackWith(t, stackOptions{
		trustUpstream:      true,
		scheme:             model.AuthBearer,
		credentialValue:    value,
		extraUpstreamCerts: []*x509.Certificate{second.server.Certificate()},
	})
	// 授权快照把同一个 Binding 指向第二台上游：目标与凭证版本都来自这一次授权。
	s.auth.setBinding(&model.Binding{
		ID: s.binding.ID, CredentialID: s.credID, UpstreamOrigin: second.server.URL,
		AuthScheme: model.AuthBearer, Route: s.binding.Route, Status: model.StatusActive,
		Revision: s.binding.Revision,
	})

	resp, err := s.client.Get(s.upstream.server.URL + "/echo")
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out["matched"] != true {
		t.Fatalf("authorized target did not receive the authorized credential: %v", out)
	}
	if requests, _ := second.snapshot(); requests != 1 {
		t.Fatalf("authorized target received %d requests, want 1", requests)
	}
	if requests, _ := s.upstream.snapshot(); requests != 0 {
		t.Fatalf("connect-time target received %d requests; forwarding must use the authorized binding", requests)
	}
}

// TestBindingRevisionChangeEndsTunnel 确认同一次隧道内绑定 revision 变化时连接被结束，
// 客户端必须重新建连，而不会继续沿用旧目标的决定。
func TestBindingRevisionChangeEndsTunnel(t *testing.T) {
	s := newStack(t, true)
	s.auth.setRevisionDelta(1) // 授权返回的 revision 比建连快照新：绑定已改。

	resp, err := s.client.Get(s.upstream.server.URL + "/echo")
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d, want 409 for a stale binding revision", resp.StatusCode)
	}
	if code := proxyResultCode(resp); code != "binding_changed" {
		t.Fatalf("unexpected proxy result code %q", code)
	}
	if requests, _ := s.upstream.snapshot(); requests != 0 {
		t.Fatalf("upstream was reached despite a changed binding revision (%d requests)", requests)
	}
	stats := s.proxy.Stats()
	if stats.TunnelsEndedByBindingChange != 1 {
		t.Fatalf("binding revision change was not recorded: %+v", stats)
	}
	if stats.RequestsInjected != 0 || stats.RequestsForwarded != 0 {
		t.Fatalf("credential was used after the binding changed: %+v", stats)
	}
	closed := false
	for _, ev := range s.auth.recorded() {
		if ev.ErrorCode == "binding_revision_changed" && ev.Result == "tls_closed" {
			closed = true
		}
	}
	if !closed {
		t.Fatalf("binding revision change was not audited: %+v", s.auth.recorded())
	}

	// 回到一致状态后，客户端重新建连即可继续：证明结束的是连接而不是代理。
	s.auth.setRevisionDelta(0)
	resp2, err := s.client.Get(s.upstream.server.URL + "/echo")
	if err != nil {
		t.Fatalf("request after reconnecting failed: %v", err)
	}
	defer resp2.Body.Close()
	io.Copy(io.Discard, resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status %d after reconnect", resp2.StatusCode)
	}
	if got := s.proxy.Stats().ConnectsAccepted; got < 2 {
		t.Fatalf("tunnel was not closed after the binding change: connects=%d", got)
	}
}

// TestVaultLockedAuthorizationRejectsRequest 确认主库锁定时代理拒绝用钥：
// 后台返回 VAULT_LOCKED，请求被拒绝且凭证没有离开进程。
func TestVaultLockedAuthorizationRejectsRequest(t *testing.T) {
	s := newStack(t, true)
	s.auth.setError(model.NewError(model.CodeVaultLocked, "vault is locked"))

	resp, err := s.client.Get(s.upstream.server.URL + "/echo")
	if err != nil {
		t.Fatalf("expected a stable proxy error response, got transport error: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 when the vault is locked", resp.StatusCode)
	}
	if code := proxyResultCode(resp); code != string(model.CodeVaultLocked) {
		t.Fatalf("unexpected proxy result code %q", code)
	}
	if requests, _ := s.upstream.snapshot(); requests != 0 {
		t.Fatalf("upstream was reached while the vault was locked (%d requests)", requests)
	}
	stats := s.proxy.Stats()
	if stats.RequestsInjected != 0 || stats.RequestsForwarded != 0 {
		t.Fatalf("proxy used a credential while the vault was locked: %+v", stats)
	}

	// 解锁后重新建连即可继续用钥。
	s.auth.setError(nil)
	resp2, err := s.client.Get(s.upstream.server.URL + "/echo")
	if err != nil {
		t.Fatalf("request after unlock failed: %v", err)
	}
	defer resp2.Body.Close()
	io.Copy(io.Discard, resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status %d after unlock", resp2.StatusCode)
	}
	if got := s.proxy.Stats().ConnectsAccepted; got < 2 {
		t.Fatalf("locked tunnel was not closed: connects=%d", got)
	}
}
