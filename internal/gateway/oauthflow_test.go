package gateway_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/gateway"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

// tokenEndpoint 是受控 token 提供方：记录换取次数与客户端认证方式，
// 并可按测试需要返回失败。它不落盘任何 token。
type tokenEndpoint struct {
	server *httptest.Server

	// clientID / clientSecret 是受控端点认可的客户端凭据（测试值）。
	clientID     string
	clientSecret string

	mu           sync.Mutex
	count        int
	grants       []string
	authMode     string
	lastClientID string
	lastSecret   string
	scopes       []string
	issued       []string
	expiresIn    int64
	status       int
	errorCode    string
	errorDesc    string

	// checkAssertion 在 jwt-bearer 授予时校验断言；返回错误则失败。
	checkAssertion func(assertion string) error
}

func newTokenEndpoint(t *testing.T, clientID, clientSecret string) *tokenEndpoint {
	t.Helper()
	te := &tokenEndpoint{expiresIn: 3600}
	te.server = httptest.NewServer(http.HandlerFunc(te.handle))
	t.Cleanup(te.server.Close)
	te.clientID, te.clientSecret = clientID, clientSecret
	return te
}

func (te *tokenEndpoint) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token" {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	form := r.PostForm

	te.mu.Lock()
	te.count++
	te.grants = append(te.grants, form.Get("grant_type"))
	status, errCode, errDesc := te.status, te.errorCode, te.errorDesc
	te.mu.Unlock()

	if status != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": errCode, "error_description": errDesc})
		return
	}

	switch form.Get("grant_type") {
	case "client_credentials":
		user, pass, ok := r.BasicAuth()
		mode := "basic"
		if !ok {
			mode = "post"
			user, pass = form.Get("client_id"), form.Get("client_secret")
		}
		te.mu.Lock()
		te.authMode = mode
		te.lastClientID, te.lastSecret = user, pass
		te.scopes = append(te.scopes, form.Get("scope"))
		te.mu.Unlock()
		if user != te.clientID || pass != te.clientSecret {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client"})
			return
		}
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		assertion := form.Get("assertion")
		if te.checkAssertion != nil {
			if err := te.checkAssertion(assertion); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant", "error_description": err.Error()})
				return
			}
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "unsupported_grant_type"})
		return
	}

	token := "issued-" + randomString("tok")
	te.mu.Lock()
	te.issued = append(te.issued, token)
	expires := te.expiresIn
	te.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   expires,
		"scope":        form.Get("scope"),
	})
}

func (te *tokenEndpoint) setFailure(status int, code, desc string) {
	te.mu.Lock()
	defer te.mu.Unlock()
	te.status, te.errorCode, te.errorDesc = status, code, desc
}

func (te *tokenEndpoint) clearFailure() {
	te.setFailure(0, "", "")
}

func (te *tokenEndpoint) calls() int {
	te.mu.Lock()
	defer te.mu.Unlock()
	return te.count
}

func (te *tokenEndpoint) lastIssued() string {
	te.mu.Lock()
	defer te.mu.Unlock()
	if len(te.issued) == 0 {
		return ""
	}
	return te.issued[len(te.issued)-1]
}

// safeClock 是并发安全的测试时钟：网关在响应后写审计，测试同时推进时间。
type safeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *safeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *safeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// oauthStack 是 OAuth 网关测试的最小栈：受控 token 端点 + 受控上游 + 网关。
type oauthStack struct {
	t        *testing.T
	store    *store.Memory
	broker   *broker.Broker
	gw       *gateway.Gateway
	server   *httptest.Server
	upstream *httptest.Server
	clock    *safeClock
	session  secret.Value
	credID   string
	binding  string
	route    string

	mu    sync.Mutex
	auths []string
}

func newOAuthStack(t *testing.T, scheme model.AuthScheme, fields map[string]string) *oauthStack {
	t.Helper()
	return newOAuthStackMode(t, scheme, fields, model.ModeProxy)
}

func newOAuthStackMode(t *testing.T, scheme model.AuthScheme, fields map[string]string, grantMode model.DeliveryMode) *oauthStack {
	t.Helper()
	st := store.NewMemory()
	src := broker.NewMemorySource()
	clock := &safeClock{t: time.Now().UTC()}

	s := &oauthStack{t: t, store: st, clock: clock, route: "svc"}
	s.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.auths = append(s.auths, r.Header.Get("Authorization"))
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "path": r.URL.Path})
	}))
	t.Cleanup(s.upstream.Close)

	values := make(map[string]secret.Value, len(fields))
	for k, v := range fields {
		values[k] = secret.New(v)
	}
	credID := "cred_oauth"
	src.Put(model.CredentialVersion{CredentialID: credID, Version: 1, Fields: values})
	ctx := context.Background()
	principal := &store.Principal{ID: "principal_oauth_test", IdentityType: "local_user", IdentityReference: "uid:501", Status: model.StatusActive}
	if err := st.PutPrincipal(ctx, principal); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCredential(ctx, &model.Credential{ID: credID, Kind: model.KindOAuth, Label: "oauth test", CurrentVersion: 1, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	b := &model.Binding{
		ID: "binding_oauth", CredentialID: credID, UpstreamOrigin: s.upstream.URL,
		AuthScheme: scheme, Route: s.route, Status: model.StatusActive,
	}
	if err := st.PutBinding(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(ctx, &model.Grant{ID: "grant_oauth_" + string(grantMode), PrincipalID: principal.ID, BindingID: b.ID,
		DeliveryMode: grantMode, MaxLeaseDuration: time.Hour, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}

	// 时钟会被推进到 token 过期之后，会话与许可的期限必须留足余量。
	br := broker.New(st, src, broker.Options{SessionTTL: 48 * time.Hour, MaxLeaseDuration: time.Hour, Now: clock.now})
	_, token, err := br.CreateSession(ctx, principal.ID, "oauth gateway test")
	if err != nil {
		t.Fatal(err)
	}
	s.broker, s.credID, s.binding, s.session = br, credID, b.ID, token
	s.gw = gateway.New(br, gateway.Options{Now: clock.now})
	s.server = httptest.NewServer(s.gw)
	t.Cleanup(s.server.Close)
	return s
}

func (s *oauthStack) request() (*http.Response, []byte) {
	s.t.Helper()
	req, err := http.NewRequest(http.MethodGet, s.server.URL+"/gateway/"+s.route+"/echo", nil)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("X-KeyKoi-Session", s.session.RevealString())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func (s *oauthStack) upstreamAuths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.auths))
	copy(out, s.auths)
	return out
}

func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, body)
	}
	return parsed.Error.Code
}

func errorMessage(t *testing.T, body []byte) string {
	t.Helper()
	var parsed struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, body)
	}
	return parsed.Error.Message
}

func clientCredentialsFields(endpoint, clientID, clientSecret string, extra map[string]string) map[string]string {
	fields := map[string]string{
		"token_endpoint": endpoint,
		"client_id":      clientID,
		"client_secret":  clientSecret,
		"scope":          "chat.read chat.write",
	}
	for k, v := range extra {
		fields[k] = v
	}
	return fields
}

func TestOAuthClientCredentialsBasicInjection(t *testing.T) {
	const clientID, clientSecret = "client-keykoi", "client-secret-value"
	te := newTokenEndpoint(t, clientID, clientSecret)
	s := newOAuthStack(t, model.AuthOAuthClientCredentials, clientCredentialsFields(te.server.URL+"/token", clientID, clientSecret, nil))

	resp, body := s.request()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", resp.StatusCode, body)
	}
	if got := te.calls(); got != 1 {
		t.Fatalf("token endpoint calls: want 1 got %d", got)
	}
	te.mu.Lock()
	mode, scope, grant := te.authMode, te.scopes[0], te.grants[0]
	te.mu.Unlock()
	if mode != "basic" {
		t.Fatalf("client auth: want basic got %q", mode)
	}
	if grant != "client_credentials" {
		t.Fatalf("grant_type: want client_credentials got %q", grant)
	}
	if scope != "chat.read chat.write" {
		t.Fatalf("scope: want %q got %q", "chat.read chat.write", scope)
	}
	want := "Bearer " + te.lastIssued()
	if auths := s.upstreamAuths(); len(auths) != 1 || auths[0] != want {
		t.Fatalf("upstream authorization: want %q got %v", want, auths)
	}
}

func TestOAuthClientCredentialsPostInjection(t *testing.T) {
	const clientID, clientSecret = "client-post", "client-secret-post"
	te := newTokenEndpoint(t, clientID, clientSecret)
	fields := clientCredentialsFields(te.server.URL+"/token", clientID, clientSecret, map[string]string{"client_auth": "post", "audience": "https://api.keykoi.test"})
	s := newOAuthStack(t, model.AuthOAuthClientCredentials, fields)

	resp, body := s.request()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", resp.StatusCode, body)
	}
	te.mu.Lock()
	mode, gotID, gotSecret := te.authMode, te.lastClientID, te.lastSecret
	te.mu.Unlock()
	if mode != "post" {
		t.Fatalf("client auth: want post got %q", mode)
	}
	if gotID != clientID || gotSecret != clientSecret {
		t.Fatalf("client credentials were not sent in the form body")
	}
	if auths := s.upstreamAuths(); len(auths) != 1 || auths[0] != "Bearer "+te.lastIssued() {
		t.Fatalf("upstream authorization: got %v", auths)
	}
}

// newRSAKeyPEM 生成测试用 RSA 私钥，返回 PKCS#8 PEM 与其公钥。
func newRSAKeyPEM(t *testing.T) (string, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return pemText, &key.PublicKey
}

// verifyRS256 独立验证 JWT 的 RS256 签名，返回其声明。
func verifyRS256(t *testing.T, assertion string, pub *rsa.PublicKey) map[string]any {
	t.Helper()
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion is not a compact JWT: %d segments", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("assertion signature is not base64url: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("assertion signature does not verify with the public key: %v", err)
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("assertion header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		t.Fatalf("assertion header is not JSON: %v", err)
	}
	if header["alg"] != "RS256" {
		t.Fatalf("assertion alg: want RS256 got %v", header["alg"])
	}
	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("assertion claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		t.Fatalf("assertion claims are not JSON: %v", err)
	}
	return claims
}

func TestOAuthJWTBearerAssertion(t *testing.T) {
	const email = "keykoi-test@example.iam.gserviceaccount.com"
	privatePEM, pub := newRSAKeyPEM(t)
	te := newTokenEndpoint(t, "", "")

	var verifyErr error
	te.checkAssertion = func(assertion string) error {
		claims := verifyRS256(t, assertion, pub)
		if claims["iss"] != email {
			verifyErr = fmt.Errorf("iss: want %q got %v", email, claims["iss"])
			return verifyErr
		}
		if claims["aud"] != te.server.URL+"/token" {
			verifyErr = fmt.Errorf("aud: want token_uri got %v", claims["aud"])
			return verifyErr
		}
		if claims["scope"] != "https://www.googleapis.com/auth/cloud-platform" {
			verifyErr = fmt.Errorf("scope claim missing or wrong: %v", claims["scope"])
			return verifyErr
		}
		iat, iok := claims["iat"].(float64)
		exp, eok := claims["exp"].(float64)
		if !iok || !eok {
			verifyErr = fmt.Errorf("iat/exp must be numeric: %v/%v", claims["iat"], claims["exp"])
			return verifyErr
		}
		if exp-iat > 3600 {
			verifyErr = fmt.Errorf("assertion lifetime exceeds 1h: %v", exp-iat)
			return verifyErr
		}
		if exp <= float64(time.Now().Unix()) {
			verifyErr = fmt.Errorf("assertion is already expired")
			return verifyErr
		}
		return nil
	}

	fields := map[string]string{
		"client_email": email,
		"private_key":  privatePEM,
		"token_uri":    te.server.URL + "/token",
		"scope":        "https://www.googleapis.com/auth/cloud-platform",
	}
	s := newOAuthStack(t, model.AuthOAuthJWTBearer, fields)
	resp, body := s.request()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d: %s (%v)", resp.StatusCode, body, verifyErr)
	}
	if verifyErr != nil {
		t.Fatalf("assertion check failed: %v", verifyErr)
	}
	te.mu.Lock()
	grant := te.grants[0]
	te.mu.Unlock()
	if grant != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Fatalf("grant_type: got %q", grant)
	}
	if auths := s.upstreamAuths(); len(auths) != 1 || auths[0] != "Bearer "+te.lastIssued() {
		t.Fatalf("upstream authorization: got %v", auths)
	}
}

func TestOAuthTokenCacheHit(t *testing.T) {
	const clientID, clientSecret = "client-cache", "client-secret-cache"
	te := newTokenEndpoint(t, clientID, clientSecret)
	s := newOAuthStack(t, model.AuthOAuthClientCredentials, clientCredentialsFields(te.server.URL+"/token", clientID, clientSecret, nil))

	for i := 0; i < 3; i++ {
		if resp, body := s.request(); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: want 200 got %d: %s", i, resp.StatusCode, body)
		}
	}
	if got := te.calls(); got != 1 {
		t.Fatalf("three gateway requests must reuse one token: calls=%d", got)
	}
	want := "Bearer " + te.lastIssued()
	for _, auth := range s.upstreamAuths() {
		if auth != want {
			t.Fatalf("upstream authorization differs from the cached token: %q", auth)
		}
	}
}

func TestOAuthTokenSingleFlight(t *testing.T) {
	const clientID, clientSecret = "client-flight", "client-secret-flight"
	te := newTokenEndpoint(t, clientID, clientSecret)
	s := newOAuthStack(t, model.AuthOAuthClientCredentials, clientCredentialsFields(te.server.URL+"/token", clientID, clientSecret, nil))

	const workers = 24
	var wg sync.WaitGroup
	statuses := make([]int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, _ := s.request()
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	for i, code := range statuses {
		if code != http.StatusOK {
			t.Fatalf("concurrent request %d: status %d", i, code)
		}
	}
	if got := te.calls(); got != 1 {
		t.Fatalf("concurrent requests must share one exchange: calls=%d", got)
	}
	if got := len(s.upstreamAuths()); got != workers {
		t.Fatalf("upstream requests: want %d got %d", workers, got)
	}
}

func TestOAuthTokenExpiryRefresh(t *testing.T) {
	const clientID, clientSecret = "client-expiry", "client-secret-expiry"
	te := newTokenEndpoint(t, clientID, clientSecret)
	s := newOAuthStack(t, model.AuthOAuthClientCredentials, clientCredentialsFields(te.server.URL+"/token", clientID, clientSecret, nil))

	if resp, body := s.request(); resp.StatusCode != http.StatusOK {
		t.Fatalf("first request: %d %s", resp.StatusCode, body)
	}
	// 到期 = 3600s - 60s = 3540s；尚未过期时仍应命中缓存。
	s.clock.advance(3000 * time.Second)
	if resp, body := s.request(); resp.StatusCode != http.StatusOK {
		t.Fatalf("cached request: %d %s", resp.StatusCode, body)
	}
	if got := te.calls(); got != 1 {
		t.Fatalf("token must still be cached: calls=%d", got)
	}
	// 越过 3540s 后必须重新换取。
	s.clock.advance(601 * time.Second)
	if resp, body := s.request(); resp.StatusCode != http.StatusOK {
		t.Fatalf("refreshed request: %d %s", resp.StatusCode, body)
	}
	if got := te.calls(); got != 2 {
		t.Fatalf("expired token must be re-exchanged: calls=%d", got)
	}
}

func TestOAuthTokenFailureNotCached(t *testing.T) {
	const clientID, clientSecret = "client-failure", "client-secret-failure"
	te := newTokenEndpoint(t, clientID, clientSecret)
	s := newOAuthStack(t, model.AuthOAuthClientCredentials, clientCredentialsFields(te.server.URL+"/token", clientID, clientSecret, nil))

	te.setFailure(http.StatusUnauthorized, "invalid_client", "client authentication failed")
	resp, body := s.request()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token 4xx must surface as 401, got %d: %s", resp.StatusCode, body)
	}
	if code := errorCode(t, body); code != "UPSTREAM_AUTH_FAILED" {
		t.Fatalf("error code: want UPSTREAM_AUTH_FAILED got %s", code)
	}
	if msg := errorMessage(t, body); strings.Contains(msg, clientSecret) {
		t.Fatalf("error message leaked client_secret: %s", msg)
	}
	if got := len(s.upstreamAuths()); got != 0 {
		t.Fatalf("upstream must not be called when the exchange fails: %d", got)
	}
	// 失败不缓存：端点恢复后下一次请求必须真正重试。
	te.clearFailure()
	if resp, body := s.request(); resp.StatusCode != http.StatusOK {
		t.Fatalf("retry after failure: want 200 got %d: %s", resp.StatusCode, body)
	}
	if got := te.calls(); got != 2 {
		t.Fatalf("failed exchange must not be cached: calls=%d", got)
	}
}

func TestOAuthTokenUpstreamUnavailable(t *testing.T) {
	const clientID, clientSecret = "client-5xx", "client-secret-5xx"
	te := newTokenEndpoint(t, clientID, clientSecret)
	s := newOAuthStack(t, model.AuthOAuthClientCredentials, clientCredentialsFields(te.server.URL+"/token", clientID, clientSecret, nil))

	te.setFailure(http.StatusInternalServerError, "server_error", "temporarily broken")
	resp, body := s.request()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("token 5xx must surface as 502, got %d: %s", resp.StatusCode, body)
	}
	if code := errorCode(t, body); code != "UPSTREAM_UNAVAILABLE" {
		t.Fatalf("error code: want UPSTREAM_UNAVAILABLE got %s", code)
	}

	// 网络层失败同样归类为上游不可用。
	te.server.Close()
	if resp, body := s.request(); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("network failure must surface as 502, got %d: %s", resp.StatusCode, body)
	}
}

func TestOAuthTokenRedactsReflectedSecret(t *testing.T) {
	const clientID, clientSecret = "client-reflect", "client-secret-reflected-value"
	te := newTokenEndpoint(t, clientID, clientSecret)
	s := newOAuthStack(t, model.AuthOAuthClientCredentials, clientCredentialsFields(te.server.URL+"/token", clientID, clientSecret, nil))

	// 恶意/异常端点把客户端凭据反射进 error_description：网关必须替换掉。
	te.setFailure(http.StatusBadRequest, "invalid_request", "rejected for "+clientSecret)
	resp, body := s.request()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d: %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), clientSecret) {
		t.Fatalf("gateway error body reflected client_secret: %s", body)
	}
	if !strings.Contains(errorMessage(t, body), "<redacted>") {
		t.Fatalf("reflected secret was not replaced: %s", body)
	}
}

func TestOAuthTokenMissingFieldsAndUnsupportedModes(t *testing.T) {
	te := newTokenEndpoint(t, "id", "secret")

	cases := []struct {
		name   string
		scheme model.AuthScheme
		fields map[string]string
		status int
		code   string
	}{
		{
			name:   "client_credentials without token_endpoint",
			scheme: model.AuthOAuthClientCredentials,
			fields: map[string]string{"client_id": "id", "client_secret": "secret"},
			status: http.StatusServiceUnavailable,
			code:   "CREDENTIAL_UNAVAILABLE",
		},
		{
			name:   "client_credentials without client_secret",
			scheme: model.AuthOAuthClientCredentials,
			fields: map[string]string{"token_endpoint": te.server.URL + "/token", "client_id": "id"},
			status: http.StatusServiceUnavailable,
			code:   "CREDENTIAL_UNAVAILABLE",
		},
		{
			name:   "client_credentials with a static bearer credential",
			scheme: model.AuthOAuthClientCredentials,
			fields: map[string]string{"token": "static-token"},
			status: http.StatusServiceUnavailable,
			code:   "CREDENTIAL_UNAVAILABLE",
		},
		{
			name:   "client_credentials with unknown client_auth",
			scheme: model.AuthOAuthClientCredentials,
			fields: map[string]string{
				"token_endpoint": te.server.URL + "/token", "client_id": "id", "client_secret": "secret", "client_auth": "mtls",
			},
			status: http.StatusNotImplemented,
			code:   "ADAPTER_UNSUPPORTED",
		},
		{
			name:   "jwt_bearer without private_key",
			scheme: model.AuthOAuthJWTBearer,
			fields: map[string]string{"client_email": "sa@example.test", "token_uri": te.server.URL + "/token"},
			status: http.StatusServiceUnavailable,
			code:   "CREDENTIAL_UNAVAILABLE",
		},
		{
			name:   "jwt_bearer with a non-RSA private_key",
			scheme: model.AuthOAuthJWTBearer,
			fields: map[string]string{
				"client_email": "sa@example.test", "token_uri": te.server.URL + "/token",
				"private_key": "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n",
			},
			status: http.StatusServiceUnavailable,
			code:   "CREDENTIAL_UNAVAILABLE",
		},
		{
			name:   "jwt_bearer without client_email",
			scheme: model.AuthOAuthJWTBearer,
			fields: map[string]string{"token_uri": te.server.URL + "/token", "private_key": "x"},
			status: http.StatusServiceUnavailable,
			code:   "CREDENTIAL_UNAVAILABLE",
		},
		{
			name:   "jwt_bearer with an invalid token_uri",
			scheme: model.AuthOAuthJWTBearer,
			fields: map[string]string{"client_email": "sa@example.test", "token_uri": "not-a-url", "private_key": "x"},
			status: http.StatusServiceUnavailable,
			code:   "CREDENTIAL_UNAVAILABLE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newOAuthStack(t, tc.scheme, tc.fields)
			resp, body := s.request()
			if resp.StatusCode != tc.status {
				t.Fatalf("status: want %d got %d: %s", tc.status, resp.StatusCode, body)
			}
			if code := errorCode(t, body); code != tc.code {
				t.Fatalf("code: want %s got %s (%s)", tc.code, code, body)
			}
			if got := te.calls(); got != 0 {
				t.Fatalf("invalid credential must not reach the token endpoint: calls=%d", got)
			}
			if got := len(s.upstreamAuths()); got != 0 {
				t.Fatalf("invalid credential must not reach the upstream: %d", got)
			}
		})
	}
}

// TestOAuthBindingRejectsModeEscalation 确认 OAuth 换取发生在授权通过之后：
// 只有 runtime_delivery 许可时，proxy 请求在碰 token 端点之前就被拒绝。
func TestOAuthBindingRejectsModeEscalation(t *testing.T) {
	const clientID, clientSecret = "client-mode", "client-secret-mode"
	te := newTokenEndpoint(t, clientID, clientSecret)
	fields := clientCredentialsFields(te.server.URL+"/token", clientID, clientSecret, nil)
	s := newOAuthStackMode(t, model.AuthOAuthClientCredentials, fields, model.ModeRuntimeDelivery)

	resp, body := s.request()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mode escalation must be rejected with 403, got %d: %s", resp.StatusCode, body)
	}
	if code := errorCode(t, body); code != "USE_NOT_ALLOWED" {
		t.Fatalf("error code: want USE_NOT_ALLOWED got %s", code)
	}
	if got := te.calls(); got != 0 {
		t.Fatalf("token endpoint must not be called before authorization: calls=%d", got)
	}
	if got := len(s.upstreamAuths()); got != 0 {
		t.Fatalf("upstream must not be called: %d", got)
	}
}

func TestOAuthTokenNotLeakedIntoAuditOrError(t *testing.T) {
	const clientID, clientSecret = "client-audit", "client-secret-audit"
	te := newTokenEndpoint(t, clientID, clientSecret)
	s := newOAuthStack(t, model.AuthOAuthClientCredentials, clientCredentialsFields(te.server.URL+"/token", clientID, clientSecret, nil))

	if resp, body := s.request(); resp.StatusCode != http.StatusOK {
		t.Fatalf("request: %d %s", resp.StatusCode, body)
	}
	issued := te.lastIssued()
	events, err := s.store.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatalf("audit events: %v", err)
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), issued) || strings.Contains(string(raw), clientSecret) {
		t.Fatalf("audit events leaked a token or client_secret: %s", raw)
	}
}
