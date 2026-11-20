package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

// ---------- 受控 OAuth 提供方（httptest） ----------

type issued struct {
	access  string
	refresh string
}

type testProvider struct {
	t          *testing.T
	server     *httptest.Server
	clientID   string
	clientSec  string
	redirect   string
	expiresIn  int64
	failStatus int
	failNet    bool

	mu           sync.Mutex
	codes        map[string]string // code -> code_challenge
	codeRedirect map[string]string
	usedCodes    map[string]bool
	access       map[string]bool
	refresh      map[string]bool
	latest       issued
	authorize    int
	tokenCode    int
	tokenRefresh int
	rejected     int
	lastVerifier string
	refreshDelay time.Duration
}

func newTestProvider(t *testing.T) *testProvider {
	p := &testProvider{
		t:            t,
		clientID:     "client-" + randomSuffix(t),
		clientSec:    "secret-" + randomSuffix(t),
		redirect:     "http://127.0.0.1:0/callback",
		expiresIn:    300,
		codes:        map[string]string{},
		codeRedirect: map[string]string{},
		usedCodes:    map[string]bool{},
		access:       map[string]bool{},
		refresh:      map[string]bool{},
	}
	p.server = httptest.NewServer(http.HandlerFunc(p.handle))
	t.Cleanup(p.server.Close)
	return p
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("random: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (p *testProvider) tokenEndpoint() string     { return p.server.URL + "/token" }
func (p *testProvider) authorizeEndpoint() string { return p.server.URL + "/authorize" }
func (p *testProvider) resourceEndpoint() string  { return p.server.URL + "/resource" }

func (p *testProvider) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/authorize":
		p.handleAuthorize(w, r)
	case "/token":
		p.handleToken(w, r)
	case "/resource":
		p.handleResource(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *testProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.authorize++
	p.mu.Unlock()
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != p.clientID {
		http.Error(w, "invalid authorize request", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "PKCE S256 is required", http.StatusBadRequest)
		return
	}
	if q.Get("state") == "" {
		http.Error(w, "state is required", http.StatusBadRequest)
		return
	}
	code := "code_" + randomSuffix(p.t)
	p.mu.Lock()
	p.codes[code] = q.Get("code_challenge")
	p.codeRedirect[code] = q.Get("redirect_uri")
	p.mu.Unlock()

	target, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	tq := target.Query()
	tq.Set("code", code)
	tq.Set("state", q.Get("state"))
	target.RawQuery = tq.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (p *testProvider) setFailNet(v bool) {
	p.mu.Lock()
	p.failNet = v
	p.mu.Unlock()
}

func (p *testProvider) setFailStatus(code int) {
	p.mu.Lock()
	p.failStatus = code
	p.mu.Unlock()
}

func (p *testProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	failNet, failStatus := p.failNet, p.failStatus
	p.mu.Unlock()
	if failNet {
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
				return
			}
		}
		http.Error(w, "network failure", http.StatusBadGateway)
		return
	}
	if failStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(failStatus)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "temporarily_unavailable"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthErrorJSON(w, http.StatusBadRequest, "invalid_request", "form body required")
		return
	}
	if !p.clientAuthOK(r) {
		p.mu.Lock()
		p.rejected++
		p.mu.Unlock()
		writeOAuthErrorJSON(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		p.tokenCodeFlow(w, r)
	case "refresh_token":
		p.tokenRefreshFlow(w, r)
	default:
		writeOAuthErrorJSON(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (p *testProvider) clientAuthOK(r *http.Request) bool {
	if user, pass, ok := r.BasicAuth(); ok {
		return user == p.clientID && pass == p.clientSec
	}
	return r.PostForm.Get("client_id") == p.clientID && r.PostForm.Get("client_secret") == p.clientSec
}

func (p *testProvider) tokenCodeFlow(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	verifier := r.PostForm.Get("code_verifier")
	p.mu.Lock()
	challenge, ok := p.codes[code]
	redirect := p.codeRedirect[code]
	p.mu.Unlock()
	if !ok {
		p.mu.Lock()
		p.rejected++
		p.mu.Unlock()
		writeOAuthErrorJSON(w, http.StatusBadRequest, "invalid_grant", "authorization code is unknown or already used")
		return
	}
	if redirect != "" && r.PostForm.Get("redirect_uri") != redirect {
		writeOAuthErrorJSON(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		p.mu.Lock()
		p.lastVerifier = "MISMATCH"
		p.mu.Unlock()
		writeOAuthErrorJSON(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	p.mu.Lock()
	delete(p.codes, code)
	p.usedCodes[code] = true
	p.tokenCode++
	p.lastVerifier = "OK"
	tokens := p.issueLocked()
	p.mu.Unlock()
	writeTokenJSON(w, tokens, p.expiresIn)
}

func (p *testProvider) tokenRefreshFlow(w http.ResponseWriter, r *http.Request) {
	rt := r.PostForm.Get("refresh_token")
	p.mu.Lock()
	delay := p.refreshDelay
	p.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	p.mu.Lock()
	valid := p.refresh[rt]
	p.mu.Unlock()
	if !valid {
		p.mu.Lock()
		p.rejected++
		p.mu.Unlock()
		writeOAuthErrorJSON(w, http.StatusBadRequest, "invalid_grant", "refresh token is not valid")
		return
	}
	p.mu.Lock()
	delete(p.refresh, rt)
	delete(p.access, p.latest.access)
	p.tokenRefresh++
	tokens := p.issueLocked()
	p.mu.Unlock()
	writeTokenJSON(w, tokens, p.expiresIn)
}

// issueLocked 发放一组新 token（调用方持锁）。
func (p *testProvider) issueLocked() issued {
	n := len(p.access) + len(p.refresh) + 1
	tokens := issued{
		access:  fmt.Sprintf("at_%s_%d", randomSuffix(p.t), n),
		refresh: fmt.Sprintf("rt_%s_%d", randomSuffix(p.t), n),
	}
	p.access[tokens.access] = true
	p.refresh[tokens.refresh] = true
	p.latest = tokens
	return tokens
}

func (p *testProvider) handleResource(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.Lock()
	ok := p.access[token]
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "sub": "fixture-user"})
}

func (p *testProvider) revokeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.access = map[string]bool{}
	p.refresh = map[string]bool{}
}

func (p *testProvider) counts() (auth, code, refresh, rejected int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.authorize, p.tokenCode, p.tokenRefresh, p.rejected
}

func (p *testProvider) current() issued {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.latest
}

func writeTokenJSON(w http.ResponseWriter, tokens issued, expiresIn int64) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  tokens.access,
		"refresh_token": tokens.refresh,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"scope":         "read write",
	})
}

func writeOAuthErrorJSON(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

// ---------- 伪造凭证存储（等价于 vault.AddVersion 的原子切换语义） ----------

type fakeStore struct {
	mu       sync.Mutex
	cred     model.Credential
	versions map[int]model.CredentialVersion
	commits  int
	loads    int
	revoked  int

	commitErr             error
	markErr               error
	loadErr               error
	failLoadAt            int
	disableBeforeActivate bool
	statusLog             []model.EntityStatus
	// beforeCommit 在提交真正写入之前执行（调用时已持有 s.mu），用来注入
	// “写前核对已通过、提交尚未写入”窗口内的并行改动。
	beforeCommit func()
}

func newFakeStore(t *testing.T, initial model.CredentialVersion) *fakeStore {
	t.Helper()
	s := &fakeStore{
		cred: model.Credential{
			ID: "cred_oauth_test", Kind: model.KindOAuth, Label: "oauth fixture",
			CurrentVersion: 1, Status: model.StatusActive,
			// 与真实存储一致：凭证记录的 revision 从 1 开始，0 不是有效 revision。
			Revision: 1,
		},
		versions: map[int]model.CredentialVersion{},
	}
	initial.CredentialID = s.cred.ID
	initial.Version = 1
	s.versions[1] = initial
	return s
}

func (s *fakeStore) Load(_ context.Context, id string) (model.Credential, model.CredentialVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	if s.failLoadAt > 0 && s.loads == s.failLoadAt {
		return model.Credential{}, model.CredentialVersion{}, s.loadErr
	}
	if id != s.cred.ID {
		return model.Credential{}, model.CredentialVersion{}, store.ErrNotFound
	}
	v, ok := s.versions[s.cred.CurrentVersion]
	if !ok {
		return model.Credential{}, model.CredentialVersion{}, store.ErrNotFound
	}
	return s.cred, v.Clone(), nil
}

func (s *fakeStore) Commit(_ context.Context, id string, version model.CredentialVersion) (*model.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commitErr != nil {
		return nil, s.commitErr
	}
	if id != s.cred.ID {
		return nil, store.ErrNotFound
	}
	s.runBeforeCommitLocked()
	version.CredentialID = id
	version.Version = s.cred.CurrentVersion + 1
	s.versions[version.Version] = version.Clone()
	s.cred.CurrentVersion = version.Version
	s.cred.ProviderExpiresAt = version.ProviderExpiresAt
	s.cred.Revision++
	s.commits++
	out := s.cred
	return &out, nil
}

// runBeforeCommitLocked 执行注入的并行改动。调用方必须持有 s.mu：注入的改动与
// 提交写入落在同一个临界区内，才能稳定复现“检查通过、提交之前”的竞态。
// 注入函数只能直接修改字段，不能再次加锁。
func (s *fakeStore) runBeforeCommitLocked() {
	if s.beforeCommit == nil {
		return
	}
	hook := s.beforeCommit
	s.beforeCommit = nil
	hook()
}

// casStore 给 fakeStore 追加可选的原子提交能力，用来覆盖 Manager 的 CAS 路径。
type casStore struct{ *fakeStore }

// CommitCAS 在与 Commit 相同的锁内先执行注入的并行改动，再核对 revision：
// revision 不符时返回包装了 ErrCommitConflict 的错误，且不写入任何内容。
func (s *casStore) CommitCAS(_ context.Context, id string, expectedRevision int64, version model.CredentialVersion) (*model.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commitErr != nil {
		return nil, s.commitErr
	}
	if id != s.cred.ID {
		return nil, store.ErrNotFound
	}
	s.runBeforeCommitLocked()
	if s.cred.Revision != expectedRevision {
		return nil, fmt.Errorf("commit version %d: %w", version.Version, ErrCommitConflict)
	}
	version.CredentialID = id
	version.Version = s.cred.CurrentVersion + 1
	s.versions[version.Version] = version.Clone()
	s.cred.CurrentVersion = version.Version
	s.cred.ProviderExpiresAt = version.ProviderExpiresAt
	s.cred.Revision++
	s.commits++
	out := s.cred
	return &out, nil
}

func (s *fakeStore) MarkStatus(_ context.Context, id string, status model.EntityStatus, expectedRevision int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status == model.StatusActive && s.disableBeforeActivate {
		s.disableBeforeActivate = false
		s.cred.Status = model.StatusDisabled
		s.cred.Revision++
		s.statusLog = append(s.statusLog, model.StatusDisabled)
	}
	if expectedRevision != 0 && s.cred.Revision != expectedRevision {
		return store.ErrConflict
	}
	if s.markErr != nil {
		return s.markErr
	}
	s.statusLog = append(s.statusLog, status)
	s.cred.Status = status
	s.cred.Revision++
	return nil
}

func (s *fakeStore) RevokeLeases(_ context.Context, _ string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked++
	return 1
}

func (s *fakeStore) snapshot() (int, int, model.EntityStatus, []model.EntityStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	statuses := append([]model.EntityStatus(nil), s.statusLog...)
	return s.cred.CurrentVersion, s.commits, s.cred.Status, statuses
}

func (s *fakeStore) version(t *testing.T, n int) model.CredentialVersion {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.versions[n]
	if !ok {
		t.Fatalf("version %d missing", n)
	}
	return v.Clone()
}

// leasesRevoked 返回已失效的许可数量。
func (s *fakeStore) leasesRevoked() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked
}

// disableForTest 模拟管理员停用：改状态并递增 revision。调用方必须持有 s.mu。
func disableForTest(s *fakeStore) {
	s.cred.Status = model.StatusDisabled
	s.cred.Revision++
	s.statusLog = append(s.statusLog, model.StatusDisabled)
}

// ---------- 测试时钟 ----------

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *testClock {
	return &testClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---------- 测试装配 ----------

type harness struct {
	provider *testProvider
	store    *fakeStore
	manager  *Manager
	clock    *testClock
	cfg      ProviderConfig
	states   *StateStore
}

func newHarness(t *testing.T, expiresIn int64, initialExpiry *time.Time) *harness {
	t.Helper()
	provider := newTestProvider(t)
	provider.expiresIn = expiresIn
	clock := newClock()
	cfg := ProviderConfig{
		ClientID:          provider.clientID,
		ClientSecret:      secret.New(provider.clientSec),
		TokenEndpoint:     provider.tokenEndpoint(),
		AuthorizeEndpoint: provider.authorizeEndpoint(),
		RedirectURI:       provider.redirect,
		Scopes:            []string{"read", "write"},
	}
	v1 := model.CredentialVersion{
		Fields: map[string]secret.Value{
			FieldAccessToken:       secret.New("stale-access"),
			FieldRefreshToken:      secret.New("stale-refresh"),
			FieldClientID:          secret.New(provider.clientID),
			FieldClientSecret:      secret.New(provider.clientSec),
			FieldTokenEndpoint:     secret.New(provider.tokenEndpoint()),
			FieldAuthorizeEndpoint: secret.New(provider.authorizeEndpoint()),
			FieldRedirectURI:       secret.New(provider.redirect),
			FieldScope:             secret.New("read write"),
		},
		ProviderExpiresAt: initialExpiry,
	}
	// 提供方认识初始组合，后续刷新才会轮换。
	provider.mu.Lock()
	provider.access["stale-access"] = true
	provider.refresh["stale-refresh"] = true
	provider.mu.Unlock()
	st := newFakeStore(t, v1)
	states := NewStateStore()
	svc := NewService()
	// 受控提供方是 httptest 的明文回环服务：显式放行回环明文。
	svc.AllowLoopbackHTTP = true
	svc.HTTP = provider.server.Client()
	svc.Now = clock.Now
	svc.Pending.SetClock(clock.Now)
	mgr := &Manager{Service: svc, Store: st, States: states, Now: clock.Now, Skew: 30 * time.Second}
	return &harness{provider: provider, store: st, manager: mgr, clock: clock, cfg: cfg, states: states}
}

// useCAS 让 Manager 走带预期 revision 的提交路径。hook 在 CAS 的“核对 revision、
// 写入新版本”之间执行（同一临界区），用来注入窗口内的并行改动。
func (h *harness) useCAS(hook func(s *fakeStore)) {
	st := &casStore{fakeStore: h.store}
	if hook != nil {
		st.beforeCommit = func() { hook(h.store) }
	}
	h.manager.Store = st
}

// injectBeforeCommit 在没有 CAS 能力的提交里注入并行改动：它落在 Manager 写前
// 核对之后、Commit 真正写入之前，用来覆盖回退流程的提交窗口。
func (h *harness) injectBeforeCommit(hook func(s *fakeStore)) {
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	h.store.beforeCommit = func() { hook(h.store) }
}

// login 走完 begin → 受控提供方自动授权 → callback。
func (h *harness) login(t *testing.T) (Result, Authorization) {
	t.Helper()
	auth, err := h.manager.BeginAuthorization(t.Context(), h.store.cred.ID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if auth.State == "" || !strings.Contains(auth.URL, "code_challenge_method=S256") {
		t.Fatalf("begin did not produce a PKCE authorization URL: %s", auth.URL)
	}
	if strings.Contains(auth.URL, "code_verifier") {
		t.Fatalf("code_verifier leaked into the authorization URL")
	}
	code, state := h.authorize(t, auth.URL)
	if state != auth.State {
		t.Fatalf("state mismatch: begin=%q provider=%q", auth.State, state)
	}
	res, err := h.manager.CompleteAuthorization(t.Context(), h.store.cred.ID, state, code)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	return res, auth
}

// authorize 模拟受信入口处的浏览器：不跟随跳转，只取出回调代码。
func (h *harness) authorize(t *testing.T, authURL string) (code, state string) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize returned HTTP %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	return loc.Query().Get("code"), loc.Query().Get("state")
}

// ---------- 用例 ----------

func TestLoginThenRefreshRotatesCompleteCombination(t *testing.T) {
	h := newHarness(t, 300, nil)
	res, _ := h.login(t)

	if !res.Refreshed || res.Version != 2 || res.Status != model.StatusActive {
		t.Fatalf("unexpected login result: %+v", res)
	}
	if res.TokenType != "Bearer" || res.Provider != ProviderKind {
		t.Fatalf("login metadata incomplete: %+v", res)
	}
	if res.ExpiresAt == nil || !res.ExpiresAt.Equal(h.clock.Now().Add(300*time.Second)) {
		t.Fatalf("provider expiry must be the real one: %v", res.ExpiresAt)
	}
	if res.CacheExpiresAt == nil || !res.CacheExpiresAt.Equal(res.ExpiresAt.Add(-30*time.Second)) {
		t.Fatalf("cache expiry must be real expiry minus skew: %v", res.CacheExpiresAt)
	}
	v2 := h.store.version(t, 2)
	access, err := v2.Field(FieldAccessToken)
	if err != nil {
		t.Fatalf("v2 access_token missing: %v", err)
	}
	refreshTok, err := v2.Field(FieldRefreshToken)
	if err != nil {
		t.Fatalf("v2 refresh_token missing: %v", err)
	}
	if access.EqualString("stale-access") || refreshTok.EqualString("stale-refresh") {
		t.Fatalf("login did not replace the token combination")
	}
	for _, name := range []string{FieldClientID, FieldClientSecret, FieldTokenEndpoint} {
		if _, err := v2.Field(name); err != nil {
			t.Fatalf("client field %q lost after refresh: %v", name, err)
		}
	}
	// 托管 access_token 能被提供方识别。
	req, _ := http.NewRequest(http.MethodGet, h.provider.resourceEndpoint(), nil)
	req.Header.Set("Authorization", "Bearer "+access.RevealString())
	resp, err := h.provider.server.Client().Do(req)
	if err != nil {
		t.Fatalf("resource request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stored access_token is not usable upstream: HTTP %d", resp.StatusCode)
	}

	// 到期后刷新：版本推进到 3，refresh_token 轮换。
	h.clock.Advance(301 * time.Second)
	before := h.provider.current()
	refreshed, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !refreshed.Refreshed || !refreshed.Rotated || refreshed.Version != 3 {
		t.Fatalf("unexpected refresh result: %+v", refreshed)
	}
	if refreshed.RevokedLeases == 0 {
		t.Fatalf("version switch must revoke existing leases")
	}
	v3 := h.store.version(t, 3)
	newAccess, _ := v3.Field(FieldAccessToken)
	newRefresh, _ := v3.Field(FieldRefreshToken)
	if newAccess.EqualString(before.access) || newRefresh.EqualString(before.refresh) {
		t.Fatalf("refresh did not persist the upstream token combination")
	}
	// 旧 refresh_token 在上游已失效：再用旧值刷新必须得到 invalid_grant。
	_, err = h.manager.Service.Refresh(t.Context(), h.cfg, secret.New(before.refresh))
	if ClassOf(err) != ClassRevoked {
		t.Fatalf("rotated-away refresh token must be revoked, got %v", err)
	}
	if strings.Contains(err.Error(), before.refresh) || strings.Contains(err.Error(), newAccess.RevealString()) {
		t.Fatalf("error text leaked a token: %v", err)
	}
}

func TestConcurrentRefreshAdvancesOnce(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)

	const workers = 8
	var wg sync.WaitGroup
	results := make([]Result, workers)
	errs := make([]error, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{})
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d failed: %v", i, errs[i])
		}
	}
	_, code, refreshes, _ := h.provider.counts()
	if refreshes != 1 {
		t.Fatalf("expected exactly one upstream refresh call, got %d", refreshes)
	}
	if code != 0 {
		t.Fatalf("refresh must not perform a code exchange, got %d", code)
	}
	version, commits, status, _ := h.store.snapshot()
	if commits != 1 || version != 2 {
		t.Fatalf("expected one committed version, got commits=%d version=%d", commits, version)
	}
	if status != model.StatusActive {
		t.Fatalf("status after refresh = %s", status)
	}
	advanced := 0
	for _, res := range results {
		if res.Refreshed {
			advanced++
		}
		if res.Version != 2 {
			t.Fatalf("all callers must observe version 2, got %+v", res)
		}
	}
	if advanced != 1 {
		t.Fatalf("exactly one caller should advance the refresh, got %d", advanced)
	}
}

func TestQueuedRefreshWithStaleExpectationReportsConflict(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)

	// 版本推进来自手工轮换（不是本进程的刷新）：排队中的刷新必须报冲突。
	rotated := h.store.version(t, 1)
	// 手工轮换写入了新值但仍已过期：排队中的刷新无法判断推进方做了什么，必须报冲突。
	expiry := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	rotated.ProviderExpiresAt = &expiry
	if _, err := h.store.Commit(t.Context(), h.store.cred.ID, rotated); err != nil {
		t.Fatalf("manual rotation: %v", err)
	}
	// 第二个请求在排队时看到的是版本 1；取得锁后发现已推进：不得再调上游，
	// 也不得覆盖对方的写入，必须返回可区分的冲突。
	second, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{Force: true, ExpectVersion: 1})
	requireConflictCode(t, err, CodeVersionConflict)
	if second.Refreshed {
		t.Fatalf("queued refresh must not advance again: %+v", second)
	}
	if second.Version != 2 {
		t.Fatalf("queued refresh must report the advanced version, got %d", second.Version)
	}
	// 冲突路径不调上游：这次请求在排队期间发现版本已被手工轮换推进。
	if _, _, refreshes, _ := h.provider.counts(); refreshes != 0 {
		t.Fatalf("conflicting refresh must not call upstream, got %d", refreshes)
	}
	if version, commits, _, _ := h.store.snapshot(); version != 2 || commits != 1 {
		t.Fatalf("stale expectation must not write: version=%d commits=%d", version, commits)
	}
}

// 排队期间另一个刷新完成时，调用方按无事可做成功返回，不报冲突。
func TestQueuedRefreshAfterAnotherRefreshSucceedsAsNoop(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)
	first, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{Force: true, ExpectVersion: 1})
	if err != nil || !first.Refreshed || first.Version != 2 {
		t.Fatalf("first refresh must advance: %+v %v", first, err)
	}
	second, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{Force: true, ExpectVersion: 1})
	if err != nil {
		t.Fatalf("a queued refresh that finds a completed refresh must succeed: %v", err)
	}
	if second.Refreshed || second.Version != 2 {
		t.Fatalf("queued refresh must report the advanced version without re-refreshing: %+v", second)
	}
	if _, _, refreshes, _ := h.provider.counts(); refreshes != 1 {
		t.Fatalf("upstream refresh count = %d, want 1", refreshes)
	}
}

func TestRefreshHonoursCacheSkew(t *testing.T) {
	near := time.Date(2026, 3, 1, 11, 59, 50, 0, time.UTC) // 距时钟 10s，小于 30s 余量
	h := newHarness(t, 300, &near)
	// 非强制刷新也应推进：余量内视为需要刷新。
	res, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !res.Refreshed {
		t.Fatalf("credential inside the clock skew must be refreshed: %+v", res)
	}
	// 刚刷新完的版本必须被判为新鲜，不再调用上游。
	again, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{})
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if again.Refreshed {
		t.Fatalf("fresh credential must not hit the upstream again: %+v", again)
	}
	_, _, refreshes, _ := h.provider.counts()
	if refreshes != 1 {
		t.Fatalf("upstream refresh count = %d, want 1", refreshes)
	}
}

func TestRefreshAfterRevocationRequiresReauth(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)
	h.provider.revokeAll()

	res, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{})
	if ClassOf(err) != ClassRevoked {
		t.Fatalf("revoked refresh token must be classified revoked, got %v", err)
	}
	if !NeedsReauth(err) || IsRetryable(err) {
		t.Fatalf("revocation must require re-auth and not be retryable: %+v", err)
	}
	if res.NextAction != "reauth" {
		t.Fatalf("result must point at re-auth: %+v", res)
	}
	version, commits, status, statuses := h.store.snapshot()
	if commits != 0 || version != 1 {
		t.Fatalf("revocation must not write a new version: version=%d commits=%d", version, commits)
	}
	if status != model.StatusRevoked {
		t.Fatalf("revocation must be persisted as revoked, got %s", status)
	}
	if len(statuses) == 0 || statuses[len(statuses)-1] != model.StatusRevoked {
		t.Fatalf("status transition log missing revoked: %v", statuses)
	}
	// 已撤销的凭证再次刷新：直接要求重新登录，不再打上游。
	_, _, refreshes, _ := h.provider.counts()
	_, err = h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{})
	if ClassOf(err) != ClassReauth {
		t.Fatalf("second refresh on a revoked credential must be reauth, got %v", err)
	}
	_, _, refreshes2, _ := h.provider.counts()
	if refreshes2 != refreshes {
		t.Fatalf("revoked credential must not reach the upstream again")
	}
}

func TestRefreshNetworkFailureIsRetryableAndWritesNothing(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)
	h.provider.setFailNet(true)

	_, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{})
	if ClassOf(err) != ClassRetryable {
		t.Fatalf("network failure must be retryable, got %v", err)
	}
	if !IsRetryable(err) || NeedsReauth(err) {
		t.Fatalf("network failure must not require re-auth: %v", err)
	}
	version, commits, status, _ := h.store.snapshot()
	if commits != 0 || version != 1 || status != model.StatusActive {
		t.Fatalf("network failure must leave state untouched: version=%d commits=%d status=%s", version, commits, status)
	}

	// 网络恢复后同一个凭证可以直接重试成功。
	h.provider.setFailNet(false)
	res, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{})
	if err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	if !res.Refreshed || res.Version != 2 {
		t.Fatalf("retry must advance the version: %+v", res)
	}
}

func TestRefreshTemporaryUpstreamFailureIsRetryable(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)
	h.provider.setFailStatus(http.StatusServiceUnavailable)

	_, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{})
	if ClassOf(err) != ClassRetryable {
		t.Fatalf("5xx must be retryable, got %v", err)
	}
	version, commits, _, _ := h.store.snapshot()
	if commits != 0 || version != 1 {
		t.Fatalf("temporary failure must not write: version=%d commits=%d", version, commits)
	}
}

func TestCommitFailureAfterUpstreamRotationIsVisibleRecovery(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)
	h.store.commitErr = fmt.Errorf("injected local write failure")
	h.store.markErr = fmt.Errorf("injected status write failure")

	res, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{})
	if ClassOf(err) != ClassRecovery || !RecoveryRequired(err) {
		t.Fatalf("commit failure after rotation must be recovery_required, got %v", err)
	}
	if !res.RecoveryRequired || res.NextAction != "reauth" {
		t.Fatalf("result must expose the recovery state: %+v", res)
	}
	if _, code, refreshes, _ := h.provider.counts(); refreshes != 1 || code != 0 {
		t.Fatalf("upstream refresh count = %d, want 1", refreshes)
	}
	if version, commits, _, _ := h.store.snapshot(); commits != 0 || version != 1 {
		t.Fatalf("commit must not have happened: version=%d commits=%d", version, commits)
	}
	// 即使状态写入也失败，运行时标记仍让状态可见。
	status, err := h.manager.Status(t.Context(), h.store.cred.ID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.RecoveryRequired || status.NextAction != "reauth" {
		t.Fatalf("recovery state must stay visible: %+v", status)
	}
	if mark, ok := h.states.Recovery(h.store.cred.ID); !ok || mark.Reason != "commit_failed" {
		t.Fatalf("recovery mark missing: %+v", mark)
	}
	// 处于恢复状态时刷新不再打上游，必须重新授权。
	_, err = h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{Force: true})
	if ClassOf(err) != ClassRecovery {
		t.Fatalf("refresh in recovery state must stay recovery_required, got %v", err)
	}
	if _, _, refreshes, _ := h.provider.counts(); refreshes != 1 {
		t.Fatalf("recovery state must not call the upstream again")
	}
}

func TestRecoveryResolvedByReauthorization(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)
	// 先做一次登录，让提供方持有可用 refresh_token。
	if _, _ = h.login(t); false {
		t.Fatal("unreachable")
	}

	h.store.mu.Lock()
	h.store.commitErr = fmt.Errorf("injected local write failure")
	h.store.mu.Unlock()
	h.clock.Advance(301 * time.Second)
	if _, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{}); !RecoveryRequired(err) {
		t.Fatalf("expected recovery_required, got %v", err)
	}

	// 本地可写后重新授权：版本继续推进，状态回到 active，恢复标记清除。
	h.store.mu.Lock()
	h.store.commitErr = nil
	h.store.markErr = nil
	h.store.mu.Unlock()
	res, _ := h.login(t)
	if res.RecoveryRequired {
		t.Fatalf("re-authorization must clear the recovery state: %+v", res)
	}
	if res.Status != model.StatusActive {
		t.Fatalf("re-authorization must restore active status, got %s", res.Status)
	}
	if _, ok := h.states.Recovery(h.store.cred.ID); ok {
		t.Fatalf("recovery mark must be cleared after re-authorization")
	}
	if _, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{}); err != nil {
		t.Fatalf("refresh after recovery: %v", err)
	}
}

func TestCallbackRejectsUnknownAndReplayedState(t *testing.T) {
	h := newHarness(t, 300, nil)
	auth, err := h.manager.BeginAuthorization(t.Context(), h.store.cred.ID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := h.manager.CompleteAuthorization(t.Context(), h.store.cred.ID, "forged-state", "code"); ClassOf(err) != ClassReauth {
		t.Fatalf("unknown state must be rejected, got %v", err)
	}
	code, state := h.authorize(t, auth.URL)
	if _, err := h.manager.CompleteAuthorization(t.Context(), h.store.cred.ID, state, code); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	if _, err := h.manager.CompleteAuthorization(t.Context(), h.store.cred.ID, state, code); ClassOf(err) != ClassReauth {
		t.Fatalf("replayed state must be rejected, got %v", err)
	}
	// 另一个凭证不能使用别人发起的 state。
	auth2, _ := h.manager.BeginAuthorization(t.Context(), h.store.cred.ID)
	code2, state2 := h.authorize(t, auth2.URL)
	h.store.mu.Lock()
	h.store.cred.ID = "cred_other"
	h.store.mu.Unlock()
	if _, err := h.manager.CompleteAuthorization(t.Context(), "cred_other", state2, code2); ClassOf(err) != ClassReauth {
		t.Fatalf("state must be bound to its credential, got %v", err)
	}
}

func TestWrongClientSecretIsConfigError(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)
	bad := h.cfg
	bad.ClientSecret = secret.New("wrong-secret")

	if _, err := h.manager.Service.Refresh(t.Context(), bad, secret.New("stale-refresh")); ClassOf(err) != ClassConfig {
		t.Fatalf("rejected client credentials must be a config error, got %v", err)
	}
}

func TestPendingStoreExpiry(t *testing.T) {
	clock := newClock()
	p := NewPendingStore(time.Minute)
	p.SetClock(clock.Now)
	p.Put(Pending{State: "s1", CredentialID: "c1", CodeVerifier: "v"})
	if _, ok := p.Take("s1"); !ok {
		t.Fatalf("pending authorization should be available")
	}
	if _, ok := p.Take("s1"); ok {
		t.Fatalf("pending authorization must be single-use")
	}
	p.Put(Pending{State: "s2", CredentialID: "c1"})
	clock.Advance(2 * time.Minute)
	if _, ok := p.Take("s2"); ok {
		t.Fatalf("expired pending authorization must not be accepted")
	}
	if p.Len() != 0 {
		t.Fatalf("pending store must drop expired entries")
	}
}

func TestClientSecretPostAuthMethod(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)
	post := h.cfg
	post.AuthMethod = AuthClientSecretPost
	res, err := h.manager.Service.Refresh(t.Context(), post, secret.New("stale-refresh"))
	if err != nil {
		t.Fatalf("client_secret_post refresh: %v", err)
	}
	if res.AccessToken.IsEmpty() || res.RefreshToken.IsEmpty() || !res.Rotated {
		t.Fatalf("client_secret_post flow returned an incomplete token set: %+v", res)
	}
	none := h.cfg
	none.AuthMethod = AuthNone
	none.ClientSecret = secret.Empty
	if _, err := h.manager.Service.Refresh(t.Context(), none, secret.New("whatever")); err == nil {
		t.Fatalf("public client without PKCE refresh must be rejected by the provider")
	}
}

func TestConfigFromVersionRequiresClientFields(t *testing.T) {
	missing := model.CredentialVersion{CredentialID: "cred_x", Fields: map[string]secret.Value{
		FieldTokenEndpoint: secret.New("http://127.0.0.1:1/token"),
	}}
	if _, err := ConfigFromVersion(missing); ClassOf(err) != ClassConfig {
		t.Fatalf("missing client_id must be a config error, got %v", err)
	}
	bad := model.CredentialVersion{CredentialID: "cred_x", Fields: map[string]secret.Value{
		FieldClientID:      secret.New("c"),
		FieldTokenEndpoint: secret.New("ftp://example.test/token"),
	}}
	if _, err := ConfigFromVersion(bad); ClassOf(err) != ClassConfig {
		t.Fatalf("non-http token_endpoint must be a config error, got %v", err)
	}
	missingAuthorize := model.CredentialVersion{CredentialID: "cred_x", Fields: map[string]secret.Value{
		FieldClientID:      secret.New("c"),
		FieldTokenEndpoint: secret.New("http://127.0.0.1:1/token"),
		FieldRedirectURI:   secret.New("http://127.0.0.1:9/cb"),
	}}
	if _, err := ConfigFromVersion(missingAuthorize); err != nil {
		t.Fatalf("config for refresh-only use must be accepted: %v", err)
	}
	svc := NewService()
	if _, err := svc.Begin(mustConfig(t, missingAuthorize), "cred_x"); ClassOf(err) != ClassConfig {
		t.Fatalf("begin without authorize_endpoint must be a config error, got %v", err)
	}
}

func mustConfig(t *testing.T, v model.CredentialVersion) ProviderConfig {
	t.Helper()
	cfg, err := ConfigFromVersion(v)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// ---------- 缺陷 10：令牌端点的传输与跳转策略 ----------

// requireConflictCode 断言错误是冲突类且带有指定的稳定 Code。
func requireConflictCode(t *testing.T, err error, code string) {
	t.Helper()
	if !IsConflict(err) {
		t.Fatalf("expected conflict %q, got %v", code, err)
	}
	var oe *Error
	if !errors.As(err, &oe) || oe.Code != code {
		t.Fatalf("conflict code = %v, want %q", err, code)
	}
}

// TestTokenEndpointRequiresHTTPSByDefault 覆盖默认拒绝明文、拒绝非回环明文，
// 以及授权入口同样受 https 约束。
func TestTokenEndpointRequiresHTTPSByDefault(t *testing.T) {
	t.Setenv(LoopbackHTTPEnv, "")
	ctx := t.Context()
	cases := []struct {
		name     string
		endpoint string
		optIn    bool
		wantOK   bool
	}{
		{name: "明文非回环默认被拒", endpoint: "http://example.test/token"},
		{name: "回环明文默认被拒", endpoint: "http://127.0.0.1:1/token"},
		{name: "localhost 明文默认被拒", endpoint: "http://localhost:1/token"},
		{name: "IPv6 回环明文默认被拒", endpoint: "http://[::1]:1/token"},
		{name: "显式放行也不允许非回环明文", endpoint: "http://example.test/token", optIn: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewService()
			svc.AllowLoopbackHTTP = tc.optIn
			cfg := ProviderConfig{ClientID: "client", TokenEndpoint: tc.endpoint}
			_, err := svc.Refresh(ctx, cfg, secret.New("refresh-token"))
			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected the endpoint to be accepted, got %v", err)
				}
				return
			}
			if ClassOf(err) != ClassConfig {
				t.Fatalf("plaintext token endpoint must be a config error, got %v", err)
			}
			if !strings.Contains(err.Error(), "https") {
				t.Fatalf("error must explain the https requirement: %v", err)
			}
		})
	}

	// 授权入口同样默认拒绝明文。
	svc := NewService()
	cfg := ProviderConfig{
		ClientID:          "client",
		TokenEndpoint:     "https://as.example.test/token",
		AuthorizeEndpoint: "http://127.0.0.1:1/authorize",
		RedirectURI:       "http://127.0.0.1:9/callback",
	}
	if _, err := svc.Begin(cfg, "cred_x"); ClassOf(err) != ClassConfig {
		t.Fatalf("plaintext authorize endpoint must be a config error by default, got %v", err)
	}
	svc.AllowLoopbackHTTP = true
	if _, err := svc.Begin(cfg, "cred_x"); err != nil {
		t.Fatalf("loopback opt-in must allow the plaintext authorize endpoint, got %v", err)
	}
}

// TestLoopbackPlaintextRequiresExplicitOptIn 覆盖回环显式放行开关：
// 同一个回环明文提供方在默认配置下被拒，打开开关后才可用。
func TestLoopbackPlaintextRequiresExplicitOptIn(t *testing.T) {
	t.Setenv(LoopbackHTTPEnv, "")
	ctx := t.Context()
	h := newHarness(t, 300, nil)

	strict := NewService()
	strict.HTTP = h.provider.server.Client()
	if _, err := strict.Refresh(ctx, h.cfg, secret.New("stale-refresh")); ClassOf(err) != ClassConfig {
		t.Fatalf("loopback plaintext must be rejected unless explicitly enabled, got %v", err)
	}

	allowed := NewService()
	allowed.AllowLoopbackHTTP = true
	allowed.HTTP = h.provider.server.Client()
	tokens, err := allowed.Refresh(ctx, h.cfg, secret.New("stale-refresh"))
	if err != nil {
		t.Fatalf("explicit loopback opt-in must allow plaintext http: %v", err)
	}
	if tokens.AccessToken.IsEmpty() {
		t.Fatalf("loopback opt-in refresh returned no access_token")
	}
	if _, _, refreshes, _ := h.provider.counts(); refreshes != 1 {
		t.Fatalf("upstream refresh count = %d, want 1", refreshes)
	}
}

// TestLoopbackEnvOptIn 覆盖环境变量形式的显式开关：只有明确取值才打开。
func TestLoopbackEnvOptIn(t *testing.T) {
	t.Setenv(LoopbackHTTPEnv, "")
	if svc := NewService(); svc.AllowLoopbackHTTP {
		t.Fatalf("loopback plaintext must be off by default")
	}
	t.Setenv(LoopbackHTTPEnv, "1")
	if svc := NewService(); !svc.AllowLoopbackHTTP {
		t.Fatalf("explicit opt-in env must enable loopback plaintext")
	}
	t.Setenv(LoopbackHTTPEnv, "true")
	if svc := NewService(); !svc.AllowLoopbackHTTP {
		t.Fatalf("explicit opt-in env (true) must enable loopback plaintext")
	}
	t.Setenv(LoopbackHTTPEnv, "yes")
	if svc := NewService(); svc.AllowLoopbackHTTP {
		t.Fatalf("ambiguous values must not enable loopback plaintext")
	}
}

// TestTokenEndpointRejectsInsecureTransport 覆盖“证书必须被校验”：
// 关闭证书校验的传输层不允许用于令牌交换。
func TestTokenEndpointRejectsInsecureTransport(t *testing.T) {
	svc := NewService()
	svc.HTTP = &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	cfg := ProviderConfig{ClientID: "client", TokenEndpoint: "https://127.0.0.1:1/token"}
	_, err := svc.Refresh(t.Context(), cfg, secret.New("refresh-token"))
	if ClassOf(err) != ClassConfig {
		t.Fatalf("a transport that skips certificate verification must be a config error, got %v", err)
	}
	if !strings.Contains(err.Error(), "verification") {
		t.Fatalf("error must explain the certificate requirement: %v", err)
	}
}

// TestTokenRequestRejectsRedirects 覆盖令牌请求的跳转策略：跨 origin 与同
// origin 的跳转都不跟随，跳转响应也不视为成功，目标端点一次都不会被访问。
func TestTokenRequestRejectsRedirects(t *testing.T) {
	ctx := t.Context()

	var echoHits, sameOriginHits int32
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&echoHits, 1)
		writeTokenJSON(w, issued{access: "leaked-access", refresh: "leaked-refresh"}, 300)
	}))
	defer echo.Close()

	crossOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, echo.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer crossOrigin.Close()

	var sameOrigin *httptest.Server
	sameOrigin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			http.Redirect(w, r, sameOrigin.URL+"/token2", http.StatusFound)
		case "/token2":
			atomic.AddInt32(&sameOriginHits, 1)
			writeTokenJSON(w, issued{access: "second-hop", refresh: "second-hop"}, 300)
		default:
			http.NotFound(w, r)
		}
	}))
	defer sameOrigin.Close()

	cases := []struct {
		name     string
		endpoint string
		hits     *int32
	}{
		{name: "跨 origin 307 不跟随", endpoint: crossOrigin.URL + "/token", hits: &echoHits},
		{name: "同 origin 302 不跟随", endpoint: sameOrigin.URL + "/token", hits: &sameOriginHits},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewService()
			svc.AllowLoopbackHTTP = true
			cfg := ProviderConfig{ClientID: "client", TokenEndpoint: tc.endpoint}
			_, err := svc.Refresh(ctx, cfg, secret.New("refresh-token"))
			if ClassOf(err) != ClassRejected {
				t.Fatalf("redirect response must be rejected, got %v", err)
			}
			var oe *Error
			if !errors.As(err, &oe) || oe.Code != "redirect_not_followed" {
				t.Fatalf("redirect error code = %v, want redirect_not_followed", err)
			}
			if got := atomic.LoadInt32(tc.hits); got != 0 {
				t.Fatalf("redirect target was contacted %d times; token requests must not follow redirects", got)
			}
		})
	}
}

// TestCallbackFollowsNoRedirectOnCrossOrigin 验证跨 origin 跳转目标即使返回
// 合法 token 组合也不会被当成成功写入。
func TestCallbackFollowsNoRedirectOnCrossOrigin(t *testing.T) {
	h := newHarness(t, 300, nil)
	var leaked int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&leaked, 1)
		writeTokenJSON(w, issued{access: "evil-access", refresh: "evil-refresh"}, 300)
	}))
	defer evil.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	cfg := h.cfg
	cfg.TokenEndpoint = redirector.URL + "/token"
	svc := NewService()
	svc.AllowLoopbackHTTP = true
	_, err := svc.Exchange(t.Context(), cfg, "code", "verifier", cfg.RedirectURI)
	if ClassOf(err) != ClassRejected {
		t.Fatalf("cross-origin redirect must be rejected, got %v", err)
	}
	if got := atomic.LoadInt32(&leaked); got != 0 {
		t.Fatalf("the redirect target received %d requests", got)
	}
}

// ---------- 缺陷 11：回调不得复活管理员停用，版本必须匹配 ----------

// TestCallbackKeepsAdminDisabledStatus 覆盖等待回调期间管理员停用凭证：
// 回调必须放弃提交，保留停用状态，并返回可区分的冲突结果。
func TestCallbackKeepsAdminDisabledStatus(t *testing.T) {
	h := newHarness(t, 300, nil)
	auth, err := h.manager.BeginAuthorization(t.Context(), h.store.cred.ID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	code, state := h.authorize(t, auth.URL)

	// 管理员在浏览器授权与回调之间停用凭证。
	h.store.mu.Lock()
	h.store.cred.Status = model.StatusDisabled
	h.store.cred.Revision++
	h.store.mu.Unlock()

	res, err := h.manager.CompleteAuthorization(t.Context(), h.store.cred.ID, state, code)
	requireConflictCode(t, err, CodeCredentialChanged)
	if res.Status != model.StatusDisabled {
		t.Fatalf("result must keep the administrator status, got %s", res.Status)
	}
	version, commits, status, statuses := h.store.snapshot()
	if commits != 0 || version != 1 {
		t.Fatalf("in-flight login must not write a version: version=%d commits=%d", version, commits)
	}
	if status != model.StatusDisabled {
		t.Fatalf("administrator status was overwritten: %s", status)
	}
	for _, got := range statuses {
		if got == model.StatusActive {
			t.Fatalf("callback re-activated a disabled credential: %v", statuses)
		}
	}
	if _, codeExchanges, _, _ := h.provider.counts(); codeExchanges != 0 {
		t.Fatalf("callback must not exchange the code after the record changed, got %d exchanges", codeExchanges)
	}
}

// TestCallbackDetectsVersionConflictFromManualRotation 覆盖等待期间的手工轮换
// 推进了版本：回调不覆盖新版本，返回冲突。
func TestCallbackDetectsVersionConflictFromManualRotation(t *testing.T) {
	h := newHarness(t, 300, nil)
	auth, err := h.manager.BeginAuthorization(t.Context(), h.store.cred.ID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	code, state := h.authorize(t, auth.URL)

	// 并行的手工轮换直接写入新版本。
	if _, err := h.store.Commit(t.Context(), h.store.cred.ID, model.CredentialVersion{
		Fields: map[string]secret.Value{FieldAccessToken: secret.New("manual-rotation")},
	}); err != nil {
		t.Fatalf("manual rotation: %v", err)
	}

	res, err := h.manager.CompleteAuthorization(t.Context(), h.store.cred.ID, state, code)
	requireConflictCode(t, err, CodeCredentialChanged)
	if res.Version != 2 {
		t.Fatalf("result must report the current version, got %d", res.Version)
	}
	version, commits, _, statuses := h.store.snapshot()
	if version != 2 || commits != 1 {
		t.Fatalf("in-flight login must not overwrite the manual rotation: version=%d commits=%d", version, commits)
	}
	current := h.store.version(t, 2)
	if access, _ := current.Field(FieldAccessToken); !access.EqualString("manual-rotation") {
		t.Fatalf("manual rotation was overwritten")
	}
	if len(statuses) != 0 {
		t.Fatalf("callback must not touch status, got %v", statuses)
	}
}

// TestCallbackReactivatesUntouchedRevokedCredential 确认没有过度收紧：
// 发起登录时记录已是 revoked，等待期间无人改动，重新登录仍可恢复 active。
func TestCallbackReactivatesUntouchedRevokedCredential(t *testing.T) {
	h := newHarness(t, 300, nil)
	h.store.mu.Lock()
	h.store.cred.Status = model.StatusRevoked
	h.store.cred.Revision++
	h.store.mu.Unlock()

	res, _ := h.login(t)
	if res.Status != model.StatusActive {
		t.Fatalf("re-login of an untouched revoked credential must restore active, got %s", res.Status)
	}
	if version, _, status, _ := h.store.snapshot(); version != 2 || status != model.StatusActive {
		t.Fatalf("unexpected store state: version=%d status=%s", version, status)
	}
}

func TestCommitReadFailureRequiresRecovery(t *testing.T) {
	h := newHarness(t, 300, nil)
	ctx := t.Context()
	cred, version, err := h.store.Load(ctx, h.store.cred.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	h.store.mu.Lock()
	h.store.loadErr = errors.New("controlled read failure")
	h.store.failLoadAt = 2
	h.store.mu.Unlock()

	res := h.manager.metadata(cred, version)
	_, err = h.manager.commitTokens(ctx, cred, version, TokenSet{
		AccessToken: secret.New("uncommitted-access"), RefreshToken: secret.New("uncommitted-refresh"), Rotated: true,
	}, "login", res, true)
	if ClassOf(err) != ClassRecovery {
		t.Fatalf("commit read failure must require recovery, got %v", err)
	}
	_, commits, status, _ := h.store.snapshot()
	if commits != 0 || status != model.StatusRecovery {
		t.Fatalf("read failure must not commit a version: commits=%d status=%s", commits, status)
	}
}

func TestCallbackPreservesDisableBetweenCommitAndReactivation(t *testing.T) {
	h := newHarness(t, 300, nil)
	h.store.mu.Lock()
	h.store.cred.Status = model.StatusRevoked
	h.store.mu.Unlock()
	auth, err := h.manager.BeginAuthorization(t.Context(), h.store.cred.ID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	code, state := h.authorize(t, auth.URL)
	h.store.mu.Lock()
	h.store.disableBeforeActivate = true
	h.store.mu.Unlock()

	res, err := h.manager.CompleteAuthorization(t.Context(), h.store.cred.ID, state, code)
	requireConflictCode(t, err, CodeCredentialChanged)
	if res.Status != model.StatusDisabled {
		t.Fatalf("administrator disable must win, got %s", res.Status)
	}
	version, commits, status, statuses := h.store.snapshot()
	if version != 2 || commits != 1 || status != model.StatusDisabled {
		t.Fatalf("unexpected final state: version=%d commits=%d status=%s", version, commits, status)
	}
	for _, got := range statuses {
		if got == model.StatusActive {
			t.Fatalf("stale callback re-activated a disabled credential: %v", statuses)
		}
	}
}

// TestCommitDiscardsParallelRotation 覆盖提交前的 compare-and-set：
// 提交时记录已被并行轮换推进，旧快照不得覆盖新版本。
func TestCommitDiscardsParallelRotation(t *testing.T) {
	h := newHarness(t, 300, nil)
	ctx := t.Context()
	cred, version, err := h.store.Load(ctx, h.store.cred.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// 并行的手工轮换在本次提交之前完成。
	if _, err := h.store.Commit(ctx, h.store.cred.ID, model.CredentialVersion{
		Fields: map[string]secret.Value{FieldAccessToken: secret.New("parallel-rotation")},
	}); err != nil {
		t.Fatalf("parallel rotation: %v", err)
	}
	res := h.manager.metadata(cred, version)
	_, err = h.manager.commitTokens(ctx, cred, version, TokenSet{
		AccessToken:  secret.New("stale-access"),
		RefreshToken: secret.New("stale-refresh"),
		Rotated:      true,
	}, "refresh", res, false)
	requireConflictCode(t, err, CodeCredentialChanged)
	gotVersion, commits, _, _ := h.store.snapshot()
	if gotVersion != 2 || commits != 1 {
		t.Fatalf("stale snapshot must not be committed: version=%d commits=%d", gotVersion, commits)
	}
	current := h.store.version(t, 2)
	if access, _ := current.Field(FieldAccessToken); !access.EqualString("parallel-rotation") {
		t.Fatalf("parallel rotation was overwritten by a stale snapshot")
	}
}

// ---------- 缺陷 11 回归：检查与提交之间的窗口 ----------

// TestCallbackCommitCASRejectsDisableInCommitWindow 覆盖管理员停用恰好落在
// “写前核对已通过、CAS 尚未写入”的窗口内：提交被拒绝，不写版本，也不激活。
func TestCallbackCommitCASRejectsDisableInCommitWindow(t *testing.T) {
	h := newHarness(t, 300, nil)
	auth, err := h.manager.BeginAuthorization(t.Context(), h.store.cred.ID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	code, state := h.authorize(t, auth.URL)
	// 管理员停用发生在提交的临界区内、revision 核对之前。
	h.useCAS(disableForTest)

	res, err := h.manager.CompleteAuthorization(t.Context(), h.store.cred.ID, state, code)
	requireConflictCode(t, err, CodeCredentialChanged)
	if res.Status != model.StatusDisabled || res.Version != 1 {
		t.Fatalf("conflict must report the administrator record: status=%s version=%d", res.Status, res.Version)
	}
	version, commits, status, statuses := h.store.snapshot()
	if commits != 0 || version != 1 {
		t.Fatalf("CAS rejection must not write a version: version=%d commits=%d", version, commits)
	}
	if status != model.StatusDisabled {
		t.Fatalf("administrator status was overwritten: %s", status)
	}
	for _, got := range statuses {
		if got == model.StatusActive {
			t.Fatalf("callback re-activated a disabled credential: %v", statuses)
		}
	}
	// 代码交换在提交之前完成，说明测试确实走到了提交窗口而不是更早的绑定校验。
	if _, codeExchanges, _, _ := h.provider.counts(); codeExchanges != 1 {
		t.Fatalf("expected the code exchange before the commit, got %d", codeExchanges)
	}
}

// TestRefreshCommitCASRejectsDisableInCommitWindow 覆盖刷新路径的同一竞态：
// 管理员在提交窗口内停用，刷新不得写入新版本，也不得失效许可。
func TestRefreshCommitCASRejectsDisableInCommitWindow(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)
	h.useCAS(disableForTest)

	res, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{Force: true})
	requireConflictCode(t, err, CodeCredentialChanged)
	if res.Refreshed {
		t.Fatalf("rejected commit must not report a refresh: %+v", res)
	}
	if res.Status != model.StatusDisabled || res.Version != 1 {
		t.Fatalf("refresh conflict must report the administrator record: %+v", res)
	}
	version, commits, status, statuses := h.store.snapshot()
	if commits != 0 || version != 1 || status != model.StatusDisabled {
		t.Fatalf("disable during refresh must stop the commit: version=%d commits=%d status=%s", version, commits, status)
	}
	if got := h.store.leasesRevoked(); got != 0 {
		t.Fatalf("rejected commit must not revoke leases, got %d", got)
	}
	for _, got := range statuses {
		if got == model.StatusActive {
			t.Fatalf("refresh re-activated a disabled credential: %v", statuses)
		}
	}
	if _, _, refreshes, _ := h.provider.counts(); refreshes != 1 {
		t.Fatalf("upstream refresh happens before the commit; got %d", refreshes)
	}
	current := h.store.version(t, 1)
	if access, _ := current.Field(FieldAccessToken); !access.EqualString("stale-access") {
		t.Fatalf("rejected refresh must keep the stored combination")
	}
}

// TestCallbackCommitLoadFailureAbortsBeforeWrite 覆盖提交前第二次读取失败：
// 必须中止提交（不写版本），并留下可见的恢复状态。
func TestCallbackCommitLoadFailureAbortsBeforeWrite(t *testing.T) {
	h := newHarness(t, 300, nil)
	auth, err := h.manager.BeginAuthorization(t.Context(), h.store.cred.ID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	code, state := h.authorize(t, auth.URL)
	// 读取序列：begin 一次，CompleteAuthorization 的快照一次，提交前核对一次。
	// 让提交前的读取失败：不能用未知状态继续写入。
	h.store.mu.Lock()
	h.store.loadErr = errors.New("controlled read failure")
	h.store.failLoadAt = 3
	h.store.mu.Unlock()

	res, err := h.manager.CompleteAuthorization(t.Context(), h.store.cred.ID, state, code)
	if ClassOf(err) != ClassRecovery {
		t.Fatalf("commit read failure must require recovery, got %v", err)
	}
	if !res.RecoveryRequired {
		t.Fatalf("result must be visible as recovery_required: %+v", res)
	}
	version, commits, status, _ := h.store.snapshot()
	if commits != 0 || version != 1 {
		t.Fatalf("read failure must not write a version: version=%d commits=%d", version, commits)
	}
	if status == model.StatusActive {
		t.Fatalf("failed commit must not leave the credential active")
	}
	if status != model.StatusRecovery {
		t.Fatalf("upstream rotated tokens without a local commit; status = %s", status)
	}
}

// TestCallbackFallbackCommitPreservesDisableInCommitWindow 覆盖 Store 没有 CAS 能力
// 时的回退流程：窗口内的并行写仍可能写入版本，但绝不重新激活管理员停用的凭证。
func TestCallbackFallbackCommitPreservesDisableInCommitWindow(t *testing.T) {
	h := newHarness(t, 300, nil)
	auth, err := h.manager.BeginAuthorization(t.Context(), h.store.cred.ID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	code, state := h.authorize(t, auth.URL)
	h.injectBeforeCommit(disableForTest)

	res, err := h.manager.CompleteAuthorization(t.Context(), h.store.cred.ID, state, code)
	requireConflictCode(t, err, CodeCredentialChanged)
	version, commits, status, statuses := h.store.snapshot()
	if commits != 1 || version != 2 {
		t.Fatalf("fallback cannot reject the write, expected a detected conflict post-commit: version=%d commits=%d", version, commits)
	}
	if status != model.StatusDisabled {
		t.Fatalf("administrator status was overwritten: %s", status)
	}
	for _, got := range statuses {
		if got == model.StatusActive {
			t.Fatalf("fallback re-activated a disabled credential: %v", statuses)
		}
	}
	if res.Status != model.StatusDisabled || res.Version != 2 {
		t.Fatalf("conflict must report the preserved status and committed version: %+v", res)
	}
}

// TestCallbackCASReactivatesUntouchedRevokedCredential 确认 CAS 路径不过度收紧：
// 发起登录时已是 revoked、窗口内无人改动，重新登录仍可恢复 active。
func TestCallbackCASReactivatesUntouchedRevokedCredential(t *testing.T) {
	h := newHarness(t, 300, nil)
	h.store.mu.Lock()
	h.store.cred.Status = model.StatusRevoked
	h.store.cred.Revision++
	h.store.mu.Unlock()
	h.useCAS(nil)

	res, _ := h.login(t)
	if res.Status != model.StatusActive {
		t.Fatalf("untouched revoked credential must be reactivated, got %s", res.Status)
	}
	if version, commits, status, _ := h.store.snapshot(); version != 2 || commits != 1 || status != model.StatusActive {
		t.Fatalf("unexpected store state: version=%d commits=%d status=%s", version, commits, status)
	}
}

// TestRefreshCommitCASAdvancesAndRevokesLeases 覆盖 CAS 成功路径：版本推进一次，
// 旧许可失效。
func TestRefreshCommitCASAdvancesAndRevokesLeases(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newHarness(t, 300, &past)
	h.useCAS(nil)

	res, err := h.manager.Refresh(t.Context(), h.store.cred.ID, RefreshOptions{Force: true})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !res.Refreshed || res.Version != 2 || res.Status != model.StatusActive {
		t.Fatalf("unexpected refresh result: %+v", res)
	}
	if got := h.store.leasesRevoked(); got != 1 {
		t.Fatalf("version switch must revoke leases, got %d", got)
	}
	if version, commits, status, _ := h.store.snapshot(); version != 2 || commits != 1 || status != model.StatusActive {
		t.Fatalf("unexpected store state: version=%d commits=%d status=%s", version, commits, status)
	}
}

// TestUnboundPendingLoginKeepsLegacyBehavior 覆盖没有登记绑定的旧调用点：
// 回调照旧完成提交，不受绑定校验影响。
func TestUnboundPendingLoginKeepsLegacyBehavior(t *testing.T) {
	h := newHarness(t, 300, nil)
	// 旧调用点直接通过 Service.Begin 发起，不登记发起时刻的记录状态。
	auth, err := h.manager.Service.Begin(h.cfg, h.store.cred.ID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	code, state := h.authorize(t, auth.URL)
	if h.manager.Service.Pending == nil {
		t.Fatalf("pending store must be initialized")
	}
	res, err := h.manager.CompleteAuthorization(t.Context(), h.store.cred.ID, state, code)
	if err != nil {
		t.Fatalf("legacy callback: %v", err)
	}
	if !res.Refreshed || res.Version != 2 || res.Status != model.StatusActive {
		t.Fatalf("legacy callback must commit as before: %+v", res)
	}
}
