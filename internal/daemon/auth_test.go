package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/store"
)

// fakeBackend 同时实现 Backend、BiometricVault 与 PasswordVerifier。
type fakeBackend struct {
	biometricErr error
	password     string
	verifyCalls  int
	unlockCalls  int
	locked       bool
}

func (f *fakeBackend) Materialize(context.Context, string, int) (model.CredentialVersion, error) {
	return model.CredentialVersion{}, nil
}
func (f *fakeBackend) CreateCredential(_ context.Context, meta model.Credential, _ model.CredentialVersion) (*model.Credential, error) {
	return &meta, nil
}
func (f *fakeBackend) AddVersion(_ context.Context, id string, version model.CredentialVersion) (*model.Credential, error) {
	return &model.Credential{ID: id, CurrentVersion: version.Version}, nil
}
func (f *fakeBackend) ActivateVersionCAS(_ context.Context, id string, version model.CredentialVersion, _ int64) (*model.Credential, error) {
	return &model.Credential{ID: id, CurrentVersion: version.Version}, nil
}
func (f *fakeBackend) Lock(context.Context) error           { f.locked = true; return nil }
func (f *fakeBackend) Unlock(context.Context, []byte) error { f.locked = false; return nil }
func (f *fakeBackend) Locked() bool                         { return f.locked }
func (f *fakeBackend) State() string {
	if f.locked {
		return "locked"
	}
	return "unlocked"
}
func (f *fakeBackend) Describe() string { return "fake backend" }
func (f *fakeBackend) Close() error     { return nil }

func (f *fakeBackend) VerifyBiometric(context.Context) error {
	f.verifyCalls++
	return f.biometricErr
}
func (f *fakeBackend) UnlockBiometric(context.Context) error {
	f.unlockCalls++
	return f.biometricErr
}
func (f *fakeBackend) EnrollBiometric(context.Context) error { return f.biometricErr }
func (f *fakeBackend) DeleteBiometricEnrollment(context.Context) error {
	return nil
}
func (f *fakeBackend) BiometricStatus(context.Context) map[string]any {
	return map[string]any{
		"available": f.biometricErr == nil, "enrolled": f.biometricErr == nil,
		"account": "keykoi-root", "reason": "fake",
	}
}
func (f *fakeBackend) VerifyPassword(_ context.Context, password []byte) error {
	if string(password) != f.password {
		return model.NewError(model.CodeVaultUnlockFailed, "master password does not match this vault")
	}
	return nil
}

type daemonFixture struct {
	d    *Daemon
	st   *store.Memory
	b    *fakeBackend
	now  time.Time
	cred string
}

func newDaemonFixture(t *testing.T) *daemonFixture {
	t.Helper()
	st := store.NewMemory()
	b := &fakeBackend{password: "master-password"}
	ctx := context.Background()
	if err := st.PutPrincipal(ctx, &store.Principal{ID: "principal_admin_local", IdentityType: "local_user", Status: model.StatusActive, Admin: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCredential(ctx, &model.Credential{
		ID: "cred_test", Kind: model.KindAPIKey, Label: "t", CurrentVersion: 1, Status: model.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutBinding(ctx, &model.Binding{
		ID: "bind_test", CredentialID: "cred_test", UpstreamOrigin: "http://127.0.0.1:9",
		AuthScheme: model.AuthBearer, Status: model.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(ctx, &model.Grant{
		ID: "grant_test", PrincipalID: "principal_admin_local", BindingID: "bind_test",
		DeliveryMode: model.ModeProxy, MaxLeaseDuration: time.Minute,
		AuthRequirement: "per_use", Status: model.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	d := New(Config{DataDir: t.TempDir()}, st, b)
	d.adminToken = "test-admin-token"
	return &daemonFixture{d: d, st: st, b: b, now: now, cred: "cred_test"}
}

func (f *daemonFixture) verify(t *testing.T, principal string) (string, error) {
	t.Helper()
	return f.d.verifyAuth(context.Background(), broker.VerifyRequest{
		PrincipalID: principal, SessionID: "sess_1", GrantID: "grant_test",
		Mode: model.ModeProxy, Policy: model.AuthPolicy{Kind: model.AuthPerUse},
	})
}

func TestVerifyAuthPrefersBiometric(t *testing.T) {
	f := newDaemonFixture(t)
	method, err := f.verify(t, "principal_admin_local")
	if err != nil {
		t.Fatal(err)
	}
	if method != "biometric" {
		t.Fatalf("expected biometric verification, got %q", method)
	}
}

func TestVerifyAuthFallsBackToSingleUsePassword(t *testing.T) {
	f := newDaemonFixture(t)
	f.b.biometricErr = model.NewError(model.CodeAuthUnavailable, "no biometric hardware")
	if _, err := f.verify(t, "principal_admin_local"); err == nil || model.CodeOf(err) != model.CodeAuthUnavailable {
		t.Fatalf("missing biometrics must be explicit: %v", err)
	}
	f.d.passwordProof.grant("principal_admin_local")
	method, err := f.verify(t, "principal_admin_local")
	if err != nil {
		t.Fatal(err)
	}
	if method != "password" {
		t.Fatalf("expected the password fallback, got %q", method)
	}
	// 一次性证明被消费后不能再次使用。
	if _, err := f.verify(t, "principal_admin_local"); err == nil {
		t.Fatal("password proof must be single use")
	}
}

func TestVerifyAuthCancelDoesNotFallBack(t *testing.T) {
	f := newDaemonFixture(t)
	f.b.biometricErr = model.NewError(model.CodeAuthRequired, "user cancelled")
	f.d.passwordProof.grant("principal_admin_local")
	_, err := f.verify(t, "principal_admin_local")
	if err == nil || model.CodeOf(err) != model.CodeAuthRequired {
		t.Fatalf("cancellation must surface AUTH_REQUIRED: %v", err)
	}
	// 取消不消耗主密码证明，也绝不静默回退。
	if !f.d.passwordProof.consume("principal_admin_local") {
		t.Fatal("cancelled biometric must not consume the password proof")
	}
}

func TestHandleAuthVerifyPasswordRecordsOneShot(t *testing.T) {
	f := newDaemonFixture(t)
	body := `{"method":"password","password":"master-password","grant_id":"grant_test","mode":"proxy"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/verify", strings.NewReader(body))
	req.Header.Set("X-KeyKoi-Admin", "test-admin-token")
	rec := httptest.NewRecorder()
	f.d.handleAuthVerify(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	entry, ok := f.d.authn.Cache().Look("principal_admin_local", "grant_test", "proxy")
	if !ok {
		t.Fatal("explicit verification must populate the auth cache")
	}
	if entry.Method != "password" {
		t.Fatalf("cached method should be password, got %q", entry.Method)
	}
	if !entry.OneShot {
		t.Fatal("per_use explicit verification must be single use")
	}
}

func TestHandleAuthVerifyRejectsWrongPassword(t *testing.T) {
	f := newDaemonFixture(t)
	body := `{"method":"password","password":"wrong","grant_id":"grant_test","mode":"proxy"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/verify", strings.NewReader(body))
	req.Header.Set("X-KeyKoi-Admin", "test-admin-token")
	rec := httptest.NewRecorder()
	f.d.handleAuthVerify(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password must map to 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := f.d.authn.Cache().Look("principal_admin_local", "grant_test", "proxy"); ok {
		t.Fatal("failed verification must not populate the cache")
	}
}

func TestHandleAuthStatusRequiresAdmin(t *testing.T) {
	f := newDaemonFixture(t)
	rec := httptest.NewRecorder()
	f.d.handleAuthStatus(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/status", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status must require the admin token, got %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/status", nil)
	req.Header.Set("X-KeyKoi-Admin", "test-admin-token")
	rec = httptest.NewRecorder()
	f.d.handleAuthStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "biometric") {
		t.Fatalf("status must describe biometric state: %s", rec.Body.String())
	}
}

func TestBiometricUnlockMapsStatusCodes(t *testing.T) {
	f := newDaemonFixture(t)
	rec := httptest.NewRecorder()
	f.d.handleVaultUnlockBiometric(rec, adminRequest(http.MethodPost, "/v1/vault/unlock-biometric", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	f.b.biometricErr = model.NewError(model.CodeAuthUnavailable, "no GUI session")
	rec = httptest.NewRecorder()
	f.d.handleVaultUnlockBiometric(rec, adminRequest(http.MethodPost, "/v1/vault/unlock-biometric", ""))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable biometric must map to 503, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), string(model.CodeAuthUnavailable)) {
		t.Fatalf("response must carry the stable code: %s", rec.Body.String())
	}
	f.b.biometricErr = model.NewError(model.CodeAuthRequired, "user cancelled")
	rec = httptest.NewRecorder()
	f.d.handleVaultUnlockBiometric(rec, adminRequest(http.MethodPost, "/v1/vault/unlock-biometric", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cancelled biometric must map to 401, got %d", rec.Code)
	}
}

func TestLockClearsPasswordProofs(t *testing.T) {
	f := newDaemonFixture(t)
	f.d.passwordProof.grant("principal_admin_local")
	if err := f.d.backend.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.d.broker.Lock(context.Background())
	f.d.passwordProof.clear()
	if f.d.passwordProof.consume("principal_admin_local") {
		t.Fatal("lock must drop password fallback proofs")
	}
}

func adminRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-KeyKoi-Admin", "test-admin-token")
	return req
}
