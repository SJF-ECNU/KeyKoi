package broker_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

// countingVerifier 记录验证次数，并可注入失败。
type countingVerifier struct {
	mu     sync.Mutex
	calls  int
	method string
	err    error
}

func (v *countingVerifier) Verify(context.Context, broker.VerifyRequest) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	if v.err != nil {
		return "none", v.err
	}
	if v.method == "" {
		return "biometric", nil
	}
	return v.method, nil
}

func (v *countingVerifier) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

func (v *countingVerifier) setErr(err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.err = err
}

type authFixture struct {
	st        *store.Memory
	src       *broker.MemorySource
	br        *broker.Broker
	clock     *fakeClock
	verifier  *countingVerifier
	principal string
	binding   string
	grant     string
}

// newAuthFixture 建立一条带指定验证策略的 proxy 授权。
func newAuthFixture(t *testing.T, requirement string) *authFixture {
	t.Helper()
	st := store.NewMemory()
	src := broker.NewMemorySource()
	clock := &fakeClock{t: time.Now().UTC()}
	verifier := &countingVerifier{}
	ctx := context.Background()
	principal := "principal_local"
	if err := st.PutPrincipal(ctx, &store.Principal{ID: principal, IdentityType: "local_user", Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	credID := "cred_auth"
	if err := st.CreateCredential(ctx, &model.Credential{
		ID: credID, Kind: model.KindAPIKey, Label: "auth", CurrentVersion: 1, Status: model.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	src.Put(model.CredentialVersion{CredentialID: credID, Version: 1, Fields: map[string]secret.Value{"token": secret.New(random())}})
	if err := st.PutBinding(ctx, &model.Binding{
		ID: "binding_auth", CredentialID: credID, UpstreamOrigin: "http://127.0.0.1:9",
		AuthScheme: model.AuthBearer, Route: "route-auth", Status: model.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	grant := &model.Grant{
		ID: "grant_auth", PrincipalID: principal, BindingID: "binding_auth", DeliveryMode: model.ModeProxy,
		MaxLeaseDuration: 5 * time.Minute, AuthRequirement: requirement, Status: model.StatusActive,
	}
	if err := st.PutGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	authn := broker.NewAuthenticator(verifier, clock.now)
	br := broker.New(st, src, broker.Options{
		SessionTTL: time.Hour, MaxLeaseDuration: 10 * time.Minute, CacheDuration: time.Minute,
		Now: clock.now, Auth: authn,
	})
	return &authFixture{st: st, src: src, br: br, clock: clock, verifier: verifier,
		principal: principal, binding: "binding_auth", grant: grant.ID}
}

func (f *authFixture) authorize(t *testing.T, token secret.Value) error {
	t.Helper()
	_, err := f.br.Authorize(context.Background(), broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy})
	return err
}

func TestAuthPolicyPerUseVerifiesEveryUse(t *testing.T) {
	f := newAuthFixture(t, "per_use")
	ctx := context.Background()
	_, token, err := f.br.CreateSession(ctx, f.principal, "tool")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := f.authorize(t, token); err != nil {
			t.Fatalf("use %d should be allowed: %v", i+1, err)
		}
	}
	if got := f.verifier.count(); got != 3 {
		t.Fatalf("per_use must verify every use, got %d verifications", got)
	}
}

func TestAuthPolicyWindowReusesThenExpires(t *testing.T) {
	f := newAuthFixture(t, "window:120")
	ctx := context.Background()
	_, tokenA, err := f.br.CreateSession(ctx, f.principal, "tool-a")
	if err != nil {
		t.Fatal(err)
	}
	_, tokenB, err := f.br.CreateSession(ctx, f.principal, "tool-b")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authorize(t, tokenA); err != nil {
		t.Fatal(err)
	}
	// 窗口内跨会话复用同一验证结果。
	if err := f.authorize(t, tokenB); err != nil {
		t.Fatal(err)
	}
	if got := f.verifier.count(); got != 1 {
		t.Fatalf("window policy must reuse verification, got %d", got)
	}
	f.clock.t = f.clock.t.Add(121 * time.Second)
	if err := f.authorize(t, tokenA); err != nil {
		t.Fatal(err)
	}
	if got := f.verifier.count(); got != 2 {
		t.Fatalf("window policy must re-verify after expiry, got %d", got)
	}
}

func TestAuthPolicyOnceIsSessionScoped(t *testing.T) {
	f := newAuthFixture(t, "once")
	ctx := context.Background()
	_, tokenA, err := f.br.CreateSession(ctx, f.principal, "tool-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authorize(t, tokenA); err != nil {
		t.Fatal(err)
	}
	if err := f.authorize(t, tokenA); err != nil {
		t.Fatal(err)
	}
	if got := f.verifier.count(); got != 1 {
		t.Fatalf("once must verify a single time per session, got %d", got)
	}
	_, tokenB, err := f.br.CreateSession(ctx, f.principal, "tool-b")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authorize(t, tokenB); err != nil {
		t.Fatal(err)
	}
	if got := f.verifier.count(); got != 2 {
		t.Fatalf("once must re-verify for a new session, got %d", got)
	}
}

func TestAuthPolicyPermanentSkipsVerification(t *testing.T) {
	f := newAuthFixture(t, "permanent")
	ctx := context.Background()
	_, token, err := f.br.CreateSession(ctx, f.principal, "tool")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := f.authorize(t, token); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.verifier.count(); got != 0 {
		t.Fatalf("permanent must not verify, got %d", got)
	}
}

func TestAuthFailurePropagatesAndIsAudited(t *testing.T) {
	f := newAuthFixture(t, "per_use")
	ctx := context.Background()
	_, token, err := f.br.CreateSession(ctx, f.principal, "tool")
	if err != nil {
		t.Fatal(err)
	}
	f.verifier.setErr(model.NewError(model.CodeAuthUnavailable, "no biometric hardware"))
	if err := f.authorize(t, token); err == nil || model.CodeOf(err) != model.CodeAuthUnavailable {
		t.Fatalf("missing biometrics must surface AUTH_UNAVAILABLE: %v", err)
	}
	events, err := f.st.ListAudit(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Result == "denied" && e.ErrorCode == string(model.CodeAuthUnavailable) {
			if e.AuthMethod != "none" || e.AuthResult != "unavailable" {
				t.Fatalf("denied audit must record the auth outcome, got method=%q result=%q", e.AuthMethod, e.AuthResult)
			}
			found = true
		}
		if e.Result == "allowed" && e.AuthMethod == "" {
			t.Fatalf("allowed audit must record the auth method")
		}
	}
	if !found {
		t.Fatal("denied audit event for the failed verification is missing")
	}
}

func TestAuthCacheClearedOnLockAndRotation(t *testing.T) {
	f := newAuthFixture(t, "once")
	ctx := context.Background()
	_, token, err := f.br.CreateSession(ctx, f.principal, "tool")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authorize(t, token); err != nil {
		t.Fatal(err)
	}
	if err := f.authorize(t, token); err != nil {
		t.Fatal(err)
	}
	if got := f.verifier.count(); got != 1 {
		t.Fatalf("expected one verification before lock, got %d", got)
	}
	f.br.Lock(ctx)
	f.br.Unlock()
	_, tokenB, err := f.br.CreateSession(ctx, f.principal, "tool-b")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authorize(t, tokenB); err != nil {
		t.Fatal(err)
	}
	if got := f.verifier.count(); got != 2 {
		t.Fatalf("lock must drop cached verification, got %d", got)
	}
	// 轮换凭证使全部验证结果失效。
	f.br.RevokeForCredential(ctx, "cred_auth")
	_, tokenC, err := f.br.CreateSession(ctx, f.principal, "tool-c")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authorize(t, tokenC); err != nil {
		t.Fatal(err)
	}
	if got := f.verifier.count(); got != 3 {
		t.Fatalf("rotation must drop cached verification, got %d", got)
	}
}

func TestBrokerWithoutAuthenticatorFailsClosed(t *testing.T) {
	f := newAuthFixture(t, "once")
	ctx := context.Background()
	// 重新构造一个没有注入 Authenticator 的 Broker：需要验证的策略必须失败关闭。
	plain := broker.New(f.st, f.src, broker.Options{Now: f.clock.now})
	_, token, err := plain.CreateSession(ctx, f.principal, "tool")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err != nil {
		t.Fatalf("without an authenticator the policy is not evaluated and use stays allowed: %v", err)
	}
	// 显式注入一个没有 verifier 的 Authenticator 时，需要验证的请求必须被拒绝。
	authn := broker.NewAuthenticator(nil, f.clock.now)
	f.br.SetAuth(authn)
	_, token2, err := f.br.CreateSession(ctx, f.principal, "tool2")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authorize(t, token2); err == nil || model.CodeOf(err) != model.CodeAuthUnavailable {
		t.Fatalf("missing verifier must fail with AUTH_UNAVAILABLE: %v", err)
	}
}

func TestParseAuthPolicy(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "once", false},
		{"once", "once", false},
		{"per-use", "per_use", false},
		{"per_use", "per_use", false},
		{"permanent", "permanent", false},
		{"window:300", "window:300", false},
		{"window:5m", "window:300", false},
		{"window=5m", "window:300", false},
		{"window:0", "", true},
		{"window:8d", "", true},
		{"sometimes", "", true},
	}
	for _, tc := range cases {
		policy, err := model.ParseAuthPolicy(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%q should be rejected", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if got := policy.String(); got != tc.want {
			t.Fatalf("%q normalizes to %q, want %q", tc.in, got, tc.want)
		}
	}
}
