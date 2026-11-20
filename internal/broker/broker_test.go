package broker_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

type fixture struct {
	st      *store.Memory
	src     *broker.MemorySource
	br      *broker.Broker
	clock   *fakeClock
	credID  string
	binding string
	grantID string
	adminID string
	userID  string
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := store.NewMemory()
	src := broker.NewMemorySource()
	clock := &fakeClock{t: time.Now().UTC()}
	ctx := context.Background()
	adminID, userID := "principal_admin", "principal_local"
	if err := st.PutPrincipal(ctx, &store.Principal{ID: adminID, IdentityType: "local_user", Status: model.StatusActive, Admin: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPrincipal(ctx, &store.Principal{ID: userID, IdentityType: "local_user", Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	credID := "cred_1"
	src.Put(model.CredentialVersion{CredentialID: credID, Version: 1, Fields: map[string]secret.Value{"token": secret.New(random())}})
	if err := st.CreateCredential(ctx, &model.Credential{ID: credID, Kind: model.KindAPIKey, Label: "l", CurrentVersion: 1, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	expiry := clock.t.Add(30 * time.Minute)
	if err := st.CreateCredentialWithVersion(ctx, &model.Credential{ID: "cred_expiring", Kind: model.KindAPIKey, Label: "e", CurrentVersion: 1, Status: model.StatusActive, ProviderExpiresAt: &expiry},
		&store.VersionRecord{CredentialID: "cred_expiring", Version: 1, ProviderExpiresAt: &expiry}); err != nil {
		t.Fatal(err)
	}
	src.Put(model.CredentialVersion{CredentialID: "cred_expiring", Version: 1, Fields: map[string]secret.Value{"token": secret.New(random())}, ProviderExpiresAt: &expiry})
	binding := &model.Binding{ID: "binding_1", CredentialID: credID, UpstreamOrigin: "http://127.0.0.1:9", AuthScheme: model.AuthBearer, Route: "route1", Status: model.StatusActive}
	if err := st.PutBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	grant := &model.Grant{ID: "grant_proxy", PrincipalID: userID, BindingID: binding.ID, DeliveryMode: model.ModeProxy, MaxLeaseDuration: 5 * time.Minute, Status: model.StatusActive}
	if err := st.PutGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	br := broker.New(st, src, broker.Options{SessionTTL: time.Hour, MaxLeaseDuration: 10 * time.Minute, CacheDuration: time.Minute, Now: clock.now})
	return &fixture{st: st, src: src, br: br, clock: clock, credID: credID, binding: binding.ID, grantID: grant.ID, adminID: adminID, userID: userID}
}

func TestDeliveryModeSeparation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, token, err := f.br.CreateSession(ctx, f.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	// proxy 许可不能升级为 runtime_delivery。
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeRuntimeDelivery}); err == nil || model.CodeOf(err) != model.CodeUseNotAllowed {
		t.Fatalf("proxy must not be upgraded: %v", err)
	}
	// 同模式通过。
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err != nil {
		t.Fatalf("proxy grant should authorize: %v", err)
	}
}

func TestLeaseBoundedByGrantSessionAndProvider(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// 短许可的凭证 + 长许可的 grant。
	short := f.clock.t.Add(2 * time.Minute)
	if err := f.st.CreateCredentialWithVersion(ctx,
		&model.Credential{ID: "cred_short", Kind: model.KindAPIKey, Label: "short", CurrentVersion: 1, Status: model.StatusActive, ProviderExpiresAt: &short},
		&store.VersionRecord{CredentialID: "cred_short", Version: 1, ProviderExpiresAt: &short}); err != nil {
		t.Fatal(err)
	}
	f.src.Put(model.CredentialVersion{CredentialID: "cred_short", Version: 1, Fields: map[string]secret.Value{"token": secret.New(random())}, ProviderExpiresAt: &short})
	if err := f.st.PutBinding(ctx, &model.Binding{ID: "binding_expiring", CredentialID: "cred_short", UpstreamOrigin: "http://127.0.0.1:9", AuthScheme: model.AuthBearer, Route: "route2", Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.PutGrant(ctx, &model.Grant{ID: "grant_long", PrincipalID: f.userID, BindingID: "binding_expiring", DeliveryMode: model.ModeProxy, MaxLeaseDuration: time.Hour, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	_, token, err := f.br.CreateSession(ctx, f.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	authz, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: "binding_expiring", Mode: model.ModeProxy})
	if err != nil {
		t.Fatal(err)
	}
	if authz.Lease.UseLeaseExpiresAt.After(short.Add(time.Second)) {
		t.Fatalf("lease must not outlive provider expiry: lease=%v provider=%v", authz.Lease.UseLeaseExpiresAt, short)
	}
	if authz.Lease.ProviderCredentialExpiresAt == nil || !authz.Lease.ProviderCredentialExpiresAt.Equal(short) {
		t.Fatalf("provider expiry must be recorded separately")
	}
	if !authz.Lease.CacheExpiresAt.Before(authz.Lease.UseLeaseExpiresAt) && !authz.Lease.CacheExpiresAt.Equal(authz.Lease.UseLeaseExpiresAt) {
		t.Fatalf("cache expiry must not exceed lease")
	}
}

func TestAdminAndUsePermissionsSeparate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, userToken, err := f.br.CreateSession(ctx, f.userID, "tool")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.br.RequireAdmin(ctx, userToken); err == nil {
		t.Fatal("normal use session must not gain management rights")
	}
	_, adminToken, err := f.br.CreateSession(ctx, f.adminID, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.br.RequireAdmin(ctx, adminToken); err != nil {
		t.Fatalf("admin session should pass: %v", err)
	}
}

func TestReferenceAndAddressAloneNotEnough(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// 只给引用/ID 而没有会话令牌。
	if _, err := f.br.Authorize(ctx, broker.Request{Token: secret.New(""), BindingID: f.binding, Mode: model.ModeProxy}); err == nil {
		t.Fatal("empty token must be rejected")
	}
	if _, err := f.br.Authorize(ctx, broker.Request{Token: secret.New("kks_" + random()), BindingID: f.binding, Mode: model.ModeProxy}); err == nil {
		t.Fatal("forged token must be rejected")
	}
}

func TestRevocationAndRotationBlockReuse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sess, token, err := f.br.CreateSession(ctx, f.userID, "tool")
	if err != nil {
		t.Fatal(err)
	}
	authz, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy})
	if err != nil {
		t.Fatal(err)
	}
	// 撤销 grant：下一次授权必须拒绝。
	if err := f.st.UpdateGrantStatus(ctx, f.grantID, model.StatusRevoked, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err == nil || model.CodeOf(err) != model.CodeUseNotAllowed {
		t.Fatalf("revoked grant must block new use: %v", err)
	}
	// 版本切换使既有许可失效。
	if err := f.st.UpdateGrantStatus(ctx, f.grantID, model.StatusActive, 0); err != nil {
		t.Fatal(err)
	}
	authz2, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy})
	if err != nil {
		t.Fatal(err)
	}
	if n := f.br.RevokeForCredential(ctx, f.credID); n == 0 {
		t.Fatal("rotation must revoke associated leases")
	}
	if _, err := f.br.Lease(authz2.Lease.ID); err == nil {
		t.Fatal("revoked lease must not resolve")
	}
	// 会话关闭后令牌失效。
	if err := f.br.CloseSession(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err == nil || model.CodeOf(err) != model.CodeSessionInvalid {
		t.Fatalf("closed session must be invalid: %v", err)
	}
	_ = authz
}

func TestLockBlocksNewUse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, token, err := f.br.CreateSession(ctx, f.userID, "tool")
	if err != nil {
		t.Fatal(err)
	}
	f.br.Lock(ctx)
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err == nil || model.CodeOf(err) != model.CodeVaultLocked {
		t.Fatalf("locked broker must reject: %v", err)
	}
	f.br.Unlock()
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err == nil {
		t.Fatal("old token must not revive after unlock")
	}
}

func TestAuditContainsNoSecrets(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, token, err := f.br.CreateSession(ctx, f.userID, "tool")
	if err != nil {
		t.Fatal(err)
	}
	authz, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy})
	if err != nil {
		t.Fatal(err)
	}
	tok := token.RevealString()
	secretVal := authz.Version.Fields["token"].RevealString()
	events, err := f.st.ListAudit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events")
	}
	for _, e := range events {
		if e.Detail == tok || e.Detail == secretVal {
			t.Fatal("audit must not contain tokens or secrets")
		}
	}
	// 审计至少记录一次允许结果与一次会话创建。
	var allowed, created bool
	for _, e := range events {
		if e.Result == "allowed" {
			allowed = true
		}
		if e.Result == "created" {
			created = true
		}
	}
	if !allowed || !created {
		t.Fatalf("missing audit coverage: %+v", events)
	}
}

func random() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
