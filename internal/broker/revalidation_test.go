package broker_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/store"
)

// hookSource 在取值时执行一次回调，用来模拟「授权判定之后、交付之前」发生撤销、
// 停用或轮换。真实系统里这段窗口由 Touch ID 等待或网络往返构成。
type hookSource struct {
	inner  *broker.MemorySource
	onRead func()
	once   sync.Once
}

func (h *hookSource) Materialize(ctx context.Context, credentialID string, version int) (model.CredentialVersion, error) {
	if h.onRead != nil {
		h.once.Do(h.onRead)
	}
	return h.inner.Materialize(ctx, credentialID, version)
}

func (h *hookSource) Locked() bool { return h.inner.Locked() }

// newHookFixture 用可插入回调的 Source 构造 Broker。
func newHookFixture(t *testing.T) (*fixture, *hookSource) {
	t.Helper()
	f := newFixture(t)
	hook := &hookSource{inner: f.src}
	f.br = broker.New(f.st, hook, broker.Options{
		SessionTTL: time.Hour, MaxLeaseDuration: 10 * time.Minute, CacheDuration: time.Minute, Now: f.clock.now,
	})
	return f, hook
}

// 交付前重校验：授权判定后撤销授权，本次用钥不得返回真实值。
func TestAuthorizeRejectsGrantRevokedDuringDelivery(t *testing.T) {
	f, hook := newHookFixture(t)
	ctx := context.Background()
	_, token, err := f.br.CreateSession(ctx, f.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	hook.onRead = func() {
		if err := f.st.UpdateGrantStatus(ctx, f.grantID, model.StatusRevoked, 0); err != nil {
			t.Errorf("revoke grant: %v", err)
		}
	}
	authz, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy})
	if err == nil {
		t.Fatalf("authorization must fail when the grant is revoked before delivery, got lease %s", authz.Lease.ID)
	}
	if model.CodeOf(err) != model.CodeUseNotAllowed {
		t.Fatalf("expected USE_NOT_ALLOWED, got %v", err)
	}
	if n := f.br.ActiveLeaseCount(); n != 0 {
		t.Fatalf("no lease may be registered after a failed revalidation, got %d", n)
	}
}

// 交付前重校验：授权判定后轮换凭证，本次用钥不得交付旧版本。
func TestAuthorizeRejectsRotationDuringDelivery(t *testing.T) {
	f, hook := newHookFixture(t)
	ctx := context.Background()
	_, token, err := f.br.CreateSession(ctx, f.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	hook.onRead = func() {
		rec := storeVersionRecord(f.credID)
		if _, err := f.st.ActivateVersion(ctx, f.credID, &rec); err != nil {
			t.Errorf("rotate credential: %v", err)
		}
	}
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err == nil {
		t.Fatal("authorization must not deliver the old version after rotation")
	} else if model.CodeOf(err) != model.CodeCredentialUnavailable {
		t.Fatalf("expected CREDENTIAL_UNAVAILABLE, got %v", err)
	}
}

// 交付前重校验：授权判定后锁库，本次用钥不得继续。
func TestAuthorizeRejectsLockDuringDelivery(t *testing.T) {
	f, hook := newHookFixture(t)
	ctx := context.Background()
	_, token, err := f.br.CreateSession(ctx, f.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	hook.onRead = func() { f.br.Lock(ctx) }
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err == nil {
		t.Fatal("authorization must not continue after the vault was locked")
	} else if model.CodeOf(err) != model.CodeVaultLocked {
		t.Fatalf("expected VAULT_LOCKED, got %v", err)
	}
}

// once 策略：有会话的验证只在该会话内复用；没有会话的验证是一次性交换。
func TestOnceVerificationScope(t *testing.T) {
	auth := broker.NewAuthenticator(nil, nil)
	cache := auth.Cache()
	policy := model.AuthPolicy{Kind: model.AuthOnce}
	base := broker.VerifyRequest{PrincipalID: "p1", GrantID: "g1", Mode: model.ModeProxy, Policy: policy}

	if _, err := auth.RecordVerification(withSession(base, "s1"), "biometric"); err != nil {
		t.Fatalf("once verification with a session id must be accepted: %v", err)
	}
	// 另一个会话不能消费这条记录，也不会把它用掉。
	if entry, ok := cache.TakeMatching("p1", "g1", string(model.ModeProxy), func(e broker.AuthEntry) bool {
		return e.SessionID == "s2"
	}); ok {
		t.Fatalf("verification must not be reusable across sessions, got %+v", entry)
	}
	if _, ok := cache.Look("p1", "g1", string(model.ModeProxy)); !ok {
		t.Fatal("a mismatched session must not consume the record")
	}
	if _, ok := cache.TakeMatching("p1", "g1", string(model.ModeProxy), func(e broker.AuthEntry) bool {
		return e.SessionID == "s1"
	}); !ok {
		t.Fatal("the recording session must be able to consume its verification")
	}

	// 没有会话的预验证：只能消费一次，任何会话都可以，但第二次不再有效。
	auth2 := broker.NewAuthenticator(nil, nil)
	if _, err := auth2.RecordVerification(base, "password"); err != nil {
		t.Fatalf("session-less once verification must be recorded as a one-time exchange: %v", err)
	}
	accept := func(broker.AuthEntry) bool { return true }
	if _, ok := auth2.Cache().TakeMatching("p1", "g1", string(model.ModeProxy), accept); !ok {
		t.Fatal("the one-time exchange must be usable once")
	}
	if _, ok := auth2.Cache().TakeMatching("p1", "g1", string(model.ModeProxy), accept); ok {
		t.Fatal("the one-time exchange must not be reusable")
	}
}

// 中心裁定约束最终取值：本机轮换领先于中心时拒绝，避免绕过中心策略。
func TestGatePermitBlocksLocalRotationAheadOfCenter(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rec := storeVersionRecord(f.credID)
	if _, err := f.st.ActivateVersion(ctx, f.credID, &rec); err != nil {
		t.Fatal(err)
	}
	f.br = broker.New(f.st, f.src, broker.Options{
		SessionTTL: time.Hour, MaxLeaseDuration: 10 * time.Minute, CacheDuration: time.Minute, Now: f.clock.now,
		Gate: &stubGate{permit: broker.Permit{PrincipalID: f.userID, BindingID: f.binding, CredentialID: f.credID, Mode: model.ModeProxy, CredentialVersion: 1}},
	})
	_, token, err := f.br.CreateSession(ctx, f.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err == nil {
		t.Fatal("a local rotation ahead of the center must block the use")
	} else if model.CodeOf(err) != model.CodeControlUnavailable {
		t.Fatalf("expected CONTROL_UNAVAILABLE, got %v", err)
	}
}

// 中心记录的版本比本机新时（轮换尚未下发到这台设备）不阻塞用钥，
// 但交付的仍是本机当前版本，且不得声称使用了更新的版本。
func TestGatePermitCenterVersionAheadStillUsesLocalVersion(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.br = broker.New(f.st, f.src, broker.Options{
		SessionTTL: time.Hour, MaxLeaseDuration: 10 * time.Minute, CacheDuration: time.Minute, Now: f.clock.now,
		Gate: &stubGate{permit: broker.Permit{PrincipalID: f.userID, BindingID: f.binding, CredentialID: f.credID, Mode: model.ModeProxy, CredentialVersion: 7}},
	})
	_, token, err := f.br.CreateSession(ctx, f.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	authz, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy})
	if err != nil {
		t.Fatalf("a center version ahead of the local one must not block the use: %v", err)
	}
	if authz.Lease.CredentialVersion != 1 {
		t.Fatalf("the lease must carry the materialized local version, got %d", authz.Lease.CredentialVersion)
	}
	// 许可的 credential_id 是中心侧逻辑引用，与本机 ID 不同也不影响用钥。
	other := newFixture(t)
	other.br = broker.New(other.st, other.src, broker.Options{
		SessionTTL: time.Hour, MaxLeaseDuration: 10 * time.Minute, CacheDuration: time.Minute, Now: other.clock.now,
		Gate: &stubGate{permit: broker.Permit{PrincipalID: other.userID, BindingID: other.binding, CredentialID: "cred_shared", Mode: model.ModeProxy, CredentialVersion: 1}},
	})
	_, token2, err := other.br.CreateSession(ctx, other.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.br.Authorize(ctx, broker.Request{Token: token2, BindingID: other.binding, Mode: model.ModeProxy}); err != nil {
		t.Fatalf("a center-side credential reference must not block the use: %v", err)
	}
}

// 中心裁定可以收紧许可期限。
func TestGatePermitShortensLease(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.br = broker.New(f.st, f.src, broker.Options{
		SessionTTL: time.Hour, MaxLeaseDuration: 10 * time.Minute, CacheDuration: time.Minute, Now: f.clock.now,
		Gate: &stubGate{permit: broker.Permit{PrincipalID: f.userID, BindingID: f.binding, CredentialID: f.credID, Mode: model.ModeProxy, CredentialVersion: 1, MaxLeaseDuration: 5 * time.Second}},
	})
	_, token, err := f.br.CreateSession(ctx, f.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	authz, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy})
	if err != nil {
		t.Fatal(err)
	}
	if limit := f.clock.t.Add(5 * time.Second); authz.Lease.UseLeaseExpiresAt.After(limit) {
		t.Fatalf("center permit must cap the lease at %s, got %s", limit, authz.Lease.UseLeaseExpiresAt)
	}
}

// 会话关闭后必须立即释放运行时记录。
func TestCloseSessionDropsRuntimeState(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sess, token, err := f.br.CreateSession(ctx, f.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err != nil {
		t.Fatal(err)
	}
	if f.br.ActiveLeaseCount() == 0 {
		t.Fatal("expected an active lease")
	}
	if err := f.br.CloseSession(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.br.ActiveLeaseCount(); n != 0 {
		t.Fatalf("closing a session must drop its leases, got %d", n)
	}
	if _, err := f.br.SessionByToken(token); err == nil {
		t.Fatal("closed session token must be invalid")
	}
}

// stubGate 是固定裁定的中心替身。
type stubGate struct {
	permit broker.Permit
	err    error
	query  broker.UseQuery
}

func (g *stubGate) CheckUse(_ context.Context, q broker.UseQuery) (broker.Permit, error) {
	g.query = q
	return g.permit, g.err
}

func withSession(req broker.VerifyRequest, sessionID string) broker.VerifyRequest {
	req.SessionID = sessionID
	return req
}

// storeVersionRecord 构造一份可以插入的第二版本记录（内存存储不校验密文内容）。
func storeVersionRecord(credentialID string) store.VersionRecord {
	return store.VersionRecord{
		CredentialID: credentialID, Version: 2,
		Ciphertext: []byte("c"), Nonce: []byte("n"), WrappedDEK: []byte("d"), WrapNonce: []byte("w"),
		CryptoVersion: 1, CreatedAt: time.Now().UTC(),
	}
}

// 交付前重校验同样覆盖改绑：Memory 后端更新 Binding 时 revision 会前进，
// 因此旧目标与新凭证的组合不能成立。
func TestAuthorizeRejectsRebindDuringDelivery(t *testing.T) {
	f, hook := newHookFixture(t)
	ctx := context.Background()
	_, token, err := f.br.CreateSession(ctx, f.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.st.GetBinding(ctx, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	hook.onRead = func() {
		rebound, berr := f.st.GetBinding(ctx, f.binding)
		if berr != nil {
			t.Errorf("read binding: %v", berr)
			return
		}
		rebound.UpstreamOrigin = "http://127.0.0.1:8"
		if perr := f.st.PutBinding(ctx, rebound); perr != nil {
			t.Errorf("rebind: %v", perr)
		}
	}
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err == nil {
		t.Fatal("a rebind during delivery must block the use")
	} else if model.CodeOf(err) != model.CodeBindingDisabled {
		t.Fatalf("expected BINDING_DISABLED, got %v", err)
	}
	after, err := f.st.GetBinding(ctx, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision <= before.Revision {
		t.Fatalf("PutBinding must advance the revision (%d -> %d)", before.Revision, after.Revision)
	}
}

// 定期清理在没有新用钥请求时也释放过期记录。
func TestPruneExpiredDropsStaleRuntimeState(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sess, token, err := f.br.CreateSession(ctx, f.userID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.br.Authorize(ctx, broker.Request{Token: token, BindingID: f.binding, Mode: model.ModeProxy}); err != nil {
		t.Fatal(err)
	}
	if f.br.ActiveLeaseCount() == 0 {
		t.Fatal("expected an active lease before pruning")
	}
	// 时间推进到会话与许可都过期之后。
	f.clock.t = f.clock.t.Add(2 * time.Hour)
	f.br.PruneExpired()
	if n := f.br.ActiveLeaseCount(); n != 0 {
		t.Fatalf("expired leases must be pruned, got %d", n)
	}
	if _, err := f.br.SessionByToken(token); err == nil {
		t.Fatal("expired session must be pruned and rejected")
	}
	_ = sess
}
