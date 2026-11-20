package store_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"keykoi/internal/model"
	"keykoi/internal/store"
)

func seedGrantTarget(t *testing.T, st *store.SQLite) {
	t.Helper()
	ctx := context.Background()
	if err := st.PutPrincipal(ctx, &store.Principal{ID: "principal_test", IdentityType: "local_user", Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCredential(ctx, &model.Credential{ID: "cred_test", Kind: model.KindAPIKey, Label: "t", CurrentVersion: 1, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutBinding(ctx, &model.Binding{
		ID: "bind_test", CredentialID: "cred_test", UpstreamOrigin: "http://127.0.0.1:9",
		AuthScheme: model.AuthBearer, Status: model.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteGrantAuthRequirementRoundTrip(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seedGrantTarget(t, st)
	ctx := context.Background()

	for _, tc := range []struct{ id, requirement, want string }{
		{"grant_default", "", "once"},
		{"grant_window", "window:42", "window:42"},
		{"grant_peruse", "per_use", "per_use"},
		{"grant_permanent", "permanent", "permanent"},
	} {
		if err := st.PutGrant(ctx, &model.Grant{
			ID: tc.id, PrincipalID: "principal_test", BindingID: "bind_test",
			DeliveryMode: model.ModeProxy, MaxLeaseDuration: time.Minute,
			AuthRequirement: tc.requirement, Status: model.StatusActive,
		}); err != nil {
			t.Fatalf("%s: %v", tc.id, err)
		}
		got, err := st.GetGrant(ctx, tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if got.AuthRequirement != tc.want {
			t.Fatalf("%s stored %q, want %q", tc.id, got.AuthRequirement, tc.want)
		}
	}
	grants, err := st.ListGrants(ctx, "principal_test")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 4 {
		t.Fatalf("expected 4 grants, got %d", len(grants))
	}
}

func TestSQLiteAuditAuthFieldsRoundTrip(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.AppendAudit(ctx, &store.AuditEvent{
		ID: "evt_1", Time: time.Now().UTC(), PrincipalID: "p", Mode: "proxy", Result: "allowed",
		AuthMethod: "biometric", AuthResult: "verified",
	}); err != nil {
		t.Fatal(err)
	}
	// 未填写验证字段的记录必须落成安全默认值。
	if err := st.AppendAudit(ctx, &store.AuditEvent{ID: "evt_2", Time: time.Now().UTC(), Result: "lock"}); err != nil {
		t.Fatal(err)
	}
	events, err := st.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	byID := map[string]*store.AuditEvent{}
	for _, e := range events {
		byID[e.ID] = e
	}
	if byID["evt_1"].AuthMethod != "biometric" || byID["evt_1"].AuthResult != "verified" {
		t.Fatalf("auth fields lost: %+v", byID["evt_1"])
	}
	if byID["evt_2"].AuthMethod != "none" || byID["evt_2"].AuthResult != "not_required" {
		t.Fatalf("defaults not applied: %+v", byID["evt_2"])
	}
}

// TestSQLiteMigratesLegacyDatabase 用旧版表结构建库，确认 ALTER TABLE 迁移保留旧行
// 并给出安全默认策略。
func TestSQLiteMigratesLegacyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := []string{
		`CREATE TABLE grants (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, binding_id TEXT NOT NULL,
			delivery_mode TEXT NOT NULL, max_lease_seconds INTEGER NOT NULL, status TEXT NOT NULL, revision INTEGER NOT NULL)`,
		`CREATE TABLE audit_events (event_id TEXT PRIMARY KEY, time TEXT NOT NULL, principal_id TEXT NOT NULL,
			session_id TEXT NOT NULL, binding_id TEXT NOT NULL, credential_id TEXT NOT NULL, credential_version INTEGER NOT NULL,
			mode TEXT NOT NULL, result TEXT NOT NULL, error_code TEXT NOT NULL, duration_ms INTEGER NOT NULL, detail TEXT NOT NULL)`,
		`INSERT INTO grants(id, principal_id, binding_id, delivery_mode, max_lease_seconds, status, revision)
			VALUES('grant_legacy', 'principal_legacy', 'bind_legacy', 'proxy', 600, 'active', 1)`,
		`INSERT INTO audit_events(event_id, time, principal_id, session_id, binding_id, credential_id, credential_version,
			mode, result, error_code, duration_ms, detail)
			VALUES('evt_legacy', '2026-01-01T00:00:00Z', 'principal_legacy', '', 'bind_legacy', '', 0, 'proxy', 'allowed', '', 3, '')`,
	}
	for _, stmt := range legacy {
		if _, err := raw.Exec(stmt); err != nil {
			raw.Close()
			t.Fatalf("legacy schema: %v", err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	grant, err := st.GetGrant(ctx, "grant_legacy")
	if err != nil {
		t.Fatalf("legacy grant must remain readable: %v", err)
	}
	if grant.AuthRequirement != "once" {
		t.Fatalf("legacy grant migrated to %q, want once", grant.AuthRequirement)
	}
	events, err := st.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].AuthMethod != "none" || events[0].AuthResult != "not_required" {
		t.Fatalf("legacy audit rows must get safe defaults, got %+v", events)
	}
	// 迁移后可正常写入带策略的授权与带验证方式的审计。
	seedGrantTarget(t, st)
	if err := st.PutGrant(ctx, &model.Grant{
		ID: "grant_new", PrincipalID: "principal_test", BindingID: "bind_test",
		DeliveryMode: model.ModeProxy, MaxLeaseDuration: time.Minute,
		AuthRequirement: "window:30", Status: model.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	updated, err := st.GetGrant(ctx, "grant_new")
	if err != nil {
		t.Fatal(err)
	}
	if updated.AuthRequirement != "window:30" {
		t.Fatalf("post-migration grant stored %q", updated.AuthRequirement)
	}
}

// CAS 版本激活只接受未变的 revision，冲突时不写入任何内容。
func TestActivateVersionCAS(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cred := &model.Credential{ID: "cred_cas", Kind: model.KindAPIKey, Label: "c", CurrentVersion: 1, Status: model.StatusActive}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ActivateVersionCAS(ctx, "cred_cas", casRecord("cred_cas", 2), 1); err != nil {
		t.Fatalf("matching revision must commit: %v", err)
	}
	got, err := st.GetCredential(ctx, "cred_cas")
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentVersion != 2 || got.Revision != 2 {
		t.Fatalf("after CAS commit version=%d revision=%d, want 2/2", got.CurrentVersion, got.Revision)
	}
	if _, err := st.ActivateVersionCAS(ctx, "cred_cas", casRecord("cred_cas", 3), 1); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale revision must conflict, got %v", err)
	}
	after, err := st.GetCredential(ctx, "cred_cas")
	if err != nil {
		t.Fatal(err)
	}
	if after.CurrentVersion != 2 || after.Revision != 2 {
		t.Fatalf("refused CAS must not write: version=%d revision=%d", after.CurrentVersion, after.Revision)
	}
	if _, err := st.GetVersion(ctx, "cred_cas", 3); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refused CAS must not leave a version row behind: %v", err)
	}
}

// casRecord 构造一个 CAS 测试用的版本记录（存储层不校验密文内容）。
func casRecord(credentialID string, version int) *store.VersionRecord {
	return &store.VersionRecord{
		CredentialID: credentialID, Version: version,
		Ciphertext: []byte("c"), Nonce: []byte("n"), WrappedDEK: []byte("d"), WrapNonce: []byte("w"),
		CryptoVersion: 1, CreatedAt: time.Now().UTC(),
	}
}
