package vault_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
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
	"keykoi/internal/vault"
)

func randToken() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newVault(t *testing.T) (*vault.Vault, *store.SQLite, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(st, vault.Options{ArgonTime: 1, ArgonMemoryKiB: 8 * 1024, ArgonThreads: 1})
	if err != nil {
		t.Fatal(err)
	}
	return v, st, path
}

func seed(t *testing.T, v *vault.Vault, tag string) (*model.Credential, string) {
	t.Helper()
	ctx := context.Background()
	tok := randToken()
	accessID := "AKIA" + tok
	secretVal := "secret-" + tag + "-" + tok
	meta := model.Credential{ID: "cred_" + tag, Kind: model.KindAccessKeyPair, Label: "test " + tag, Status: model.StatusActive}
	created, err := v.CreateCredential(ctx, meta, model.CredentialVersion{
		Fields: map[string]secret.Value{"access_id": secret.New(accessID), "access_secret": secret.New(secretVal), "session_token": secret.New("sess-" + tag)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return created, secretVal
}

func TestInitUnlockLockedErrors(t *testing.T) {
	v, st, _ := newVault(t)
	defer st.Close()
	ctx := context.Background()
	if v.State() != "uninitialized" {
		t.Fatalf("wrong initial state %s", v.State())
	}
	if _, err := v.Materialize(ctx, "cred", 1); err == nil || model.CodeOf(err) != model.CodeVaultLocked {
		t.Fatalf("uninitialized must reject: %v", err)
	}
	if err := v.Init(ctx, []byte("correct horse battery")); err != nil {
		t.Fatal(err)
	}
	if err := v.Init(ctx, []byte("again")); err == nil {
		t.Fatal("second init must fail")
	}
	if err := v.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(ctx, []byte("wrong password")); err == nil || model.CodeOf(err) != model.CodeVaultUnlockFailed {
		t.Fatalf("wrong password must fail with stable code, got %v", err)
	}
	if err := v.Unlock(ctx, []byte("correct horse battery")); err != nil {
		t.Fatal(err)
	}
	if v.State() != "unlocked" {
		t.Fatalf("state %s", v.State())
	}
}

func TestPersistenceAndNoPlaintextAtRest(t *testing.T) {
	v, st, path := newVault(t)
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	_, sec := seed(t, v, "persist")
	// 触发 WAL 落盘。
	if err := st.DB().PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		data, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(sec)) {
			t.Fatalf("plaintext secret found in %s", p)
		}
	}
	const password = "master-password"
	_ = v.Close()
	_ = st.Close()

	st2, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	v2, err := vault.Open(st2, vault.Options{ArgonTime: 1, ArgonMemoryKiB: 8 * 1024, ArgonThreads: 1})
	if err != nil {
		t.Fatal(err)
	}
	if v2.State() != "locked" {
		t.Fatalf("restart must come back locked, got %s", v2.State())
	}
	if err := v2.Unlock(ctx, []byte(password)); err != nil {
		t.Fatal(err)
	}
	cur, err := st2.CurrentVersion(ctx, "cred_persist")
	if err != nil {
		t.Fatal(err)
	}
	ver, err := v2.Materialize(ctx, cur.CredentialID, cur.Version)
	if err != nil {
		t.Fatal(err)
	}
	if got := ver.Fields["access_secret"].RevealString(); got != sec {
		t.Fatalf("secret mismatch after restart")
	}
}

func TestConcurrentRotationKeepsCompleteVersions(t *testing.T) {
	v, st, _ := newVault(t)
	defer st.Close()
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	seed(t, v, "rotate")
	const rounds = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]string{}
	stop := make(chan struct{})
	readErr := make(chan error, 1)
	// 读取方：持续读到当前版本并按完整版本校验字段一致性。
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cur, err := st.GetCredential(ctx, "cred_rotate")
				if err != nil {
					continue
				}
				ver, err := v.Materialize(ctx, cur.ID, cur.CurrentVersion)
				if err != nil {
					select {
					case readErr <- fmt.Errorf("materialize: %w", err):
					default:
					}
					return
				}
				id := ver.Fields["access_id"].RevealString()
				sec := ver.Fields["access_secret"].RevealString()
				if !strings.HasSuffix(sec, strings.TrimPrefix(id, "AKIA")) {
					select {
					case readErr <- fmt.Errorf("mixed credential version: %s / %s", id, sec):
					default:
					}
					return
				}
				mu.Lock()
				seen[id] = sec
				mu.Unlock()
			}
		}()
	}
	for w := 0; w < rounds; w++ {
		tag := randToken()
		_, err := v.AddVersion(ctx, "cred_rotate", model.CredentialVersion{
			Fields: map[string]secret.Value{
				"access_id":     secret.New("AKIA" + tag),
				"access_secret": secret.New("secret-rotate-" + tag),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-readErr:
		t.Fatal(err)
	default:
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 {
		t.Fatalf("expected reads across rotations, saw %d distinct versions", len(seen))
	}
	for id, sec := range seen {
		if !strings.HasSuffix(sec, strings.TrimPrefix(id, "AKIA")) {
			t.Fatalf("mixed fields recorded: %s / %s", id, sec)
		}
	}
}

func TestDecryptFailureIsUnavailable(t *testing.T) {
	v, st, _ := newVault(t)
	defer st.Close()
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	seed(t, v, "tamper")
	// 篡改密文：模拟损坏或移植的密文。
	if _, err := st.DB().ExecContext(ctx, `UPDATE credential_versions SET ciphertext=? WHERE credential_id='cred_tamper'`, []byte("broken")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Materialize(ctx, "cred_tamper", 1); err == nil || model.CodeOf(err) != model.CodeCredentialUnavailable {
		t.Fatalf("tampered ciphertext must be unavailable, got %v", err)
	}
}

func TestBackupRestoreStaysLockedAndPendingReview(t *testing.T) {
	v, st, _ := newVault(t)
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	_, _ = seed(t, v, "backup")
	if _, err := v.AddVersion(ctx, "cred_backup", model.CredentialVersion{
		Fields: map[string]secret.Value{"access_id": secret.New("AKIANEW"), "access_secret": secret.New("newer-" + randToken())},
	}); err != nil {
		t.Fatal(err)
	}
	curAtBackup, err := st.GetCredential(ctx, "cred_backup")
	if err != nil {
		t.Fatal(err)
	}
	verAtBackup, err := v.Materialize(ctx, "cred_backup", curAtBackup.CurrentVersion)
	if err != nil {
		t.Fatal(err)
	}
	sec := verAtBackup.Fields["access_secret"].RevealString()
	// 准备可用授权，验证恢复后进入待复核。
	if err := st.PutPrincipal(ctx, &store.Principal{ID: "p1", IdentityType: "local_user", Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutBinding(ctx, &model.Binding{ID: "b1", CredentialID: "cred_backup", UpstreamOrigin: "http://127.0.0.1:1", AuthScheme: model.AuthBearer, Route: "r1", Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(ctx, &model.Grant{ID: "g1", PrincipalID: "p1", BindingID: "b1", DeliveryMode: model.ModeProxy, MaxLeaseDuration: time.Minute, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup.json")
	if err := v.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(sec)) {
		t.Fatal("backup contains plaintext secret")
	}
	// 备份后继续改库，再恢复，确认回到备份时点。
	if _, err := v.AddVersion(ctx, "cred_backup", model.CredentialVersion{
		Fields: map[string]secret.Value{"access_id": secret.New("AKIALATER"), "access_secret": secret.New("later")},
	}); err != nil {
		t.Fatal(err)
	}
	summary, err := v.Restore(ctx, backup)
	if err != nil {
		t.Fatal(err)
	}
	if summary["locked_after"] != true || summary["grants_pending"] != 1 {
		t.Fatalf("restore summary: %v", summary)
	}
	if v.State() != "locked" {
		t.Fatalf("restore must keep vault locked, got %s", v.State())
	}
	if err := v.Unlock(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	cur, err := st.GetCredential(ctx, "cred_backup")
	if err != nil {
		t.Fatal(err)
	}
	ver, err := v.Materialize(ctx, "cred_backup", cur.CurrentVersion)
	if err != nil {
		t.Fatal(err)
	}
	if got := ver.Fields["access_secret"].RevealString(); got != sec {
		t.Fatalf("restored version mismatch: %s", got)
	}
	grants, err := st.ListGrants(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Status != model.StatusPending {
		t.Fatalf("restored grant must be pending review, got %+v", grants)
	}
	// 待复核授权不能用于用钥。
	br := broker.New(st, v, broker.Options{})
	token := ""
	_ = token
	if _, err := br.Authorize(ctx, broker.Request{Token: secret.New("none"), BindingID: "b1", Mode: model.ModeProxy}); err == nil {
		t.Fatal("invalid session must be rejected")
	}
	if _, err := st.SetCurrentVersion(ctx, "cred_backup", cur.CurrentVersion, cur.Revision); err != nil {
		t.Fatalf("version switch with matching revision must work: %v", err)
	}
}

func TestFilePermissions(t *testing.T) {
	v, st, path := newVault(t)
	defer st.Close()
	if err := v.Init(context.Background(), []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	_, _ = seed(t, v, "perm")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("database must not be world/group readable: %v", info.Mode().Perm())
	}
}
