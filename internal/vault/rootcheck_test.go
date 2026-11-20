package vault_test

import (
	"context"
	"path/filepath"
	"testing"

	"keykoi/internal/model"
	"keykoi/internal/store"
	"keykoi/internal/vault"
)

// openVaultAt 在指定目录建立已初始化的密钥库，并返回它的根密钥（模拟系统登记）。
func openVaultAt(t *testing.T, dir string) (*vault.Vault, *store.SQLite, []byte) {
	t.Helper()
	dbPath := filepath.Join(dir, "vault.db")
	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	v, err := vault.Open(st, vault.Options{ArgonTime: 1, ArgonMemoryKiB: 8 * 1024, ArgonThreads: 1, DatabasePath: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Init(context.Background(), []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	root, err := v.RootKeyForEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	return v, st, root
}

// 恢复到另一套空库后，旧系统登记取回的根密钥不能被接受：
// 否则旧登记会用错误的根密钥接管新导入的凭证。
func TestRestoreIntoEmptyVaultRejectsPreviousRootKey(t *testing.T) {
	ctx := context.Background()
	sourceDir := t.TempDir()
	source, _, sourceRoot := openVaultAt(t, sourceDir)
	backup := filepath.Join(t.TempDir(), "empty-vault.json")
	if err := source.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	// 目标库先有自己的根密钥登记（模拟系统钥匙串里的旧登记）。
	target, _, targetRoot := openVaultAt(t, t.TempDir())
	if _, err := target.Restore(ctx, backup); err != nil {
		t.Fatal(err)
	}
	// 恢复后系统登记里仍是目标库原来的根密钥：必须被拒绝，而不是拿到「长度正确即可」。
	if err := target.UnlockWithRootKey(targetRoot); err == nil {
		t.Fatal("the previous root key must not unlock a restored vault")
	} else if model.CodeOf(err) != model.CodeVaultUnlockFailed {
		t.Fatalf("expected VAULT_UNLOCK_FAILED, got %v", err)
	}
	// 备份自带的根密钥可用；主密码同样可用并补写校验块。
	if err := target.UnlockWithRootKey(sourceRoot); err != nil {
		t.Fatalf("the backup's own root key must unlock the restored vault: %v", err)
	}
	_ = target.Lock(ctx)
	if err := target.Unlock(ctx, []byte("master-password")); err != nil {
		t.Fatalf("master password must still unlock the restored vault: %v", err)
	}
}

// 恢复会清空审计与接入状态，并留下一条说明性的审计事件。
func TestRestoreClearsAuditAndIntegrations(t *testing.T) {
	ctx := context.Background()
	source, sourceStore, _ := openVaultAt(t, t.TempDir())
	if err := sourceStore.AppendAudit(ctx, &store.AuditEvent{Mode: "control", Result: "seed"}); err != nil {
		t.Fatal(err)
	}
	if err := sourceStore.PutIntegration(ctx, &store.IntegrationRecord{ID: "int_seed", State: "attached"}); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "vault.json")
	if err := source.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}

	target, targetStore, _ := openVaultAt(t, t.TempDir())
	if err := targetStore.AppendAudit(ctx, &store.AuditEvent{Mode: "control", Result: "before_restore"}); err != nil {
		t.Fatal(err)
	}
	if err := targetStore.PutIntegration(ctx, &store.IntegrationRecord{ID: "int_before", State: "attached"}); err != nil {
		t.Fatal(err)
	}
	res, err := target.Restore(ctx, backup)
	if err != nil {
		t.Fatal(err)
	}
	if res["credentials"] != 0 {
		t.Fatalf("expected an empty restore, got %v", res["credentials"])
	}
	if integs, err := targetStore.ListIntegrations(ctx); err != nil {
		t.Fatal(err)
	} else if len(integs) != 0 {
		t.Fatalf("restore must clear integration state, got %d records", len(integs))
	}
	events, err := targetStore.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Result != "restore" {
		t.Fatalf("restore must leave exactly one explaining audit event, got %+v", events)
	}
}
