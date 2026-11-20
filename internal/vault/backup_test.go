package vault_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"keykoi/internal/model"
	"keykoi/internal/store"
	"keykoi/internal/vault"
)

// newSQLiteVault 建立一个已初始化的 SQLite 密钥库。
func newSQLiteVault(t *testing.T) (*vault.Vault, *store.SQLite, string) {
	t.Helper()
	dir := t.TempDir()
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
	t.Cleanup(func() { _ = v.Close() })
	return v, st, dbPath
}

// 备份不得写到运行库上：那会直接破坏正在使用的 SQLite。
func TestBackupRefusesRunningDatabase(t *testing.T) {
	v, _, dbPath := newSQLiteVault(t)
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Backup(context.Background(), dbPath)
	if err == nil {
		t.Fatal("backup onto the running database must be refused")
	}
	if model.CodeOf(err) != model.CodeConfigDrift {
		t.Fatalf("expected CONFIG_DRIFT, got %v", err)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the running database must not change")
	}
}

// 备份写到已存在的普通文件时原子替换，不留下半截文件。
func TestBackupReplacesExistingFileAtomically(t *testing.T) {
	v, _, _ := newSQLiteVault(t)
	path := filepath.Join(t.TempDir(), "backup.json")
	if err := os.WriteFile(path, []byte("stale content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.Backup(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snap vault.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("backup is not valid JSON: %v", err)
	}
	if snap.Format != "keykoi-encrypted-backup" {
		t.Fatalf("unexpected backup format %q", snap.Format)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("backup permissions = %v, want 0600", perm)
	}
	// 同目录不应残留临时文件。
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "backup.json" {
			t.Fatalf("unexpected leftover file %q", entry.Name())
		}
	}
}

// 恢复必须在替换前校验内部一致性：指向缺失版本的凭证不能被导入。
func TestRestoreRejectsInconsistentSnapshot(t *testing.T) {
	v, _, _ := newSQLiteVault(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := v.Backup(context.Background(), good); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatal(err)
	}
	snap["credentials"] = []any{map[string]any{
		"id": "cred_broken", "kind": "api_key", "label": "broken",
		"current_version": 3, "status": "active", "revision": 1,
	}}
	snap["credential_versions"] = []any{}
	broken, _ := json.Marshal(snap)
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Restore(context.Background(), bad); err == nil {
		t.Fatal("an inconsistent backup must be rejected before replacing the vault")
	}
	// 原库仍然可用且未初始化被重置。
	if v.State() != "unlocked" {
		t.Fatalf("vault state after a rejected restore = %s", v.State())
	}
}

// 恢复必须试解全部加密材料；任一层损坏都不能替换正在运行的密钥库。
func TestRestoreRejectsTamperedEncryptedMaterial(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*vault.Snapshot)
	}{
		{name: "wrapped root key", tamper: func(snap *vault.Snapshot) {
			snap.Meta.WrappedRootKey[len(snap.Meta.WrappedRootKey)-1] ^= 0xff
		}},
		{name: "root key check", tamper: func(snap *vault.Snapshot) {
			snap.Meta.RootCheck[len(snap.Meta.RootCheck)-1] ^= 0xff
		}},
		{name: "wrapped DEK", tamper: func(snap *vault.Snapshot) {
			snap.Versions[0].WrappedDEK[len(snap.Versions[0].WrappedDEK)-1] ^= 0xff
		}},
		{name: "credential ciphertext", tamper: func(snap *vault.Snapshot) {
			snap.Versions[0].Ciphertext[len(snap.Versions[0].Ciphertext)-1] ^= 0xff
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, st, _ := newSQLiteVault(t)
			ctx := context.Background()
			_, wantSecret := seed(t, v, "restore_tamper")
			backup := filepath.Join(t.TempDir(), "backup.json")
			if err := v.Backup(ctx, backup); err != nil {
				t.Fatal(err)
			}
			readRunningState := func() (*store.VaultMeta, *model.Credential, *store.VersionRecord) {
				t.Helper()
				meta, err := st.VaultMeta(ctx)
				if err != nil {
					t.Fatal(err)
				}
				cred, err := st.GetCredential(ctx, "cred_restore_tamper")
				if err != nil {
					t.Fatal(err)
				}
				version, err := st.GetVersion(ctx, cred.ID, cred.CurrentVersion)
				if err != nil {
					t.Fatal(err)
				}
				return meta, cred, version
			}
			beforeMeta, beforeCred, beforeVersion := readRunningState()

			data, err := os.ReadFile(backup)
			if err != nil {
				t.Fatal(err)
			}
			var snap vault.Snapshot
			if err := json.Unmarshal(data, &snap); err != nil {
				t.Fatal(err)
			}
			tt.tamper(&snap)
			data, err = json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(backup, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := v.Restore(ctx, backup); err == nil {
				t.Fatal("tampered encrypted material must be rejected before replacement")
			}
			if v.State() != "unlocked" {
				t.Fatalf("a rejected restore changed the running vault state to %s", v.State())
			}
			afterMeta, afterCred, afterVersion := readRunningState()
			if !reflect.DeepEqual(beforeMeta, afterMeta) || !reflect.DeepEqual(beforeCred, afterCred) || !reflect.DeepEqual(beforeVersion, afterVersion) {
				t.Fatal("a rejected restore changed the running vault records")
			}
			material, err := v.Materialize(ctx, afterCred.ID, afterCred.CurrentVersion)
			if err != nil {
				t.Fatalf("the running credential must remain usable: %v", err)
			}
			if got := material.Fields["access_secret"].RevealString(); got != wantSecret {
				t.Fatal("a rejected restore changed the running credential plaintext")
			}
		})
	}
}

// 锁定会话没有口令；仅根密钥解锁也不能冒充主密码完成备份 KDF 校验。
func TestRestoreRequiresMasterPasswordUnlock(t *testing.T) {
	v, _, _ := newSQLiteVault(t)
	ctx := context.Background()
	seed(t, v, "restore_password")
	backup := filepath.Join(t.TempDir(), "backup.json")
	if err := v.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	root, err := v.RootKeyForEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for i := range root {
			root[i] = 0
		}
	}()
	if err := v.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Restore(ctx, backup); err == nil || model.CodeOf(err) != model.CodeVaultLocked {
		t.Fatalf("locked restore must report VAULT_LOCKED, got %v", err)
	}
	if err := v.UnlockWithRootKey(root); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Restore(ctx, backup); err == nil || model.CodeOf(err) != model.CodeAuthRequired {
		t.Fatalf("root-key-only unlock must not replace master password validation, got %v", err)
	}
	if v.State() != "unlocked" {
		t.Fatalf("a rejected restore changed the running vault state to %s", v.State())
	}
}
