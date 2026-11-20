package vault_test

import (
	"context"
	"errors"
	"testing"

	"keykoi/internal/model"
	"keykoi/internal/store"
	"keykoi/internal/vault"
)

// fakeBiometric 记忆根密钥，模拟系统保护存储。
type fakeBiometric struct {
	available bool
	reason    string
	loadErr   error
	storeErr  error
	items     map[string][]byte
	stores    int
	loads     int
	deletes   int
}

func newFakeBiometric() *fakeBiometric {
	return &fakeBiometric{available: true, reason: "Touch ID is available", items: map[string][]byte{}}
}

func (f *fakeBiometric) Available(context.Context) (bool, string, error) {
	return f.available, f.reason, nil
}

func (f *fakeBiometric) Store(_ context.Context, account string, root []byte) error {
	if f.storeErr != nil {
		return f.storeErr
	}
	f.stores++
	f.items[account] = append([]byte(nil), root...)
	return nil
}

func (f *fakeBiometric) Load(_ context.Context, account string) ([]byte, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	root, ok := f.items[account]
	if !ok {
		return nil, model.NewError(model.CodeAuthUnavailable, "no enrolled root key")
	}
	f.loads++
	return append([]byte(nil), root...), nil
}

func (f *fakeBiometric) Delete(_ context.Context, account string) error {
	f.deletes++
	delete(f.items, account)
	return nil
}

func newBiometricVault(t *testing.T) (*vault.Vault, *fakeBiometric) {
	t.Helper()
	st := store.NewMemory()
	bio := newFakeBiometric()
	v, err := vault.Open(st, vault.Options{Biometric: bio})
	if err != nil {
		t.Fatal(err)
	}
	return v, bio
}

func TestInitAutoEnrollsBiometricRoot(t *testing.T) {
	v, bio := newBiometricVault(t)
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	if bio.stores != 1 {
		t.Fatalf("init must enroll the root key once, got %d", bio.stores)
	}
	if !v.BiometricEnrolled() {
		t.Fatal("vault must report the biometric enrollment")
	}
	status := v.BiometricStatus(ctx)
	if status["enrolled"] != true || status["available"] != true || status["auto_enroll_attempted"] != true {
		t.Fatalf("unexpected status: %v", status)
	}
	if _, ok := bio.items[vault.DefaultBiometricAccount]; !ok {
		t.Fatalf("root key must be stored under %q", vault.DefaultBiometricAccount)
	}
}

func TestInitSurvivesEnrollmentFailure(t *testing.T) {
	st := store.NewMemory()
	bio := newFakeBiometric()
	bio.storeErr = model.NewError(model.CodeAuthUnavailable, "keychain rejected the item")
	v, err := vault.Open(st, vault.Options{Biometric: bio})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatalf("enrollment failure must not block init: %v", err)
	}
	if v.State() != "unlocked" {
		t.Fatalf("vault should stay unlocked, got %s", v.State())
	}
	status := v.BiometricStatus(ctx)
	if status["enrolled"] != false {
		t.Fatalf("failed enrollment must not be reported as enrolled: %v", status)
	}
	if _, ok := status["last_error"].(string); !ok {
		t.Fatalf("failure reason must be recorded: %v", status)
	}
}

func TestRootKeyEnrollmentCopyAndUnlock(t *testing.T) {
	v, bio := newBiometricVault(t)
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	root, err := v.RootKeyForEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != vault.RootKeyLength {
		t.Fatalf("root key must be %d bytes, got %d", vault.RootKeyLength, len(root))
	}
	// 返回的是副本：修改它不能影响库内根密钥。
	for i := range root {
		root[i] = 0
	}
	if _, err := v.Materialize(ctx, "cred_missing", 1); err == nil {
		t.Fatal("vault should still be unlocked after touching the copy")
	}
	// 锁定后不再允许导出根密钥。
	if err := v.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := v.RootKeyForEnrollment(); err == nil || model.CodeOf(err) != model.CodeVaultLocked {
		t.Fatalf("locked vault must refuse root key export: %v", err)
	}
	// 用系统存储里的根密钥解锁。
	if err := v.UnlockBiometric(ctx); err != nil {
		t.Fatalf("biometric unlock should succeed: %v", err)
	}
	if v.State() != "unlocked" {
		t.Fatalf("vault should be unlocked, got %s", v.State())
	}
	if bio.loads == 0 {
		t.Fatal("biometric unlock must read the protected item")
	}
}

func TestUnlockWithWrongRootKeyFails(t *testing.T) {
	v, _ := newBiometricVault(t)
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	// 建一个版本，使根密钥可被校验。
	if _, err := v.CreateCredential(ctx, model.Credential{
		ID: "cred_bio", Kind: model.KindAPIKey, Label: "bio", Status: model.StatusActive,
	}, model.CredentialVersion{CredentialID: "cred_bio", Version: 1}); err != nil {
		t.Fatal(err)
	}
	if err := v.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	wrong := make([]byte, vault.RootKeyLength)
	for i := range wrong {
		wrong[i] = 7
	}
	if err := v.UnlockWithRootKey(wrong); err == nil || model.CodeOf(err) != model.CodeVaultUnlockFailed {
		t.Fatalf("a foreign root key must be rejected: %v", err)
	}
	if v.State() != "locked" {
		t.Fatalf("failed unlock must leave the vault locked, got %s", v.State())
	}
	if err := v.UnlockWithRootKey(make([]byte, 3)); err == nil {
		t.Fatal("short root key must be rejected")
	}
}

func TestBiometricUnavailableIsExplicit(t *testing.T) {
	st := store.NewMemory()
	bio := newFakeBiometric()
	bio.available = false
	bio.reason = "no GUI session"
	v, err := vault.Open(st, vault.Options{Biometric: bio})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	if err := v.EnrollBiometric(ctx); err == nil || model.CodeOf(err) != model.CodeAuthUnavailable {
		t.Fatalf("unavailable biometric must report AUTH_UNAVAILABLE: %v", err)
	}
	if err := v.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := v.UnlockBiometric(ctx); err == nil || model.CodeOf(err) != model.CodeAuthUnavailable {
		t.Fatalf("unlock must fail explicitly: %v", err)
	}
	if v.State() != "locked" {
		t.Fatal("vault must stay locked")
	}
	// 主密码仍然可用。
	if err := v.Unlock(ctx, []byte("master-password")); err != nil {
		t.Fatalf("master password must still work: %v", err)
	}
}

func TestVerifyBiometricDoesNotUnlock(t *testing.T) {
	v, bio := newBiometricVault(t)
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	if err := v.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyBiometric(ctx); err != nil {
		t.Fatalf("verification should succeed: %v", err)
	}
	if v.State() != "locked" {
		t.Fatalf("verification must not unlock the vault, got %s", v.State())
	}
	if bio.loads == 0 {
		t.Fatal("verification must read the protected item")
	}
}

func TestVerifyPasswordDoesNotChangeState(t *testing.T) {
	v, _ := newBiometricVault(t)
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	if err := v.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyPassword(ctx, []byte("master-password")); err != nil {
		t.Fatalf("correct password should verify: %v", err)
	}
	if v.State() != "locked" {
		t.Fatalf("verification must not unlock the vault, got %s", v.State())
	}
	err := v.VerifyPassword(ctx, []byte("wrong-password"))
	if err == nil || model.CodeOf(err) != model.CodeVaultUnlockFailed {
		t.Fatalf("wrong password must be rejected: %v", err)
	}
}

func TestBiometricCancelIsAuthRequired(t *testing.T) {
	v, bio := newBiometricVault(t)
	ctx := context.Background()
	if err := v.Init(ctx, []byte("master-password")); err != nil {
		t.Fatal(err)
	}
	if err := v.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	bio.loadErr = model.NewError(model.CodeAuthRequired, "user cancelled")
	err := v.UnlockBiometric(ctx)
	if err == nil || model.CodeOf(err) != model.CodeAuthRequired {
		t.Fatalf("cancellation must surface AUTH_REQUIRED: %v", err)
	}
	if !errors.Is(err, bio.loadErr) && model.CodeOf(err) != model.CodeAuthRequired {
		t.Fatalf("unexpected error: %v", err)
	}
}
