package vault

import (
	"context"
	"time"

	"golang.org/x/crypto/argon2"

	"keykoi/internal/model"
)

// RootKeyLength 是根密钥长度（AES-256）。
const RootKeyLength = 32

// UnlockWithRootKey 用系统保护存储取回的根密钥解锁，不需要主密码。
// 它先用现有密文校验根密钥确实属于这个密钥库，避免「解锁成功但任何版本都无法解密」。
func (v *Vault) UnlockWithRootKey(root []byte) error {
	v.restoreMu.RLock()
	defer v.restoreMu.RUnlock()
	if len(root) != RootKeyLength {
		return model.NewError(model.CodeVaultUnlockFailed, "root key must be %d bytes", RootKeyLength)
	}
	meta, err := v.st.VaultMeta(context.Background())
	if err != nil {
		return model.NewError(model.CodeVaultLocked, "vault is not initialized")
	}
	if err := v.verifyRootKey(root); err != nil {
		return err
	}
	v.mu.Lock()
	previous := v.root
	previousPassword := v.masterPassword
	v.root = append([]byte(nil), root...)
	v.masterPassword = nil
	v.initialized = true
	v.locked = false
	v.epoch = meta.AuthorizationEpoch
	v.mu.Unlock()
	zeroBytes(previous)
	zeroBytes(previousPassword)
	return nil
}

// verifyRootKey 校验根密钥确实属于这个密钥库。
//
// 优先使用每个库独立的校验块：它在空库上也能判定归属，因此恢复到另一套空库后
// 旧系统登记取回的根密钥不会解锁错误对象。旧库没有校验块时退回用版本 DEK 校验；
// 两者都没有（空库且未补写校验块）则拒绝，避免「长度正确即可解锁」。
func (v *Vault) verifyRootKey(root []byte) error {
	ctx := context.Background()
	meta, err := v.st.VaultMeta(ctx)
	if err != nil {
		return model.NewError(model.CodeVaultLocked, "vault is not initialized")
	}
	if len(meta.RootCheck) > 0 && len(meta.RootCheckNonce) > 0 {
		rootGCM, err := newGCM(root)
		if err != nil {
			return model.NewError(model.CodeVaultUnlockFailed, "root key is invalid")
		}
		plain, err := rootGCM.Open(nil, meta.RootCheckNonce, meta.RootCheck, rootCheckAAD())
		if err != nil || string(plain) != rootCheckPlaintext {
			return model.NewError(model.CodeVaultUnlockFailed,
				"root key does not match this vault; re-enroll Touch ID with the current master password")
		}
		return nil
	}
	creds, err := v.st.ListCredentials(ctx)
	if err != nil {
		return err
	}
	for _, c := range creds {
		rec, err := v.st.GetVersion(ctx, c.ID, c.CurrentVersion)
		if err != nil {
			continue
		}
		rootGCM, err := newGCM(root)
		if err != nil {
			return model.NewError(model.CodeVaultUnlockFailed, "root key is invalid")
		}
		if _, err := rootGCM.Open(nil, rec.WrapNonce, rec.WrappedDEK, wrapAAD(rec.CredentialID, rec.Version)); err != nil {
			return model.NewError(model.CodeVaultUnlockFailed, "root key does not match this vault")
		}
		return nil
	}
	return model.NewError(model.CodeVaultUnlockFailed,
		"this vault has no verification material yet; unlock once with the master password, then re-enroll Touch ID")
}

// RootKeyForEnrollment 返回根密钥副本，只用于登记系统保护存储。
// 已锁定时返回 VAULT_LOCKED。
func (v *Vault) RootKeyForEnrollment() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.locked || len(v.root) == 0 {
		return nil, model.NewError(model.CodeVaultLocked, "vault is locked")
	}
	return append([]byte(nil), v.root...), nil
}

// VerifyPassword 校验主密码但不改变解锁状态。它用于显式验证接口的回退路径，
// 避免「为了验一次密码而重新解锁」的副作用。
func (v *Vault) VerifyPassword(ctx context.Context, password []byte) error {
	meta, err := v.st.VaultMeta(ctx)
	if err != nil {
		return model.NewError(model.CodeVaultLocked, "vault is not initialized")
	}
	kek := argon2.IDKey(password, meta.KDFSalt, meta.KDFTime, meta.KDFMemoryKiB, meta.KDFThreads, 32)
	gcm, err := newGCM(kek)
	if err != nil {
		return err
	}
	root, err := gcm.Open(nil, meta.WrapNonce, meta.WrappedRootKey, rootAAD())
	if err != nil {
		return model.NewError(model.CodeVaultUnlockFailed, "master password does not match this vault")
	}
	zeroBytes(root)
	return nil
}

// EnrollBiometric 把根密钥写入系统保护存储（macOS Keychain，ACL 为 biometryCurrentSet）。
// 需要密钥库已解锁。
func (v *Vault) EnrollBiometric(ctx context.Context) error {
	storeImpl, account := v.biometricProvider()
	if storeImpl == nil {
		err := model.NewError(model.CodeAuthUnavailable, "biometric storage is not available on this system")
		v.recordBiometricError(err)
		return err
	}
	root, err := v.RootKeyForEnrollment()
	if err != nil {
		return err
	}
	defer zeroBytes(root)
	available, reason, _ := storeImpl.Available(ctx)
	v.recordBiometricAvailability(available, reason)
	if !available {
		err := model.NewError(model.CodeAuthUnavailable, "biometric enrollment is unavailable: %s", reason)
		v.recordBiometricError(err)
		return err
	}
	if err := storeImpl.Store(ctx, account, root); err != nil {
		v.recordBiometricError(err)
		return err
	}
	v.mu.Lock()
	v.bio.enrolled = true
	v.bio.enrolledAt = time.Now().UTC()
	v.bio.lastError = ""
	v.bio.autoAttempted = true
	v.mu.Unlock()
	return nil
}

// UnlockBiometric 触发系统验证并取出根密钥解锁密钥库。
func (v *Vault) UnlockBiometric(ctx context.Context) error {
	root, err := v.loadBiometricRoot(ctx)
	if err != nil {
		return err
	}
	defer zeroBytes(root)
	return v.UnlockWithRootKey(root)
}

// VerifyBiometric 只做一次系统验证（Touch ID），不改变解锁状态。
// 它用于授权策略要求「再验一次人」的场景。
func (v *Vault) VerifyBiometric(ctx context.Context) error {
	root, err := v.loadBiometricRoot(ctx)
	if err != nil {
		return err
	}
	zeroBytes(root)
	return nil
}

// BiometricEnrolled 报告最近一次登记结果。
func (v *Vault) BiometricEnrolled() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.bio.enrolled
}

// BiometricStatus 返回不含秘密的生物识别状态，供管理接口与 doctor 使用。
func (v *Vault) BiometricStatus(ctx context.Context) map[string]any {
	storeImpl, account := v.biometricProvider()
	configured := storeImpl != nil
	available, reason := false, "biometric storage is not configured"
	if configured {
		ok, why, _ := storeImpl.Available(ctx)
		available, reason = ok, why
		v.recordBiometricAvailability(ok, why)
	}
	v.mu.RLock()
	bio := v.bio
	state := v.stateLocked()
	v.mu.RUnlock()
	out := map[string]any{
		"configured":            configured,
		"available":             available,
		"enrolled":              bio.enrolled,
		"account":               account,
		"reason":                reason,
		"auto_enroll_attempted": bio.autoAttempted,
		"vault_state":           state,
	}
	if !bio.enrolledAt.IsZero() {
		out["enrolled_at"] = bio.enrolledAt
	}
	if bio.lastError != "" {
		out["last_error"] = bio.lastError
	}
	return out
}

// DeleteBiometricEnrollment 删除系统保护存储中的根密钥条目；主密码仍然可用。
func (v *Vault) DeleteBiometricEnrollment(ctx context.Context) error {
	storeImpl, account := v.biometricProvider()
	if storeImpl == nil {
		return model.NewError(model.CodeAuthUnavailable, "biometric storage is not available on this system")
	}
	// 删除是尽力而为：条目原本不存在或当前会话不可用都视为已清理。
	_ = storeImpl.Delete(ctx, account)
	v.mu.Lock()
	v.bio.enrolled = false
	v.bio.enrolledAt = time.Time{}
	v.bio.lastError = ""
	v.mu.Unlock()
	return nil
}

// loadBiometricRoot 通过系统验证取出根密钥。
func (v *Vault) loadBiometricRoot(ctx context.Context) ([]byte, error) {
	storeImpl, account := v.biometricProvider()
	if storeImpl == nil {
		return nil, model.NewError(model.CodeAuthUnavailable, "biometric storage is not available on this system")
	}
	available, reason, _ := storeImpl.Available(ctx)
	v.recordBiometricAvailability(available, reason)
	if !available {
		return nil, model.NewError(model.CodeAuthUnavailable,
			"Touch ID is unavailable (%s); fall back to the master password", reason)
	}
	root, err := storeImpl.Load(ctx, account)
	if err != nil {
		if model.CodeOf(err) == model.CodeAuthUnavailable {
			v.mu.Lock()
			v.bio.enrolled = false
			v.mu.Unlock()
		}
		v.recordBiometricError(err)
		return nil, err
	}
	v.mu.Lock()
	v.bio.enrolled = true
	v.bio.lastError = ""
	v.mu.Unlock()
	return root, nil
}

// autoEnrollBiometric 在初始化后自动登记，失败只记录状态。
func (v *Vault) autoEnrollBiometric(ctx context.Context) error {
	v.mu.Lock()
	v.bio.autoAttempted = true
	v.mu.Unlock()
	return v.EnrollBiometric(ctx)
}

// biometricProvider 返回配置的实现与账户名。
func (v *Vault) biometricProvider() (BiometricStore, string) {
	if v.opts.Biometric == nil {
		return nil, v.opts.BiometricAccount
	}
	return v.opts.Biometric, v.opts.BiometricAccount
}

func (v *Vault) recordBiometricAvailability(available bool, reason string) {
	v.mu.Lock()
	v.bio.available = available
	v.bio.reason = reason
	v.mu.Unlock()
}

func (v *Vault) recordBiometricError(err error) {
	if err == nil {
		return
	}
	code := model.CodeOf(err)
	if code == model.CodeAuthRequired {
		// 用户取消不算登记失败，保留已有登记状态。
		return
	}
	v.mu.Lock()
	v.bio.lastError = err.Error()
	v.mu.Unlock()
}

// stateLocked 在已持有读锁时返回状态字符串。
func (v *Vault) stateLocked() string {
	if !v.initialized {
		return "uninitialized"
	}
	if v.locked || v.root == nil {
		return "locked"
	}
	return "unlocked"
}

// SetBiometric 在运行期替换生物识别实现（例如切换助手路径或测试注入）。
func (v *Vault) SetBiometric(store BiometricStore, account string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.opts.Biometric = store
	if account != "" {
		v.opts.BiometricAccount = account
	}
	v.bio = biometricState{}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
