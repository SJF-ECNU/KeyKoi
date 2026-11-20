// Package vault 实现单机加密密钥库：每个凭证版本独立 DEK，根密钥用主密码
// 派生的 KEK 包装；SQL 中只保存密文与非秘密元数据。
package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

const (
	cryptoVersion = 1
	schemaVersion = 1
	// rootCheckPlaintext 是根密钥校验块的固定明文；它只证明归属，不携带秘密。
	rootCheckPlaintext = "keykoi-root-check-v1"
)

// Options 配置 KDF 参数。实际解锁使用数据库中保存的参数，便于后续升级。
type Options struct {
	ArgonTime      uint32
	ArgonMemoryKiB uint32
	ArgonThreads   uint8
	Now            func() time.Time
	// Biometric 是系统生物识别保护的根密钥存取实现；为空表示当前环境不支持。
	Biometric BiometricStore
	// BiometricAccount 是系统保护存储中的条目账户名。
	BiometricAccount string
	// DatabasePath 是当前运行库的文件路径。备份不得写到这个文件上，
	// 否则一次误操作就会覆盖正在使用的 SQLite。
	DatabasePath string
}

func (o *Options) normalize() {
	if o.ArgonTime == 0 {
		o.ArgonTime = 3
	}
	if o.ArgonMemoryKiB == 0 {
		o.ArgonMemoryKiB = 64 * 1024
	}
	if o.ArgonThreads == 0 {
		o.ArgonThreads = 4
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.BiometricAccount == "" {
		o.BiometricAccount = DefaultBiometricAccount
	}
}

// Vault 是加密密钥库后端。
type Vault struct {
	st   store.Store
	opts Options

	mu             sync.RWMutex
	root           []byte
	masterPassword []byte
	initialized    bool
	locked         bool
	epoch          string
	bio            biometricState
}

// biometricState 记录生物识别登记状态。它只说明「能不能用、是否登记成功」，
// 从不保存根密钥或验证凭据。
type biometricState struct {
	available     bool
	reason        string
	enrolled      bool
	enrolledAt    time.Time
	lastError     string
	autoAttempted bool
}

// Open 打开密钥库元数据。未初始化时返回未初始化状态，调用方应先 Init。
func Open(st store.Store, opts Options) (*Vault, error) {
	opts.normalize()
	v := &Vault{st: st, opts: opts, locked: true}
	meta, err := st.VaultMeta(context.Background())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return v, nil
		}
		return nil, err
	}
	v.initialized = true
	v.epoch = meta.AuthorizationEpoch
	return v, nil
}

// Initialized 报告密钥库是否已建立根密钥。
func (v *Vault) Initialized() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.initialized
}

// Init 用主密码建立根密钥。已初始化时返回冲突错误。
func (v *Vault) Init(ctx context.Context, password []byte) error {
	v.mu.Lock()
	if v.initialized {
		v.mu.Unlock()
		return model.NewError(model.CodeVaultLocked, "vault is already initialized")
	}
	salt := randomBytes(16)
	kek := argon2.IDKey(password, salt, v.opts.ArgonTime, v.opts.ArgonMemoryKiB, v.opts.ArgonThreads, 32)
	root := randomBytes(32)
	wrapNonce := randomBytes(12)
	gcm, err := newGCM(kek)
	if err != nil {
		v.mu.Unlock()
		return err
	}
	wrapped := gcm.Seal(nil, wrapNonce, root, rootAAD())
	rootCheck, rootCheckNonce, err := makeRootCheck(root)
	if err != nil {
		v.mu.Unlock()
		return err
	}
	meta := &store.VaultMeta{
		SchemaVersion:      schemaVersion,
		CryptoVersion:      cryptoVersion,
		KDFAlgorithm:       "argon2id",
		KDFSalt:            salt,
		KDFTime:            v.opts.ArgonTime,
		KDFMemoryKiB:       v.opts.ArgonMemoryKiB,
		KDFThreads:         v.opts.ArgonThreads,
		WrappedRootKey:     wrapped,
		WrapNonce:          wrapNonce,
		RootCheck:          rootCheck,
		RootCheckNonce:     rootCheckNonce,
		AuthorizationEpoch: randomID(),
		CreatedAt:          v.opts.Now(),
	}
	if err := v.st.PutVaultMeta(ctx, meta); err != nil {
		v.mu.Unlock()
		return err
	}
	v.root = root
	v.masterPassword = append([]byte(nil), password...)
	v.initialized = true
	v.locked = false
	v.epoch = meta.AuthorizationEpoch
	v.mu.Unlock()
	// 初始化后自动尝试登记系统生物识别保护；失败不阻塞初始化，状态留在内存供诊断。
	_ = v.autoEnrollBiometric(ctx)
	return nil
}

// Unlock 用主密码解开根密钥。密码错误与数据损坏都明确失败，不回退。
func (v *Vault) Unlock(ctx context.Context, password []byte) error {
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
		return model.NewError(model.CodeVaultUnlockFailed, "unlock failed: the master password does not match this vault")
	}
	// 旧库没有根密钥校验块时补写一份，让后续的生物识别解锁也能校验归属。
	if err := v.ensureRootCheck(ctx, meta, root); err != nil {
		zeroBytes(root)
		return err
	}
	v.mu.Lock()
	previousPassword := v.masterPassword
	v.root = root
	v.masterPassword = append([]byte(nil), password...)
	v.initialized = true
	v.locked = false
	v.epoch = meta.AuthorizationEpoch
	v.mu.Unlock()
	zeroBytes(previousPassword)
	return nil
}

// ensureRootCheck 在校验块缺失时补写一份。它只在主密码刚刚解开根密钥后调用。
func (v *Vault) ensureRootCheck(ctx context.Context, meta *store.VaultMeta, root []byte) error {
	if len(meta.RootCheck) > 0 && len(meta.RootCheckNonce) > 0 {
		return nil
	}
	check, nonce, err := makeRootCheck(root)
	if err != nil {
		return err
	}
	meta.RootCheck = check
	meta.RootCheckNonce = nonce
	return v.st.PutVaultMeta(ctx, meta)
}

// makeRootCheck 用根密钥加密固定校验串。它不含秘密，只证明「这把根密钥属于这个库」。
func makeRootCheck(root []byte) ([]byte, []byte, error) {
	gcm, err := newGCM(root)
	if err != nil {
		return nil, nil, err
	}
	nonce := randomBytes(12)
	return gcm.Seal(nil, nonce, []byte(rootCheckPlaintext), rootCheckAAD()), nonce, nil
}
func (v *Vault) Lock(context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	zeroBytes(v.root)
	zeroBytes(v.masterPassword)
	v.root = nil
	v.masterPassword = nil
	v.locked = true
	v.epoch = randomID()
	return nil
}

// Locked 报告锁定状态。
func (v *Vault) Locked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.locked || v.root == nil
}

// State 返回 locked / unlocked / uninitialized。
func (v *Vault) State() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !v.initialized {
		return "uninitialized"
	}
	if v.locked || v.root == nil {
		return "locked"
	}
	return "unlocked"
}

// Describe 返回不含秘密的摘要。
func (v *Vault) Describe() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return fmt.Sprintf("encrypted vault: crypto_version=%d state=%s", cryptoVersion, v.State())
}

// Close 清除内存根密钥。
func (v *Vault) Close() error {
	_ = v.Lock(context.Background())
	return nil
}

// Materialize 解密指定完整版本。锁定、缺失或解密失败都返回稳定错误。
func (v *Vault) Materialize(ctx context.Context, credentialID string, version int) (model.CredentialVersion, error) {
	v.mu.RLock()
	root := append([]byte(nil), v.root...)
	locked := v.locked
	v.mu.RUnlock()
	if locked || len(root) == 0 {
		return model.CredentialVersion{}, model.NewError(model.CodeVaultLocked, "vault is locked")
	}
	rec, err := v.st.GetVersion(ctx, credentialID, version)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return model.CredentialVersion{}, model.NewError(model.CodeCredentialUnavailable,
				"credential %s version %d is unavailable", credentialID, version)
		}
		return model.CredentialVersion{}, err
	}
	ver, err := decryptVersion(root, rec)
	if err != nil {
		return model.CredentialVersion{}, model.NewError(model.CodeCredentialUnavailable,
			"credential %s version %d cannot be decrypted", credentialID, version)
	}
	return ver, nil
}

// CreateCredential 加密并写入凭证索引与首个版本。
func (v *Vault) CreateCredential(ctx context.Context, meta model.Credential, version model.CredentialVersion) (*model.Credential, error) {
	root, err := v.rootKey()
	if err != nil {
		return nil, err
	}
	meta.CurrentVersion = 1
	version.Version = 1
	version.CredentialID = meta.ID
	rec, err := encryptVersion(root, version)
	if err != nil {
		return nil, err
	}
	if err := v.st.CreateCredentialWithVersion(ctx, &meta, rec); err != nil {
		return nil, err
	}
	return v.st.GetCredential(ctx, meta.ID)
}

// AddVersion 写入新版本并原子切换当前版本。
func (v *Vault) AddVersion(ctx context.Context, credentialID string, version model.CredentialVersion) (*model.Credential, error) {
	root, err := v.rootKey()
	if err != nil {
		return nil, err
	}
	cur, err := v.st.GetCredential(ctx, credentialID)
	if err != nil {
		return nil, model.NewError(model.CodeCredentialUnavailable, "credential %s is unavailable", credentialID)
	}
	version.CredentialID = credentialID
	version.Version = cur.CurrentVersion + 1
	rec, err := encryptVersion(root, version)
	if err != nil {
		return nil, err
	}
	// 插入版本、切换当前版本与同步到期时间必须在同一事务内完成：
	// 分三次写库会在中断时留下未启用的版本，并让下一次轮换撞上相同版本号。
	rec.ProviderExpiresAt = version.ProviderExpiresAt
	updated, err := v.st.ActivateVersion(ctx, credentialID, rec)
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// ActivateVersionCAS 按预期 revision 写入新版本：revision 已变时返回 store.ErrConflict，
// 用于把「记录未变」与「写入新版本」合并为一次原子提交。
func (v *Vault) ActivateVersionCAS(ctx context.Context, credentialID string, version model.CredentialVersion, expectedRevision int64) (*model.Credential, error) {
	root, err := v.rootKey()
	if err != nil {
		return nil, err
	}
	cur, err := v.st.GetCredential(ctx, credentialID)
	if err != nil {
		return nil, model.NewError(model.CodeCredentialUnavailable, "credential %s is unavailable", credentialID)
	}
	version.CredentialID = credentialID
	version.Version = cur.CurrentVersion + 1
	rec, err := encryptVersion(root, version)
	if err != nil {
		return nil, err
	}
	rec.ProviderExpiresAt = version.ProviderExpiresAt
	return v.st.ActivateVersionCAS(ctx, credentialID, rec, expectedRevision)
}

func (v *Vault) rootKey() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.locked || len(v.root) == 0 {
		return nil, model.NewError(model.CodeVaultLocked, "vault is locked")
	}
	return append([]byte(nil), v.root...), nil
}

// AAD 把凭证标识、版本与加密格式绑定到密文，防止密文被移植到别的版本。
func versionAAD(credentialID string, version, cryptoVer int) []byte {
	return []byte(fmt.Sprintf("keykoi|credential|%s|%d|%d", credentialID, version, cryptoVer))
}

func wrapAAD(credentialID string, version int) []byte {
	return []byte(fmt.Sprintf("keykoi|dek|%s|%d", credentialID, version))
}

func rootAAD() []byte { return []byte("keykoi|root|v1") }

// rootCheckAAD 绑定校验块的用途，避免与其他根密钥密文互换。
func rootCheckAAD() []byte { return []byte("keykoi|root-check|v1") }

type versionPayload struct {
	Fields            map[string]string `json:"fields"`
	ProviderExpiresAt *time.Time        `json:"provider_expires_at,omitempty"`
}

func encryptVersion(root []byte, v model.CredentialVersion) (*store.VersionRecord, error) {
	dek := randomBytes(32)
	fields := make(map[string]string, len(v.Fields))
	for k, val := range v.Fields {
		fields[k] = val.RevealString()
	}
	payload, err := json.Marshal(versionPayload{Fields: fields, ProviderExpiresAt: v.ProviderExpiresAt})
	if err != nil {
		return nil, err
	}
	dataGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(12)
	ct := dataGCM.Seal(nil, nonce, payload, versionAAD(v.CredentialID, v.Version, cryptoVersion))
	rootGCM, err := newGCM(root)
	if err != nil {
		return nil, err
	}
	wrapNonce := randomBytes(12)
	wrapped := rootGCM.Seal(nil, wrapNonce, dek, wrapAAD(v.CredentialID, v.Version))
	return &store.VersionRecord{
		CredentialID:      v.CredentialID,
		Version:           v.Version,
		Ciphertext:        ct,
		Nonce:             nonce,
		WrappedDEK:        wrapped,
		WrapNonce:         wrapNonce,
		CryptoVersion:     cryptoVersion,
		ProviderExpiresAt: v.ProviderExpiresAt,
		CreatedAt:         time.Now().UTC(),
	}, nil
}

func decryptVersion(root []byte, rec *store.VersionRecord) (model.CredentialVersion, error) {
	if rec.CryptoVersion != cryptoVersion {
		return model.CredentialVersion{}, fmt.Errorf("unsupported crypto version %d", rec.CryptoVersion)
	}
	rootGCM, err := newGCM(root)
	if err != nil {
		return model.CredentialVersion{}, err
	}
	dek, err := rootGCM.Open(nil, rec.WrapNonce, rec.WrappedDEK, wrapAAD(rec.CredentialID, rec.Version))
	if err != nil {
		return model.CredentialVersion{}, fmt.Errorf("unwrap dek: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()
	dataGCM, err := newGCM(dek)
	if err != nil {
		return model.CredentialVersion{}, err
	}
	payload, err := dataGCM.Open(nil, rec.Nonce, rec.Ciphertext, versionAAD(rec.CredentialID, rec.Version, rec.CryptoVersion))
	if err != nil {
		return model.CredentialVersion{}, fmt.Errorf("decrypt payload: %w", err)
	}
	var p versionPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return model.CredentialVersion{}, fmt.Errorf("decode payload: %w", err)
	}
	fields := make(map[string]secret.Value, len(p.Fields))
	for k, val := range p.Fields {
		fields[k] = secret.New(val)
	}
	result := model.CredentialVersion{CredentialID: rec.CredentialID, Version: rec.Version, Fields: fields, ProviderExpiresAt: p.ProviderExpiresAt}
	return result, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}

func randomID() string {
	b := randomBytes(16)
	return fmt.Sprintf("%x", b)
}

// Snapshot 是密文备份的格式。备份只含密文与恢复所需元数据。
type Snapshot struct {
	Format        string                 `json:"format"`
	SchemaVersion int                    `json:"schema_version"`
	CreatedAt     time.Time              `json:"created_at"`
	Meta          store.VaultMeta        `json:"vault_meta"`
	Credentials   []*model.Credential    `json:"credentials"`
	Versions      []*store.VersionRecord `json:"credential_versions"`
	Bindings      []*model.Binding       `json:"bindings"`
	Principals    []*store.Principal     `json:"principals"`
	Grants        []*model.Grant         `json:"grants"`
}

// Backup 写出密文备份文件（0600）。它不导出明文，也不包含运行时会话或许可。
func (v *Vault) Backup(ctx context.Context, path string) error {
	if err := v.guardBackupTarget(path); err != nil {
		return err
	}
	meta, err := v.st.VaultMeta(ctx)
	if err != nil {
		return model.NewError(model.CodeVaultLocked, "vault is not initialized")
	}
	creds, err := v.st.ListCredentials(ctx)
	if err != nil {
		return err
	}
	snap := Snapshot{Format: "keykoi-encrypted-backup", SchemaVersion: schemaVersion, CreatedAt: time.Now().UTC(), Meta: *meta,
		Credentials: creds, Bindings: []*model.Binding{}, Principals: []*store.Principal{}, Grants: []*model.Grant{}, Versions: []*store.VersionRecord{}}
	for _, c := range creds {
		versions, err := v.st.ListVersions(ctx, c.ID)
		if err != nil {
			return err
		}
		for _, ver := range versions {
			rec, err := v.st.GetVersion(ctx, c.ID, ver)
			if err != nil {
				return err
			}
			snap.Versions = append(snap.Versions, rec)
		}
	}
	if snap.Bindings, err = v.st.ListBindings(ctx); err != nil {
		return err
	}
	if snap.Principals, err = v.st.ListPrincipals(ctx); err != nil {
		return err
	}
	if snap.Grants, err = v.st.ListGrants(ctx, ""); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o600)
}

// writeFileAtomic 先写同目录临时文件并落盘，再用 rename 原子替换。
// 这样中断只会留下旧的完整备份，不会截断已有目标文件。
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keykoi-backup-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// guardBackupTarget 拒绝把备份写到运行库或另一个数据库文件上。
func (v *Vault) guardBackupTarget(path string) error {
	if v.opts.DatabasePath != "" {
		if same, err := sameFile(path, v.opts.DatabasePath); err == nil && same {
			return model.NewError(model.CodeConfigDrift,
				"refusing to back up onto the running vault database %s", v.opts.DatabasePath)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if info.IsDir() {
		return model.NewError(model.CodeConfigDrift, "backup target %s is a directory", path)
	}
	header := make([]byte, 16)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if _, err := io.ReadFull(f, header); err == nil && bytes.HasPrefix(header, []byte("SQLite format 3")) {
		return model.NewError(model.CodeConfigDrift,
			"refusing to overwrite %s: it is a SQLite database, not a backup target", path)
	}
	return nil
}

// sameFile 判断两个路径是否指向同一文件。
func sameFile(a, b string) (bool, error) {
	ia, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	ib, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(ia, ib), nil
}

// restorePassword 返回本次密码解锁会话持有的口令副本。仅用根密钥解锁时
// 没有可用于备份 KDF 的口令，必须明确失败，不能拿当前根密钥跳过口令验证。
func (v *Vault) restorePassword() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.locked || len(v.root) == 0 {
		return nil, model.NewError(model.CodeVaultLocked, "restore requires an unlocked vault")
	}
	if len(v.masterPassword) == 0 {
		return nil, model.NewError(model.CodeAuthRequired, "restore requires an unlock with the master password")
	}
	return append([]byte(nil), v.masterPassword...), nil
}

// Restore 用密文备份替换当前库，并默认保持锁定。
// 恢复出的 Grant 进入待复核状态，旧会话与许可不会复活。
func (v *Vault) Restore(ctx context.Context, path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("decode backup: %w", err)
	}
	if snap.Format != "keykoi-encrypted-backup" || snap.SchemaVersion != schemaVersion {
		return nil, fmt.Errorf("unsupported backup format %q schema %d", snap.Format, snap.SchemaVersion)
	}
	// 先完整校验再提交替换：外层格式正确但内部不一致的备份不能进入运行库。
	if err := validateSnapshot(&snap); err != nil {
		return nil, err
	}
	password, err := v.restorePassword()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(password)
	if err := validateSnapshotDecryption(&snap, password); err != nil {
		return nil, err
	}
	// 恢复会清空审计与接入状态；先记下数量，替换后写一条不带秘密的说明。
	clearedAudit, _ := v.st.ListAudit(ctx, 1<<20)
	clearedIntegrations, _ := v.st.ListIntegrations(ctx)
	pending := 0
	for _, g := range snap.Grants {
		g.Status = model.StatusPending
		pending++
	}
	snap.Meta.AuthorizationEpoch = randomID()
	if err := v.st.ReplaceVault(ctx, &snap.Meta, snap.Credentials, snap.Versions, snap.Bindings, snap.Principals, snap.Grants); err != nil {
		return nil, err
	}
	_ = v.st.AppendAudit(ctx, &store.AuditEvent{
		ID: randomID(), Time: time.Now().UTC(), Mode: "control", Result: "restore",
		Detail: fmt.Sprintf("vault replaced from backup: %d credentials, %d versions, %d grants pending review; cleared %d audit events and %d integration records",
			len(snap.Credentials), len(snap.Versions), pending, len(clearedAudit), len(clearedIntegrations)),
	})
	_ = v.Lock(ctx)
	v.mu.Lock()
	v.initialized = true
	v.epoch = snap.Meta.AuthorizationEpoch
	v.mu.Unlock()
	return map[string]any{
		"credentials":         len(snap.Credentials),
		"versions":            len(snap.Versions),
		"bindings":            len(snap.Bindings),
		"grants_pending":      pending,
		"locked_after":        true,
		"authorization_epoch": snap.Meta.AuthorizationEpoch,
	}, nil
}

// validateSnapshot 校验备份内部一致性：元数据完整、每条凭证的当前版本存在、
// 密文三段齐全、绑定与授权引用可解析、标识唯一。
func validateSnapshot(snap *Snapshot) error {
	if len(snap.Meta.WrappedRootKey) == 0 || len(snap.Meta.WrapNonce) == 0 || len(snap.Meta.KDFSalt) == 0 {
		return fmt.Errorf("backup has no usable vault metadata")
	}
	creds := map[string]*model.Credential{}
	for _, c := range snap.Credentials {
		if c.ID == "" || c.Kind == "" {
			return fmt.Errorf("backup contains a credential without id or kind")
		}
		if _, dup := creds[c.ID]; dup {
			return fmt.Errorf("backup contains duplicate credential %s", c.ID)
		}
		creds[c.ID] = c
	}
	versions := map[string]map[int]bool{}
	for _, rec := range snap.Versions {
		if rec == nil || rec.CredentialID == "" || rec.Version <= 0 {
			return fmt.Errorf("backup contains an invalid credential version")
		}
		if _, ok := creds[rec.CredentialID]; !ok {
			return fmt.Errorf("backup version references unknown credential %s", rec.CredentialID)
		}
		if len(rec.Ciphertext) == 0 || len(rec.Nonce) == 0 || len(rec.WrappedDEK) == 0 || len(rec.WrapNonce) == 0 {
			return fmt.Errorf("backup version %s#%d is missing ciphertext material", rec.CredentialID, rec.Version)
		}
		if versions[rec.CredentialID] == nil {
			versions[rec.CredentialID] = map[int]bool{}
		}
		if versions[rec.CredentialID][rec.Version] {
			return fmt.Errorf("backup contains duplicate version %s#%d", rec.CredentialID, rec.Version)
		}
		versions[rec.CredentialID][rec.Version] = true
	}
	for id, c := range creds {
		if !versions[id][c.CurrentVersion] {
			return fmt.Errorf("credential %s points at missing version %d", id, c.CurrentVersion)
		}
	}
	principals := map[string]bool{}
	for _, p := range snap.Principals {
		if p == nil || p.ID == "" {
			return fmt.Errorf("backup contains a principal without id")
		}
		principals[p.ID] = true
	}
	bindings := map[string]bool{}
	for _, b := range snap.Bindings {
		if b == nil || b.ID == "" {
			return fmt.Errorf("backup contains a binding without id")
		}
		if _, ok := creds[b.CredentialID]; !ok {
			return fmt.Errorf("binding %s references unknown credential %s", b.ID, b.CredentialID)
		}
		bindings[b.ID] = true
	}
	for _, g := range snap.Grants {
		if g == nil || g.ID == "" {
			return fmt.Errorf("backup contains a grant without id")
		}
		if !bindings[g.BindingID] {
			return fmt.Errorf("grant %s references unknown binding %s", g.ID, g.BindingID)
		}
		if !principals[g.PrincipalID] {
			return fmt.Errorf("grant %s references unknown principal %s", g.ID, g.PrincipalID)
		}
	}
	return nil
}

// validateSnapshotDecryption 用备份声明的 KDF 参数和当前密码解锁会话的口令，
// 验证根密钥、根密钥校验块以及每个版本的 DEK、密文和字段 JSON。
func validateSnapshotDecryption(snap *Snapshot, password []byte) error {
	if len(password) == 0 {
		return model.NewError(model.CodeAuthRequired, "backup decryption requires the master password")
	}
	meta := &snap.Meta
	if meta.KDFAlgorithm != "argon2id" || meta.KDFTime == 0 || meta.KDFMemoryKiB == 0 || meta.KDFThreads == 0 {
		return fmt.Errorf("backup has unsupported or invalid KDF parameters")
	}
	kek := argon2.IDKey(password, meta.KDFSalt, meta.KDFTime, meta.KDFMemoryKiB, meta.KDFThreads, 32)
	defer zeroBytes(kek)
	gcm, err := newGCM(kek)
	if err != nil {
		return fmt.Errorf("initialize backup root key cipher: %w", err)
	}
	root, err := gcm.Open(nil, meta.WrapNonce, meta.WrappedRootKey, rootAAD())
	if err != nil {
		return model.NewError(model.CodeVaultUnlockFailed, "backup root key cannot be decrypted with the current master password")
	}
	defer zeroBytes(root)
	if len(root) != RootKeyLength {
		return fmt.Errorf("backup contains an invalid root key")
	}
	if len(meta.RootCheck) > 0 || len(meta.RootCheckNonce) > 0 {
		if len(meta.RootCheck) == 0 || len(meta.RootCheckNonce) == 0 {
			return fmt.Errorf("backup contains an incomplete root key check")
		}
		rootGCM, err := newGCM(root)
		if err != nil {
			return fmt.Errorf("initialize backup root check cipher: %w", err)
		}
		plain, err := rootGCM.Open(nil, meta.RootCheckNonce, meta.RootCheck, rootCheckAAD())
		if err != nil || string(plain) != rootCheckPlaintext {
			return fmt.Errorf("backup root key check is invalid")
		}
	}
	for _, rec := range snap.Versions {
		if _, err := decryptVersion(root, rec); err != nil {
			return fmt.Errorf("backup version %s#%d cannot be decrypted: %w", rec.CredentialID, rec.Version, err)
		}
	}
	return nil
}

// Epoch 返回当前授权代次。
func (v *Vault) Epoch() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.epoch
}
