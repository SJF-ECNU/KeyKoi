// Package store 定义 KeyKoi 的持久化边界。SQLite 与 PostgreSQL 实现同一接口，
// P0 原型使用内存实现。存储只接触密文与非秘密元数据，加密由 vault 负责。
package store

import (
	"context"
	"errors"
	"time"

	"keykoi/internal/model"
)

// ErrNotFound 表示记录不存在。
var ErrNotFound = errors.New("not found")

// ErrConflict 表示版本条件或唯一约束冲突。
var ErrConflict = errors.New("conflict")

// VersionRecord 是一个加密后的完整凭证组合。
type VersionRecord struct {
	CredentialID      string
	Version           int
	Ciphertext        []byte
	Nonce             []byte
	WrappedDEK        []byte
	WrapNonce         []byte
	CryptoVersion     int
	ProviderExpiresAt *time.Time
	CreatedAt         time.Time
}

// VaultMeta 保存根密钥包装与 KDF 元数据，不含裸根密钥。
type VaultMeta struct {
	SchemaVersion  int
	CryptoVersion  int
	KDFAlgorithm   string
	KDFSalt        []byte
	KDFTime        uint32
	KDFMemoryKiB   uint32
	KDFThreads     uint8
	WrappedRootKey []byte
	WrapNonce      []byte
	// RootCheck / RootCheckNonce 是用根密钥加密的固定校验块。它让「根密钥属于
	// 这个密钥库」在空库上也可验证，恢复另一套空库后旧登记不会解锁错误对象。
	RootCheck          []byte
	RootCheckNonce     []byte
	AuthorizationEpoch string
	CreatedAt          time.Time
}

// Principal 是本机账户或注册设备。
type Principal struct {
	ID                string
	IdentityType      string
	IdentityReference string
	Status            model.EntityStatus
	// Admin 标记该主体可发起管理请求；管理与用钥权限分别评估。
	Admin bool
}

// AuditEvent 只记录允许的元数据。
type AuditEvent struct {
	ID                string
	Time              time.Time
	PrincipalID       string
	SessionID         string
	BindingID         string
	CredentialID      string
	CredentialVersion int
	Mode              string
	Result            string
	ErrorCode         string
	DurationMS        int64
	Detail            string
	// AuthMethod 是本次用钥前实际使用的验证方式：biometric / password / none。
	AuthMethod string `json:"auth_method"`
	// AuthResult 是验证策略的结果：verified / reused / not_required / failed / unavailable。
	AuthResult string `json:"auth_result"`
}

// IntegrationRecord 是已接入工具的状态、受管字段与配置指纹。
type IntegrationRecord struct {
	ID                 string
	ProfileID          string
	ToolVersion        string
	OS                 string
	Mechanism          string
	ConfigPath         string
	Section            string
	ManagedKey         string
	ManagedFingerprint string
	State              string
	VerifiedVersion    string
	BackupPath         string
	Detail             string
}

// Store 是 KeyKoi 的持久化接口。
type Store interface {
	Close() error

	VaultMeta(ctx context.Context) (*VaultMeta, error)
	PutVaultMeta(ctx context.Context, meta *VaultMeta) error

	CreateCredential(ctx context.Context, c *model.Credential) error
	// CreateCredentialWithVersion 在同一事务内写入凭证索引与首个加密版本。
	CreateCredentialWithVersion(ctx context.Context, c *model.Credential, rec *VersionRecord) error
	GetCredential(ctx context.Context, id string) (*model.Credential, error)
	ListCredentials(ctx context.Context) ([]*model.Credential, error)
	UpdateCredentialStatus(ctx context.Context, id string, status model.EntityStatus, revision int64) error
	// UpdateProviderExpiry 同步当前版本的原平台真实到期时间到凭证索引。
	UpdateProviderExpiry(ctx context.Context, id string, expires *time.Time) error

	// PutVersion 插入新版本；版本号由调用方在事务外分配，冲突返回 ErrConflict。
	PutVersion(ctx context.Context, rec *VersionRecord) error
	GetVersion(ctx context.Context, credentialID string, version int) (*VersionRecord, error)
	// CurrentVersion 按凭证记录中的 current_version 返回完整版本记录，
	// 保证一次读取只来自一个版本。
	CurrentVersion(ctx context.Context, credentialID string) (*VersionRecord, error)
	// ActivateVersionCAS 与 ActivateVersion 相同，但只在记录 revision 仍等于
	// expectedRevision 时提交；否则返回 ErrConflict 且不写入。调用方据此把
	// 「记录未变」与「写入新版本」合并成一次原子决定。
	ActivateVersionCAS(ctx context.Context, credentialID string, rec *VersionRecord, expectedRevision int64) (*model.Credential, error)
	// ActivateVersion 在同一事务内插入新版本、切换当前版本并同步原平台到期时间。
	// 轮换不能分三次写库：中断会留下已插入但未启用的版本，并让下一次轮换撞号。
	ActivateVersion(ctx context.Context, credentialID string, rec *VersionRecord) (*model.Credential, error)
	// SetCurrentVersion 在事务内校验目标版本存在并切换指针，同时递增 revision。
	SetCurrentVersion(ctx context.Context, credentialID string, version int, expectedRevision int64) (*model.Credential, error)
	ListVersions(ctx context.Context, credentialID string) ([]int, error)
	DeleteVersion(ctx context.Context, credentialID string, version int) error

	PutBinding(ctx context.Context, b *model.Binding) error
	GetBinding(ctx context.Context, id string) (*model.Binding, error)
	GetBindingByRoute(ctx context.Context, route string) (*model.Binding, error)
	ListBindings(ctx context.Context) ([]*model.Binding, error)
	UpdateBindingStatus(ctx context.Context, id string, status model.EntityStatus, revision int64) error

	PutIntegration(ctx context.Context, rec *IntegrationRecord) error
	GetIntegration(ctx context.Context, id string) (*IntegrationRecord, error)
	ListIntegrations(ctx context.Context) ([]*IntegrationRecord, error)
	DeleteIntegration(ctx context.Context, id string) error

	PutPrincipal(ctx context.Context, p *Principal) error
	GetPrincipal(ctx context.Context, id string) (*Principal, error)
	ListPrincipals(ctx context.Context) ([]*Principal, error)
	UpdatePrincipalStatus(ctx context.Context, id string, status model.EntityStatus) error

	// PutGrant 写入授权；写入 active 授权时原子取代同（主体、绑定、方式）的其他有效授权。
	PutGrant(ctx context.Context, g *model.Grant) error
	GetGrant(ctx context.Context, id string) (*model.Grant, error)
	ListGrants(ctx context.Context, principalID string) ([]*model.Grant, error)
	// UpdateGrantStatus 激活授权时若同组已有其他有效授权则返回 ErrConflict。
	UpdateGrantStatus(ctx context.Context, id string, status model.EntityStatus, revision int64) error

	// ReplaceVault 用备份内容整体替换当前密钥库行，用于密文备份恢复。
	ReplaceVault(ctx context.Context, meta *VaultMeta, creds []*model.Credential, versions []*VersionRecord, bindings []*model.Binding, principals []*Principal, grants []*model.Grant) error

	AppendAudit(ctx context.Context, e *AuditEvent) error
	ListAudit(ctx context.Context, limit int) ([]*AuditEvent, error)
}
