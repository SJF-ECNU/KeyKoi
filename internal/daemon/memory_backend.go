package daemon

import (
	"context"
	"errors"
	"sync"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/store"
)

// MemoryBackend 是 P0 原型后端：凭证只保存在进程内，不做持久化加密。
// 它存在的原因是把授权与交付链路先跑通；P1 的持久化版本由 vault 提供。
type MemoryBackend struct {
	mu     sync.Mutex
	store  store.Store
	src    *broker.MemorySource
	locked bool
}

// NewMemoryBackend 构造内存后端。
func NewMemoryBackend(st store.Store, src *broker.MemorySource) *MemoryBackend {
	return &MemoryBackend{store: st, src: src}
}

// Materialize 返回指定版本；锁定状态直接拒绝。
func (m *MemoryBackend) Materialize(ctx context.Context, credentialID string, version int) (model.CredentialVersion, error) {
	m.mu.Lock()
	locked := m.locked
	m.mu.Unlock()
	if locked {
		return model.CredentialVersion{}, model.NewError(model.CodeVaultLocked, "vault is locked")
	}
	return m.src.Materialize(ctx, credentialID, version)
}

// Locked 报告锁定状态。
func (m *MemoryBackend) Locked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.locked
}

// CreateCredential 写入凭证索引与首个版本。
func (m *MemoryBackend) CreateCredential(ctx context.Context, meta model.Credential, version model.CredentialVersion) (*model.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return nil, model.NewError(model.CodeVaultLocked, "vault is locked")
	}
	m.src.Put(version)
	if err := m.store.CreateCredential(ctx, &meta); err != nil {
		return nil, err
	}
	return m.store.GetCredential(ctx, meta.ID)
}

// AddVersion 写入新版本并切换当前版本。
func (m *MemoryBackend) AddVersion(ctx context.Context, credentialID string, version model.CredentialVersion) (*model.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return nil, model.NewError(model.CodeVaultLocked, "vault is locked")
	}
	cur, err := m.store.GetCredential(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if version.Version != cur.CurrentVersion+1 {
		version.Version = cur.CurrentVersion + 1
	}
	m.src.Put(version)
	return m.store.SetCurrentVersion(ctx, credentialID, version.Version, 0)
}

// ActivateVersionCAS 只在 revision 未变时写入新版本。
func (m *MemoryBackend) ActivateVersionCAS(ctx context.Context, credentialID string, version model.CredentialVersion, expectedRevision int64) (*model.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return nil, model.NewError(model.CodeVaultLocked, "vault is locked")
	}
	cur, err := m.store.GetCredential(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	version.Version = cur.CurrentVersion + 1
	m.src.Put(version)
	// 原型后端不做加密，但当前版本指针仍然要走存储层的事务化 CAS：
	// 记录在写入前已被并发修改时不能切换版本。
	rec := &store.VersionRecord{
		CredentialID: credentialID, Version: version.Version,
		ProviderExpiresAt: version.ProviderExpiresAt, CreatedAt: time.Now().UTC(),
	}
	return m.store.ActivateVersionCAS(ctx, credentialID, rec, expectedRevision)
}

// Lock 锁定后端并清理内存凭证引用。
func (m *MemoryBackend) Lock(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locked = true
	m.src.Lock()
	return nil
}

// Unlock 解除锁定；内存后端没有主密码。
func (m *MemoryBackend) Unlock(context.Context, []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locked = false
	m.src.Unlock()
	return nil
}

// State 返回 locked / unlocked。
func (m *MemoryBackend) State() string {
	if m.Locked() {
		return "locked"
	}
	return "unlocked"
}

// Describe 返回不含秘密的摘要。
func (m *MemoryBackend) Describe() string {
	return "memory prototype backend (no persistence). " + m.src.Describe()
}

// Close 释放资源。
func (m *MemoryBackend) Close() error { return nil }

var _ = errors.Is
