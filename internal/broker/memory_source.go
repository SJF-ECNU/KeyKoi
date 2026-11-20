package broker

import (
	"context"
	"fmt"
	"sync"

	"keykoi/internal/model"
)

// MemorySource 是 P0 原型与测试使用的内存凭证源。它只在进程内保存生成值，
// 不做持久化或应用层加密；持久化版本由 vault 实现。
type MemorySource struct {
	mu       sync.RWMutex
	versions map[string]map[int]model.CredentialVersion
	locked   bool
}

// NewMemorySource 构造空的内存凭证源。
func NewMemorySource() *MemorySource {
	return &MemorySource{versions: map[string]map[int]model.CredentialVersion{}}
}

// Put 登记一个完整凭证版本。
func (m *MemorySource) Put(v model.CredentialVersion) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byID, ok := m.versions[v.CredentialID]
	if !ok {
		byID = map[int]model.CredentialVersion{}
		m.versions[v.CredentialID] = byID
	}
	byID[v.Version] = v.Clone()
}

// Materialize 返回指定完整版本。
func (m *MemorySource) Materialize(_ context.Context, credentialID string, version int) (model.CredentialVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.locked {
		return model.CredentialVersion{}, model.NewError(model.CodeVaultLocked, "vault is locked")
	}
	v, ok := m.versions[credentialID][version]
	if !ok {
		return model.CredentialVersion{}, model.NewError(model.CodeCredentialUnavailable,
			"credential %s version %d is unavailable", credentialID, version)
	}
	return v.Clone(), nil
}

// Locked 报告是否处于锁定状态。
func (m *MemorySource) Locked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.locked
}

// Lock 模拟锁定。
func (m *MemorySource) Lock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locked = true
}

// Unlock 解除锁定。
func (m *MemorySource) Unlock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locked = false
}

// Delete 删除一个版本，用于验证不可用路径。
func (m *MemorySource) Delete(credentialID string, version int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.versions[credentialID], version)
}

// Describe 返回不含秘密的调试摘要。
func (m *MemorySource) Describe() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return fmt.Sprintf("memory source: %d credentials, locked=%v", len(m.versions), m.locked)
}
