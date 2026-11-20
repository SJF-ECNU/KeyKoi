package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"keykoi/internal/model"
)

// Memory 是 P0 原型与测试使用的内存实现。它不做加密，只用于验证授权、
// 注入与交付通道；持久化版本由 SQLite 实现。
type Memory struct {
	mu           sync.RWMutex
	meta         *VaultMeta
	credentials  map[string]*model.Credential
	versions     map[string]map[int]*VersionRecord
	bindings     map[string]*model.Binding
	principals   map[string]*Principal
	grants       map[string]*model.Grant
	audit        []*AuditEvent
	integrations map[string]*IntegrationRecord
}

// NewMemory 构造空的内存存储。
func NewMemory() *Memory {
	return &Memory{
		credentials:  map[string]*model.Credential{},
		versions:     map[string]map[int]*VersionRecord{},
		bindings:     map[string]*model.Binding{},
		principals:   map[string]*Principal{},
		grants:       map[string]*model.Grant{},
		integrations: map[string]*IntegrationRecord{},
	}
}

func (m *Memory) Close() error { return nil }

func (m *Memory) VaultMeta(context.Context) (*VaultMeta, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.meta == nil {
		return nil, ErrNotFound
	}
	cp := *m.meta
	return &cp, nil
}

func (m *Memory) PutVaultMeta(_ context.Context, meta *VaultMeta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *meta
	m.meta = &cp
	return nil
}

func (m *Memory) CreateCredential(_ context.Context, c *model.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.credentials[c.ID]; ok {
		return ErrConflict
	}
	cp := *c
	if cp.Revision == 0 {
		cp.Revision = 1
	}
	m.credentials[c.ID] = &cp
	return nil
}

func (m *Memory) CreateCredentialWithVersion(_ context.Context, c *model.Credential, rec *VersionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.credentials[c.ID]; ok {
		return ErrConflict
	}
	cp := *c
	if cp.Revision == 0 {
		cp.Revision = 1
	}
	if _, ok := m.versions[c.ID]; !ok {
		m.versions[c.ID] = map[int]*VersionRecord{}
	}
	rc := *rec
	m.versions[c.ID][rec.Version] = &rc
	m.credentials[c.ID] = &cp
	return nil
}

func (m *Memory) ReplaceVault(_ context.Context, meta *VaultMeta, creds []*model.Credential, versions []*VersionRecord, bindings []*model.Binding, principals []*Principal, grants []*model.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cpMeta := *meta
	m.meta = &cpMeta
	// 与 SQLite 实现一致：恢复同时清空审计与接入状态。
	m.audit = nil
	m.integrations = map[string]*IntegrationRecord{}
	m.credentials = map[string]*model.Credential{}
	m.versions = map[string]map[int]*VersionRecord{}
	m.bindings = map[string]*model.Binding{}
	m.principals = map[string]*Principal{}
	m.grants = map[string]*model.Grant{}
	for _, c := range creds {
		cp := *c
		m.credentials[c.ID] = &cp
	}
	for _, v := range versions {
		cp := *v
		if _, ok := m.versions[v.CredentialID]; !ok {
			m.versions[v.CredentialID] = map[int]*VersionRecord{}
		}
		m.versions[v.CredentialID][v.Version] = &cp
	}
	for _, b := range bindings {
		cp := *b
		m.bindings[b.ID] = &cp
	}
	for _, p := range principals {
		cp := *p
		m.principals[p.ID] = &cp
	}
	for _, g := range grants {
		cp := *g
		m.grants[g.ID] = &cp
	}
	return nil
}

func (m *Memory) GetCredential(_ context.Context, id string) (*model.Credential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.credentials[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (m *Memory) ListCredentials(context.Context) ([]*model.Credential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*model.Credential, 0, len(m.credentials))
	for _, c := range m.credentials {
		cp := *c
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) UpdateCredentialStatus(_ context.Context, id string, status model.EntityStatus, revision int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.credentials[id]
	if !ok {
		return ErrNotFound
	}
	if revision != 0 && c.Revision != revision {
		return ErrConflict
	}
	c.Status = status
	c.Revision++
	return nil
}

func (m *Memory) UpdateProviderExpiry(_ context.Context, id string, expires *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.credentials[id]
	if !ok {
		return ErrNotFound
	}
	c.ProviderExpiresAt = expires
	return nil
}

func (m *Memory) PutVersion(_ context.Context, rec *VersionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	byID, ok := m.versions[rec.CredentialID]
	if !ok {
		byID = map[int]*VersionRecord{}
		m.versions[rec.CredentialID] = byID
	}
	if _, exists := byID[rec.Version]; exists {
		return ErrConflict
	}
	cp := *rec
	byID[rec.Version] = &cp
	return nil
}

func (m *Memory) GetVersion(_ context.Context, credentialID string, version int) (*VersionRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	byID, ok := m.versions[credentialID]
	if !ok {
		return nil, ErrNotFound
	}
	rec, ok := byID[version]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *rec
	return &cp, nil
}

func (m *Memory) CurrentVersion(_ context.Context, credentialID string) (*VersionRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.credentials[credentialID]
	if !ok {
		return nil, ErrNotFound
	}
	rec, ok := m.versions[credentialID][c.CurrentVersion]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *rec
	return &cp, nil
}

// ActivateVersion 在一个事务语义下插入新版本并切换当前版本。
func (m *Memory) ActivateVersion(_ context.Context, credentialID string, rec *VersionRecord) (*model.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.credentials[credentialID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *rec
	if _, exists := m.versions[credentialID][rec.Version]; !exists {
		if m.versions[credentialID] == nil {
			m.versions[credentialID] = map[int]*VersionRecord{}
		}
	}
	m.versions[credentialID][rec.Version] = &cp
	c.CurrentVersion = rec.Version
	c.ProviderExpiresAt = rec.ProviderExpiresAt
	c.Revision++
	out := *c
	return &out, nil
}

// ActivateVersionCAS 只在 revision 未变时插入新版本并切换当前版本。
func (m *Memory) ActivateVersionCAS(_ context.Context, credentialID string, rec *VersionRecord, expectedRevision int64) (*model.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.credentials[credentialID]
	if !ok {
		return nil, ErrNotFound
	}
	if c.Revision != expectedRevision {
		return nil, ErrConflict
	}
	cp := *rec
	if m.versions[credentialID] == nil {
		m.versions[credentialID] = map[int]*VersionRecord{}
	}
	m.versions[credentialID][rec.Version] = &cp
	c.CurrentVersion = rec.Version
	c.ProviderExpiresAt = rec.ProviderExpiresAt
	c.Revision++
	out := *c
	return &out, nil
}

func (m *Memory) SetCurrentVersion(_ context.Context, credentialID string, version int, expectedRevision int64) (*model.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.credentials[credentialID]
	if !ok {
		return nil, ErrNotFound
	}
	if _, ok := m.versions[credentialID][version]; !ok {
		return nil, fmt.Errorf("version %d: %w", version, ErrNotFound)
	}
	if expectedRevision != 0 && c.Revision != expectedRevision {
		return nil, ErrConflict
	}
	c.CurrentVersion = version
	c.Revision++
	cp := *c
	return &cp, nil
}

func (m *Memory) ListVersions(_ context.Context, credentialID string) ([]int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []int
	for v := range m.versions[credentialID] {
		out = append(out, v)
	}
	sort.Ints(out)
	return out, nil
}

func (m *Memory) DeleteVersion(_ context.Context, credentialID string, version int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	byID, ok := m.versions[credentialID]
	if !ok {
		return ErrNotFound
	}
	if _, ok := byID[version]; !ok {
		return ErrNotFound
	}
	if c := m.credentials[credentialID]; c != nil && c.CurrentVersion == version {
		return ErrConflict
	}
	delete(byID, version)
	return nil
}

func (m *Memory) PutBinding(_ context.Context, b *model.Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *b
	if existing, ok := m.bindings[b.ID]; ok {
		// 与 SQLite 的 upsert 一致：每次更新都前进 revision，交付重校验才能发现改绑。
		cp.Revision = existing.Revision + 1
	} else {
		if cp.Revision == 0 {
			cp.Revision = 1
		}
		b.Revision = cp.Revision
	}
	m.bindings[b.ID] = &cp
	return nil
}

func (m *Memory) GetBinding(_ context.Context, id string) (*model.Binding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.bindings[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *b
	return &cp, nil
}

func (m *Memory) GetBindingByRoute(_ context.Context, route string) (*model.Binding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// 与 SQLite 实现保持同样的选择规则：有效状态优先，其次按 id 排序。
	var chosen *model.Binding
	for _, b := range m.bindings {
		if b.Route != route {
			continue
		}
		if chosen == nil {
			chosen = b
			continue
		}
		chosenActive := chosen.Status == model.StatusActive
		candidateActive := b.Status == model.StatusActive
		if candidateActive != chosenActive {
			if candidateActive {
				chosen = b
			}
			continue
		}
		if b.ID < chosen.ID {
			chosen = b
		}
	}
	if chosen == nil {
		return nil, ErrNotFound
	}
	cp := *chosen
	return &cp, nil
}

func (m *Memory) ListBindings(context.Context) ([]*model.Binding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*model.Binding, 0, len(m.bindings))
	for _, b := range m.bindings {
		cp := *b
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) UpdateBindingStatus(_ context.Context, id string, status model.EntityStatus, revision int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bindings[id]
	if !ok {
		return ErrNotFound
	}
	if revision != 0 && b.Revision != revision {
		return ErrConflict
	}
	b.Status = status
	b.Revision++
	return nil
}

func (m *Memory) PutIntegration(_ context.Context, rec *IntegrationRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *rec
	m.integrations[rec.ID] = &cp
	return nil
}

func (m *Memory) GetIntegration(_ context.Context, id string) (*IntegrationRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.integrations[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *rec
	return &cp, nil
}

func (m *Memory) ListIntegrations(context.Context) ([]*IntegrationRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*IntegrationRecord, 0, len(m.integrations))
	for _, rec := range m.integrations {
		cp := *rec
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) DeleteIntegration(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.integrations, id)
	return nil
}

func (m *Memory) PutPrincipal(_ context.Context, p *Principal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *p
	m.principals[p.ID] = &cp
	return nil
}

func (m *Memory) GetPrincipal(_ context.Context, id string) (*Principal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.principals[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (m *Memory) ListPrincipals(context.Context) ([]*Principal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Principal, 0, len(m.principals))
	for _, p := range m.principals {
		cp := *p
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) UpdatePrincipalStatus(_ context.Context, id string, status model.EntityStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.principals[id]
	if !ok {
		return ErrNotFound
	}
	p.Status = status
	return nil
}

func (m *Memory) PutGrant(_ context.Context, g *model.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g.Revision == 0 {
		g.Revision = 1
	}
	if g.Status == model.StatusActive {
		// 新建与取代在同一把存储锁内完成，不能给并发请求留下两个有效授权。
		for id, old := range m.grants {
			if id != g.ID && old.Status == model.StatusActive && old.PrincipalID == g.PrincipalID &&
				old.BindingID == g.BindingID && old.DeliveryMode == g.DeliveryMode {
				old.Status = model.StatusRevoked
				old.Revision++
			}
		}
	}
	cp := *g
	m.grants[g.ID] = &cp
	return nil
}

func (m *Memory) GetGrant(_ context.Context, id string) (*model.Grant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.grants[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *g
	return &cp, nil
}

func (m *Memory) ListGrants(_ context.Context, principalID string) ([]*model.Grant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*model.Grant
	for _, g := range m.grants {
		if principalID == "" || g.PrincipalID == principalID {
			cp := *g
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) UpdateGrantStatus(_ context.Context, id string, status model.EntityStatus, revision int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return ErrNotFound
	}
	if revision != 0 && g.Revision != revision {
		return ErrConflict
	}
	if status == model.StatusActive && g.Status != model.StatusActive {
		// approve 不能复活已被新授权取代的旧记录。
		for otherID, other := range m.grants {
			if otherID != id && other.Status == model.StatusActive && other.PrincipalID == g.PrincipalID &&
				other.BindingID == g.BindingID && other.DeliveryMode == g.DeliveryMode {
				return ErrConflict
			}
		}
	}
	g.Status = status
	g.Revision++
	return nil
}

func (m *Memory) AppendAudit(_ context.Context, e *AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *e
	if cp.Time.IsZero() {
		cp.Time = time.Now().UTC()
	}
	m.audit = append(m.audit, &cp)
	return nil
}

func (m *Memory) ListAudit(_ context.Context, limit int) ([]*AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*AuditEvent, len(m.audit))
	copy(out, m.audit)
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}
