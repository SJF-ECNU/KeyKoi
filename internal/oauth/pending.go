package oauth

import (
	"sync"
	"time"

	"keykoi/internal/model"
)

// Pending 是一次已开始但未完成的授权：PKCE verifier 只在这里驻留。
type Pending struct {
	State        string
	CredentialID string
	CodeVerifier string
	RedirectURI  string
	CreatedAt    time.Time
	// Version / Revision / Status 是发起登录时观察到的凭证记录状态。
	// 回调提交时据此判断记录是否被管理员停用或并行轮换改过；Version 为 0
	// 表示该待完成授权没有登记绑定（保持旧行为）。
	Version  int
	Revision int64
	Status   model.EntityStatus
}

// PendingStore 按 state 保存待完成授权。它同时承担两个职责：
//   - state 只有在此登记过才可能被回调接受（防伪造回调）；
//   - verifier 不出进程，CLI 与工具都拿不到。
type PendingStore struct {
	mu    sync.Mutex
	ttl   time.Duration
	items map[string]Pending
	now   func() time.Time
}

// NewPendingStore 构造待完成授权存储。ttl 为零时使用 10 分钟。
func NewPendingStore(ttl time.Duration) *PendingStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &PendingStore{ttl: ttl, items: map[string]Pending{}, now: func() time.Time { return time.Now().UTC() }}
}

// SetClock 便于测试注入时钟。
func (p *PendingStore) SetClock(now func() time.Time) {
	if now == nil {
		return
	}
	p.mu.Lock()
	p.now = now
	p.mu.Unlock()
}

// Put 登记一次待完成授权并返回其到期时间。
func (p *PendingStore) Put(pending Pending) time.Time {
	if pending.CreatedAt.IsZero() {
		pending.CreatedAt = p.now()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked()
	p.items[pending.State] = pending
	return pending.CreatedAt.Add(p.ttl)
}

// Take 取出并删除待完成授权；缺失或过期返回 false。取出即作废，防重放。
func (p *PendingStore) Take(state string) (Pending, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked()
	item, ok := p.items[state]
	if !ok {
		return Pending{}, false
	}
	delete(p.items, state)
	return item, true
}

// Len 返回当前未过期条目数，供测试与诊断使用。
func (p *PendingStore) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked()
	return len(p.items)
}

func (p *PendingStore) expireLocked() {
	now := p.now()
	for state, item := range p.items {
		if !now.Before(item.CreatedAt.Add(p.ttl)) {
			delete(p.items, state)
		}
	}
}

// RecoveryMark 记录一次“上游已推进但本地提交失败”的可见状态。
type RecoveryMark struct {
	At         time.Time
	Reason     string
	Version    int
	NextAction string
	Detail     string
}

// StateStore 保存进程级运行时状态：恢复标记与最近一次成功刷新的版本。
// 它不保存任何 token。恢复标记既写入凭证状态（持久），也留在这里，保证
// 状态可通过管理接口被诊断为 recovery_required。
type StateStore struct {
	mu        sync.Mutex
	recovery  map[string]RecoveryMark
	lastFresh map[string]int
}

// NewStateStore 构造运行时状态存储。
func NewStateStore() *StateStore {
	return &StateStore{recovery: map[string]RecoveryMark{}, lastFresh: map[string]int{}}
}

// MarkRecovery 记录恢复标记。
func (s *StateStore) MarkRecovery(credentialID string, mark RecoveryMark) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if mark.At.IsZero() {
		mark.At = time.Now().UTC()
	}
	s.recovery[credentialID] = mark
}

// Clear 清除恢复标记（重新授权成功后调用）。
func (s *StateStore) Clear(credentialID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.recovery, credentialID)
}

// Recovery 读取恢复标记。
func (s *StateStore) Recovery(credentialID string) (RecoveryMark, bool) {
	if s == nil {
		return RecoveryMark{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	mark, ok := s.recovery[credentialID]
	return mark, ok
}

// NoteFresh 记录最近一次成功写入的版本号。
func (s *StateStore) NoteFresh(credentialID string, version int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastFresh[credentialID] = version
}

// Fresh 返回最近一次成功写入的版本。
func (s *StateStore) Fresh(credentialID string) (int, bool) {
	if s == nil {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.lastFresh[credentialID]
	return v, ok
}
