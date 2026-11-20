package daemon

import (
	"context"
	"sync"
)

// RunnerRegistry 跟踪受管理系统运行，用于锁定与服务停止时取消。
type RunnerRegistry struct {
	mu     sync.Mutex
	cancel map[string]context.CancelFunc
}

// NewRunnerRegistry 构造空注册表。
func NewRunnerRegistry() *RunnerRegistry {
	return &RunnerRegistry{cancel: map[string]context.CancelFunc{}}
}

// Add 登记一个运行。
func (r *RunnerRegistry) Add(id string, cancel context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cancel[id] = cancel
}

// Remove 解除登记。
func (r *RunnerRegistry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cancel, id)
}

// KillAll 取消全部登记运行。
func (r *RunnerRegistry) KillAll() {
	r.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(r.cancel))
	for _, c := range r.cancel {
		cancels = append(cancels, c)
	}
	r.cancel = map[string]context.CancelFunc{}
	r.mu.Unlock()
	for _, c := range cancels {
		c()
	}
}

// IntegrationState 是接入的运行时状态摘要，供诊断展示。
type IntegrationState struct {
	ID                string `json:"id"`
	ProfileID         string `json:"profile_id"`
	State             string `json:"state"`
	ToolVersion       string `json:"tool_version"`
	OS                string `json:"os"`
	ConfigPath        string `json:"config_path"`
	ConfigFingerprint string `json:"config_fingerprint"`
	VerifiedVersion   string `json:"verified_version"`
}

// IntegrationRegistry 保存接入的运行时状态。
type IntegrationRegistry struct {
	mu sync.Mutex
	m  map[string]*IntegrationState
}

// NewIntegrationRegistry 构造空注册表。
func NewIntegrationRegistry() *IntegrationRegistry {
	return &IntegrationRegistry{m: map[string]*IntegrationState{}}
}

// OAuthRegistry 为同一凭证的刷新提供串行锁。
type OAuthRegistry struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// NewOAuthRegistry 构造空注册表。
func NewOAuthRegistry() *OAuthRegistry {
	return &OAuthRegistry{locks: map[string]*sync.Mutex{}}
}

// Lock 返回凭证级互斥锁，保证同一 Credential 的刷新串行。
func (o *OAuthRegistry) Lock(credentialID string) *sync.Mutex {
	o.mu.Lock()
	defer o.mu.Unlock()
	if l, ok := o.locks[credentialID]; ok {
		return l
	}
	l := &sync.Mutex{}
	o.locks[credentialID] = l
	return l
}
