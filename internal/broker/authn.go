package broker

import (
	"context"
	"sync"
	"time"

	"keykoi/internal/model"
)

// VerifyRequest 描述一次需要额外验证的授权请求。验证结果只影响这一次用钥，
// 或者按 Grant 的策略在该主体的缓存窗口内复用。
type VerifyRequest struct {
	PrincipalID string
	SessionID   string
	GrantID     string
	BindingID   string
	Mode        model.DeliveryMode
	Policy      model.AuthPolicy
	// CredentialVersion 与 BindingRevision 记录发起验证时的状态；状态变化后
	// 旧验证结果不再复用。
	CredentialVersion int
	BindingRevision   int64
}

// Verifier 触发一次系统级验证（macOS 上由 Touch ID 完成），返回实际使用的
// 验证方式：biometric / password。失败必须返回带稳定错误码的错误：
// AUTH_REQUIRED（用户取消或验证失败）或 AUTH_UNAVAILABLE（无生物识别/非 GUI 会话）。
type Verifier interface {
	Verify(ctx context.Context, req VerifyRequest) (method string, err error)
}

// VerifierFunc 让普通函数满足 Verifier。
type VerifierFunc func(ctx context.Context, req VerifyRequest) (string, error)

// Verify 调用函数本身。
func (f VerifierFunc) Verify(ctx context.Context, req VerifyRequest) (string, error) {
	return f(ctx, req)
}

// AuthEntry 是一条已验证记录。它只驻留内存，不含秘密。
type AuthEntry struct {
	PrincipalID string
	GrantID     string
	BindingID   string
	Mode        string
	Method      string
	SessionID   string
	VerifiedAt  time.Time
	ExpiresAt   time.Time
	// OneShot 标记该记录只能被消费一次（显式验证为 per_use 策略准备的一次性证明）。
	OneShot bool
	// CredentialVersion 与 BindingRevision 是在验证时观察到的状态。
	CredentialVersion int
	BindingRevision   int64
}

type authKey struct {
	principal string
	grant     string
	mode      string
}

// AuthCache 保存「主体 + 授权 + 方式」维度的验证状态。锁库、撤销、轮换与服务
// 重启都会清空它，因此它从不是持久授权。
type AuthCache struct {
	mu      sync.Mutex
	entries map[authKey]AuthEntry
	now     func() time.Time
}

// NewAuthCache 构造空缓存。now 为空时使用系统时钟。
func NewAuthCache(now func() time.Time) *AuthCache {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &AuthCache{entries: map[authKey]AuthEntry{}, now: now}
}

// Put 写入一条验证记录。
func (c *AuthCache) Put(e AuthEntry) {
	if e.PrincipalID == "" || e.GrantID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[authKey{principal: e.PrincipalID, grant: e.GrantID, mode: e.Mode}] = e
}

// Take 返回可复用的验证记录。过期记录被丢弃；一次性记录在返回时被消费。
func (c *AuthCache) Take(principalID, grantID, mode string) (AuthEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := authKey{principal: principalID, grant: grantID, mode: mode}
	e, ok := c.entries[key]
	if !ok {
		return AuthEntry{}, false
	}
	if !e.ExpiresAt.IsZero() && !c.now().Before(e.ExpiresAt) {
		delete(c.entries, key)
		return AuthEntry{}, false
	}
	if e.OneShot {
		delete(c.entries, key)
	}
	return e, true
}

// TakeMatching 取用一条满足条件的验证记录。不满足条件的记录保持原样，
// 不会被消费，因此不会因为「别的会话或别的版本」把有效记录用掉。
func (c *AuthCache) TakeMatching(principalID, grantID, mode string, accept func(AuthEntry) bool) (AuthEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := authKey{principal: principalID, grant: grantID, mode: mode}
	e, ok := c.entries[key]
	if !ok {
		return AuthEntry{}, false
	}
	if !e.ExpiresAt.IsZero() && !c.now().Before(e.ExpiresAt) {
		delete(c.entries, key)
		return AuthEntry{}, false
	}
	if accept != nil && !accept(e) {
		return AuthEntry{}, false
	}
	if e.OneShot {
		delete(c.entries, key)
	}
	return e, true
}

// Look 只读查询，不消费一次性记录，供状态展示使用。
func (c *AuthCache) Look(principalID, grantID, mode string) (AuthEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[authKey{principal: principalID, grant: grantID, mode: mode}]
	if !ok {
		return AuthEntry{}, false
	}
	if !e.ExpiresAt.IsZero() && !c.now().Before(e.ExpiresAt) {
		return AuthEntry{}, false
	}
	return e, true
}

// Clear 清空全部验证状态。
func (c *AuthCache) Clear() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.entries)
	c.entries = map[authKey]AuthEntry{}
	return n
}

// ClearForSession 清空某个会话的验证状态。
func (c *AuthCache) ClearForSession(sessionID string) int {
	if sessionID == "" {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k, e := range c.entries {
		if e.SessionID == sessionID {
			delete(c.entries, k)
			n++
		}
	}
	return n
}

// ClearForGrant 清空某个授权的验证状态。
func (c *AuthCache) ClearForGrant(grantID string) int {
	if grantID == "" {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k, e := range c.entries {
		if e.GrantID == grantID {
			delete(c.entries, k)
			n++
		}
	}
	return n
}

// Len 返回当前缓存的验证记录数。
func (c *AuthCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// AuthDecision 是一次授权策略的结果，直接写入审计。
type AuthDecision struct {
	Policy     string
	Method     string
	Result     string
	VerifiedAt time.Time
	Cached     bool
	// pending 是等待提交的验证记录。它只有在交付前重校验通过后才写入缓存，
	// 避免验证期间发生撤销、停用或轮换后仍留下可复用的旧决定。
	pending *AuthEntry
}

// Commit 在交付前重校验通过后提交本次验证结果。未产生记录或策略为 per_use 时
// 什么也不做。
func (a *Authenticator) Commit(d AuthDecision) {
	if a == nil || d.pending == nil {
		return
	}
	a.cache.Put(*d.pending)
}

// Authenticator 按 Grant 的验证策略决定是否需要系统验证，并维护内存验证状态。
type Authenticator struct {
	cache    *AuthCache
	verifier Verifier
	now      func() time.Time
}

// NewAuthenticator 构造授权策略执行器。verifier 为空时所有需要验证的策略都会
// 以 AUTH_UNAVAILABLE 拒绝，绝不静默放行。
func NewAuthenticator(v Verifier, now func() time.Time) *Authenticator {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Authenticator{cache: NewAuthCache(now), verifier: v, now: now}
}

// Cache 暴露内存验证状态，供 daemon 显式验证与清理使用。
func (a *Authenticator) Cache() *AuthCache { return a.cache }

// Require 执行一次策略判定。返回的 AuthDecision 无论成功失败都可用于审计。
func (a *Authenticator) Require(ctx context.Context, req VerifyRequest) (AuthDecision, error) {
	policy := req.Policy
	if policy.Kind == "" {
		policy = model.AuthPolicy{Kind: model.AuthOnce}
	}
	decision := AuthDecision{Policy: policy.String(), Method: "none", Result: "not_required"}
	if !policy.RequiresVerification() {
		return decision, nil
	}
	if entry, ok := a.cache.TakeMatching(req.PrincipalID, req.GrantID, string(req.Mode), func(e AuthEntry) bool {
		// 凭证版本或绑定改版后，旧验证结果不再适用于新状态。
		if e.CredentialVersion != 0 && req.CredentialVersion != 0 && e.CredentialVersion != req.CredentialVersion {
			return false
		}
		if e.BindingRevision != 0 && req.BindingRevision != 0 && e.BindingRevision != req.BindingRevision {
			return false
		}
		// once 只在其产生它的会话内复用；没有会话的预验证是一次性交换，
		// 只能被消费一次，不会变成跨会话通配。
		if policy.Kind == model.AuthOnce {
			if e.SessionID == "" {
				return e.OneShot
			}
			return req.SessionID != "" && e.SessionID == req.SessionID
		}
		return true
	}); ok {
		return AuthDecision{
			Policy: policy.String(), Method: entry.Method, Result: "reused",
			VerifiedAt: entry.VerifiedAt, Cached: true,
		}, nil
	}
	if a.verifier == nil {
		return AuthDecision{Policy: policy.String(), Method: "none", Result: "unavailable"},
			model.NewError(model.CodeAuthUnavailable, "no verification provider is configured for auth policy %q", policy.String())
	}
	method, err := a.verifier.Verify(ctx, req)
	if err != nil {
		decision.Result = "failed"
		if model.CodeOf(err) == model.CodeAuthUnavailable {
			decision.Result = "unavailable"
		}
		return decision, err
	}
	if method == "" {
		method = "biometric"
	}
	now := a.now()
	decision = AuthDecision{Policy: policy.String(), Method: method, Result: "verified", VerifiedAt: now}
	// 验证本身已经完成这次请求的校验；只有 once/window 需要写入可复用的记录。
	// 记录先挂起，等交付前重校验通过再由 Broker 提交。
	if policy.Kind != model.AuthPerUse {
		entry := entryFor(policy, req, method, now)
		if policy.Kind == model.AuthOnce && entry.SessionID == "" {
			// 没有会话的 once 验证不能复用，只对当前这次用钥有效。
			return decision, nil
		}
		decision.pending = &entry
	}
	return decision, nil
}

// RecordVerification 记录一次显式验证（POST /v1/auth/verify）的结果。
// 它按该 Grant 的策略决定复用范围：once 必须绑定具体会话，window 给定时长，
// per_use 只放行一次，permanent 不记录。
func (a *Authenticator) RecordVerification(req VerifyRequest, method string) (AuthDecision, error) {
	policy := req.Policy
	if policy.Kind == "" {
		policy = model.AuthPolicy{Kind: model.AuthOnce}
	}
	now := a.now()
	decision := AuthDecision{Policy: policy.String(), Method: method, Result: "verified", VerifiedAt: now}
	if !policy.RequiresVerification() {
		return decision, nil
	}
	entry := entryFor(policy, req, method, now)
	if policy.Kind == model.AuthOnce && req.SessionID == "" {
		// 没有会话的预验证是明确的一次性交换：只能放行一次，消费即失效。
		entry.OneShot = true
		decision.Result = "verified_once"
	}
	a.cache.Put(entry)
	return decision, nil
}

// entryFor 把一次成功的验证转换成缓存记录。
func entryFor(policy model.AuthPolicy, req VerifyRequest, method string, now time.Time) AuthEntry {
	e := AuthEntry{
		PrincipalID:       req.PrincipalID,
		GrantID:           req.GrantID,
		BindingID:         req.BindingID,
		Mode:              string(req.Mode),
		Method:            method,
		SessionID:         req.SessionID,
		VerifiedAt:        now,
		CredentialVersion: req.CredentialVersion,
		BindingRevision:   req.BindingRevision,
	}
	switch policy.Kind {
	case model.AuthWindow:
		e.ExpiresAt = now.Add(policy.Window)
	case model.AuthPerUse:
		e.OneShot = true
	}
	return e
}
