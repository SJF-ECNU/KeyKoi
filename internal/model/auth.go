package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AuthPolicyKind 是 Grant 的额外验证策略。它回答「这次用钥之前需不需要再验一次人」，
// 与 DeliveryMode（工具能否看到真实值）是两个正交的维度。
type AuthPolicyKind string

const (
	// AuthOnce 表示同一会话内只验证一次；新会话需要重新验证。
	AuthOnce AuthPolicyKind = "once"
	// AuthWindow 表示验证后 N 秒内复用同一主体的验证结果。
	AuthWindow AuthPolicyKind = "window"
	// AuthPerUse 表示每次用钥都触发系统验证（Touch ID）。
	AuthPerUse AuthPolicyKind = "per_use"
	// AuthPermanent 表示不要求额外验证；只应在用户二次确认后使用。
	AuthPermanent AuthPolicyKind = "permanent"
)

// DefaultAuthRequirement 是新建 Grant 的默认策略：会话内验证一次。
const DefaultAuthRequirement = "once"

// maxAuthWindow 限制 window 策略的上限，避免写出一份实际等于 permanent 的策略。
const maxAuthWindow = 7 * 24 * time.Hour

// AuthPolicy 是解析后的验证策略。
type AuthPolicy struct {
	Kind AuthPolicyKind
	// Window 只在 Kind == AuthWindow 时有意义。
	Window time.Duration
}

// RequiresVerification 报告该策略是否需要系统验证。
func (p AuthPolicy) RequiresVerification() bool {
	switch p.Kind {
	case AuthOnce, AuthWindow, AuthPerUse:
		return true
	}
	return false
}

// String 返回入库用的规范形式：once、window:<秒>、per_use、permanent。
func (p AuthPolicy) String() string {
	switch p.Kind {
	case AuthWindow:
		return "window:" + strconv.Itoa(int(p.Window/time.Second))
	case AuthPerUse:
		return string(AuthPerUse)
	case AuthPermanent:
		return string(AuthPermanent)
	case AuthOnce:
		return string(AuthOnce)
	}
	return DefaultAuthRequirement
}

// Describe 返回面向界面的中文说明。
func (p AuthPolicy) Describe() string {
	switch p.Kind {
	case AuthWindow:
		return fmt.Sprintf("验证后 %d 秒内复用", int(p.Window/time.Second))
	case AuthPerUse:
		return "每次用钥都验证"
	case AuthPermanent:
		return "永久授权（不验证）"
	case AuthOnce:
		return "同一会话内验证一次"
	}
	return "同一会话内验证一次"
}

// ParseAuthPolicy 解析 once|window:N|per_use|permanent。空串按默认 once 处理。
// 接受 per-use、window=300、window:5m 等写法，输出统一存为规范形式。
func ParseAuthPolicy(raw string) (AuthPolicy, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return AuthPolicy{Kind: AuthOnce}, nil
	}
	switch s {
	case "once", "session":
		return AuthPolicy{Kind: AuthOnce}, nil
	case "per_use", "per-use", "peruse", "each":
		return AuthPolicy{Kind: AuthPerUse}, nil
	case "permanent", "always", "never":
		return AuthPolicy{Kind: AuthPermanent}, nil
	}
	if rest, ok := strings.CutPrefix(s, "window:"); ok || strings.HasPrefix(s, "window=") {
		if !ok {
			rest = strings.TrimPrefix(s, "window=")
		}
		window, err := parseAuthWindow(strings.TrimSpace(rest))
		if err != nil {
			return AuthPolicy{}, fmt.Errorf("invalid window in auth policy %q: %w", raw, err)
		}
		if window <= 0 || window > maxAuthWindow {
			return AuthPolicy{}, fmt.Errorf("auth policy window must be between 1s and %s", maxAuthWindow)
		}
		return AuthPolicy{Kind: AuthWindow, Window: window}, nil
	}
	return AuthPolicy{}, fmt.Errorf("invalid auth policy %q: expected once, window:<seconds>, per_use or permanent", raw)
}

func parseAuthWindow(v string) (time.Duration, error) {
	if v == "" {
		return 0, fmt.Errorf("empty window")
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(v)
}

// AuthPolicy 返回该 Grant 的验证策略。历史库中的空值按 once 处理。
func (g Grant) AuthPolicy() AuthPolicy {
	p, err := ParseAuthPolicy(g.AuthRequirement)
	if err != nil {
		return AuthPolicy{Kind: AuthOnce}
	}
	return p
}
