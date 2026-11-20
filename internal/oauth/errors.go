package oauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Class 是可操作失败类别。调用方据此决定重试、重新登录还是人工恢复。
type Class string

const (
	// ClassRetryable：网络错误、上游 5xx/429/408，可原样重试。
	ClassRetryable Class = "retryable"
	// ClassRevoked：refresh_token 已被撤销或轮换失效（invalid_grant），需重新登录。
	ClassRevoked Class = "revoked"
	// ClassReauth：缺少或无法使用 refresh_token、授权码失效，需重新登录。
	ClassReauth Class = "reauth_required"
	// ClassRejected：上游明确拒绝请求（配置或参数问题），重试无意义。
	ClassRejected Class = "upstream_rejected"
	// ClassMalformed：上游响应不合规，未写入任何本地版本。
	ClassMalformed Class = "malformed_response"
	// ClassConfig：凭证字段缺少或非法。
	ClassConfig Class = "config_invalid"
	// ClassRecovery：上游已经轮换成功，但本地提交失败；旧 refresh_token 可能已失效。
	ClassRecovery Class = "recovery_required"
	// ClassConflict：记录在操作期间被并行改动（版本、修订号或状态），本次写入被放弃。
	ClassConflict Class = "conflict"
	// ClassLocal：本地读写或内部错误。
	ClassLocal Class = "local"
)

// 冲突错误使用的稳定 Code 值，供调用方区分具体原因（正文只用于展示）。
const (
	// CodeCredentialChanged：记录在在途操作期间被管理员或并行轮换改动。
	CodeCredentialChanged = "credential_changed"
	// CodeVersionConflict：调用方的预期版本与当前版本不一致。
	CodeVersionConflict = "version_conflict"
)

// Error 是 OAuth 交互的结构化错误。正文与 Hint 都不含 token 原文。
type Error struct {
	Class Class
	// Op 是 begin / exchange / refresh / commit / status。
	Op string
	// Code 是上游 OAuth error 值（如 invalid_grant）或空。
	Code string
	// Status 是上游 HTTP 状态码；0 表示没有响应。
	Status int
	// Message 是可直接展示的短说明。
	Message string
	// Retryable 与 RecoveryRequired 是给调用方的机器可读提示。
	Retryable        bool
	RecoveryRequired bool
	// Version 是操作涉及的凭证版本（可用时）。
	Version int
	Cause   error
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("oauth")
	if e.Op != "" {
		b.WriteString(" " + e.Op)
	}
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	if e.Status > 0 {
		fmt.Fprintf(&b, " (upstream HTTP %d)", e.Status)
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Cause }

func newError(class Class, op, code string, status int, cause error, format string, args ...any) *Error {
	e := &Error{Class: class, Op: op, Code: code, Status: status, Message: fmt.Sprintf(format, args...), Cause: cause}
	switch class {
	case ClassRetryable:
		e.Retryable = true
	case ClassRecovery:
		e.RecoveryRequired = true
	}
	return e
}

func configError(format string, args ...any) *Error {
	return newError(ClassConfig, "", "", 0, nil, format, args...)
}

func localError(op string, cause error) *Error {
	return newError(ClassLocal, op, "", 0, cause, "local persistence or runtime error")
}

func networkError(op string, cause error) *Error {
	msg := "upstream token endpoint is unreachable"
	var nerr net.Error
	if errors.As(cause, &nerr) && nerr.Timeout() {
		msg = "upstream token endpoint timed out"
	}
	if errors.Is(cause, context.Canceled) {
		msg = "oauth request canceled"
	}
	return newError(ClassRetryable, op, "", 0, cause, "%s", msg)
}

func malformedError(op, msg string) *Error {
	return newError(ClassMalformed, op, "", 0, nil, "%s", msg)
}

// conflictError 表示记录在操作期间被并行改动，本次写入已被放弃。
func conflictError(op, code string, format string, args ...any) *Error {
	return newError(ClassConflict, op, code, 0, nil, format, args...)
}

// redirectError 表示令牌端点返回了跳转。跟踪跳转会把表单带离登记的端点，
// 所以跳转既不被跟随，也不被当作成功。
func redirectError(op string, status int) *Error {
	return newError(ClassRejected, op, "redirect_not_followed", status, nil,
		"token endpoint responded with HTTP %d redirect; token requests never leave the registered token endpoint", status)
}

func reauthError(op, msg string) *Error {
	return newError(ClassReauth, op, "", 0, nil, "%s", msg)
}

// upstreamStatusError 把上游错误按 OAuth 语义分流：
// invalid_grant 代表凭证已失效（撤销/轮换），其余 4xx 是请求被拒绝，
// 5xx/429/408 是可重试的临时故障。
func upstreamStatusError(op string, status int, code, description string) *Error {
	desc := strings.TrimSpace(sanitize(description))
	code = strings.TrimSpace(code)
	switch {
	case status == http.StatusTooManyRequests, status == http.StatusRequestTimeout, status >= 500:
		return newError(ClassRetryable, op, code, status, nil, "token endpoint temporary failure%s", suffix(desc))
	case code == "invalid_grant":
		return newError(ClassRevoked, op, code, status, nil, "refresh token was revoked or already rotated; re-authorization is required%s", suffix(desc))
	case code == "invalid_client", code == "unauthorized_client":
		return newError(ClassConfig, op, code, status, nil, "client credentials were rejected by the token endpoint%s", suffix(desc))
	case code == "invalid_request", code == "unsupported_grant_type", code == "invalid_scope":
		return newError(ClassRejected, op, code, status, nil, "token endpoint rejected the request%s", suffix(desc))
	case code != "":
		return newError(ClassRejected, op, code, status, nil, "token endpoint returned %s%s", code, suffix(desc))
	default:
		return newError(ClassRejected, op, code, status, nil, "token endpoint returned HTTP %d%s", status, suffix(desc))
	}
}

func suffix(desc string) string {
	if desc == "" {
		return ""
	}
	return ": " + desc
}

// sanitize 限制上游描述长度，避免把大块响应写进日志或错误正文。
func sanitize(s string) string {
	s = strings.ToValidUTF8(strings.TrimSpace(s), "")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// ClassOf 提取错误类别；非 oauth 错误返回空。
func ClassOf(err error) Class {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return ""
}

// IsRetryable 报告错误是否可原样重试。
func IsRetryable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Retryable || e.Class == ClassRetryable
	}
	return false
}

// NeedsReauth 报告是否必须重新走登录流程。
func NeedsReauth(err error) bool {
	c := ClassOf(err)
	return c == ClassRevoked || c == ClassReauth
}

// IsConflict 报告记录是否在操作期间被并行改动，导致本次写入被放弃。
func IsConflict(err error) bool {
	return ClassOf(err) == ClassConflict
}

// RecoveryRequired 报告“上游已轮换但本地提交失败”的恢复状态。
func RecoveryRequired(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.RecoveryRequired || e.Class == ClassRecovery
	}
	return false
}
