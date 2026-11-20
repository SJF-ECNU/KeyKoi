package model

import (
	"errors"
	"fmt"
)

// Code 是稳定错误码。响应不带秘密与完整请求内容。
type Code string

const (
	CodeVaultLocked           Code = "VAULT_LOCKED"
	CodeVaultUnlockFailed     Code = "VAULT_UNLOCK_FAILED"
	CodeSessionInvalid        Code = "SESSION_INVALID"
	CodeUseNotAllowed         Code = "USE_NOT_ALLOWED"
	CodeBindingDisabled       Code = "BINDING_DISABLED"
	CodeLeaseExpired          Code = "LEASE_EXPIRED"
	CodeCredentialUnavailable Code = "CREDENTIAL_UNAVAILABLE"
	CodeAdapterUnsupported    Code = "ADAPTER_UNSUPPORTED"
	CodeConfigDrift           Code = "CONFIG_DRIFT"
	CodeUpstreamAuthFailed    Code = "UPSTREAM_AUTH_FAILED"
	CodeUpstreamUnavailable   Code = "UPSTREAM_UNAVAILABLE"
	CodeControlUnavailable    Code = "CONTROL_UNAVAILABLE"
	// CodeAuthRequired 表示这次请求还需要一次显式验证（生物识别被取消或拒绝）。
	CodeAuthRequired Code = "AUTH_REQUIRED"
	// CodeAuthUnavailable 表示当前环境无法完成额外验证（无生物识别、非 GUI 会话、
	// 未登记根密钥）。调用方应回退主密码；回退也不可用时必须明确报错。
	CodeAuthUnavailable Code = "AUTH_UNAVAILABLE"
)

// Error 是 KeyKoi 自身的可识别错误封装。
type Error struct {
	Code    Code
	Message string
	// Cause 为底层原因；调用方不应把它拼进面向工具的错误正文。
	Cause error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

// NewError 构造稳定错误。
func NewError(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// WrapError 构造带原因的稳定错误。
func WrapError(code Code, cause error, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Cause: cause}
}

// CodeOf 提取错误码；非 KeyKoi 错误返回空。
func CodeOf(err error) Code {
	var ke *Error
	if errors.As(err, &ke) {
		return ke.Code
	}
	return ""
}
