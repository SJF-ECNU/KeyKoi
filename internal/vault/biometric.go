package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"keykoi/internal/model"
)

// BiometricStore 抽象「由系统生物识别保护的根密钥存取」。macOS 上由
// packaging/macos/keykoi-biometric.swift 编译出的助手实现；测试用替身实现同一契约。
//
// 设计约束：根密钥始终是随机 32 字节，只在 Keychain 条目的 ACL 上绑定
// biometryCurrentSet；指纹本身不参与密钥派生，因此新增或删除指纹会使条目失效，
// 主密码仍是唯一可恢复的入口。
type BiometricStore interface {
	// Available 报告当前会话能否使用生物识别；reason 为面向人的说明。
	Available(ctx context.Context) (available bool, reason string, err error)
	// Store 把根密钥写入系统保护存储。
	Store(ctx context.Context, account string, root []byte) error
	// Load 触发系统验证后取出根密钥。
	Load(ctx context.Context, account string) ([]byte, error)
	// Delete 删除已登记的根密钥条目。
	Delete(ctx context.Context, account string) error
}

// 助手进程的退出码语义，与 Swift 助手保持一致。
const (
	BiometricExitOK          = 0
	BiometricExitNoBiometry  = 2
	BiometricExitCancelled   = 3
	BiometricExitUnavailable = 4
)

// HelperClient 调用 macOS 生物识别助手。
type HelperClient struct {
	Path    string
	Account string
	Timeout time.Duration
}

// NewHelperClient 构造助手客户端。path 为空时所有调用都返回 AUTH_UNAVAILABLE。
func NewHelperClient(path, account string) *HelperClient {
	if account == "" {
		account = DefaultBiometricAccount
	}
	return &HelperClient{Path: path, Account: account, Timeout: 60 * time.Second}
}

// DefaultBiometricAccount 是 Keychain 条目的账户名。
const DefaultBiometricAccount = "keykoi-root"

func (c *HelperClient) account(override string) string {
	if override != "" {
		return override
	}
	if c.Account != "" {
		return c.Account
	}
	return DefaultBiometricAccount
}

// Available 调用助手的 available 子命令。
func (c *HelperClient) Available(ctx context.Context) (bool, string, error) {
	if c == nil || c.Path == "" {
		return false, "biometric helper is not configured", nil
	}
	_, stderr, err := c.run(ctx, "available", nil)
	if err == nil {
		return true, "Touch ID is available", nil
	}
	reason := strings.TrimSpace(string(stderr))
	if reason == "" {
		reason = err.Error()
	}
	return false, reason, nil
}

// Store 把根密钥交给系统保护存储。
func (c *HelperClient) Store(ctx context.Context, account string, root []byte) error {
	if c == nil || c.Path == "" {
		return model.NewError(model.CodeAuthUnavailable, "biometric helper is not configured")
	}
	payload := []byte(base64.StdEncoding.EncodeToString(root) + "\n")
	_, _, err := c.run(ctx, "store", payload, "--account", c.account(account))
	return err
}

// Load 触发系统验证并返回根密钥副本。
func (c *HelperClient) Load(ctx context.Context, account string) ([]byte, error) {
	if c == nil || c.Path == "" {
		return nil, model.NewError(model.CodeAuthUnavailable, "biometric helper is not configured")
	}
	stdout, _, err := c.run(ctx, "load", nil, "--account", c.account(account))
	if err != nil {
		return nil, err
	}
	root, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(stdout)))
	if decErr != nil {
		return nil, model.NewError(model.CodeAuthUnavailable, "biometric helper returned malformed data")
	}
	if len(root) != 32 {
		return nil, model.NewError(model.CodeAuthUnavailable, "biometric helper returned a root key of %d bytes", len(root))
	}
	return root, nil
}

// Delete 删除已登记的条目。
func (c *HelperClient) Delete(ctx context.Context, account string) error {
	if c == nil || c.Path == "" {
		return model.NewError(model.CodeAuthUnavailable, "biometric helper is not configured")
	}
	_, _, err := c.run(ctx, "delete", nil, "--account", c.account(account))
	return err
}

// run 执行助手子命令并映射退出码到稳定错误码。
func (c *HelperClient) run(ctx context.Context, sub string, stdin []byte, extra ...string) ([]byte, []byte, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := append([]string{sub}, extra...)
	cmd := exec.CommandContext(runCtx, c.Path, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), stderr.Bytes(), nil
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return stdout.Bytes(), stderr.Bytes(), model.WrapError(model.CodeAuthUnavailable, err,
			"biometric verification timed out after %s", timeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = fmt.Sprintf("biometric helper exited with code %d", exitErr.ExitCode())
		}
		switch exitErr.ExitCode() {
		case BiometricExitNoBiometry:
			return stdout.Bytes(), stderr.Bytes(), model.WrapError(model.CodeAuthUnavailable, err, "no biometric hardware or enrollment: %s", msg)
		case BiometricExitCancelled:
			return stdout.Bytes(), stderr.Bytes(), model.WrapError(model.CodeAuthRequired, err, "biometric verification was cancelled: %s", msg)
		case BiometricExitUnavailable:
			return stdout.Bytes(), stderr.Bytes(), model.WrapError(model.CodeAuthUnavailable, err, "biometric verification is unavailable: %s", msg)
		}
		return stdout.Bytes(), stderr.Bytes(), model.WrapError(model.CodeAuthUnavailable, err, "biometric helper failed: %s", msg)
	}
	return stdout.Bytes(), stderr.Bytes(), model.WrapError(model.CodeAuthUnavailable, err, "cannot run biometric helper %s", c.Path)
}
