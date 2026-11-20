// Package helper 实现原生外部凭证助手协议。首批目标是 AWS CLI 的
// credential_process：助手按 CLI 要求把凭证组合写到 stdout，且只走声明通道。
package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"keykoi/internal/ipcclient"
)

// AWSOutput 是 AWS CLI credential_process 的 JSON 结构。
// 字段名由 CLI 固定；Expiration 只来自原平台真实到期时间。
type AWSOutput struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}

// AWSOptions 配置 AWS 助手。
type AWSOptions struct {
	Client    *ipcclient.Client
	BindingID string
	// Mode 固定为 runtime_delivery；Helper 不能借用 proxy 许可。
	Mode string
	// Now 便于测试注入时钟。
	Now func() time.Time
}

// RunAWS 通过受认证 IPC 取得完整凭证版本，并按 CLI 协议写到 w。
// 任何失败只输出稳定错误码，不输出凭证内容。
func RunAWS(_ context.Context, opts AWSOptions, w io.Writer) error {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	sess, err := opts.Client.CreateSession("helper:aws-credential-process", false)
	if err != nil {
		return err
	}
	mode := opts.Mode
	if mode == "" {
		mode = "runtime_delivery"
	}
	res, err := opts.Client.Resolve(sess.Token, opts.BindingID, mode)
	if err != nil {
		return err
	}
	out := AWSOutput{Version: 1}
	out.AccessKeyID = res.Fields["access_id"]
	out.SecretAccessKey = res.Fields["access_secret"]
	out.SessionToken = res.Fields["session_token"]
	if out.AccessKeyID == "" || out.SecretAccessKey == "" {
		return fmt.Errorf("CREDENTIAL_UNAVAILABLE: binding %s does not expose access_id/access_secret", opts.BindingID)
	}
	// 严格采用原平台真实有效期：没有真实到期时间的静态 key 不输出 Expiration。
	if res.ProviderExpiresAt != nil {
		out.Expiration = res.ProviderExpiresAt.UTC().Format(time.RFC3339)
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("HELPER_OUTPUT_FAILED: %w", err)
	}
	return nil
}

// GitOutput 是 git credential helper 的协议响应。
type GitOutput struct {
	Username string
	Password string
}

// RunGit 实现 git credential helper 的 get 动作。store/erase 为只读策略：
// 一次 store 不覆盖已有托管值，一次 erase 不删除中心凭证。
func RunGit(ctx context.Context, opts AWSOptions, action string, input io.Reader, w io.Writer) error {
	switch action {
	case "get":
		sess, err := opts.Client.CreateSession("helper:git-credential", false)
		if err != nil {
			return err
		}
		mode := opts.Mode
		if mode == "" {
			mode = "runtime_delivery"
		}
		res, err := opts.Client.Resolve(sess.Token, opts.BindingID, mode)
		if err != nil {
			return err
		}
		user := res.Fields["username"]
		if user == "" {
			user = res.Fields["access_id"]
		}
		pw := res.Fields["password"]
		if pw == "" {
			pw = res.Fields["token"]
		}
		if pw == "" {
			return fmt.Errorf("CREDENTIAL_UNAVAILABLE: binding %s has no password/token field", opts.BindingID)
		}
		_, err = fmt.Fprintf(w, "username=%s\npassword=%s\n", user, pw)
		return err
	case "store":
		// 只读首版：接受输入但不写回中心存储。
		_, _ = io.Copy(io.Discard, input)
		return nil
	case "erase":
		// 只读首版：erase 不删除托管凭证。
		_, _ = io.Copy(io.Discard, input)
		return nil
	default:
		return fmt.Errorf("ADAPTER_UNSUPPORTED: unknown git credential action %q", action)
	}
}
