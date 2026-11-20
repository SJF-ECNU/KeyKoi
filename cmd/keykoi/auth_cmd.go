package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"keykoi/internal/ipcclient"
)

// cmdVault 提供密钥库层面的生物识别登记操作。
func cmdVault(sub string, args []string) error {
	switch sub {
	case "enroll-biometric":
		var out map[string]any
		if err := client().Post("/v1/vault/enroll-biometric", map[string]any{}, &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out)
		}
		fmt.Println("root key enrolled for Touch ID unlock (macOS Keychain, biometryCurrentSet)")
		fmt.Println("主密码仍是唯一可用恢复入口：删除指纹或条目后仍可用主密码解锁。")
		return nil
	case "status":
		return cmdAuth("status", args)
	}
	return fmt.Errorf("unknown vault subcommand %q (expected enroll-biometric|status)", sub)
}

// cmdAuth 提供显式验证与生物识别状态查询。
func cmdAuth(sub string, args []string) error {
	switch sub {
	case "", "status":
		return cmdAuthStatus()
	case "verify":
		return cmdAuthVerify(args)
	}
	return fmt.Errorf("unknown auth subcommand %q (expected status|verify)", sub)
}

func cmdAuthStatus() error {
	var out struct {
		Biometric map[string]any   `json:"biometric"`
		Auth      map[string]any   `json:"auth"`
		Grants    []map[string]any `json:"grants"`
	}
	if err := client().Get("/v1/auth/status", &out); err != nil {
		return err
	}
	if g.json {
		return printJSON(out)
	}
	bio := out.Biometric
	fmt.Printf("biometric: available=%v enrolled=%v account=%v\n", bio["available"], bio["enrolled"], bio["account"])
	if reason, ok := bio["reason"].(string); ok && reason != "" {
		fmt.Printf("  reason:  %s\n", reason)
	}
	if last, ok := bio["last_error"].(string); ok && last != "" {
		fmt.Printf("  problem: %s\n", last)
	}
	if auth := out.Auth; auth != nil {
		fmt.Printf("default policy: %v   password fallback: %v\n", auth["default_policy"], auth["password_fallback"])
		if cached, ok := auth["cached_verifications"]; ok {
			fmt.Printf("cached verifications: %v\n", cached)
		}
	}
	if len(out.Grants) > 0 {
		fmt.Println("grant policies:")
		for _, row := range out.Grants {
			fmt.Printf("  %v  %v  %v/%v\n", row["grant_id"], row["auth_requirement"], row["principal_id"], row["delivery_mode"])
		}
	}
	return nil
}

func cmdAuthVerify(args []string) error {
	fs := flag.NewFlagSet("auth verify", flag.ContinueOnError)
	method := fs.String("method", "biometric", "biometric|password")
	grantID := fs.String("grant", "", "grant id to pre-authorize (optional)")
	mode := fs.String("mode", "", "delivery mode for the pre-authorized grant")
	sessionID := fs.String("session", "", "session id for once-policy verification")
	fromStdin := fs.Bool("password-stdin", false, "read the master password from stdin (--method password)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body := map[string]any{"method": *method, "grant_id": *grantID, "mode": *mode, "session_id": *sessionID}
	if *method == "password" {
		pw, err := readPassword(*fromStdin)
		if err != nil {
			return fmt.Errorf("AUTH_UNAVAILABLE: master password fallback is not available: %w", err)
		}
		body["password"] = string(pw)
	} else if *method != "biometric" {
		return fmt.Errorf("unsupported --method %q (expected biometric|password)", *method)
	}
	var out map[string]any
	if err := client().Post("/v1/auth/verify", body, &out); err != nil {
		var apiErr *ipcclient.APIError
		if errors.As(err, &apiErr) && apiErr.Code == "AUTH_UNAVAILABLE" && *method == "biometric" {
			fmt.Fprintln(os.Stderr, "Touch ID 不可用；可用 --method password 回退主密码。")
		}
		return err
	}
	if g.json {
		return printJSON(out)
	}
	fmt.Printf("verified with %v", out["method"])
	if gid, ok := out["grant_id"].(string); ok && gid != "" {
		fmt.Printf("; grant %s auth=%v", gid, out["auth_requirement"])
	}
	fmt.Println()
	return nil
}
