package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"keykoi/internal/oauth"
)

// cmdOAuth 是托管 OAuth 登录与刷新的管理入口。
// 所有子命令都只输出元数据：token 原文不经过 CLI。
func cmdOAuth(sub string, args []string) error {
	switch sub {
	case "begin":
		return oauthBegin(args)
	case "callback":
		return oauthCallback(args)
	case "refresh":
		return oauthRefresh(args)
	case "status":
		return oauthStatus(args)
	case "", "help", "--help", "-h":
		oauthUsage()
		return nil
	}
	return fmt.Errorf("unknown oauth subcommand %q", sub)
}

func oauthUsage() {
	fmt.Print(`用法:
  keykoi oauth begin    --credential ID [--out url.txt]
  keykoi oauth callback --credential ID --code CODE --state STATE
  keykoi oauth refresh  --credential ID [--force]
  keykoi oauth status   --credential ID

说明:
  begin     生成 PKCE + state，输出受信授权入口 URL；PKCE verifier 不出后台。
  callback  用回调代码完成交换，原子写入新版本并失效旧许可。
  refresh   串行刷新同一凭证；--force 忽略缓存有效期，但同一凭证仍然只推进一次。
  status    只显示版本、真实到期、缓存到期与状态。

提供方形态: ` + oauth.ProviderKind + `
`)
}

func oauthBegin(args []string) error {
	fs := flag.NewFlagSet("oauth begin", flag.ContinueOnError)
	cred := fs.String("credential", "", "credential id")
	out := fs.String("out", "", "write the authorization URL to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cred == "" {
		return fmt.Errorf("--credential is required")
	}
	var res struct {
		AuthorizationURL string `json:"authorization_url"`
		State            string `json:"state"`
		RedirectURI      string `json:"redirect_uri"`
		ExpiresAt        string `json:"expires_at"`
		Provider         string `json:"provider"`
	}
	if err := client().Post("/v1/oauth/begin", map[string]any{"credential_id": *cred}, &res); err != nil {
		return err
	}
	if res.AuthorizationURL == "" || res.State == "" {
		return fmt.Errorf("keykoid returned an incomplete authorization entry")
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(res.AuthorizationURL+"\n"), 0o600); err != nil {
			return err
		}
	}
	if g.json {
		return printJSON(res)
	}
	fmt.Printf("authorize: %s\n", res.AuthorizationURL)
	fmt.Printf("state:     %s\n", res.State)
	fmt.Printf("redirect:  %s\n", res.RedirectURI)
	fmt.Printf("expires:   %s\n", res.ExpiresAt)
	if *out != "" {
		fmt.Printf("url file:  %s\n", *out)
	}
	fmt.Println("下一步: 在受信浏览器完成授权，然后执行 keykoi oauth callback --credential " + *cred + " --code CODE --state STATE")
	return nil
}

func oauthCallback(args []string) error {
	fs := flag.NewFlagSet("oauth callback", flag.ContinueOnError)
	cred := fs.String("credential", "", "credential id")
	code := fs.String("code", "", "authorization code from the callback")
	state := fs.String("state", "", "state returned by the provider")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cred == "" || *code == "" || *state == "" {
		return fmt.Errorf("--credential, --code and --state are required")
	}
	var res oauth.Result
	if err := client().Post("/v1/oauth/callback", map[string]any{
		"credential_id": *cred, "code": *code, "state": *state,
	}, &res); err != nil {
		return err
	}
	if g.json {
		return printJSON(res)
	}
	fmt.Printf("authorized %s at version %d (status=%s)\n", res.CredentialID, res.Version, res.Status)
	printOAuthMetadata(res)
	return nil
}

func oauthRefresh(args []string) error {
	fs := flag.NewFlagSet("oauth refresh", flag.ContinueOnError)
	cred := fs.String("credential", "", "credential id")
	force := fs.Bool("force", false, "refresh even when the cached expiry looks fresh")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cred == "" {
		return fmt.Errorf("--credential is required")
	}
	var res oauth.Result
	if err := client().Post("/v1/oauth/refresh", map[string]any{
		"credential_id": *cred, "force": *force,
	}, &res); err != nil {
		return err
	}
	if g.json {
		return printJSON(res)
	}
	if res.Refreshed {
		fmt.Printf("refreshed %s to version %d (rotated=%t)\n", res.CredentialID, res.Version, res.Rotated)
	} else {
		fmt.Printf("no refresh needed for %s (version %d, next_action=%s)\n", res.CredentialID, res.Version, res.NextAction)
	}
	printOAuthMetadata(res)
	return nil
}

func oauthStatus(args []string) error {
	fs := flag.NewFlagSet("oauth status", flag.ContinueOnError)
	cred := fs.String("credential", "", "credential id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cred == "" {
		return fmt.Errorf("--credential is required")
	}
	var res oauth.Result
	if err := client().Post("/v1/oauth/refresh", map[string]any{
		"credential_id": *cred, "dry_run": true,
	}, &res); err != nil {
		return err
	}
	if g.json {
		return printJSON(res)
	}
	fmt.Printf("%s  version=%d status=%s\n", res.CredentialID, res.Version, res.Status)
	printOAuthMetadata(res)
	return nil
}

// printOAuthMetadata 只展示元数据；token 原文永远不会出现在这里。
func printOAuthMetadata(res oauth.Result) {
	fmt.Printf("  expires_at:        %s\n", timeOrDash(res.ExpiresAt))
	fmt.Printf("  cache_expires_at:  %s\n", timeOrDash(res.CacheExpiresAt))
	fmt.Printf("  expired:           %t\n", res.Expired)
	fmt.Printf("  recovery_required: %t\n", res.RecoveryRequired)
	fmt.Printf("  next_action:       %s\n", res.NextAction)
	if res.TokenType != "" {
		fmt.Printf("  token_type:        %s\n", res.TokenType)
	}
	if res.RevokedLeases > 0 {
		fmt.Printf("  revoked_leases:    %d\n", res.RevokedLeases)
	}
}

func timeOrDash(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}
