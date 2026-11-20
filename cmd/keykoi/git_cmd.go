package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"keykoi/internal/integration"
)

func cmdGit(sub string, args []string) error {
	switch sub {
	case "setup":
		return gitSetup(args)
	case "teardown":
		return gitTeardown(args)
	default:
		return fmt.Errorf("unknown git subcommand %q; use setup|teardown", sub)
	}
}

func gitSetup(args []string) error {
	fs := flag.NewFlagSet("git setup", flag.ContinueOnError)
	host := fs.String("host", "", "repository host to intercept, e.g. github.com")
	binding := fs.String("binding", "", "binding id used for proxy authorization")
	route := fs.String("route", "", "gateway route name (default: looked up from the binding)")
	gateway := fs.String("gateway", "", "gateway address (default: from daemon status)")
	configFile := fs.String("file", "", "git config file (default: ~/.gitconfig)")
	self := fs.String("keykoi-bin", "", "keykoi binary used by the credential helper")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" || *binding == "" {
		return fmt.Errorf("--host and --binding are required")
	}
	hostName := normalizeHost(*host)
	routeName := *route
	if routeName == "" {
		r, err := bindingRoute(*binding)
		if err != nil {
			return err
		}
		routeName = r
	}
	gw := *gateway
	if gw == "" {
		st, err := client().Status()
		if err != nil {
			return err
		}
		gw, _ = st["gateway"].(string)
		if gw == "" {
			return fmt.Errorf("daemon has no gateway address; pass --gateway")
		}
	}
	bin := *self
	if bin == "" {
		if exe, err := os.Executable(); err == nil {
			bin = exe
		} else {
			bin = "keykoi"
		}
	}
	base := "http://" + gw + "/gateway/" + routeName
	cfg := *configFile
	if cfg == "" {
		home, _ := os.UserHomeDir()
		cfg = filepath.Join(home, ".gitconfig")
	}
	// git 按最后一段识别配置键，URL 中的点因此在 key 里保持原样。
	if err := gitConfig(cfg, "url."+base+"/.insteadOf", "https://"+hostName+"/"); err != nil {
		return err
	}
	// git 以 sh 执行 helper 值；按 sh 语法引用，可执行文件路径含空格（macOS 默认
	// 安装位置）时也能启动。
	helperValue := integration.GitCredentialHelper(bin, *binding)
	if err := gitConfig(cfg, "credential."+base+".helper", helperValue); err != nil {
		return err
	}
	if err := gitConfig(cfg, "credential."+base+".username", "keykoi"); err != nil {
		return err
	}
	fmt.Printf("git rewritten: https://%s/ -> %s/\n", hostName, base)
	fmt.Printf("credential helper: %s\n", strings.TrimPrefix(helperValue, "!"))
	fmt.Println("仓库只会拿到中介令牌；真实凭据由网关注入。")
	return nil
}

func gitTeardown(args []string) error {
	fs := flag.NewFlagSet("git teardown", flag.ContinueOnError)
	host := fs.String("host", "", "repository host")
	route := fs.String("route", "", "gateway route name")
	gateway := fs.String("gateway", "", "gateway address")
	configFile := fs.String("file", "", "git config file (default: ~/.gitconfig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	gw := *gateway
	if gw == "" {
		if st, err := client().Status(); err == nil {
			gw, _ = st["gateway"].(string)
		}
	}
	cfg := *configFile
	if cfg == "" {
		home, _ := os.UserHomeDir()
		cfg = filepath.Join(home, ".gitconfig")
	}
	if *route != "" && gw != "" {
		base := "http://" + gw + "/gateway/" + *route
		_ = gitUnset(cfg, "url."+base+"/.insteadOf")
		_ = gitUnset(cfg, "credential."+base+".helper")
		_ = gitUnset(cfg, "credential."+base+".username")
	}
	if *host != "" && gw != "" && *route != "" {
		fmt.Printf("removed git rewrite for https://%s/\n", normalizeHost(*host))
	}
	return nil
}

func normalizeHost(h string) string {
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	return strings.TrimSuffix(h, "/")
}

func bindingRoute(id string) (string, error) {
	var out struct {
		Bindings []struct {
			ID    string `json:"id"`
			Route string `json:"route"`
		} `json:"bindings"`
	}
	if err := client().Get("/v1/bindings", &out); err != nil {
		return "", err
	}
	for _, b := range out.Bindings {
		if b.ID == id && b.Route != "" {
			return b.Route, nil
		}
	}
	return "", fmt.Errorf("binding %s has no route; pass --route", id)
}

func gitConfig(file, key, value string) error {
	cmd := exec.Command("git", "config", "--file", file, "--replace-all", key, value)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git config failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func gitUnset(file, key string) error {
	cmd := exec.Command("git", "config", "--file", file, "--unset-all", key)
	_, err := cmd.CombinedOutput()
	return err
}

var _ = json.Marshal
