package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"keykoi/internal/osruntime"
	"keykoi/internal/shim"
)

func cmdShim(sub string, args []string) error {
	switch sub {
	case "install":
		return shimInstall(args)
	case "remove":
		return shimRemove(args)
	case "", "list":
		return shimList(args)
	}
	return fmt.Errorf("unknown shim subcommand %q; use install|list|remove", sub)
}

func shimInstall(args []string) error {
	fs := flag.NewFlagSet("shim install", flag.ContinueOnError)
	name := fs.String("name", "", "command name to intercept (e.g. aliyun)")
	exe := fs.String("exe", "", "absolute path of the real tool")
	binding := fs.String("binding", "", "binding id used for runtime_delivery")
	inherit := fs.Bool("inherit-env", true, "inherit the current shell environment (mapped names are overridden)")
	updateShell := fs.Bool("update-shell", false, "add the shim directory to PATH in the shell startup file")
	shellRC := fs.String("shell-rc", "", "shell startup file (default: ~/.zshrc)")
	skipCheck := fs.Bool("skip-check", false, "skip the preflight authorization check")
	var env kvFlag
	var prepend sliceFlag
	fs.Var(&env, "env", "NAME=field:<field> | NAME=runtime:session_token | NAME=literal:<value>")
	fs.Var(&prepend, "prepend-arg", "argument inserted before user args for credential calls (repeatable, e.g. --config-path /path/no-config.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *exe == "" || *binding == "" {
		return fmt.Errorf("--name, --exe and --binding are required")
	}
	dataDir := g.dataDir
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if !*skipCheck {
		if err := preflightBinding(dataDir, *binding); err != nil {
			return fmt.Errorf("preflight failed: %w (rerun with --skip-check to install anyway)", err)
		}
	}
	rec, err := shim.Install(shim.InstallConfig{
		DataDir: dataDir, Name: *name, Executable: *exe, BindingID: *binding,
		Env: env.Map(), InheritEnv: *inherit, PrependArgs: []string(prepend),
		Socket: osruntime.SocketPath(dataDir), SelfPath: self,
	})
	if err != nil {
		return err
	}
	fmt.Printf("installed shim %s -> %s (binding %s)\n", *name, rec.Executable, rec.BindingID)
	warnPlaintextToolConfig(rec)
	fmt.Printf("shim directory: %s\n", shim.Dir(dataDir))
	pathLine := `export PATH="` + shim.Dir(dataDir) + `:$PATH"`
	if *updateShell {
		rc := *shellRC
		if rc == "" {
			home, _ := os.UserHomeDir()
			rc = filepath.Join(home, ".zshrc")
		}
		if err := updateShellBlock(rc, pathLine); err != nil {
			return err
		}
		fmt.Printf("updated %s; open a new shell or run: source %s\n", rc, rc)
	} else {
		fmt.Println("add this to your shell profile to make it seamless:")
		fmt.Println("  " + pathLine)
	}
	return nil
}

func shimRemove(args []string) error {
	fs := flag.NewFlagSet("shim remove", flag.ContinueOnError)
	name := fs.String("name", "", "command name")
	updateShell := fs.Bool("update-shell", false, "remove the PATH block from the shell startup file")
	shellRC := fs.String("shell-rc", "", "shell startup file (default: ~/.zshrc)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	if err := shim.Remove(g.dataDir, *name); err != nil {
		return err
	}
	if *updateShell {
		rc := *shellRC
		if rc == "" {
			home, _ := os.UserHomeDir()
			rc = filepath.Join(home, ".zshrc")
		}
		if err := updateShellBlock(rc, ""); err != nil {
			return err
		}
	}
	fmt.Printf("removed shim %s\n", *name)
	return nil
}

func shimList(args []string) error {
	recs, err := shim.List(g.dataDir)
	if err != nil {
		return err
	}
	if g.json {
		return printJSON(recs)
	}
	if len(recs) == 0 {
		fmt.Println("no shims installed")
		return nil
	}
	for _, r := range recs {
		fmt.Printf("%-12s -> %-40s binding=%-20s env=%d inherit=%v\n", r.Name, r.Executable, r.BindingID, len(r.Env), r.InheritEnv)
	}
	return nil
}

// preflightBinding 用普通会话确认该 binding 存在且当前用户有 runtime_delivery 许可。
func preflightBinding(dataDir, bindingID string) error {
	c := client()
	sess, err := c.CreateSession("shim-preflight", false)
	if err != nil {
		return err
	}
	return c.Post("/v1/use-leases", map[string]any{
		"token": sess.Token, "binding_id": bindingID, "mode": "runtime_delivery",
	}, nil)
}

// sliceFlag 收集可重复的字符串参数。
type sliceFlag []string

func (f *sliceFlag) String() string { return strings.Join(*f, " ") }

func (f *sliceFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// warnPlaintextToolConfig 提示工具自带配置里仍存在明文凭证的情况。
// shim 通过隔离参数绕开它，但旧文件本身仍应清理。
func warnPlaintextToolConfig(rec *shim.Record) {
	base := filepath.Base(rec.Executable)
	if base != "aliyun" {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	path := filepath.Join(home, ".aliyun", "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if strings.Contains(string(data), `"access_key_secret":"`) && !strings.Contains(string(data), `"access_key_secret":""`) {
		fmt.Fprintf(os.Stderr, "warning: %s 仍保存明文访问密钥；shim 会通过 --config-path 隔离它，建议用 `aliyun configure delete --profile <name>` 或删除该条目。\n", path)
	}
}

const shellBlockStart = "# >>> keykoi shim >>>"
const shellBlockEnd = "# <<< keykoi shim <<<"

// updateShellBlock 维护 shim 的 PATH 片段。
func updateShellBlock(rcPath, pathLine string) error {
	return updateManagedBlock(rcPath, "shim", pathLine)
}

// updateManagedBlock 用受管标记维护一段 shell 配置；line 为空时删除该段。
func updateManagedBlock(rcPath, tag, line string) error {
	start := "# >>> keykoi " + tag + " >>>"
	end := "# <<< keykoi " + tag + " <<<"
	existing, err := os.ReadFile(rcPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var out strings.Builder
	lines := strings.Split(string(existing), "\n")
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == start {
			inBlock = true
			continue
		}
		if trimmed == end {
			inBlock = false
			continue
		}
		if inBlock {
			continue
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	content := strings.TrimRight(out.String(), "\n")
	if line != "" {
		if content != "" {
			content += "\n\n"
		}
		content += start + "\n" + line + "\n" + end + "\n"
	} else if content != "" {
		content += "\n"
	}
	return os.WriteFile(rcPath, []byte(content), 0o600)
}
