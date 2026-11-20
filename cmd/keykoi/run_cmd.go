package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"keykoi/internal/runner"
)

// cmdRun 以受管理方式运行原命令：参数数组、受控环境、原 stdio 与退出码。
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	binding := fs.String("binding", "", "binding id used for runtime_delivery")
	mode := fs.String("mode", "runtime", "runtime (inject real values) | proxy (inject only session token and gateway base)")
	route := fs.String("route", "", "gateway route name for proxy mode")
	ttl := fs.Duration("session-ttl", 0, "session lifetime for the child process (proxy mode); capped at 24h")
	exe := fs.String("exe", "", "absolute path of the original tool")
	inherit := fs.Bool("inherit-env", false, "inherit the current environment (sensitive names are still not injected)")
	dryRun := fs.Bool("dry-run", false, "resolve and print the environment variable names only")
	report := fs.String("report", "", "write the run result JSON to this file (keeps child stdout separate)")
	var envFlags kvFlag
	fs.Var(&envFlags, "env", "NAME=field:<field> | NAME=runtime:session_token | NAME=runtime:gateway_base")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if *exe == "" {
		return fmt.Errorf("--exe is required")
	}
	if *mode != "runtime" && *mode != "proxy" {
		return fmt.Errorf("--mode must be runtime or proxy")
	}
	if *mode == "runtime" && *binding == "" {
		return fmt.Errorf("--binding is required for runtime mode")
	}
	if *mode == "proxy" && *route == "" {
		return fmt.Errorf("--route is required for proxy mode")
	}
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	spec := runner.Spec{BindingID: *binding, ProxyOnly: *mode == "proxy", Route: *route,
		SessionTTL: *ttl, Executable: *exe, Args: rest, InheritEnv: *inherit,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	for name, source := range envFlags.Map() {
		spec.Env = append(spec.Env, runner.EnvMapping{Name: name, Source: source})
	}
	if *dryRun {
		fmt.Printf("mode=%s binding=%s route=%s executable=%s\n", *mode, spec.BindingID, spec.Route, spec.Executable)
		fmt.Printf("env=%s\n", runner.FormatEnvNames(spec))
		fmt.Printf("args=%q\n", spec.Args)
		return nil
	}
	res, err := runner.Run(context.Background(), runner.IPCResolver{Client: client()}, spec, func(cmd *exec.Cmd) error {
		return cmd.Start()
	})
	if err != nil {
		return err
	}
	if *report != "" {
		if err := writeRunReport(*report, res); err != nil {
			return err
		}
	} else if g.json {
		_ = printJSON(res)
	} else if res.CleanupStatus != "no_leftover_processes" {
		fmt.Fprintf(os.Stderr, "cleanup: %s %v\n", res.CleanupStatus, res.LeftoverPIDs)
	}
	if res.ExitCode != 0 {
		os.Exit(res.ExitCode)
	}
	return nil
}

// writeRunReport 把运行结果写入 0600 文件，避免与子进程 stdout 混在一起。
func writeRunReport(path string, res runner.Result) error {
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

var _ = strings.TrimSpace
