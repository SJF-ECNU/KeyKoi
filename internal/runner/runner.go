// Package runner 实现受管理运行：按适配声明把凭证注入子进程环境或 Helper，
// 并用参数数组启动原命令，保留 stdio、退出码、信号与工作目录语义。
package runner

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"keykoi/internal/model"
)

// EnvMapping 描述一个环境变量的来源。
// Source 形式：
//   - "field:<name>"：取凭证组合中的字段
//   - "runtime:session_token"：中介会话令牌
//   - "runtime:gateway_base"：本机网关基址（不含路由）
type EnvMapping struct {
	Name   string
	Source string
}

// Resolver 是运行器取得受控凭证的接口。生产环境由 ipcclient 适配，
// 测试可注入假实现。
type Resolver interface {
	CreateSession(ctx context.Context, purpose string, ttl time.Duration) (token, sessionID string, err error)
	CloseSession(ctx context.Context, sessionID string) error
	Resolve(ctx context.Context, token, bindingID, mode string) (Resolved, error)
	RevokeLease(ctx context.Context, leaseID string) error
	GatewayBase(ctx context.Context) (string, error)
}

// Resolved 是一次 runtime_delivery 结果。
type Resolved struct {
	LeaseID           string
	Fields            map[string]string
	ProviderExpiresAt *time.Time
}

// Spec 描述一次受管理运行。
type Spec struct {
	BindingID string
	// ProxyOnly 为 true 时只建立会话并注入令牌/网关地址，不读取真实凭证。
	ProxyOnly bool
	// Route 是网关路由名，配合 runtime:gateway_route 使用。
	Route string
	// SessionTTL 是会话有效期，0 表示后台默认值。
	SessionTTL time.Duration
	// Executable 必须是受信安装记录中的绝对路径。
	Executable string
	Args       []string
	Dir        string
	Env        []EnvMapping
	// InheritEnv 为 true 时继承当前进程环境；默认只保留基础变量。
	InheritEnv bool
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	// CancelGrace 是取消时等待进程退出的时间，超时后强制结束进程组。
	CancelGrace time.Duration
}

// Result 是一次运行的结果与清理状态。
type Result struct {
	ExitCode      int    `json:"exit_code"`
	Signal        string `json:"signal,omitempty"`
	DurationMS    int64  `json:"duration_ms"`
	LeaseID       string `json:"lease_id"`
	CleanupStatus string `json:"cleanup_status"`
	LeftoverPIDs  []int  `json:"leftover_pids,omitempty"`
	Cancelled     bool   `json:"cancelled"`
}

// baseEnv 是默认保留的非敏感环境变量。真实凭证从不从父环境继承。
var baseEnv = []string{"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LC_ALL", "TMPDIR", "PWD"}

// Run 解析凭证、启动原命令并等待结束，最后撤销许可。
func Run(ctx context.Context, r Resolver, spec Spec, spawn func(*exec.Cmd) error) (Result, error) {
	res := Result{}
	if !strings.HasPrefix(spec.Executable, "/") {
		return res, model.NewError(model.CodeAdapterUnsupported, "executable must be an absolute path from a trusted installation record")
	}
	if !spec.ProxyOnly && spec.BindingID == "" {
		return res, model.NewError(model.CodeAdapterUnsupported, "binding is required")
	}
	if spec.CancelGrace <= 0 {
		spec.CancelGrace = 3 * time.Second
	}
	token, sessionID, err := r.CreateSession(ctx, "managed-run", spec.SessionTTL)
	if err != nil {
		return res, err
	}
	defer func() { _ = r.CloseSession(context.Background(), sessionID) }()
	var resolved Resolved
	if !spec.ProxyOnly {
		resolved, err = r.Resolve(ctx, token, spec.BindingID, string(model.ModeRuntimeDelivery))
		if err != nil {
			return res, err
		}
		res.LeaseID = resolved.LeaseID
		defer func() { _ = r.RevokeLease(context.Background(), resolved.LeaseID) }()
	}

	env, err := buildEnv(ctx, r, spec, resolved, token)
	if err != nil {
		return res, err
	}
	cmd := exec.Command(spec.Executable, spec.Args...)
	cmd.Env = env
	cmd.Dir = spec.Dir
	cmd.Stdin = spec.Stdin
	cmd.Stdout = spec.Stdout
	cmd.Stderr = spec.Stderr
	attr := &syscall.SysProcAttr{Setpgid: true}
	// 交互式工具需要前台终端；退出时再把终端还给启动器。
	restoreTerminal := applyForeground(attr, spec.Stdin)
	defer restoreTerminal()
	cmd.SysProcAttr = attr

	start := time.Now()
	if err := spawnFn(cmd, spawn); err != nil {
		return res, model.NewError(model.CodeAdapterUnsupported, "cannot start %s: %v", spec.Executable, err)
	}
	// 取消与信号转发：中断请求转发到子进程组，不被启动器吞掉。
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	var cancelled bool
	var mu sync.Mutex
	// terminate 先转发收到的信号（保留交互式语义，例如 SIGINT 对应 130），
	// 再在短宽限后发送 SIGTERM，最后按 CancelGrace 强制结束进程组。
	// 非交互 shell 的后台子进程可能以忽略 SIGINT 启动，因此必须有兜底。
	terminate := func(sig syscall.Signal) {
		mu.Lock()
		already := cancelled
		cancelled = true
		mu.Unlock()
		if already {
			return
		}
		if sig == 0 {
			sig = syscall.SIGTERM
		}
		_ = syscall.Kill(-cmd.Process.Pid, sig)
		time.AfterFunc(400*time.Millisecond, func() {
			if groupAlive(cmd.Process.Pid) {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			}
		})
		time.AfterFunc(spec.CancelGrace, func() {
			if groupAlive(cmd.Process.Pid) {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		})
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig, ok := <-sigCh:
				if !ok {
					return
				}
				terminate(sig.(syscall.Signal))
			case <-done:
				return
			}
		}
	}()
	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			terminate(syscall.SIGTERM)
		case <-ctxDone:
		}
	}()
	waitErr := cmd.Wait()
	close(ctxDone)
	close(done)
	elapsed := time.Since(start)
	res.DurationMS = elapsed.Milliseconds()
	mu.Lock()
	res.Cancelled = cancelled
	mu.Unlock()
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			sig := ws.Signal()
			res.Signal = sig.String()
			res.ExitCode = 128 + int(sig)
		}
	}
	if waitErr != nil && res.ExitCode <= 0 {
		res.ExitCode = 1
	}
	// 主进程结束后检查进程组：残留后代按声明终止并报告。
	leftovers := reapProcessGroup(cmd.Process.Pid, spec.CancelGrace)
	res.LeftoverPIDs = leftovers.PIDs
	res.CleanupStatus = leftovers.Status
	return res, nil
}

func spawnFn(cmd *exec.Cmd, spawn func(*exec.Cmd) error) error {
	if spawn != nil {
		return spawn(cmd)
	}
	return cmd.Start()
}

type reapResult struct {
	PIDs   []int
	Status string
}

// reapProcessGroup 检查主进程组是否仍有后代。有则先 SIGTERM，仍未退出则 SIGKILL。
func reapProcessGroup(pgid int, grace time.Duration) reapResult {
	if !groupAlive(pgid) {
		return reapResult{Status: "no_leftover_processes"}
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if !groupAlive(pgid) {
			return reapResult{Status: "terminated_leftover_processes"}
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	time.Sleep(100 * time.Millisecond)
	if groupAlive(pgid) {
		return reapResult{Status: "leftover_processes_remain"}
	}
	return reapResult{Status: "killed_leftover_processes"}
}

func groupAlive(pgid int) bool {
	err := syscall.Kill(-pgid, 0)
	return err == nil || err == syscall.EPERM
}

func buildEnv(ctx context.Context, r Resolver, spec Spec, resolved Resolved, token string) ([]string, error) {
	env := map[string]string{}
	if spec.InheritEnv {
		for _, kv := range os.Environ() {
			if k, v, ok := strings.Cut(kv, "="); ok {
				env[k] = v
			}
		}
	} else {
		for _, name := range baseEnv {
			if v, ok := os.LookupEnv(name); ok && !isSensitiveName(name) {
				env[name] = v
			}
		}
	}
	for _, m := range spec.Env {
		switch {
		case strings.HasPrefix(m.Source, "field:"):
			field := strings.TrimPrefix(m.Source, "field:")
			val, ok := resolved.Fields[field]
			if !ok {
				return nil, model.NewError(model.CodeCredentialUnavailable, "field %q is not present in the credential", field)
			}
			env[m.Name] = val
		case strings.HasPrefix(m.Source, "literal:"):
			env[m.Name] = strings.TrimPrefix(m.Source, "literal:")
		case m.Source == "runtime:session_token":
			env[m.Name] = token
		case m.Source == "runtime:gateway_base":
			base, err := r.GatewayBase(ctx)
			if err != nil {
				return nil, err
			}
			env[m.Name] = base
		case m.Source == "runtime:gateway_route":
			if spec.Route == "" {
				return nil, model.NewError(model.CodeAdapterUnsupported, "runtime:gateway_route requires a route name")
			}
			base, err := r.GatewayBase(ctx)
			if err != nil {
				return nil, err
			}
			env[m.Name] = strings.TrimRight(base, "/") + "/gateway/" + spec.Route
		default:
			return nil, model.NewError(model.CodeAdapterUnsupported, "unsupported env source %q", m.Source)
		}
	}
	out := make([]string, 0, len(env))
	for _, k := range sortedKeys(env) {
		out = append(out, k+"="+env[k])
	}
	return out, nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isSensitiveName(name string) bool {
	up := strings.ToUpper(name)
	for _, frag := range []string{"KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL"} {
		if strings.Contains(up, frag) {
			return true
		}
	}
	return false
}

// FormatEnvNames 返回变量名清单，用于诊断而不泄露值。
func FormatEnvNames(spec Spec) string {
	names := make([]string, 0, len(spec.Env))
	for _, m := range spec.Env {
		names = append(names, m.Name+"<-"+m.Source)
	}
	return strings.Join(names, ",")
}
