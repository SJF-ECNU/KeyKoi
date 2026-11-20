// Package shim 提供无感入口：把一个指向 keykoi 二进制的符号链接放到 PATH 前面，
// 用户照常执行原命令，shim 读取受保护的安装记录，按 runtime_delivery 注入环境后
// 执行真实二进制。它保留参数数组、stdio、退出码与信号语义。
package shim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"keykoi/internal/ipcclient"
	"keykoi/internal/osruntime"
	"keykoi/internal/runner"
)

// Record 是受保护的工具安装记录。它不包含凭证，只含引用与环境映射。
type Record struct {
	Name       string            `json:"name"`
	Executable string            `json:"executable"`
	BindingID  string            `json:"binding_id"`
	Env        map[string]string `json:"env"`
	InheritEnv bool              `json:"inherit_env"`
	// PrependArgs 在每个需要凭证的调用前追加的参数（如 --config-path <空配置>），
	// 用于隔离工具自带的明文配置文件。
	PrependArgs []string  `json:"prepend_args,omitempty"`
	Socket      string    `json:"socket"`
	DataDir     string    `json:"data_dir"`
	ToolVersion string    `json:"tool_version,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Dir 返回 shim 目录。
func Dir(dataDir string) string { return filepath.Join(dataDir, "shims") }

// RecordPath 返回单个 shim 记录路径。
func RecordPath(dataDir, name string) string { return filepath.Join(Dir(dataDir), name+".json") }

// DefaultDataDir 与 CLI 使用同一规则解析数据目录。
// DefaultDataDir 返回与主 CLI 相同的数据目录。shim 分支在 main 的普通 CLI
// 解析之前运行，如果各自解析，安装后的入口会落到旧默认目录。
func DefaultDataDir() string {
	return osruntime.ResolveDataDir()
}

// Load 读取 shim 记录。
func Load(dataDir, name string) (*Record, error) {
	data, err := os.ReadFile(RecordPath(dataDir, name))
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("decode shim record: %w", err)
	}
	if r.Name != name {
		return nil, fmt.Errorf("shim record %s names %s", RecordPath(dataDir, name), r.Name)
	}
	return &r, nil
}

func save(dataDir string, r *Record) error {
	if err := os.MkdirAll(Dir(dataDir), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	path := RecordPath(dataDir, r.Name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// List 列出已安装的 shim。
func List(dataDir string) ([]*Record, error) {
	entries, err := os.ReadDir(Dir(dataDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Record
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		r, err := Load(dataDir, name)
		if err != nil {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// InstallConfig 描述安装一个 shim。
type InstallConfig struct {
	DataDir     string
	Name        string
	Executable  string
	BindingID   string
	Env         map[string]string
	InheritEnv  bool
	PrependArgs []string
	Socket      string
	// SelfPath 是 keykoi 二进制自身路径（绝对），由调用方提供。
	SelfPath string
}

// Install 校验并写入安装记录与符号链接。
func Install(cfg InstallConfig) (*Record, error) {
	if cfg.Name == "" || cfg.Executable == "" || cfg.BindingID == "" {
		return nil, fmt.Errorf("name, executable and binding are required")
	}
	if strings.ContainsAny(cfg.Name, `/\`) || cfg.Name == "." || cfg.Name == ".." {
		return nil, fmt.Errorf("shim name must be a plain command name")
	}
	switch cfg.Name {
	case "keykoi", "keykoid", "keykoi-central", "keykoi-shim":
		return nil, fmt.Errorf("%q is reserved", cfg.Name)
	}
	if !filepath.IsAbs(cfg.Executable) {
		return nil, fmt.Errorf("executable must be an absolute path")
	}
	info, err := os.Stat(cfg.Executable)
	if err != nil {
		return nil, fmt.Errorf("tool executable is not available: %w", err)
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("%s is not an executable file", cfg.Executable)
	}
	if !filepath.IsAbs(cfg.SelfPath) {
		return nil, fmt.Errorf("keykoi binary path must be absolute")
	}
	selfReal, err := filepath.EvalSymlinks(cfg.SelfPath)
	if err != nil {
		selfReal = cfg.SelfPath
	}
	exeReal, err := filepath.EvalSymlinks(cfg.Executable)
	if err != nil {
		exeReal = cfg.Executable
	}
	if selfReal == exeReal {
		return nil, fmt.Errorf("the tool path resolves to KeyKoi; use the original executable path from `keykoi shim list` or your tool installation")
	}
	if len(cfg.PrependArgs) > 0 && !strings.HasPrefix(cfg.PrependArgs[0], "-") {
		return nil, fmt.Errorf("prepend args must start with a flag (got %q)", cfg.PrependArgs[0])
	}
	for _, arg := range cfg.PrependArgs {
		if arg == "" {
			return nil, fmt.Errorf("prepend args cannot be empty")
		}
	}
	for envName, src := range cfg.Env {
		if !strings.HasPrefix(src, "field:") && !strings.HasPrefix(src, "runtime:") && !strings.HasPrefix(src, "literal:") {
			return nil, fmt.Errorf("env %s has unsupported source %q", envName, src)
		}
	}
	if err := os.MkdirAll(Dir(cfg.DataDir), 0o700); err != nil {
		return nil, err
	}
	link := filepath.Join(Dir(cfg.DataDir), cfg.Name)
	_ = os.Remove(link)
	if err := os.Symlink(cfg.SelfPath, link); err != nil {
		return nil, fmt.Errorf("create shim symlink: %w", err)
	}
	rec := &Record{
		Name: cfg.Name, Executable: cfg.Executable, BindingID: cfg.BindingID,
		Env: cfg.Env, InheritEnv: cfg.InheritEnv, PrependArgs: cfg.PrependArgs, Socket: cfg.Socket, DataDir: cfg.DataDir,
		CreatedAt: time.Now().UTC(),
	}
	if rec.Env == nil {
		rec.Env = map[string]string{}
	}
	if err := save(cfg.DataDir, rec); err != nil {
		_ = os.Remove(link)
		return nil, err
	}
	return rec, nil
}

// Remove 删除 shim 符号链接与记录。
func Remove(dataDir, name string) error {
	link := filepath.Join(Dir(dataDir), name)
	errLink := os.Remove(link)
	errRec := os.Remove(RecordPath(dataDir, name))
	if errLink != nil && !os.IsNotExist(errLink) {
		return errLink
	}
	if errRec != nil && !os.IsNotExist(errRec) {
		return errRec
	}
	if os.IsNotExist(errLink) && os.IsNotExist(errRec) {
		return ErrNotFound
	}
	return nil
}

// ErrNotFound 表示未安装。
var ErrNotFound = errors.New("shim not found")

// MaybeRun 在 main 入口检查当前 argv[0] 是否是已安装的 shim。
// 返回 handled=false 表示按普通 keykoi 命令继续。
func MaybeRun() (bool, int) {
	self := filepath.Base(os.Args[0])
	switch self {
	case "keykoi", "keykoid", "keykoi-central", "keykoi-shim", "":
		return false, 0
	}
	dataDir := DefaultDataDir()
	rec, err := Load(dataDir, self)
	if err != nil {
		return false, 0
	}
	code := runShim(rec, os.Args[1:])
	return true, code
}

// credentialFree only recognizes unambiguous standalone long options.
func credentialFree(args []string) bool {
	return len(args) == 1 && (args[0] == "--help" || args[0] == "--version")
}

// runPlain 不取凭证，直接执行原命令（仅用于帮助、版本等本地命令）。
func runPlain(rec *Record, args []string) int {
	cmd := exec.Command(rec.Executable, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitCodeOf(exitErr)
	}
	fmt.Fprintf(os.Stderr, "alias %s: %v\n", rec.Name, err)
	return 1
}

// applyPrepend 在用户参数前插入隔离参数；用户显式使用同名参数时拒绝，
// 避免 KeyKoi 注入被静默绕过。
func applyPrepend(rec *Record, args []string) ([]string, error) {
	if len(rec.PrependArgs) == 0 {
		return args, nil
	}
	guards := map[string]bool{}
	for _, a := range rec.PrependArgs {
		if strings.HasPrefix(a, "-") {
			guards[a] = true
		}
	}
	for _, a := range args {
		flagName := a
		if i := strings.IndexByte(a, '='); i > 0 {
			flagName = a[:i]
		}
		if guards[flagName] {
			return nil, fmt.Errorf("command-line %s is not supported through the shim; run `keykoi run` explicitly instead", flagName)
		}
	}
	out := make([]string, 0, len(rec.PrependArgs)+len(args))
	out = append(out, rec.PrependArgs...)
	out = append(out, args...)
	return out, nil
}

func runShim(rec *Record, args []string) int {
	if len(rec.PrependArgs) == 0 && credentialFree(args) {
		return runPlain(rec, args)
	}
	socket := rec.Socket
	if socket == "" {
		socket = osruntime.SocketPath(rec.DataDir)
	}
	client := ipcclient.New(socket, "")
	return runManaged(context.Background(), rec, args, runner.IPCResolver{Client: client})
}

func runManaged(ctx context.Context, rec *Record, args []string, resolver runner.Resolver) int {
	args, err := applyPrepend(rec, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "alias %s: %v\n", rec.Name, err)
		return 2
	}
	spec := runner.Spec{
		BindingID: rec.BindingID, Executable: rec.Executable, Args: args,
		InheritEnv: rec.InheritEnv, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	}
	names := make([]string, 0, len(rec.Env))
	for name := range rec.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		spec.Env = append(spec.Env, runner.EnvMapping{Name: name, Source: rec.Env[name]})
	}
	res, err := runner.Run(ctx, resolver, spec, func(cmd *exec.Cmd) error {
		return cmd.Start()
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "alias %s: %v\n", rec.Name, err)
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" && op.Net == "unix" {
			fmt.Fprintln(os.Stderr, "Run `keykoi status` to check the service. For local tool help, version or configuration, find the original executable path with `keykoi shim list` and call it directly.")
		}
		return 1
	}
	if res.Cancelled {
		return 130
	}
	return res.ExitCode
}

// exitCodeOf 把子进程结束原因映射为 shell 退出码。
// 被信号终止时 exit code 是 -1，必须换算成 128+信号值，
// 否则 `kill -TERM` 之类的正常结果会被报告成成功或普通失败。
func exitCodeOf(err *exec.ExitError) int {
	if code := err.ExitCode(); code >= 0 {
		return code
	}
	if status, ok := err.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return 1
}
