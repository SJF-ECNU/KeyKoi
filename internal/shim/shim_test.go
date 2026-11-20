package shim

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"keykoi/internal/runner"
)

func selfPath(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInstallListRemove(t *testing.T) {
	dir := t.TempDir()
	rec, err := Install(InstallConfig{
		DataDir: dir, Name: "demotool", Executable: "/bin/echo", BindingID: "bind_x",
		Env: map[string]string{"DEMO_KEY": "field:token"}, InheritEnv: true,
		SelfPath: selfPath(t), Socket: filepath.Join(dir, "keykoid.sock"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Env["DEMO_KEY"] != "field:token" {
		t.Fatalf("env mapping lost: %+v", rec.Env)
	}
	link := filepath.Join(Dir(dir), "demotool")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if target != selfPath(t) {
		t.Fatalf("symlink target %q", target)
	}
	info, err := os.Stat(RecordPath(dir, "demotool"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("record permissions %v", info.Mode().Perm())
	}
	recs, err := List(dir)
	if err != nil || len(recs) != 1 || recs[0].Name != "demotool" {
		t.Fatalf("list: %+v %v", recs, err)
	}
	if got, err := Load(dir, "demotool"); err != nil || got.BindingID != "bind_x" {
		t.Fatalf("load: %+v %v", got, err)
	}
	if err := Remove(dir, "demotool"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("symlink should be removed")
	}
	if err := Remove(dir, "demotool"); err != ErrNotFound {
		t.Fatalf("second remove should report not found, got %v", err)
	}
}

func TestRejectsUnsafeInstall(t *testing.T) {
	dir := t.TempDir()
	self := selfPath(t)
	cases := []InstallConfig{
		{DataDir: dir, Name: "keykoi", Executable: "/bin/echo", BindingID: "b", SelfPath: self},
		{DataDir: dir, Name: "a/b", Executable: "/bin/echo", BindingID: "b", SelfPath: self},
		{DataDir: dir, Name: "rel", Executable: "echo", BindingID: "b", SelfPath: self},
		{DataDir: dir, Name: "self", Executable: self, BindingID: "b", SelfPath: self},
		{DataDir: dir, Name: "badenv", Executable: "/bin/echo", BindingID: "b", SelfPath: self, Env: map[string]string{"X": "shell:$(id)"}},
	}
	for _, cfg := range cases {
		if _, err := Install(cfg); err == nil {
			t.Fatalf("install should be rejected: %+v", cfg)
		}
	}
}

func TestRecordNameMismatch(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(Dir(dir), 0o700)
	os.WriteFile(RecordPath(dir, "x"), []byte(`{"name":"y","executable":"/bin/echo","binding_id":"b"}`), 0o600)
	if _, err := Load(dir, "x"); err == nil {
		t.Fatal("mismatched record should be rejected")
	}
}

func TestApplyPrependGuards(t *testing.T) {
	rec := &Record{PrependArgs: []string{"--config-path", "/tmp/no-config.json"}}
	out, err := applyPrepend(rec, []string{"ecs", "DescribeRegions"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 || out[0] != "--config-path" || out[2] != "ecs" {
		t.Fatalf("prepend order wrong: %v", out)
	}
	if _, err := applyPrepend(rec, []string{"ecs", "--config-path", "/my/own.json"}); err == nil {
		t.Fatal("user-supplied guarded flag must be refused")
	}
	if _, err := applyPrepend(rec, []string{"ecs", "--config-path=/my/own.json"}); err == nil {
		t.Fatal("user-supplied guarded flag with = must be refused")
	}
	if _, err := applyPrepend(&Record{}, []string{"ecs"}); err != nil {
		t.Fatal("no prepend should pass through")
	}
}

type managedRunResolver struct{}

func (managedRunResolver) CreateSession(context.Context, string, time.Duration) (string, string, error) {
	return "token", "session", nil
}

func (managedRunResolver) CloseSession(context.Context, string) error { return nil }

func (managedRunResolver) Resolve(context.Context, string, string, string) (runner.Resolved, error) {
	return runner.Resolved{LeaseID: "lease"}, nil
}

func (managedRunResolver) RevokeLease(context.Context, string) error { return nil }

func (managedRunResolver) GatewayBase(context.Context) (string, error) { return "", nil }

func TestRunManagedMapsRunnerResults(t *testing.T) {
	script := writeShimScript(t, `#!/bin/sh
case "$1" in
signal)
  kill -"$2" "$$"
  ;;
exit)
  exit "$2"
  ;;
wait)
  sleep 10
  ;;
esac
`)
	rec := &Record{Name: "managed-test", Executable: script, BindingID: "binding"}
	for _, tc := range []struct {
		name string
		sig  syscall.Signal
	}{
		{name: "TERM", sig: syscall.SIGTERM},
		{name: "INT", sig: syscall.SIGINT},
		{name: "KILL", sig: syscall.SIGKILL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runManaged(context.Background(), rec, []string{"signal", tc.name}, managedRunResolver{})
			want := 128 + int(tc.sig)
			if got != want {
				t.Fatalf("runManaged exit code = %d, want %d", got, want)
			}
		})
	}
	if got := runManaged(context.Background(), rec, []string{"exit", "7"}, managedRunResolver{}); got != 7 {
		t.Fatalf("ordinary non-zero exit code = %d, want 7", got)
	}
}

func TestRunManagedCancelledReturns130(t *testing.T) {
	script := writeShimScript(t, "#!/bin/sh\nsleep 10\n")
	rec := &Record{Name: "managed-test", Executable: script, BindingID: "binding"}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if got := runManaged(ctx, rec, []string{"wait"}, managedRunResolver{}); got != 130 {
		t.Fatalf("cancelled exit code = %d, want 130", got)
	}
}

func writeShimScript(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "managed-tool.sh")
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// 被信号终止的子进程必须映射成 128+信号值，不能报告成成功或普通失败。
func TestExitCodeOfMapsSignals(t *testing.T) {
	cases := map[string]syscall.Signal{"TERM": syscall.SIGTERM, "INT": syscall.SIGINT, "KILL": syscall.SIGKILL}
	for name, sig := range cases {
		cmd := exec.Command("sh", "-c", "kill -"+name+" $$")
		err := cmd.Run()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("%s: expected an ExitError, got %v", name, err)
		}
		want := 128 + int(sig)
		if got := exitCodeOf(exitErr); got != want {
			t.Fatalf("%s: exit code = %d, want %d", name, got, want)
		}
	}
	// 普通非零退出码保持原值。
	if err := exec.Command("sh", "-c", "exit 7").Run(); err == nil {
		t.Fatal("expected a non-zero exit")
	} else {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatal(err)
		}
		if got := exitCodeOf(exitErr); got != 7 {
			t.Fatalf("exit code = %d, want 7", got)
		}
	}
}
