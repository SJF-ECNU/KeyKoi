package runner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeResolver struct {
	fields      map[string]string
	leaseID     string
	revoked     []string
	closed      []string
	gateway     string
	resolveErr  error
	resolveCall int
}

func (f *fakeResolver) CreateSession(context.Context, string, time.Duration) (string, string, error) {
	return "kks_test_token", "session_1", nil
}

func (f *fakeResolver) CloseSession(_ context.Context, id string) error {
	f.closed = append(f.closed, id)
	return nil
}

func (f *fakeResolver) Resolve(context.Context, string, string, string) (Resolved, error) {
	f.resolveCall++
	if f.resolveErr != nil {
		return Resolved{}, f.resolveErr
	}
	return Resolved{LeaseID: f.leaseID, Fields: f.fields}, nil
}

func (f *fakeResolver) RevokeLease(_ context.Context, id string) error {
	f.revoked = append(f.revoked, id)
	return nil
}

func (f *fakeResolver) GatewayBase(context.Context) (string, error) { return f.gateway, nil }

func TestEnvInjectionAndExitCode(t *testing.T) {
	f := &fakeResolver{fields: map[string]string{"token": "runtime-secret-value"}, leaseID: "lease_1"}
	var out, errBuf bytes.Buffer
	res, err := Run(context.Background(), f, Spec{
		BindingID:  "b1",
		Executable: "/bin/sh",
		Args:       []string{"-c", `printf '%s' "$INJECTED"; printf 'err' 1>&2; exit 7`},
		Env:        []EnvMapping{{Name: "INJECTED", Source: "field:token"}},
		Stdout:     &out,
		Stderr:     &errBuf,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "runtime-secret-value" {
		t.Fatalf("stdout mismatch: %q", out.String())
	}
	if errBuf.String() != "err" {
		t.Fatalf("stderr not preserved: %q", errBuf.String())
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit code not preserved: %d", res.ExitCode)
	}
	if len(f.revoked) != 1 || f.revoked[0] != "lease_1" {
		t.Fatalf("lease must be revoked after run: %v", f.revoked)
	}
}

func TestSignalExitCodeAndSignal(t *testing.T) {
	script := writeRunnerScript(t, "#!/bin/sh\nkill -\"$1\" \"$$\"\n")
	cases := []struct {
		name string
		sig  syscall.Signal
	}{
		{name: "TERM", sig: syscall.SIGTERM},
		{name: "INT", sig: syscall.SIGINT},
		{name: "KILL", sig: syscall.SIGKILL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeResolver{fields: map[string]string{"token": "x"}, leaseID: "l"}
			res, err := Run(context.Background(), f, Spec{
				BindingID: "b1", Executable: script, Args: []string{tc.name},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := 128 + int(tc.sig)
			if res.ExitCode != want {
				t.Fatalf("exit code = %d, want %d; result: %+v", res.ExitCode, want, res)
			}
			if res.Signal != tc.sig.String() {
				t.Fatalf("signal = %q, want %q", res.Signal, tc.sig.String())
			}
			if res.Cancelled {
				t.Fatal("a child-initiated signal must not be marked as launcher cancellation")
			}
		})
	}
}

func writeRunnerScript(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tool.sh")
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestArgsAreNotShellInterpolated(t *testing.T) {
	f := &fakeResolver{fields: map[string]string{"token": "x"}, leaseID: "l"}
	var out bytes.Buffer
	res, err := Run(context.Background(), f, Spec{
		BindingID: "b1", Executable: "/bin/echo",
		Args:   []string{"a b", "$(touch /tmp/keykoi-should-not-exist)", "; rm -rf /"},
		Stdout: &out,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d", res.ExitCode)
	}
	if _, err := os.Stat("/tmp/keykoi-should-not-exist"); err == nil {
		t.Fatal("args were shell interpolated")
	}
	if !strings.Contains(out.String(), "$(touch") {
		t.Fatalf("args were not passed literally: %q", out.String())
	}
}

func TestParentSensitiveEnvNotInherited(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "parent-secret")
	t.Setenv("PATH", os.Getenv("PATH"))
	f := &fakeResolver{fields: map[string]string{"token": "x"}, leaseID: "l"}
	var out bytes.Buffer
	if _, err := Run(context.Background(), f, Spec{
		BindingID: "b1", Executable: "/bin/sh",
		Args:   []string{"-c", `printf '%s' "${AWS_SECRET_ACCESS_KEY:-unset}"`},
		Stdout: &out,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if out.String() != "unset" {
		t.Fatalf("sensitive parent env leaked: %q", out.String())
	}
}

func TestCancellation(t *testing.T) {
	f := &fakeResolver{fields: map[string]string{"token": "x"}, leaseID: "l"}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := Run(ctx, f, Spec{
		BindingID: "b1", Executable: "/bin/sh", Args: []string{"-c", "sleep 10"},
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
		CancelGrace: 500 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cancelled || res.ExitCode == 0 {
		t.Fatalf("cancellation not reflected: %+v", res)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("cancellation did not terminate the process")
	}
}

func TestRequiresAbsoluteExecutable(t *testing.T) {
	f := &fakeResolver{}
	if _, err := Run(context.Background(), f, Spec{BindingID: "b1", Executable: "sh"}, nil); err == nil {
		t.Fatal("relative executable must be rejected")
	}
}

func TestMissingFieldRejected(t *testing.T) {
	f := &fakeResolver{fields: map[string]string{}, leaseID: "l"}
	_, err := Run(context.Background(), f, Spec{
		BindingID: "b1", Executable: "/bin/echo", Args: []string{"x"},
		Env:    []EnvMapping{{Name: "X", Source: "field:token"}},
		Stdout: &bytes.Buffer{},
	}, nil)
	if err == nil {
		t.Fatal("missing field must be rejected")
	}
}

func TestProxyOnlyModeSkipsCredentialRead(t *testing.T) {
	f := &fakeResolver{fields: map[string]string{"token": "should-not-be-read"}, gateway: "http://127.0.0.1:9999"}
	var out bytes.Buffer
	res, err := Run(context.Background(), f, Spec{
		ProxyOnly: true, Route: "model-prod", Executable: "/bin/sh",
		Args: []string{"-c", `printf '%s|%s' "$TOK" "$BASE"`},
		Env: []EnvMapping{
			{Name: "TOK", Source: "runtime:session_token"},
			{Name: "BASE", Source: "runtime:gateway_route"},
		},
		Stdout: &out, Stderr: &bytes.Buffer{},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.resolveCall != 0 {
		t.Fatal("proxy-only mode must not read the credential")
	}
	if out.String() != "kks_test_token|http://127.0.0.1:9999/gateway/model-prod" {
		t.Fatalf("unexpected env: %q", out.String())
	}
	if len(f.closed) != 1 || f.closed[0] != "session_1" {
		t.Fatalf("session must be closed: %v", f.closed)
	}
	if res.LeaseID != "" {
		t.Fatalf("proxy-only run must not hold a lease: %q", res.LeaseID)
	}
}

func TestResolveErrorPropagates(t *testing.T) {
	f := &fakeResolver{resolveErr: errors.New("USE_NOT_ALLOWED")}
	_, err := Run(context.Background(), f, Spec{BindingID: "b1", Executable: "/bin/echo"}, nil)
	if err == nil {
		t.Fatal("resolve failure must propagate")
	}
}
