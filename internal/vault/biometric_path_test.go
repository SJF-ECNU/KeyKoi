package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"keykoi/internal/vault"
)

// makeAppBundle 造一个最小的 .app 目录结构，用于路径归一化测试。
func makeAppBundle(t *testing.T, root string) (bundle, exe string) {
	t.Helper()
	bundle = filepath.Join(root, vault.BiometricAppBundleName)
	macOS := filepath.Join(bundle, "Contents", "MacOS")
	if err := os.MkdirAll(macOS, 0o755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	exe = filepath.Join(macOS, vault.BiometricHelperName)
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	return bundle, exe
}

func TestResolveHelperPathExplicitWins(t *testing.T) {
	t.Setenv(vault.BiometricHelperEnv, "/from/env/keykoi-biometric")
	got := vault.ResolveHelperPath("/from/flag/keykoi-biometric")
	if got != "/from/flag/keykoi-biometric" {
		t.Fatalf("explicit path should win, got %q", got)
	}
}

func TestResolveHelperPathEnvAcceptsAppBundle(t *testing.T) {
	root := t.TempDir()
	bundle, exe := makeAppBundle(t, root)
	t.Setenv(vault.BiometricHelperEnv, bundle)

	if got := vault.ResolveHelperPath(""); got != exe {
		t.Fatalf("env .app bundle should resolve to inner executable\nwant %q\ngot  %q", exe, got)
	}
}

func TestResolveHelperPathEnvAcceptsBundleMacOSDir(t *testing.T) {
	root := t.TempDir()
	bundle, exe := makeAppBundle(t, root)
	t.Setenv(vault.BiometricHelperEnv, filepath.Join(bundle, "Contents", "MacOS"))

	if got := vault.ResolveHelperPath(""); got != exe {
		t.Fatalf("env Contents/MacOS dir should resolve to inner executable, got %q", got)
	}
}

func TestResolveHelperPathEnvKeepsBareBinary(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, vault.BiometricHelperName)
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	t.Setenv(vault.BiometricHelperEnv, exe)

	if got := vault.ResolveHelperPath(""); got != exe {
		t.Fatalf("bare binary should pass through, got %q", got)
	}
}

func TestResolveHelperPathWithoutAnyCandidate(t *testing.T) {
	t.Setenv(vault.BiometricHelperEnv, "")
	t.Setenv("PATH", t.TempDir())

	if got := vault.ResolveHelperPath(""); got != "" {
		t.Fatalf("no candidate should resolve to empty, got %q", got)
	}
}

// 显式传入 .app 包时同样要落到包内可执行文件，避免上层把目录当成程序执行。
func TestNormalizeHelperPathAppBundle(t *testing.T) {
	root := t.TempDir()
	bundle, exe := makeAppBundle(t, root)
	if got := vault.NormalizeHelperPath(bundle); got != exe {
		t.Fatalf("normalize bundle: want %q got %q", exe, got)
	}
	if got := vault.NormalizeHelperPath(exe); got != exe {
		t.Fatalf("normalize executable: want %q got %q", exe, got)
	}
	if got := vault.NormalizeHelperPath(""); got != "" {
		t.Fatalf("normalize empty: want empty got %q", got)
	}
}
