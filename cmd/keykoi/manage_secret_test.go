package main

import (
	"os"
	"strings"
	"testing"
)

// 只给字段名时从 stdin 读取秘密值：值不进入 argv，也就不进 shell 历史。
func TestKVFlagResolvesNameOnlyFromStdin(t *testing.T) {
	orig := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("s3cr3t-from-stdin\n"); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	os.Stdin = r
	defer func() { os.Stdin = orig; _ = r.Close() }()

	var kv kvFlag
	if err := kv.Set("access_secret"); err != nil {
		t.Fatalf("a name-only field must be accepted: %v", err)
	}
	if err := kv.Set("access_id=literal"); err != nil {
		t.Fatal(err)
	}
	got, err := kv.Resolve(true)
	if err != nil {
		t.Fatal(err)
	}
	if got["access_secret"] != "s3cr3t-from-stdin" {
		t.Fatalf("secret value = %q", got["access_secret"])
	}
	if got["access_id"] != "literal" {
		t.Fatalf("explicit value = %q", got["access_id"])
	}
	if strings.Contains(strings.Join(kv.order, ","), "access_secret") {
		t.Fatal("a prompted field must not be recorded as an argv-provided value")
	}
}

// 空名字段被拒绝，避免悄悄生成无名字段。
func TestKVFlagRejectsEmptyName(t *testing.T) {
	var kv kvFlag
	if err := kv.Set("=value"); err == nil {
		t.Fatal("an empty field name must be rejected")
	}
}
