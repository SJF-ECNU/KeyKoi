package central

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveListenPlan 验证明文监听只允许回环，跨机器部署必须有 TLS。
func TestResolveListenPlan(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	for _, p := range []string{cert, key} {
		if err := os.WriteFile(p, []byte("test-material"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name    string
		addr    string
		cert    string
		key     string
		wantErr string
		tls     bool
	}{
		{name: "loopback plaintext", addr: "127.0.0.1:8390"},
		{name: "ipv6 loopback plaintext", addr: "[::1]:8390"},
		{name: "localhost plaintext", addr: "localhost:8390"},
		{name: "loopback explicit tls", addr: "127.0.0.1:8390", cert: cert, key: key, tls: true},
		{name: "all interfaces needs tls", addr: "0.0.0.0:8390", wantErr: "requires both --tls-cert and --tls-key"},
		{name: "lan address needs tls", addr: "192.168.1.10:8390", wantErr: "requires both --tls-cert and --tls-key"},
		{name: "empty host needs tls", addr: ":8390", wantErr: "requires both --tls-cert and --tls-key"},
		{name: "tls without key", addr: "127.0.0.1:8390", cert: cert, wantErr: "--tls-cert and --tls-key must be provided together"},
		{name: "lan with tls", addr: "192.168.1.10:8390", cert: cert, key: key, tls: true},
		{name: "missing tls material", addr: "192.168.1.10:8390", cert: filepath.Join(dir, "absent.pem"), key: key, wantErr: "is not readable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := ResolveListenPlan(tc.addr, tc.cert, tc.key)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if plan.TLS != tc.tls {
				t.Fatalf("tls=%v, want %v", plan.TLS, tc.tls)
			}
			wantScheme := "http://"
			if tc.tls {
				wantScheme = "https://"
			}
			if !strings.HasPrefix(plan.Describe(), wantScheme) {
				t.Fatalf("describe %q must start with %q", plan.Describe(), wantScheme)
			}
		})
	}
}
