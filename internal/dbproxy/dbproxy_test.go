package dbproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
)

const testToken = "kks_test_session_token"

// startProxy 启动一个监听 127.0.0.1:0 的代理，返回服务器与地址。
func startProxy(t *testing.T, b Broker, cfg Config) (*Server, string) {
	t.Helper()
	cfg.ListenAddr = "127.0.0.1:0"
	if cfg.BindingID == "" {
		cfg.BindingID = "bind_test_db"
	}
	if cfg.ClientUser == "" {
		cfg.ClientUser = "keykoi"
	}
	srv, err := New(b, cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ctx); err != nil {
			t.Logf("serve returned: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = srv.Shutdown(shutdownCtx)
		<-done
	})
	return srv, srv.Addrs()[0]
}

// startProxyWithConfig 与 startProxy 相同，但只返回服务器，供需要检查监听地址的测试使用。
func startProxyWithConfig(t *testing.T, b Broker, cfg Config) *Server {
	t.Helper()
	cfg.ListenAddr = "127.0.0.1:0"
	if cfg.BindingID == "" {
		cfg.BindingID = "bind_test_db"
	}
	if cfg.ClientUser == "" {
		cfg.ClientUser = "keykoi"
	}
	srv, err := New(b, cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ctx); err != nil {
			t.Logf("serve returned: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = srv.Shutdown(shutdownCtx)
		<-done
	})
	return srv
}

// connect 用真实驱动（pgconn）经代理建立连接。
func connect(t *testing.T, addr, user, password, database string) (*pgconn.PgConn, error) {
	t.Helper()
	connString := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable&connect_timeout=5",
		url.QueryEscape(user), url.QueryEscape(password), addr, url.QueryEscape(database))
	cfg, err := pgconn.ParseConfig(connString)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgconn.ConnectConfig(ctx, cfg)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestProxyRelaysQueryAfterSCRAMUpstreamAuth(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	conn, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("connect through proxy: %v", err)
	}
	defer conn.Close(context.Background())

	results, err := conn.Exec(context.Background(), "select 1").ReadAll()
	if err != nil {
		t.Fatalf("exec select 1: %v", err)
	}
	if len(results) != 1 || results[0].CommandTag.String() != "SELECT 1" {
		t.Fatalf("unexpected result: %+v", results)
	}
	queries, _, conns, failures := up.snapshot()
	if failures != 0 {
		t.Fatalf("fake upstream reported %d failures: %v", failures, up.lastErr)
	}
	if conns != 1 {
		t.Fatalf("expected 1 upstream connection, got %d", conns)
	}
	if len(queries) != 1 || queries[0] != "select 1" {
		t.Fatalf("upstream saw queries %v", queries)
	}
}

func TestProxyRejectsWrongSessionToken(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	_, err := connect(t, addr, "keykoi", "kks_not_a_real_token", "keykoi_test")
	if err == nil {
		t.Fatal("expected wrong token to be rejected")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != codeInvalidPassword {
		t.Fatalf("expected SQLSTATE %s, got %v", codeInvalidPassword, err)
	}
	// 令牌无效时不得向上游发起连接。
	if _, _, conns, _ := up.snapshot(); conns != 0 {
		t.Fatalf("upstream must not be contacted for an unauthorized token; conns=%d", conns)
	}
}

func TestProxyRejectsMissingRuntimeDeliveryGrant(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	b.denial = &ipcclient.APIError{Code: string(model.CodeUseNotAllowed), Message: "no proxy grant for binding bind_test_db"}
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	_, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err == nil {
		t.Fatal("expected a missing grant to be rejected")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != codeInvalidPassword {
		t.Fatalf("expected SQLSTATE %s, got %v", codeInvalidPassword, err)
	}
	if _, _, conns, _ := up.snapshot(); conns != 0 {
		t.Fatalf("upstream must not be contacted without a grant; conns=%d", conns)
	}
}

func TestProxyRejectsUnknownClientUser(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	_, err := connect(t, addr, "postgres", testToken, "keykoi_test")
	if err == nil {
		t.Fatal("expected an unsupported client user to be rejected")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != codeInvalidAuthSpec {
		t.Fatalf("expected SQLSTATE %s, got %v", codeInvalidAuthSpec, err)
	}
}

func TestProxyRejectsUnregisteredBinding(t *testing.T) {
	b := newFakeBroker("bind_other")
	_, addr := startProxy(t, b, Config{BindingID: "bind_test_db"})

	_, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err == nil {
		t.Fatal("expected an unregistered binding to be rejected")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != codeCannotConnectNow {
		t.Fatalf("expected SQLSTATE %s, got %v", codeCannotConnectNow, err)
	}
}

func TestProxyRejectsCredentialWithoutDatabaseFields(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	delete(b.fields, "password")
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	_, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err == nil {
		t.Fatal("expected a credential without a password field to be rejected")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != codeCannotConnectNow {
		t.Fatalf("expected SQLSTATE %s, got %v", codeCannotConnectNow, err)
	}
}

func TestProxyForwardsCancelRequest(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	conn, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("connect through proxy: %v", err)
	}
	defer conn.Close(context.Background())

	mrr := conn.Exec(context.Background(), "select pg_sleep(5)")
	waitFor(t, "upstream to receive the query", func() bool {
		queries, _, _, _ := up.snapshot()
		return len(queries) == 1
	})

	if err := conn.CancelRequest(context.Background()); err != nil {
		t.Fatalf("cancel request: %v", err)
	}
	waitFor(t, "upstream to receive a cancel request", func() bool {
		_, cancels, _, _ := up.snapshot()
		return len(cancels) == 1
	})
	_, cancels, _, _ := up.snapshot()
	wantPid := uint32(4242)
	wantSecret := binary.BigEndian.Uint32([]byte{0xde, 0xad, 0xbe, 0xef})
	if cancels[0] != [2]uint32{wantPid, wantSecret} {
		t.Fatalf("cancel request carried pid/secret %v, want [%d %d]", cancels[0], wantPid, wantSecret)
	}

	_, err = mrr.ReadAll()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "57014" {
		t.Fatalf("expected cancellation error 57014, got %v", err)
	}
	if !strings.Contains(err.Error(), "canceling statement") {
		t.Fatalf("unexpected cancellation message: %v", err)
	}
}

func TestProxyClosesBothSidesOnClientDisconnect(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	srv, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	conn, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("connect through proxy: %v", err)
	}
	if _, err := conn.Exec(context.Background(), "select 1").ReadAll(); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if err := conn.Close(context.Background()); err != nil {
		t.Fatalf("close client: %v", err)
	}
	waitFor(t, "proxy to release the connection", func() bool {
		active, total, _ := srv.Stats()
		return total == 1 && active == 0
	})
	// 关闭后代理仍可服务新连接。
	conn2, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("second connect: %v", err)
	}
	defer conn2.Close(context.Background())
	if _, err := conn2.Exec(context.Background(), "select 1").ReadAll(); err != nil {
		t.Fatalf("second exec: %v", err)
	}
}

func TestProxyConnectionLimit(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable, MaxConnections: 1})

	first, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	defer first.Close(context.Background())

	_, err = connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err == nil {
		t.Fatal("expected the second connection to be rejected")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != codeTooManyConnections {
		t.Fatalf("expected SQLSTATE %s, got %v", codeTooManyConnections, err)
	}
}

func TestProxyDeclinesClientSideTLS(t *testing.T) {
	b := newFakeBroker("bind_test_db")
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer raw.Close()
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], codeSSLRequest)
	if _, err := raw.Write(req); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	reply := make([]byte, 1)
	raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(raw, reply); err != nil {
		t.Fatalf("read SSLRequest reply: %v", err)
	}
	if reply[0] != 'N' {
		t.Fatalf("expected the proxy to decline client TLS with 'N', got %q", reply[0])
	}
}

func TestProxyRejectsUnsupportedStartupVersion(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer raw.Close()
	packet := make([]byte, 8)
	binary.BigEndian.PutUint32(packet[0:4], 8)
	binary.BigEndian.PutUint32(packet[4:8], 12345)
	if _, err := raw.Write(packet); err != nil {
		t.Fatalf("write startup: %v", err)
	}
	raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, frame, err := readFrame(bufio.NewReader(raw))
	if err != nil {
		t.Fatalf("read error frame: %v", err)
	}
	if typ != 'E' {
		t.Fatalf("expected an error frame, got %q", typ)
	}
	var resp pgproto3.ErrorResponse
	if err := resp.Decode(frame[5:]); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.Code != codeProtocolViolation {
		t.Fatalf("expected SQLSTATE %s, got %s", codeProtocolViolation, resp.Code)
	}
}

func TestProxyUpstreamTLSVerifiedWithCustomCA(t *testing.T) {
	caPath, cert := testCertificates(t)
	up := newFakeUpstream(t, "scram").withTLS(cert)
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSRequire, UpstreamCA: caPath})

	conn, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("connect through TLS upstream: %v", err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), "select 1").ReadAll(); err != nil {
		t.Fatalf("exec over TLS upstream: %v", err)
	}
	if !up.usedTLS() {
		t.Fatal("expected the proxy to negotiate TLS with the upstream")
	}
}

func TestProxyRejectsUpstreamCertificateFromUnknownCA(t *testing.T) {
	_, cert := testCertificates(t)
	up := newFakeUpstream(t, "scram").withTLS(cert)
	// 另一张真实 CA：不包含签发上游证书的 CA，因此校验必须失败。
	otherCAPath, _ := testCertificates(t)
	otherPath := otherCAPath

	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSRequire, UpstreamCA: otherPath})

	_, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err == nil {
		t.Fatal("expected an unverifiable upstream certificate to be rejected")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != codeConnectionFailure {
		t.Fatalf("expected SQLSTATE %s, got %v", codeConnectionFailure, err)
	}
}

func TestProxyRequiresTLSWhenUpstreamDoesNotOfferIt(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{})

	_, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err == nil {
		t.Fatal("expected default TLS policy to fail against a plaintext upstream")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != codeConnectionFailure {
		t.Fatalf("expected SQLSTATE %s, got %v", codeConnectionFailure, err)
	}
}

func TestProxySupportsMD5AndCleartextUpstreamAuth(t *testing.T) {
	for _, mode := range []string{"md5", "cleartext"} {
		t.Run(mode, func(t *testing.T) {
			up := newFakeUpstream(t, mode)
			b := newFakeBroker("bind_test_db")
			b.setOrigin("http://" + up.Addr())
			_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

			conn, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
			if err != nil {
				t.Fatalf("connect with %s upstream auth: %v", mode, err)
			}
			defer conn.Close(context.Background())
			if _, err := conn.Exec(context.Background(), "select 1").ReadAll(); err != nil {
				t.Fatalf("exec: %v", err)
			}
			if _, _, _, failures := up.snapshot(); failures != 0 {
				t.Fatalf("upstream reported failures: %v", up.lastErr)
			}
		})
	}
}

func TestProxyRejectsWrongUpstreamPassword(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	b.fields["password"] = "wrong-upstream-secret"
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	_, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err == nil {
		t.Fatal("expected upstream authentication failure to be surfaced")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != codeConnectionFailure {
		t.Fatalf("expected SQLSTATE %s, got %v", codeConnectionFailure, err)
	}
}

func TestWarmUpCachesUpstreamAddressForCancel(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	srv, _ := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	if err := srv.WarmUp(context.Background(), testToken); err != nil {
		t.Fatalf("warm up: %v", err)
	}
	addr, ok := srv.cachedUpstreamAddr()
	if !ok || addr != up.Addr() {
		t.Fatalf("cached upstream address %q, want %q", addr, up.Addr())
	}
}

// 默认 libpq/pgconn 会先发 SSLRequest；代理回 'N' 后客户端应继续明文握手。
func TestProxyHandlesSSLRequestThenStartup(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	connString := fmt.Sprintf("postgres://keykoi:%s@%s/keykoi_test?sslmode=prefer&connect_timeout=5", url.QueryEscape(testToken), addr)
	cfg, err := pgconn.ParseConfig(connString)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect with sslmode=prefer: %v", err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), "select 1").ReadAll(); err != nil {
		t.Fatalf("exec: %v", err)
	}
}

// Unix socket 监听：真实驱动按 libpq 约定使用 <dir>/.s.PGSQL.<port>。
func TestProxyUnixSocketListener(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	// unix socket 路径有长度上限，使用短目录。
	dir, err := os.MkdirTemp("", "kkdb")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	srv := startProxyWithConfig(t, b, Config{UpstreamTLS: TLSDisable, ListenSocket: filepath.Join(dir, ".s.PGSQL.55432")})
	addrs := srv.Addrs()
	if len(addrs) != 2 || addrs[1] != "unix:"+filepath.Join(dir, ".s.PGSQL.55432") {
		t.Fatalf("unexpected listen addresses %v", addrs)
	}

	cfg, err := pgconn.ParseConfig(fmt.Sprintf("postgres://keykoi:%s@/keykoi_test?host=%s&port=55432&sslmode=disable",
		url.QueryEscape(testToken), url.QueryEscape(dir)))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect over unix socket: %v", err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), "select 1").ReadAll(); err != nil {
		t.Fatalf("exec over unix socket: %v", err)
	}
	if info, err := os.Stat(filepath.Join(dir, ".s.PGSQL.55432")); err == nil {
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("unix socket permissions %v, want 0600", info.Mode().Perm())
		}
	}
}

// TestProxyUsesAuthorizedBindingSnapshot 断言上游目标只来自同一次授权返回的 Binding 快照：
// 已废弃的 /v1/bindings 双读路径不再参与，改绑后也不会把新凭证发到旧目标。
func TestProxyUsesAuthorizedBindingSnapshot(t *testing.T) {
	legacy := newFakeUpstream(t, "scram")
	authorized := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + legacy.Addr())
	b.authorizeOrigin("http://" + authorized.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	conn, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("connect through proxy: %v", err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), "select 1").ReadAll(); err != nil {
		t.Fatalf("exec: %v", err)
	}

	queries, _, conns, _ := authorized.snapshot()
	if conns != 1 || len(queries) != 1 {
		t.Fatalf("authorized upstream saw conns=%d queries=%v", conns, queries)
	}
	if _, _, legacyConns, _ := legacy.snapshot(); legacyConns != 0 {
		t.Fatalf("the read-only binding list was used as the target: legacy upstream saw %d connection(s)", legacyConns)
	}
	if b.listCalls != 0 {
		t.Fatalf("proxy still listed /v1/bindings %d time(s)", b.listCalls)
	}
}

// TestResolveTargetFollowsBindingChange 断言两次授权各自用自己返回的目标：
// 改绑后的连接用新目标，且不复用第一次授权的目标或字段。
func TestResolveTargetFollowsBindingChange(t *testing.T) {
	b := newFakeBroker("bind_test_db")
	// 凭证里不带 database 字段，目标数据库才会回落到客户端启动包里的库名。
	delete(b.fields, "database")
	srv, err := New(b, Config{BindingID: "bind_test_db", ClientUser: "keykoi"})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	b.authorizeOrigin("http://127.0.0.1:15432")
	first, err := srv.resolveTarget(context.Background(), testToken, "db_one")
	if err != nil {
		t.Fatalf("resolve before rebinding: %v", err)
	}
	if first.Addr != "127.0.0.1:15432" || first.Database != "db_one" {
		t.Fatalf("first target = %s", first)
	}

	b.authorizeOrigin("http://127.0.0.1:25432")
	second, err := srv.resolveTarget(context.Background(), testToken, "db_two")
	if err != nil {
		t.Fatalf("resolve after rebinding: %v", err)
	}
	if second.Addr != "127.0.0.1:25432" || second.Database != "db_two" {
		t.Fatalf("second target = %s", second)
	}
	if b.listCalls != 0 {
		t.Fatalf("proxy read the binding list instead of the authorization snapshot")
	}
}

func TestProxyEndsConnectionWhenBindingRevisionChanges(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable, RevalidateInterval: 20 * time.Millisecond})

	conn, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("connect through proxy: %v", err)
	}
	defer conn.Close(context.Background())
	// 改绑只改变 daemon 侧登记的绑定，既有连接手里仍是旧快照。
	b.reviseLive("http://127.0.0.1:1", 7)

	waitFor(t, "the revised binding to end the existing connection", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err := conn.Exec(ctx, "select 1").ReadAll()
		return err != nil
	})
	// One authorization spans the whole connection and is finished after disconnect.
	deadline := time.Now().Add(time.Second)
	for {
		resolved, finished := b.leaseCounts()
		if resolved == 1 && finished == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected one completed execution, got resolved=%d finished=%d", resolved, finished)
		}
		time.Sleep(time.Millisecond)
	}
	b.mu.Lock()
	getCalls := b.getCalls
	b.mu.Unlock()
	if getCalls == 0 {
		t.Fatal("the proxy never checked the binding revision on the existing connection")
	}
}

// TestExistingConnectionEndsWhenBindingStatusChanges 断言状态不再是 active 时结束连接。
func TestExistingConnectionEndsWhenBindingStatusChanges(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable, RevalidateInterval: 20 * time.Millisecond})

	conn, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("connect through proxy: %v", err)
	}
	defer conn.Close(context.Background())
	b.setLiveStatus(model.StatusDisabled)

	waitFor(t, "the disabled binding to end the existing connection", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err := conn.Exec(ctx, "select 1").ReadAll()
		return err != nil
	})
}

// TestExistingConnectionEndsWhenUpstreamOriginChanges 断言 revision 不变但目标 origin
// 改绑时同样结束连接；旧连接不会被引导到新目标上。
func TestExistingConnectionEndsWhenUpstreamOriginChanges(t *testing.T) {
	oldUpstream := newFakeUpstream(t, "scram")
	newUpstream := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + oldUpstream.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable, RevalidateInterval: 20 * time.Millisecond})

	conn, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("connect through proxy: %v", err)
	}
	defer conn.Close(context.Background())
	// revision 保持不变，只把登记的目标换成另一台上游。
	b.reviseLive("http://"+newUpstream.Addr(), 0)

	waitFor(t, "the changed upstream origin to end the existing connection", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err := conn.Exec(ctx, "select 1").ReadAll()
		return err != nil
	})
	if _, _, conns, _ := newUpstream.snapshot(); conns != 0 {
		t.Fatalf("the moved target was contacted on the old connection: %d connection(s)", conns)
	}
}

// TestBindingCheckFailureKeepsConnection 断言 daemon 暂时不可达时不断开连接，
// 恢复后仍能按新的 revision 结束连接（失败只记录并重试）。
func TestBindingCheckFailureKeepsConnection(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable, RevalidateInterval: 20 * time.Millisecond})

	conn, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("connect through proxy: %v", err)
	}
	defer conn.Close(context.Background())

	b.failGets(errors.New("keykoid is unreachable"))
	time.Sleep(120 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, "select 1").ReadAll(); err != nil {
		t.Fatalf("a failed binding check closed the connection: %v", err)
	}
	b.mu.Lock()
	failedChecks := b.getCalls
	b.mu.Unlock()
	if failedChecks < 2 {
		t.Fatalf("binding checks were not retried: %d attempt(s)", failedChecks)
	}

	b.failGets(nil)
	b.reviseLive("http://127.0.0.1:1", 3)
	waitFor(t, "the connection to end once checks succeed again", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err := conn.Exec(ctx, "select 1").ReadAll()
		return err != nil
	})
}

// TestBindingCheckIsThrottledAndCoversIdleConnections 断言转发环里的核对既不是
// 逐消息触发、也不会因为连接空闲而停止。
func TestBindingCheckIsThrottledAndCoversIdleConnections(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	_, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable, RevalidateInterval: 100 * time.Millisecond})

	conn, err := connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err != nil {
		t.Fatalf("connect through proxy: %v", err)
	}
	defer conn.Close(context.Background())
	for i := 0; i < 30; i++ {
		if _, err := conn.Exec(context.Background(), "select 1").ReadAll(); err != nil {
			t.Fatalf("exec %d: %v", i, err)
		}
	}
	b.mu.Lock()
	burstChecks := b.getCalls
	b.mu.Unlock()
	if burstChecks > 5 {
		t.Fatalf("binding checks followed every message: %d checks for 30 queries", burstChecks)
	}
	waitFor(t, "an idle connection to be checked again", func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.getCalls > burstChecks
	})
}

// TestShutdownCancelsIdleConnections 断言关闭时先取消活跃连接再限时等待：
// 空闲连接不会让退出无限挂起。
func TestShutdownCancelsIdleConnections(t *testing.T) {
	up := newFakeUpstream(t, "scram")
	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + up.Addr())
	srv, addr := startProxy(t, b, Config{UpstreamTLS: TLSDisable})

	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer raw.Close()
	waitFor(t, "the proxy to accept the connection", func() bool {
		active, _, _ := srv.Stats()
		return active == 1
	})

	start := time.Now()
	// 没有截止时间的 ctx：实现内部仍取默认排空上限。
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("shutdown took %v, an idle connection kept it open", elapsed)
	}
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := raw.Read(make([]byte, 1)); err == nil {
		t.Fatalf("client connection was left open after shutdown")
	}
	waitFor(t, "the active counter to drop", func() bool {
		active, _, _ := srv.Stats()
		return active == 0
	})
}

// TestUpstreamHandshakeDeadline 断言上游接受连接却不回包时，认证读取按 AuthTimeout 结束。
func TestUpstreamHandshakeDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	release := make(chan struct{})
	defer close(release)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				<-release // 接受连接但永远不完成上游握手
			}(c)
		}
	}()

	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + ln.Addr().String())
	_, addr := startProxy(t, b, Config{AuthTimeout: 700 * time.Millisecond, UpstreamTLS: TLSDisable})

	start := time.Now()
	_, err = connect(t, addr, "keykoi", testToken, "keykoi_test")
	if err == nil {
		t.Fatal("expected the upstream handshake to time out")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("upstream handshake deadline did not apply: %v", elapsed)
	}
}

// startPasswordAuth 完成代理的客户端侧认证（启动包 + cleartext 令牌），
// 然后停在代理等待上游握手的位置，便于验证上游静默时的截止时间。
func startPasswordAuth(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	startup := &pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters:      map[string]string{"user": "keykoi", "database": "keykoi_test"},
	}
	frame, err := startup.Encode(nil)
	if err != nil {
		t.Fatalf("encode startup: %v", err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write startup: %v", err)
	}
	r := bufio.NewReader(conn)
	if typ, _, err := readTypedMessage(r); err != nil || typ != 'R' {
		t.Fatalf("expected an authentication request, got %q err=%v", typ, err)
	}
	password, err := (&pgproto3.PasswordMessage{Password: testToken}).Encode(nil)
	if err != nil {
		t.Fatalf("encode password: %v", err)
	}
	if _, err := conn.Write(password); err != nil {
		t.Fatalf("write password: %v", err)
	}
	return conn
}

// TestShutdownIsBoundedWhileUpstreamHandshakeBlocks 断言 Shutdown 不裸等待：
// 客户端已认证、代理正阻塞在“上游接受连接却不回 SSLRequest”时，关闭仍按排空
// 截止时间返回，而不是等上游握手超时。
func TestShutdownIsBoundedWhileUpstreamHandshakeBlocks(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c // 接受连接但永远不回 SSLRequest
		}
	}()

	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + ln.Addr().String())
	srv := startProxyWithConfig(t, b, Config{
		DialTimeout: 3 * time.Second,
		AuthTimeout: 3 * time.Second,
	})

	_ = startPasswordAuth(t, srv.Addrs()[0])
	var upstreamConn net.Conn
	select {
	case upstreamConn = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("the proxy never dialed the upstream")
	}
	defer upstreamConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	// 两条有界路径都算通过：排空计时器到点返回 nil，或 ctx 先到点返回 DeadlineExceeded。
	if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Fatalf("shutdown waited for the stuck upstream handshake: %v", elapsed)
	}
	// 放掉卡住的上游连接，让处理协程退出，后续清理不必等握手超时。
	_ = upstreamConn.Close()
	waitFor(t, "the blocked handler to exit", func() bool {
		active, _, _ := srv.Stats()
		return active == 0
	})
}

// TestUpstreamSSLRequestHonorsDeadline 断言 SSLRequest 的写与读、以及 TLS 握手都在
// deadline 之下：上游接受连接却不回包时，dialUpstream 必须超时返回。
func TestUpstreamSSLRequestHonorsDeadline(t *testing.T) {
	tests := []struct {
		name  string
		reply byte // 0 表示完全静默
	}{
		{name: "silent after accept"},
		{name: "silent during tls handshake", reply: 'S'},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			release := make(chan struct{})
			defer close(release)
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						if tt.reply != 0 {
							_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
							buf := make([]byte, 8)
							if _, err := io.ReadFull(c, buf); err != nil {
								return
							}
							if _, err := c.Write([]byte{tt.reply}); err != nil {
								return
							}
						}
						<-release // 之后不再回任何字节
					}(c)
				}
			}()

			target := UpstreamTarget{Host: "127.0.0.1", Addr: ln.Addr().String()}
			start := time.Now()
			up, err := dialUpstream(context.Background(), target, TLSPrefer, "", 200*time.Millisecond)
			if err == nil {
				up.close()
				t.Fatal("dialUpstream succeeded against a silent upstream")
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("SSLRequest/TLS handshake deadline did not apply: %v", elapsed)
			}
		})
	}
}

// TestProxyFailsWithinDeadlineWhenUpstreamSilentOnSSLRequest 断言整条路径上的
// SSLRequest 静默也按 DialTimeout 结束，客户端不会永久挂起。
func TestProxyFailsWithinDeadlineWhenUpstreamSilentOnSSLRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	release := make(chan struct{})
	defer close(release)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				<-release
			}(c)
		}
	}()

	b := newFakeBroker("bind_test_db")
	b.setOrigin("http://" + ln.Addr().String())
	_, addr := startProxy(t, b, Config{DialTimeout: 200 * time.Millisecond, AuthTimeout: 400 * time.Millisecond})

	start := time.Now()
	if _, err := connect(t, addr, "keykoi", testToken, "keykoi_test"); err == nil {
		t.Fatal("expected the upstream handshake to fail")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("the client waited for a silent upstream: %v", elapsed)
	}
}
