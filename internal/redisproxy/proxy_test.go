package redisproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
)

// fakeBroker 是 IPC 的测试替身。Resolve 返回凭证与同一次授权的 Binding 快照；
// Get 提供单条绑定详情（既有连接核对改绑用）与旧的绑定列表（断言代理不再读它）。
type fakeBroker struct {
	mu         sync.Mutex
	fields     map[string]string
	resolveErr error
	binding    model.Binding
	// authorized 是 Resolve 返回的 Binding 快照；nil 表示用 binding。
	authorized *model.Binding
	// getCalls 是单条绑定查询次数，listCalls 是旧的列表读取次数。
	getCalls  int
	listCalls int
	// getErr 非 nil 时单条绑定查询失败（模拟 daemon 暂时不可达）。
	getErr  error
	calls   int
	revoked []string
}

// authorize 让 Resolve 返回与 binding 不同的快照（模拟改绑后的目标）。
func (b *fakeBroker) authorize(origin string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	snapshot := b.binding
	snapshot.UpstreamOrigin = origin
	b.authorized = &snapshot
}

func (b *fakeBroker) rebind(origin string, revision int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.binding.UpstreamOrigin = origin
	b.binding.Revision = revision
	if b.authorized != nil {
		b.authorized.UpstreamOrigin = origin
		b.authorized.Revision = revision
	}
}

// reviseLive 只改当前登记的绑定，不动本次连接手里的授权快照。
func (b *fakeBroker) reviseLive(origin string, revision int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.binding.UpstreamOrigin = origin
	b.binding.Revision = revision
}

// setLiveStatus 改当前登记的绑定状态。
func (b *fakeBroker) setLiveStatus(status model.EntityStatus) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.binding.Status = status
}

// failGets 让单条绑定查询按给定错误失败（nil 表示恢复）。
func (b *fakeBroker) failGets(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.getErr = err
}

func (b *fakeBroker) RevokeLease(leaseID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revoked = append(b.revoked, leaseID)
	return nil
}

func (b *fakeBroker) leaseCounts() (resolved, revoked int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls, len(b.revoked)
}

func (b *fakeBroker) Resolve(token, bindingID, mode string) (*ipcclient.Resolved, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.resolveErr != nil {
		return nil, b.resolveErr
	}
	if token != "kks_test_token" {
		return nil, &ipcclient.APIError{Code: string(model.CodeSessionInvalid), Message: "session is invalid"}
	}
	if mode != string(model.ModeRuntimeDelivery) {
		return nil, &ipcclient.APIError{Code: string(model.CodeUseNotAllowed), Message: "mode not allowed"}
	}
	out := &ipcclient.Resolved{Fields: map[string]string{}}
	for k, v := range b.fields {
		out.Fields[k] = v
	}
	snapshot := b.binding
	if b.authorized != nil {
		snapshot = *b.authorized
	}
	out.Binding = &snapshot
	out.Lease = model.UseLease{ID: fmt.Sprintf("lease-%d", b.calls), BindingRevision: snapshot.Revision}
	return out, nil
}

func (b *fakeBroker) Get(path string, out any) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if path == "/v1/bindings" {
		b.listCalls++
		target, ok := out.(*struct {
			Bindings []model.Binding `json:"bindings"`
		})
		if !ok {
			return fmt.Errorf("unexpected output type %T", out)
		}
		target.Bindings = []model.Binding{b.binding}
		return nil
	}
	b.getCalls++
	if b.getErr != nil {
		return b.getErr
	}
	if path != "/v1/bindings/"+b.binding.ID {
		return fmt.Errorf("unexpected path %s", path)
	}
	target, ok := out.(*model.Binding)
	if !ok {
		return fmt.Errorf("unexpected output type %T", out)
	}
	*target = b.binding
	return nil
}

// fakeRedis 是最小 Redis 上游，只实现测试需要的命令。
type fakeRedis struct {
	ln       net.Listener
	password string
	// tlsConfig 非 nil 时上游要求 TLS，握手成功后才读命令。
	tlsConfig *tls.Config
	// rejectHELLO3 模拟只支持 RESP2 的上游。
	rejectHELLO3 bool

	mu       sync.Mutex
	commands [][]string
	tlsUsed  bool
	conns    int
	closed   chan struct{}
}

// fakeRedisOption 在启动 accept 循环之前配置上游，避免与处理协程共享可变字段。
type fakeRedisOption func(*fakeRedis)

// withFakeTLS 让上游要求 TLS。
func withFakeTLS(cert tls.Certificate) fakeRedisOption {
	return func(f *fakeRedis) {
		f.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
}

// withRESP2Only 让上游拒绝 HELLO，模拟只支持 RESP2 的服务端。
func withRESP2Only() fakeRedisOption {
	return func(f *fakeRedis) { f.rejectHELLO3 = true }
}

func newFakeRedis(t *testing.T, password string) *fakeRedis {
	t.Helper()
	return newFakeRedisWith(t, password)
}

func newFakeRedisWith(t *testing.T, password string, opts ...fakeRedisOption) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeRedis{ln: ln, password: password, closed: make(chan struct{}, 4)}
	for _, opt := range opts {
		opt(f)
	}
	go f.accept()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeRedis) addr() string { return f.ln.Addr().String() }

func (f *fakeRedis) accept() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
			if f.tlsConfig != nil {
				tc := tls.Server(c, f.tlsConfig)
				if err := tc.Handshake(); err != nil {
					_ = c.Close()
					return
				}
				f.mu.Lock()
				f.tlsUsed = true
				f.mu.Unlock()
				c = tc
			}
			f.handle(c)
		}(c)
	}
}

// connCount 返回上游收到过的 TCP 连接数。
func (f *fakeRedis) connCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

// usedTLS 报告上游是否完成过 TLS 握手。
func (f *fakeRedis) usedTLS() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tlsUsed
}

func (f *fakeRedis) record(args []string) {
	f.mu.Lock()
	f.commands = append(f.commands, append([]string(nil), args...))
	f.mu.Unlock()
}

func (f *fakeRedis) seen() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.commands))
	copy(out, f.commands)
	return out
}

func (f *fakeRedis) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	store := map[string]string{}
	authed := f.password == ""
	for {
		_, args, err := readCommand(r)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		f.record(args)
		switch strings.ToUpper(args[0]) {
		case "AUTH":
			if len(args) == 2 && args[1] == f.password {
				authed = true
				_, _ = c.Write(simpleString("OK"))
			} else if len(args) == 3 && args[2] == f.password {
				authed = true
				_, _ = c.Write(simpleString("OK"))
			} else if f.password == "" {
				_, _ = c.Write(errorString("ERR Client sent AUTH, but no password is set. Did you mean AUTH <username> <password>?"))
			} else {
				_, _ = c.Write(errorString("WRONGPASS invalid username-password pair or user is disabled."))
			}
		case "HELLO":
			if f.rejectHELLO3 {
				_, _ = c.Write(errorString("ERR unknown command 'HELLO'"))
				continue
			}
			if !authed {
				_, _ = c.Write(errorString("NOAUTH HELLO must be called with the client already authenticated"))
				continue
			}
			_, _ = c.Write(helloReply(3))
		case "PING":
			if !authed {
				_, _ = c.Write(errorString("NOAUTH Authentication required."))
				continue
			}
			_, _ = c.Write(simpleString("PONG"))
		case "SELECT":
			_, _ = c.Write(simpleString("OK"))
		case "SET":
			store[args[1]] = args[2]
			_, _ = c.Write(simpleString("OK"))
		case "GET":
			if v, ok := store[args[1]]; ok {
				_, _ = c.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(v), v)))
			} else {
				_, _ = c.Write([]byte("$-1\r\n"))
			}
		case "INFO":
			body := "# Server\r\nredis_version:8.6.0\r\n"
			_, _ = c.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(body), body)))
		case "BLPOP":
			// 阻塞命令：等待客户端断开或超时，用于验证双向转发不被代理截断。
			time.Sleep(50 * time.Millisecond)
			_, _ = c.Write([]byte("*0\r\n"))
		case "QUIT":
			_, _ = c.Write(simpleString("OK"))
			return
		default:
			_, _ = c.Write(errorString("ERR unknown command '" + args[0] + "'"))
		}
	}
}

func startProxy(t *testing.T, upstreamAddr string, fields map[string]string) (*Server, string) {
	t.Helper()
	broker := &fakeBroker{
		fields: fields,
		binding: model.Binding{
			ID:             "bind_redis_test",
			UpstreamOrigin: "http://" + upstreamAddr,
			Status:         model.StatusActive,
		},
	}
	srv, err := New(broker, Config{
		BindingID:   "bind_redis_test",
		ListenAddr:  "127.0.0.1:0",
		AuthTimeout: 5 * time.Second,
		// 测试上游是明文 redis：按配置显式声明，默认路径要求 TLS。
		InsecureUpstream: true,
		Logger:           log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = srv.Shutdown(context.Background())
		<-done
	})
	return srv, srv.Addrs()[0]
}

func dialProxy(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, bufio.NewReader(conn)
}

func send(t *testing.T, conn net.Conn, args ...string) {
	t.Helper()
	if _, err := conn.Write(encodeCommand(args)); err != nil {
		t.Fatalf("write %v: %v", args, err)
	}
}

func reply(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	b, err := readReply(r)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return string(b)
}

func TestAuthThenTransparentCommands(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	_, addr := startProxy(t, up.addr(), map[string]string{"password": "s3cret-upstream", "username": ""})
	conn, r := dialProxy(t, addr)

	send(t, conn, "AUTH", "kks_test_token")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("AUTH reply = %q", got)
	}
	send(t, conn, "SET", "k", "v")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("SET reply = %q", got)
	}
	send(t, conn, "GET", "k")
	if got := reply(t, r); got != "$1\r\nv\r\n" {
		t.Fatalf("GET reply = %q", got)
	}
	send(t, conn, "PING")
	if got := reply(t, r); got != "+PONG\r\n" {
		t.Fatalf("PING reply = %q", got)
	}
	send(t, conn, "SELECT", "0")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("SELECT reply = %q", got)
	}
	send(t, conn, "INFO")
	if got := reply(t, r); !strings.Contains(got, "redis_version:8.6.0") {
		t.Fatalf("INFO reply = %q", got)
	}

	// 上游只应看到真实密码，绝不出现会话令牌。
	for _, cmd := range up.seen() {
		for _, a := range cmd {
			if a == "kks_test_token" {
				t.Fatalf("session token leaked to upstream: %v", cmd)
			}
		}
	}
}

func TestWrongTokenRejected(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	_, addr := startProxy(t, up.addr(), map[string]string{"password": "s3cret-upstream"})
	conn, r := dialProxy(t, addr)

	send(t, conn, "AUTH", "kks_wrong")
	got := reply(t, r)
	if !strings.HasPrefix(got, "-NOAUTH ") {
		t.Fatalf("wrong token reply = %q", got)
	}
	if strings.Contains(got, "kks_wrong") {
		t.Fatalf("reply echoed the token: %q", got)
	}
}

func TestNoGrantRejected(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	broker := &fakeBroker{
		resolveErr: &ipcclient.APIError{Code: string(model.CodeUseNotAllowed), Message: "no runtime_delivery grant"},
		binding: model.Binding{
			ID: "bind_redis_test", UpstreamOrigin: "http://" + up.addr(), Status: model.StatusActive,
		},
	}
	srv, err := New(broker, Config{BindingID: "bind_redis_test", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	conn, r := dialProxy(t, srv.Addrs()[0])
	send(t, conn, "AUTH", "kks_test_token")
	got := reply(t, r)
	if !strings.HasPrefix(got, "-NOAUTH ") || !strings.Contains(got, "not authorized") {
		t.Fatalf("no-grant reply = %q", got)
	}
}

func TestCommandBeforeAuthIsRejectedThenAuthSucceeds(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	_, addr := startProxy(t, up.addr(), map[string]string{"password": "s3cret-upstream"})
	conn, r := dialProxy(t, addr)

	send(t, conn, "PING")
	if got := reply(t, r); got != unauthorizedReply {
		t.Fatalf("pre-auth PING reply = %q", got)
	}
	send(t, conn, "AUTH", "kks_test_token")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("AUTH reply = %q", got)
	}
	send(t, conn, "PING")
	if got := reply(t, r); got != "+PONG\r\n" {
		t.Fatalf("PING reply = %q", got)
	}
}

func TestReAuthAfterConnectRewritesPassword(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	_, addr := startProxy(t, up.addr(), map[string]string{"password": "s3cret-upstream"})
	conn, r := dialProxy(t, addr)

	send(t, conn, "AUTH", "kks_test_token")
	_ = reply(t, r)
	send(t, conn, "AUTH", "default", "kks_test_token")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("re-AUTH reply = %q", got)
	}
	seen := up.seen()
	if len(seen) < 2 {
		t.Fatalf("upstream saw %d commands", len(seen))
	}
	last := seen[len(seen)-1]
	if last[0] != "AUTH" || last[len(last)-1] != "s3cret-upstream" {
		t.Fatalf("upstream re-auth command = %v", last)
	}
	for _, a := range last {
		if strings.Contains(a, "kks_") {
			t.Fatalf("session token leaked on re-auth: %v", last)
		}
	}
}

func TestHelloWithAuth(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	_, addr := startProxy(t, up.addr(), map[string]string{"password": "s3cret-upstream"})
	conn, r := dialProxy(t, addr)

	send(t, conn, "HELLO", "3", "AUTH", "default", "kks_test_token")
	raw, err := readReply(r)
	if err != nil {
		t.Fatalf("read hello reply: %v", err)
	}
	if len(raw) == 0 || raw[0] != '%' {
		t.Fatalf("hello reply = %q", raw)
	}
	send(t, conn, "PING")
	if got := reply(t, r); got != "+PONG\r\n" {
		t.Fatalf("PING reply = %q", got)
	}
}

func TestUpstreamRejectsRegisteredCredential(t *testing.T) {
	up := newFakeRedis(t, "correct-password")
	_, addr := startProxy(t, up.addr(), map[string]string{"password": "wrong-password"})
	conn, r := dialProxy(t, addr)

	send(t, conn, "AUTH", "kks_test_token")
	got := reply(t, r)
	if !strings.HasPrefix(got, "-NOAUTH ") {
		t.Fatalf("upstream auth failure reply = %q", got)
	}
	if strings.Contains(got, "correct-password") || strings.Contains(got, "wrong-password") {
		t.Fatalf("reply leaked a password: %q", got)
	}
}

func TestClientDisconnectClosesUpstream(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	srv, addr := startProxy(t, up.addr(), map[string]string{"password": "s3cret-upstream"})
	conn, r := dialProxy(t, addr)
	send(t, conn, "AUTH", "kks_test_token")
	_ = reply(t, r)
	_ = conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		active, total, _ := srv.Stats()
		if active == 0 && total == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active connections did not return to 0: active=%d total=%d", active, total)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestUnsupportedUpstreamSchemeRejected(t *testing.T) {
	broker := &fakeBroker{
		fields:  map[string]string{"password": "x"},
		binding: model.Binding{ID: "bind_redis_test", UpstreamOrigin: "ftp://127.0.0.1:6379", Status: model.StatusActive},
	}
	srv, err := New(broker, Config{BindingID: "bind_redis_test", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	conn, r := dialProxy(t, srv.Addrs()[0])
	send(t, conn, "AUTH", "kks_test_token")
	got := reply(t, r)
	if !strings.HasPrefix(got, "-NOAUTH ") {
		t.Fatalf("invalid origin reply = %q", got)
	}
}

func TestBrokerErrorDoesNotLeakDetail(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	broker := &fakeBroker{
		resolveErr: errors.New("vault: internal path /Users/secret/leak"),
		binding:    model.Binding{ID: "bind_redis_test", UpstreamOrigin: "http://" + up.addr(), Status: model.StatusActive},
	}
	srv, err := New(broker, Config{BindingID: "bind_redis_test", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	conn, r := dialProxy(t, srv.Addrs()[0])
	send(t, conn, "AUTH", "kks_test_token")
	got := reply(t, r)
	if strings.Contains(got, "/Users/secret/leak") {
		t.Fatalf("broker error leaked to client: %q", got)
	}
}

func TestReadCommandRoundTrip(t *testing.T) {
	raw := encodeCommand([]string{"SET", "k", "hello world"})
	r := bufio.NewReader(strings.NewReader(string(raw)))
	gotRaw, args, err := readCommand(r)
	if err != nil {
		t.Fatalf("readCommand: %v", err)
	}
	if string(gotRaw) != string(raw) {
		t.Fatalf("raw = %q want %q", gotRaw, raw)
	}
	if strings.Join(args, "|") != "SET|k|hello world" {
		t.Fatalf("args = %v", args)
	}

	// inline 命令
	r = bufio.NewReader(strings.NewReader("PING\r\n"))
	_, args, err = readCommand(r)
	if err != nil || strings.Join(args, "|") != "PING" {
		t.Fatalf("inline args = %v err=%v", args, err)
	}

	// RESP3 map 原样透传
	resp3 := "%1\r\n$1\r\na\r\n:1\r\n"
	r = bufio.NewReader(strings.NewReader(resp3))
	gotRaw, args, err = readCommand(r)
	if err != nil || args != nil || string(gotRaw) != resp3 {
		t.Fatalf("resp3 raw=%q args=%v err=%v", gotRaw, args, err)
	}
}

// ---- 04：目标只来自同一次授权 ----

func TestProxyUsesAuthorizedBindingSnapshot(t *testing.T) {
	legacy := newFakeRedis(t, "s3cret-upstream")
	authorized := newFakeRedis(t, "s3cret-upstream")
	broker := &fakeBroker{
		fields: map[string]string{"password": "s3cret-upstream"},
		// 旧的 /v1/bindings 读取路径指向被替换掉的旧目标。
		binding: model.Binding{ID: "bind_redis_test", UpstreamOrigin: "http://" + legacy.addr(), Status: model.StatusActive},
	}
	broker.authorize("http://" + authorized.addr())

	srv, err := New(broker, Config{
		BindingID:        "bind_redis_test",
		ListenAddr:       "127.0.0.1:0",
		AuthTimeout:      5 * time.Second,
		InsecureUpstream: true,
		Logger:           log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	defer func() {
		cancel()
		_ = srv.Shutdown(context.Background())
	}()

	conn, r := dialProxy(t, srv.Addrs()[0])
	send(t, conn, "AUTH", "kks_test_token")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("AUTH reply = %q", got)
	}
	if len(authorized.seen()) == 0 {
		t.Fatalf("the authorized upstream never saw AUTH")
	}
	if len(legacy.seen()) != 0 || legacy.connCount() != 0 {
		t.Fatalf("the stale binding list target was used: conns=%d commands=%v", legacy.connCount(), legacy.seen())
	}
	broker.mu.Lock()
	listCalls := broker.listCalls
	broker.mu.Unlock()
	if listCalls != 0 {
		t.Fatalf("proxy still listed /v1/bindings %d time(s)", listCalls)
	}
}

// startRedisProxyWithBroker 用给定替身启动代理，返回服务器与地址。
func startRedisProxyWithBroker(t *testing.T, broker *fakeBroker, audit Config) (*Server, string) {
	t.Helper()
	cfg := audit
	cfg.BindingID = "bind_redis_test"
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.AuthTimeout = 5 * time.Second
	cfg.InsecureUpstream = true
	cfg.Logger = log.New(io.Discard, "", 0)
	srv, err := New(broker, cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = srv.Shutdown(context.Background())
		<-done
	})
	return srv, srv.Addrs()[0]
}

// readBindingChangeReply 断言代理在改绑后先回 -ERR 再关闭连接。
func readBindingChangeReply(t *testing.T, conn net.Conn, r *bufio.Reader) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := readReply(r)
	if err != nil {
		t.Fatalf("expected an -ERR reply before the connection closes: %v", err)
	}
	if !strings.HasPrefix(string(got), "-ERR") || !strings.Contains(string(got), "binding") {
		t.Fatalf("binding change reply = %q, want an -ERR about the binding", got)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection remained open after the binding changed")
	}
}

func writeCommand(conn net.Conn, args ...string) error {
	_, err := conn.Write(encodeCommand(args))
	return err
}

func TestProxyEndsConnectionWhenBindingRevisionChanges(t *testing.T) {
	oldUpstream := newFakeRedis(t, "s3cret-upstream")
	newUpstream := newFakeRedis(t, "new-secret")
	broker := &fakeBroker{
		fields:  map[string]string{"password": "s3cret-upstream"},
		binding: model.Binding{ID: "bind_redis_test", UpstreamOrigin: "http://" + oldUpstream.addr(), Status: model.StatusActive},
	}
	_, addr := startRedisProxyWithBroker(t, broker, Config{RevalidateInterval: 20 * time.Millisecond})

	conn, r := dialProxy(t, addr)
	send(t, conn, "AUTH", "kks_test_token")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("AUTH reply = %q", got)
	}

	// 只改 daemon 侧登记的绑定：既有连接手里仍是旧快照。
	broker.reviseLive("http://"+newUpstream.addr(), 2)
	readBindingChangeReply(t, conn, r)
	if newUpstream.connCount() != 0 {
		t.Fatal("the revised target was contacted on the old connection")
	}
	// 旧连接不做第二次授权：许可只在建立时创建并已经释放。
	if resolved, revoked := broker.leaseCounts(); resolved != 1 || revoked != 1 {
		t.Fatalf("existing connection re-authorized: resolved=%d revoked=%d", resolved, revoked)
	}
}

// TestExistingConnectionEndsWhenBindingStatusChanges 断言状态不再是 active 时结束连接。
func TestExistingConnectionEndsWhenBindingStatusChanges(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	broker := &fakeBroker{
		fields:  map[string]string{"password": "s3cret-upstream"},
		binding: model.Binding{ID: "bind_redis_test", UpstreamOrigin: "http://" + up.addr(), Status: model.StatusActive},
	}
	_, addr := startRedisProxyWithBroker(t, broker, Config{RevalidateInterval: 20 * time.Millisecond})
	conn, r := dialProxy(t, addr)
	send(t, conn, "AUTH", "kks_test_token")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("AUTH reply = %q", got)
	}
	broker.setLiveStatus(model.StatusDisabled)
	readBindingChangeReply(t, conn, r)
}

// TestExistingConnectionEndsWhenUpstreamOriginChanges 断言 revision 不变但 origin
// 改绑时同样结束连接，旧连接不会被引导到新目标。
func TestExistingConnectionEndsWhenUpstreamOriginChanges(t *testing.T) {
	oldUpstream := newFakeRedis(t, "s3cret-upstream")
	newUpstream := newFakeRedis(t, "s3cret-upstream")
	broker := &fakeBroker{
		fields:  map[string]string{"password": "s3cret-upstream"},
		binding: model.Binding{ID: "bind_redis_test", UpstreamOrigin: "http://" + oldUpstream.addr(), Status: model.StatusActive},
	}
	_, addr := startRedisProxyWithBroker(t, broker, Config{RevalidateInterval: 20 * time.Millisecond})
	conn, r := dialProxy(t, addr)
	send(t, conn, "AUTH", "kks_test_token")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("AUTH reply = %q", got)
	}
	broker.reviseLive("http://"+newUpstream.addr(), 0)
	readBindingChangeReply(t, conn, r)
	if newUpstream.connCount() != 0 {
		t.Fatalf("the moved target was contacted on the old connection: %d connection(s)", newUpstream.connCount())
	}
}

// TestBindingCheckFailureKeepsConnection 断言 daemon 暂时不可达时不断开连接，
// 恢复后仍能按新的 revision 结束连接（失败只记录并重试）。
func TestBindingCheckFailureKeepsConnection(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	broker := &fakeBroker{
		fields:  map[string]string{"password": "s3cret-upstream"},
		binding: model.Binding{ID: "bind_redis_test", UpstreamOrigin: "http://" + up.addr(), Status: model.StatusActive},
	}
	_, addr := startRedisProxyWithBroker(t, broker, Config{RevalidateInterval: 20 * time.Millisecond})
	conn, r := dialProxy(t, addr)
	send(t, conn, "AUTH", "kks_test_token")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("AUTH reply = %q", got)
	}

	broker.failGets(errors.New("keykoid is unreachable"))
	time.Sleep(120 * time.Millisecond)
	send(t, conn, "PING")
	if got := reply(t, r); got != "+PONG\r\n" {
		t.Fatalf("a failed binding check closed the connection: %q", got)
	}
	broker.mu.Lock()
	failedChecks := broker.getCalls
	broker.mu.Unlock()
	if failedChecks < 2 {
		t.Fatalf("binding checks were not retried: %d attempt(s)", failedChecks)
	}

	broker.failGets(nil)
	broker.reviseLive("http://127.0.0.1:1", 3)
	readBindingChangeReply(t, conn, r)
}

// TestBindingCheckIsThrottledAndCoversIdleConnections 断言转发环里的核对既不是
// 逐消息触发、也不会因为连接空闲而停止。
func TestBindingCheckIsThrottledAndCoversIdleConnections(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	broker := &fakeBroker{
		fields:  map[string]string{"password": "s3cret-upstream"},
		binding: model.Binding{ID: "bind_redis_test", UpstreamOrigin: "http://" + up.addr(), Status: model.StatusActive},
	}
	_, addr := startRedisProxyWithBroker(t, broker, Config{RevalidateInterval: 100 * time.Millisecond})
	conn, r := dialProxy(t, addr)
	send(t, conn, "AUTH", "kks_test_token")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("AUTH reply = %q", got)
	}
	for i := 0; i < 30; i++ {
		send(t, conn, "PING")
		if got := reply(t, r); got != "+PONG\r\n" {
			t.Fatalf("PING %d reply = %q", i, got)
		}
	}
	broker.mu.Lock()
	burstChecks := broker.getCalls
	broker.mu.Unlock()
	if burstChecks > 5 {
		t.Fatalf("binding checks followed every message: %d checks for 30 commands", burstChecks)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		broker.mu.Lock()
		checks := broker.getCalls
		broker.mu.Unlock()
		if checks > burstChecks {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("an idle connection was never checked again")
}

func TestPlaintextUpstreamRequiresExplicitOptIn(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	broker := &fakeBroker{
		fields:  map[string]string{"password": "s3cret-upstream"},
		binding: model.Binding{ID: "bind_redis_test", UpstreamOrigin: "http://" + up.addr(), Status: model.StatusActive},
	}
	srv, err := New(broker, Config{BindingID: "bind_redis_test", ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	defer func() {
		cancel()
		_ = srv.Shutdown(context.Background())
	}()

	conn, r := dialProxy(t, srv.Addrs()[0])
	send(t, conn, "AUTH", "kks_test_token")
	got := reply(t, r)
	if !strings.HasPrefix(got, "-NOAUTH ") {
		t.Fatalf("plaintext upstream reply = %q", got)
	}
	if strings.Contains(got, "s3cret-upstream") {
		t.Fatalf("reply leaked the upstream password: %q", got)
	}
	// 关键断言：拒绝时上游一个 AUTH 都没有收到。
	for _, cmd := range up.seen() {
		if strings.EqualFold(cmd[0], "AUTH") {
			t.Fatalf("the proxy sent AUTH to a plaintext upstream: %v", cmd)
		}
	}
}

func TestUpstreamTLSVerifiedBeforeAuth(t *testing.T) {
	caPath, cert := testTLSMaterials(t)
	up := newFakeRedisWith(t, "s3cret-upstream", withFakeTLS(cert))

	broker := &fakeBroker{
		fields: map[string]string{"password": "s3cret-upstream"},
		// https:// 的登记 origin 表示上游必须走受验证的 TLS。
		binding: model.Binding{ID: "bind_redis_test", UpstreamOrigin: "https://" + up.addr(), Status: model.StatusActive},
	}
	srv, err := New(broker, Config{
		BindingID:   "bind_redis_test",
		ListenAddr:  "127.0.0.1:0",
		AuthTimeout: 5 * time.Second,
		UpstreamCA:  caPath,
		Logger:      log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	defer func() {
		cancel()
		_ = srv.Shutdown(context.Background())
	}()

	conn, r := dialProxy(t, srv.Addrs()[0])
	send(t, conn, "AUTH", "kks_test_token")
	if got := reply(t, r); got != "+OK\r\n" {
		t.Fatalf("AUTH over TLS reply = %q", got)
	}
	if !up.usedTLS() {
		t.Fatal("the proxy did not establish TLS with the upstream")
	}
	seen := up.seen()
	if len(seen) == 0 || !strings.EqualFold(seen[0][0], "AUTH") {
		t.Fatalf("upstream commands = %v", seen)
	}
}

func TestUpstreamTLSRejectsUntrustedCertificate(t *testing.T) {
	_, cert := testTLSMaterials(t)
	// 另一套真实 CA：不含签发上游证书的 CA，握手必须失败。
	otherCAPath, _ := testTLSMaterials(t)
	up := newFakeRedisWith(t, "s3cret-upstream", withFakeTLS(cert))

	broker := &fakeBroker{
		fields:  map[string]string{"password": "s3cret-upstream"},
		binding: model.Binding{ID: "bind_redis_test", UpstreamOrigin: "https://" + up.addr(), Status: model.StatusActive},
	}
	srv, err := New(broker, Config{BindingID: "bind_redis_test", ListenAddr: "127.0.0.1:0", UpstreamCA: otherCAPath})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	defer func() {
		cancel()
		_ = srv.Shutdown(context.Background())
	}()

	conn, r := dialProxy(t, srv.Addrs()[0])
	send(t, conn, "AUTH", "kks_test_token")
	if got := reply(t, r); !strings.HasPrefix(got, "-NOAUTH ") {
		t.Fatalf("untrusted certificate reply = %q", got)
	}
	for _, cmd := range up.seen() {
		if strings.EqualFold(cmd[0], "AUTH") {
			t.Fatalf("AUTH was sent despite the failed certificate verification: %v", cmd)
		}
	}
}

// ---- 14：认证前的解析上限 ----

func TestPreAuthRejectsOversizedBulk(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	_, addr := startProxy(t, up.addr(), map[string]string{"password": "s3cret-upstream"})
	conn, r := dialProxy(t, addr)

	payload := "*2\r\n$4\r\nAUTH\r\n$9999999999\r\n"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := reply(t, r)
	if !strings.HasPrefix(got, "-ERR ") || !strings.Contains(got, "exceeds the limit") {
		t.Fatalf("oversized bulk reply = %q", got)
	}
	assertClosed(t, conn)
}

func TestPreAuthRejectsOversizedArray(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	_, addr := startProxy(t, up.addr(), map[string]string{"password": "s3cret-upstream"})
	conn, r := dialProxy(t, addr)

	if _, err := conn.Write([]byte("*100000\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := reply(t, r)
	if !strings.HasPrefix(got, "-ERR ") || !strings.Contains(got, "exceeds the limit") {
		t.Fatalf("oversized array reply = %q", got)
	}
	assertClosed(t, conn)
}

func TestPreAuthRejectsDeepNesting(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	_, addr := startProxy(t, up.addr(), map[string]string{"password": "s3cret-upstream"})
	conn, r := dialProxy(t, addr)

	payload := strings.Repeat("*1\r\n", 32)
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := reply(t, r)
	if !strings.HasPrefix(got, "-ERR ") || !strings.Contains(got, "nesting") {
		t.Fatalf("deep nesting reply = %q", got)
	}
	assertClosed(t, conn)
}

// assertClosed 断言代理在拒绝后立即断开连接。
func assertClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the proxy kept the connection open after a limit violation")
	}
}

// ---- 24：RESP 版本一致性 ----

func TestHelloDowngradesWhenUpstreamIsRESP2(t *testing.T) {
	up := newFakeRedisWith(t, "s3cret-upstream", withRESP2Only())
	_, addr := startProxy(t, up.addr(), map[string]string{"password": "s3cret-upstream"})
	conn, r := dialProxy(t, addr)

	send(t, conn, "HELLO", "3", "AUTH", "default", "kks_test_token")
	raw, err := readReply(r)
	if err != nil {
		t.Fatalf("read hello reply: %v", err)
	}
	// 上游只支持 RESP2：前端必须拿到 RESP2 数组，而不是被承诺 RESP3 map。
	if raw[0] != '*' {
		t.Fatalf("hello reply = %q, want a RESP2 array", raw)
	}
	if !strings.Contains(string(raw), "$5\r\nproto\r\n$1\r\n2\r\n") {
		t.Fatalf("hello reply advertises a proto the upstream does not support: %q", raw)
	}
	sawHELLO := false
	for _, cmd := range up.seen() {
		if strings.EqualFold(cmd[0], "HELLO") {
			sawHELLO = true
		}
	}
	if !sawHELLO {
		t.Fatalf("the proxy advertised RESP3 negotiation but never asked the upstream: %v", up.seen())
	}
	send(t, conn, "PING")
	if got := reply(t, r); got != "+PONG\r\n" {
		t.Fatalf("PING reply = %q", got)
	}
}

// ---- 25：限时排空 ----

func TestShutdownCancelsIdleConnections(t *testing.T) {
	up := newFakeRedis(t, "s3cret-upstream")
	srv, addr := startProxy(t, up.addr(), map[string]string{"password": "s3cret-upstream"})
	conn, _ := dialProxy(t, addr)

	deadline := time.Now().Add(2 * time.Second)
	for {
		active, _, _ := srv.Stats()
		if active == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connection was not accepted")
		}
		time.Sleep(10 * time.Millisecond)
	}

	start := time.Now()
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("shutdown took %v, an idle connection kept it open", elapsed)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("client connection was left open after shutdown")
	}
}

// testTLSMaterials 生成一套测试用 CA + 服务端证书（IP SAN 127.0.0.1），
// 返回可交给 UpstreamCA 的 PEM 路径与证书。
func testTLSMaterials(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "keykoi-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return caPath, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}
