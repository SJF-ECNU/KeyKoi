package mysqlproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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

type testBroker struct {
	mu         sync.Mutex
	fields     map[string]string
	resolveErr error
	binding    model.Binding
	// authorized 是 Resolve 返回的 Binding 快照；nil 表示用 binding。
	authorized *model.Binding
	// upstreamCA 交给代理用于校验测试上游的 TLS 证书。
	upstreamCA string
	// upstreamTLSMode 覆盖上游 TLS 校验强度（默认 verify-full）。
	upstreamTLSMode UpstreamTLSMode
	// insecureUpstream 让代理显式允许明文上游（测试降级路径用）。
	insecureUpstream   bool
	revalidateInterval time.Duration
	// getCalls 是单条绑定查询次数，listCalls 是旧的列表读取次数。
	getCalls  int
	listCalls int
	// getErr 非 nil 时单条绑定查询失败（模拟 daemon 暂时不可达）。
	getErr  error
	calls   int
	revoked []string
}

// authorize 让 Resolve 返回与 binding 不同的快照（模拟改绑后的目标）。
func (b *testBroker) authorize(origin string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	snapshot := b.binding
	snapshot.UpstreamOrigin = origin
	b.authorized = &snapshot
}

func (b *testBroker) rebind(origin string, revision int64) {
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
func (b *testBroker) reviseLive(origin string, revision int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.binding.UpstreamOrigin = origin
	b.binding.Revision = revision
}

// setLiveStatus 改当前登记的绑定状态。
func (b *testBroker) setLiveStatus(status model.EntityStatus) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.binding.Status = status
}

// failGets 让单条绑定查询按给定错误失败（nil 表示恢复）。
func (b *testBroker) failGets(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.getErr = err
}

func (b *testBroker) RevokeLease(leaseID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revoked = append(b.revoked, leaseID)
	return nil
}

func (b *testBroker) leaseCounts() (resolved, revoked int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls, len(b.revoked)
}

func (b *testBroker) Resolve(token, bindingID, mode string) (*ipcclient.Resolved, error) {
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

func (b *testBroker) Get(path string, out any) error {
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

// fakeMySQL 是最小 MySQL 上游：可选 TLS + caching_sha2_password 完整认证。
type fakeMySQL struct {
	ln        net.Listener
	user      string
	password  string
	tlsConfig *tls.Config
	caPath    string

	mu          sync.Mutex
	queries     []string
	gotPassword string
	gotUser     string
	tokenSeen   bool
	tlsUsed     bool
	conns       int
	authPackets int
}

func newFakeMySQL(t *testing.T, user, password string) *fakeMySQL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	caPath, cert := testTLSMaterials(t)
	f := &fakeMySQL{
		ln:        ln,
		user:      user,
		password:  password,
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		caPath:    caPath,
	}
	go f.accept()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

// newPlaintextFakeMySQL 是明确不宣告 TLS 的上游，用于验证代理的默认拒绝与降级声明。
func newPlaintextFakeMySQL(t *testing.T, user, password string) *fakeMySQL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeMySQL{ln: ln, user: user, password: password}
	go f.accept()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeMySQL) addr() string { return f.ln.Addr().String() }

func (f *fakeMySQL) usedTLS() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tlsUsed
}

func (f *fakeMySQL) connCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

func (f *fakeMySQL) accept() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeMySQL) handle(c net.Conn) {
	defer c.Close()
	f.mu.Lock()
	f.conns++
	f.mu.Unlock()

	nonce := make([]byte, 20)
	_, _ = rand.Read(nonce)
	offerTLS := f.tlsConfig != nil
	if err := writeGreeting(c, 1, nonce, pluginCacheSha, offerTLS); err != nil {
		return
	}
	// 整个连接只用一个 bufio.Reader：每次新建 reader 会丢掉已缓冲的后续包。
	r := bufio.NewReader(c)
	seq, payload, err := readPacket(r)
	if err != nil {
		return
	}
	if offerTLS && len(payload) == 32 && binary.LittleEndian.Uint32(payload[:4])&clientSSL != 0 {
		tc := tls.Server(c, f.tlsConfig)
		if err := tc.Handshake(); err != nil {
			return
		}
		f.mu.Lock()
		f.tlsUsed = true
		f.mu.Unlock()
		c = tc
		r = bufio.NewReader(c)
		seq, payload, err = readPacket(r)
		if err != nil {
			return
		}
		if seq != 2 {
			// 真实服务端要求握手响应接着 SSLRequest 递增序号。
			_ = writePacket(c, seq+1, errorPacket(errAccessDenied, sqlStateAccess, "unexpected handshake sequence"))
			return
		}
	}
	resp, err := parseClientResponse(payload)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.gotUser = resp.username
	f.mu.Unlock()
	if resp.username != f.user {
		_ = writePacket(c, seq+1, errorPacket(errAccessDenied, sqlStateAccess, "unknown user"))
		return
	}
	if err := writePacket(c, seq+1, []byte{0x01, moreDataFullAuth}); err != nil {
		return
	}
	seq, payload, err = readPacket(r)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.authPackets++
	f.mu.Unlock()
	// TLS 上缓存认证的完整阶段直接提交明文口令（NUL 结尾）。
	pw := string(trimNul(payload))
	f.mu.Lock()
	f.gotPassword = pw
	if strings.Contains(pw, "kks_") {
		f.tokenSeen = true
	}
	f.mu.Unlock()
	if pw != f.password {
		_ = writePacket(c, seq+1, errorPacket(errAccessDenied, sqlStateAccess, "Access denied for user"))
		return
	}
	if err := writePacket(c, seq+1, okPacket()); err != nil {
		return
	}
	for {
		_, payload, err := readPacket(r)
		if err != nil {
			return
		}
		if len(payload) == 0 {
			return
		}
		switch payload[0] {
		case 0x01: // COM_QUIT
			return
		case 0x03: // COM_QUERY
			f.mu.Lock()
			f.queries = append(f.queries, string(payload[1:]))
			f.mu.Unlock()
			if err := writePacket(c, 1, okPacket()); err != nil {
				return
			}
		default:
			if err := writePacket(c, 1, errorPacket(1047, "08S01", "unsupported command")); err != nil {
				return
			}
		}
	}
}

func startTestProxy(t *testing.T, broker Broker, disableTLS bool) (*Server, string) {
	t.Helper()
	cfg := Config{
		BindingID:        "bind_mysql_test",
		ListenAddr:       "127.0.0.1:0",
		AuthTimeout:      5 * time.Second,
		DisableClientTLS: disableTLS,
		Logger:           log.New(io.Discard, "", 0),
	}
	if tb, ok := broker.(*testBroker); ok {
		cfg.RevalidateInterval = tb.revalidateInterval
		cfg.UpstreamCA = tb.upstreamCA
		cfg.UpstreamTLSMode = tb.upstreamTLSMode
		if tb.insecureUpstream {
			cfg.InsecureUpstream = true
		}
	}
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

func brokerFor(up *fakeMySQL) *testBroker {
	return &testBroker{
		fields:     map[string]string{"username": "kkuser", "password": "upstream-secret", "database": "appdb"},
		binding:    model.Binding{ID: "bind_mysql_test", UpstreamOrigin: "http://" + up.addr(), Status: model.StatusActive},
		upstreamCA: up.caPath,
	}
}

func brokerForAddr(addr string) *testBroker {
	return &testBroker{
		fields:  map[string]string{"username": "kkuser", "password": "upstream-secret", "database": "appdb"},
		binding: model.Binding{ID: "bind_mysql_test", UpstreamOrigin: "http://" + addr, Status: model.StatusActive},
	}
}

// mysqlClient 是测试用的最小 MySQL 客户端，走明文 + RSA 公钥提交令牌。
type mysqlClient struct {
	conn  net.Conn
	r     *bufio.Reader
	nonce []byte
	seq   byte
}

func dialMySQLClient(t *testing.T, addr string) *mysqlClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	_, payload, err := readPacket(r)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	g, err := parseGreeting(payload)
	if err != nil {
		t.Fatalf("parse greeting: %v", err)
	}
	c := &mysqlClient{conn: conn, r: r, nonce: g.nonce}
	caps := keykoiCaps & g.caps
	c.seq = 1
	if err := writePacket(conn, c.seq, buildClientResponse(caps, "anyuser", "", pluginCacheSha,
		cachingSha2Password("kks_initial_scramble", g.nonce))); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	return c
}

// auth 完成缓存完整认证流程，返回服务端最后一条回复。
func (c *mysqlClient) auth(t *testing.T, token string) []byte {
	t.Helper()
	seq, payload, err := readPacket(c.r)
	if err != nil {
		t.Fatalf("read full-auth request: %v", err)
	}
	c.seq = seq
	if !(len(payload) == 2 && payload[0] == 0x01 && payload[1] == moreDataFullAuth) {
		t.Fatalf("expected full auth request, got %x", payload)
	}
	if err := writePacket(c.conn, c.seq+1, []byte{0x02}); err != nil {
		t.Fatalf("request public key: %v", err)
	}
	seq, payload, err = readPacket(c.r)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	c.seq = seq
	// 客户端侧：用代理提供的公钥加密（口令 + NUL 与 nonce 异或）。
	pub, err := parseTestPublicKey(payload[1:])
	if err != nil {
		t.Fatalf("parse proxy public key: %v", err)
	}
	enc, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, xorNonce(append([]byte(token), 0), c.nonce), nil)
	if err != nil {
		t.Fatalf("encrypt token: %v", err)
	}
	if err := writePacket(c.conn, c.seq+1, enc); err != nil {
		t.Fatalf("send encrypted token: %v", err)
	}
	seq, payload, err = readPacket(c.r)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	c.seq = seq
	return payload
}

func (c *mysqlClient) query(t *testing.T, q string) []byte {
	t.Helper()
	if err := writePacket(c.conn, 0, append([]byte{0x03}, q...)); err != nil {
		t.Fatalf("send query: %v", err)
	}
	seq, payload, err := readPacket(c.r)
	if err != nil {
		t.Fatalf("read query reply: %v", err)
	}
	if seq != 1 {
		t.Fatalf("query reply sequence = %d", seq)
	}
	return payload
}

func TestProxyEndToEnd(t *testing.T) {
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	_, addr := startTestProxy(t, brokerFor(up), false)

	c := dialMySQLClient(t, addr)
	reply := c.auth(t, "kks_test_token")
	if len(reply) == 0 || reply[0] != 0x00 {
		t.Fatalf("auth reply = %x", reply)
	}
	qr := c.query(t, "select 1")
	if len(qr) == 0 || qr[0] != 0x00 {
		t.Fatalf("query reply = %x", qr)
	}

	up.mu.Lock()
	defer up.mu.Unlock()
	if up.gotUser != "kkuser" || up.gotPassword != "upstream-secret" {
		t.Fatalf("upstream saw user=%q password=%q", up.gotUser, up.gotPassword)
	}
	if up.tokenSeen {
		t.Fatalf("session token reached the upstream")
	}
	if len(up.queries) != 1 || up.queries[0] != "select 1" {
		t.Fatalf("upstream queries = %v", up.queries)
	}
}

func TestClientTLSAndCleartextToken(t *testing.T) {
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	_, addr := startTestProxy(t, brokerFor(up), false)

	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(raw)
	_, payload, err := readPacket(r)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	g, err := parseGreeting(payload)
	if err != nil {
		t.Fatalf("parse greeting: %v", err)
	}
	if g.caps&clientSSL == 0 {
		t.Fatalf("proxy did not offer TLS")
	}
	// SSLRequest
	var sslReq [32]byte
	binary.LittleEndian.PutUint32(sslReq[0:4], clientProtocol41|clientSSL)
	binary.LittleEndian.PutUint32(sslReq[4:8], 16<<20)
	sslReq[8] = 45
	if err := writePacket(raw, 1, sslReq[:]); err != nil {
		t.Fatalf("ssl request: %v", err)
	}
	tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	tr := bufio.NewReader(tlsConn)
	caps := keykoiCaps & g.caps
	if err := writePacket(tlsConn, 2, buildClientResponse(caps, "anyuser", "", pluginCacheSha,
		cachingSha2Password("kks_over_tls", g.nonce))); err != nil {
		t.Fatalf("handshake response: %v", err)
	}
	seq, payload, err := readPacket(tr)
	if err != nil {
		t.Fatalf("read full auth request: %v", err)
	}
	if !(len(payload) == 2 && payload[1] == moreDataFullAuth) {
		t.Fatalf("expected full auth, got %x", payload)
	}
	// TLS 上客户端直接提交明文口令（此处是会话令牌）。
	if err := writePacket(tlsConn, seq+1, append([]byte("kks_test_token"), 0)); err != nil {
		t.Fatalf("send token: %v", err)
	}
	seq, payload, err = readPacket(tr)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	if len(payload) == 0 || payload[0] != 0x00 {
		t.Fatalf("auth reply = %x", payload)
	}
	if err := writePacket(tlsConn, 0, append([]byte{0x03}, "select 2"...)); err != nil {
		t.Fatalf("send query: %v", err)
	}
	if _, payload, err = readPacket(tr); err != nil || payload[0] != 0x00 {
		t.Fatalf("query reply = %x err=%v", payload, err)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.gotPassword != "upstream-secret" {
		t.Fatalf("upstream password = %q", up.gotPassword)
	}
}

func TestWrongTokenRejected(t *testing.T) {
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	_, addr := startTestProxy(t, brokerFor(up), false)
	c := dialMySQLClient(t, addr)
	reply := c.auth(t, "kks_wrong")
	if len(reply) < 2 || reply[0] != 0xff {
		t.Fatalf("wrong token reply = %x", reply)
	}
	if strings.Contains(string(reply), "kks_wrong") {
		t.Fatalf("reply echoed the token: %q", reply)
	}
}

func TestNoGrantRejected(t *testing.T) {
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	broker := brokerFor(up)
	broker.resolveErr = &ipcclient.APIError{Code: string(model.CodeUseNotAllowed), Message: "no grant"}
	_, addr := startTestProxy(t, broker, false)
	c := dialMySQLClient(t, addr)
	reply := c.auth(t, "kks_test_token")
	if len(reply) < 2 || reply[0] != 0xff {
		t.Fatalf("no-grant reply = %x", reply)
	}
}

func TestUpstreamPasswordMismatch(t *testing.T) {
	up := newFakeMySQL(t, "kkuser", "other-secret")
	_, addr := startTestProxy(t, brokerFor(up), false)
	c := dialMySQLClient(t, addr)
	reply := c.auth(t, "kks_test_token")
	if len(reply) < 2 || reply[0] != 0xff {
		t.Fatalf("upstream mismatch reply = %x", reply)
	}
	if strings.Contains(string(reply), "upstream-secret") || strings.Contains(string(reply), "other-secret") {
		t.Fatalf("reply leaked an upstream password: %q", reply)
	}
}

func TestClientDisconnectReleasesUpstream(t *testing.T) {
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	srv, addr := startTestProxy(t, brokerFor(up), false)
	c := dialMySQLClient(t, addr)
	if reply := c.auth(t, "kks_test_token"); reply[0] != 0x00 {
		t.Fatalf("auth reply = %x", reply)
	}
	_ = c.conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		active, total, _ := srv.Stats()
		if active == 0 && total == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active connections did not drop: active=%d total=%d", active, total)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestUnsupportedOriginScheme(t *testing.T) {
	broker := brokerForAddr("127.0.0.1:3306")
	broker.binding.UpstreamOrigin = "ftp://127.0.0.1:3306"
	_, addr := startTestProxy(t, broker, false)
	c := dialMySQLClient(t, addr)
	reply := c.auth(t, "kks_test_token")
	if len(reply) < 2 || reply[0] != 0xff {
		t.Fatalf("invalid origin reply = %x", reply)
	}
}

func TestBrokerErrorDetailNotLeaked(t *testing.T) {
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	broker := brokerFor(up)
	broker.resolveErr = errors.New("vault: internal path /Users/secret/leak")
	_, addr := startTestProxy(t, broker, false)
	c := dialMySQLClient(t, addr)
	reply := c.auth(t, "kks_test_token")
	if strings.Contains(string(reply), "/Users/secret/leak") {
		t.Fatalf("broker error leaked to the client: %q", reply)
	}
}

// parseTestPublicKey 解析代理下发的 PKIX PEM 公钥（测试客户端侧）。
func parseTestPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("not PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return pub, nil
}

// testTLSMaterials 生成测试用 CA + 上游服务端证书（IP SAN 127.0.0.1）。
func testTLSMaterials(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	return tlsMaterials(t, true)
}

// testTLSMaterialsNoSAN 生成不带 IP/DNS SAN 的服务端证书，模拟 MySQL 自动生成的证书。
func testTLSMaterialsNoSAN(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	return tlsMaterials(t, false)
}

func tlsMaterials(t *testing.T, withSAN bool) (string, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "keykoi-mysql-test-ca"},
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
		Subject:      pkix.Name{CommonName: "MySQL_Server_Auto_Generated_Server_Certificate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if withSAN {
		leafTmpl.Subject = pkix.Name{CommonName: "127.0.0.1"}
		leafTmpl.DNSNames = []string{"localhost"}
		leafTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
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

// readNextPacket 读取代理的下一条包（不假定它是完整认证请求）。
func (c *mysqlClient) readNextPacket(t *testing.T) []byte {
	t.Helper()
	_, payload, err := readPacket(c.r)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	return payload
}

// ---- 04：目标只来自同一次授权 ----

func TestProxyUsesAuthorizedBindingSnapshot(t *testing.T) {
	legacy := newFakeMySQL(t, "kkuser", "upstream-secret")
	authorized := newFakeMySQL(t, "kkuser", "upstream-secret")
	broker := brokerFor(authorized)
	// 旧的 /v1/bindings 读取路径指向被替换掉的旧目标。
	broker.binding.UpstreamOrigin = "http://" + legacy.addr()
	broker.authorize("http://" + authorized.addr())
	_, addr := startTestProxy(t, broker, false)

	c := dialMySQLClient(t, addr)
	if reply := c.auth(t, "kks_test_token"); len(reply) == 0 || reply[0] != 0x00 {
		t.Fatalf("auth reply = %x", reply)
	}
	if authorized.connCount() != 1 {
		t.Fatalf("authorized upstream saw %d connection(s)", authorized.connCount())
	}
	if legacy.connCount() != 0 {
		t.Fatalf("the stale binding list target was used: %d connection(s)", legacy.connCount())
	}
	if broker.listCalls != 0 {
		t.Fatalf("proxy still listed /v1/bindings %d time(s)", broker.listCalls)
	}
}

// queryErr 发一条查询并读回包；连接已被代理结束时返回错误。
func (c *mysqlClient) queryErr(q string) ([]byte, error) {
	if err := writePacket(c.conn, 0, append([]byte{0x03}, q...)); err != nil {
		return nil, err
	}
	_, payload, err := readPacket(c.r)
	return payload, err
}

// waitForClosed 轮询查询，直到代理结束连接（ERR 包或读错误）。
func waitForClosed(t *testing.T, c *mysqlClient) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		payload, err := c.queryErr("select 1")
		if err != nil || (len(payload) > 0 && payload[0] == 0xff) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the existing connection was not ended after the binding changed")
}

func TestProxyEndsConnectionWhenBindingRevisionChanges(t *testing.T) {
	oldUpstream := newFakeMySQL(t, "kkuser", "upstream-secret")
	newUpstream := newFakeMySQL(t, "kkuser", "new-secret")
	broker := brokerFor(oldUpstream)
	broker.revalidateInterval = 20 * time.Millisecond
	_, addr := startTestProxy(t, broker, false)
	c := dialMySQLClient(t, addr)
	if reply := c.auth(t, "kks_test_token"); len(reply) == 0 || reply[0] != 0x00 {
		t.Fatalf("auth reply = %x", reply)
	}

	// 只改 daemon 侧登记的绑定：既有连接手里仍是旧快照。
	broker.reviseLive("http://"+newUpstream.addr(), 2)
	waitForClosed(t, c)
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
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	broker := brokerFor(up)
	broker.revalidateInterval = 20 * time.Millisecond
	_, addr := startTestProxy(t, broker, false)
	c := dialMySQLClient(t, addr)
	if reply := c.auth(t, "kks_test_token"); len(reply) == 0 || reply[0] != 0x00 {
		t.Fatalf("auth reply = %x", reply)
	}
	broker.setLiveStatus(model.StatusDisabled)
	waitForClosed(t, c)
}

// TestExistingConnectionEndsWhenUpstreamOriginChanges 断言 revision 不变但 origin
// 改绑时同样结束连接，旧连接不会被引导到新目标。
func TestExistingConnectionEndsWhenUpstreamOriginChanges(t *testing.T) {
	oldUpstream := newFakeMySQL(t, "kkuser", "upstream-secret")
	newUpstream := newFakeMySQL(t, "kkuser", "upstream-secret")
	broker := brokerFor(oldUpstream)
	broker.revalidateInterval = 20 * time.Millisecond
	_, addr := startTestProxy(t, broker, false)
	c := dialMySQLClient(t, addr)
	if reply := c.auth(t, "kks_test_token"); len(reply) == 0 || reply[0] != 0x00 {
		t.Fatalf("auth reply = %x", reply)
	}
	broker.reviseLive("http://"+newUpstream.addr(), 0)
	waitForClosed(t, c)
	if newUpstream.connCount() != 0 {
		t.Fatalf("the moved target was contacted on the old connection: %d connection(s)", newUpstream.connCount())
	}
}

// TestBindingCheckFailureKeepsConnection 断言 daemon 暂时不可达时不断开连接，
// 恢复后仍能按新的 revision 结束连接（失败只记录并重试）。
func TestBindingCheckFailureKeepsConnection(t *testing.T) {
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	broker := brokerFor(up)
	broker.revalidateInterval = 20 * time.Millisecond
	_, addr := startTestProxy(t, broker, false)
	c := dialMySQLClient(t, addr)
	if reply := c.auth(t, "kks_test_token"); len(reply) == 0 || reply[0] != 0x00 {
		t.Fatalf("auth reply = %x", reply)
	}

	broker.failGets(errors.New("keykoid is unreachable"))
	time.Sleep(120 * time.Millisecond)
	if reply := c.query(t, "select 1"); len(reply) == 0 || reply[0] != 0x00 {
		t.Fatalf("a failed binding check closed the connection: %x", reply)
	}
	broker.mu.Lock()
	failedChecks := broker.getCalls
	broker.mu.Unlock()
	if failedChecks < 2 {
		t.Fatalf("binding checks were not retried: %d attempt(s)", failedChecks)
	}

	broker.failGets(nil)
	broker.reviseLive("http://127.0.0.1:1", 3)
	waitForClosed(t, c)
}

// TestBindingCheckIsThrottledAndCoversIdleConnections 断言转发环里的核对既不是
// 逐消息触发、也不会因为连接空闲而停止。
func TestBindingCheckIsThrottledAndCoversIdleConnections(t *testing.T) {
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	broker := brokerFor(up)
	broker.revalidateInterval = 100 * time.Millisecond
	_, addr := startTestProxy(t, broker, false)
	c := dialMySQLClient(t, addr)
	if reply := c.auth(t, "kks_test_token"); len(reply) == 0 || reply[0] != 0x00 {
		t.Fatalf("auth reply = %x", reply)
	}
	for i := 0; i < 30; i++ {
		if reply := c.query(t, "select 1"); len(reply) == 0 || reply[0] != 0x00 {
			t.Fatalf("query %d reply = %x", i, reply)
		}
	}
	broker.mu.Lock()
	burstChecks := broker.getCalls
	broker.mu.Unlock()
	if burstChecks > 5 {
		t.Fatalf("binding checks followed every message: %d checks for 30 queries", burstChecks)
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

// ---- 05：上游传输 ----

func TestUpstreamWithoutTLSRejectedByDefault(t *testing.T) {
	up := newPlaintextFakeMySQL(t, "kkuser", "upstream-secret")
	_, addr := startTestProxy(t, brokerFor(up), false)
	c := dialMySQLClient(t, addr)
	reply := c.auth(t, "kks_test_token")
	if len(reply) < 2 || reply[0] != 0xff {
		t.Fatalf("reply = %x, want an access-denied error", reply)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.gotUser != "" || up.gotPassword != "" {
		t.Fatalf("handshake data reached a plaintext upstream: user=%q", up.gotUser)
	}
}

func TestPlaintextUpstreamFullAuthRejected(t *testing.T) {
	up := newPlaintextFakeMySQL(t, "kkuser", "upstream-secret")
	broker := brokerFor(up)
	broker.insecureUpstream = true // 显式声明明文上游
	_, addr := startTestProxy(t, broker, false)

	c := dialMySQLClient(t, addr)
	reply := c.auth(t, "kks_test_token")
	if len(reply) < 2 || reply[0] != 0xff {
		t.Fatalf("reply = %x, want an access-denied error", reply)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.authPackets != 0 || up.gotPassword != "" {
		t.Fatalf("the proxy sent the password over a plaintext link: packets=%d", up.authPackets)
	}
}

func TestUpstreamTLSHandshakeBeforeCachingSha2(t *testing.T) {
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	_, addr := startTestProxy(t, brokerFor(up), false)

	c := dialMySQLClient(t, addr)
	if reply := c.auth(t, "kks_test_token"); len(reply) == 0 || reply[0] != 0x00 {
		t.Fatalf("auth reply = %x", reply)
	}
	if !up.usedTLS() {
		t.Fatal("the proxy did not establish TLS with the upstream")
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.gotPassword != "upstream-secret" {
		t.Fatalf("upstream password = %q", up.gotPassword)
	}
	if up.tokenSeen {
		t.Fatal("session token reached the upstream")
	}
}

// ---- 23：客户端切 TLS 时保留预读字节 ----

// gatedConn 在挂接真实连接之前把写入收进内存缓冲，用来制造“SSLRequest 与
// ClientHello 同时到达代理”的条件。
type gatedConn struct {
	mu       sync.Mutex
	out      bytes.Buffer
	conn     net.Conn
	attached chan struct{}
	once     sync.Once
}

func newGatedConn() *gatedConn { return &gatedConn{attached: make(chan struct{})} }

func (c *gatedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.conn != nil {
		conn := c.conn
		c.mu.Unlock()
		return conn.Write(p)
	}
	defer c.mu.Unlock()
	return c.out.Write(p)
}

func (c *gatedConn) Read(p []byte) (int, error) {
	<-c.attached
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	return conn.Read(p)
}

// buffered 返回已经写入缓冲但还没发出去的字节数。
func (c *gatedConn) buffered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Len()
}

// flush 取出缓冲内容并把连接切换到真实 socket。
func (c *gatedConn) flush(conn net.Conn) []byte {
	c.mu.Lock()
	data := append([]byte(nil), c.out.Bytes()...)
	c.out.Reset()
	c.conn = conn
	c.mu.Unlock()
	c.once.Do(func() { close(c.attached) })
	return data
}

func (c *gatedConn) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *gatedConn) LocalAddr() net.Addr              { return gatedAddr("local") }
func (c *gatedConn) RemoteAddr() net.Addr             { return gatedAddr("remote") }
func (c *gatedConn) SetDeadline(time.Time) error      { return nil }
func (c *gatedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *gatedConn) SetWriteDeadline(time.Time) error { return nil }

type gatedAddr string

func (a gatedAddr) Network() string { return "gate" }
func (a gatedAddr) String() string  { return string(a) }

func TestClientTLSKeepsPrefetchedHandshakeBytes(t *testing.T) {
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	_, addr := startTestProxy(t, brokerFor(up), false)

	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(raw)
	_, payload, err := readPacket(r)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	g, err := parseGreeting(payload)
	if err != nil {
		t.Fatalf("parse greeting: %v", err)
	}
	if g.caps&clientSSL == 0 {
		t.Skip("proxy did not offer TLS")
	}

	gated := newGatedConn()
	tlsConn := tls.Client(gated, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	handshakeErr := make(chan error, 1)
	go func() { handshakeErr <- tlsConn.Handshake() }()

	// 等 TLS 库把 ClientHello 写进缓冲。
	deadline := time.Now().Add(3 * time.Second)
	for gated.buffered() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("TLS client did not produce a ClientHello")
		}
		time.Sleep(time.Millisecond)
	}

	// SSLRequest 与 ClientHello 一次写出，让代理的 bufio 把握手数据一起预读进来。
	var sslReq [32]byte
	binary.LittleEndian.PutUint32(sslReq[0:4], clientProtocol41|clientSSL)
	binary.LittleEndian.PutUint32(sslReq[4:8], 16<<20)
	sslReq[8] = 45
	var framed bytes.Buffer
	if err := writePacket(&framed, 1, sslReq[:]); err != nil {
		t.Fatalf("frame SSLRequest: %v", err)
	}
	packet := append(framed.Bytes(), gated.flush(raw)...)
	if _, err := raw.Write(packet); err != nil {
		t.Fatalf("write SSLRequest+ClientHello: %v", err)
	}

	select {
	case err := <-handshakeErr:
		if err != nil {
			t.Fatalf("TLS handshake lost the prefetched bytes: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TLS handshake did not complete; the prefetched ClientHello was dropped")
	}

	// 握手后继续走完整认证，确认连接可用。
	tr := bufio.NewReader(tlsConn)
	caps := keykoiCaps & g.caps
	if err := writePacket(tlsConn, 2, buildClientResponse(caps, "anyuser", "", pluginCacheSha,
		cachingSha2Password("kks_over_tls", g.nonce))); err != nil {
		t.Fatalf("handshake response: %v", err)
	}
	seq, payload, err := readPacket(tr)
	if err != nil {
		t.Fatalf("read full auth request: %v", err)
	}
	if !(len(payload) == 2 && payload[1] == moreDataFullAuth) {
		t.Fatalf("expected full auth, got %x", payload)
	}
	if err := writePacket(tlsConn, seq+1, append([]byte("kks_test_token"), 0)); err != nil {
		t.Fatalf("send token: %v", err)
	}
	_, payload, err = readPacket(tr)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	if len(payload) == 0 || payload[0] != 0x00 {
		t.Fatalf("auth reply = %x", payload)
	}
}

// ---- 05：上游 TLS 的校验强度 ----

// TestUpstreamTLSCertificateNameMismatchRejected 断言默认 verify-full：证书链可信但
// 证书名不匹配时握手失败，且口令没有发出。
func TestUpstreamTLSCertificateNameMismatchRejected(t *testing.T) {
	caPath, cert := testTLSMaterialsNoSAN(t)
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	up.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	broker := brokerFor(up)
	broker.upstreamCA = caPath
	_, addr := startTestProxy(t, broker, false)

	c := dialMySQLClient(t, addr)
	reply := c.auth(t, "kks_test_token")
	if len(reply) < 2 || reply[0] != 0xff {
		t.Fatalf("reply = %x, want an access-denied error", reply)
	}
	if up.usedTLS() {
		t.Fatal("a certificate name mismatch must fail the handshake")
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.authPackets != 0 || up.gotPassword != "" {
		t.Fatalf("the password was sent over an unverified link: packets=%d", up.authPackets)
	}
}

// TestUpstreamTLSVerifyCAUsesPinnedCA 断言 verify-ca：仍要求证书链可信，但不核对主机名，
// 供没有 SAN 的自动生成证书使用。
func TestUpstreamTLSVerifyCAUsesPinnedCA(t *testing.T) {
	caPath, cert := testTLSMaterialsNoSAN(t)
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	up.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	broker := brokerFor(up)
	broker.upstreamCA = caPath
	broker.upstreamTLSMode = UpstreamTLSVerifyCA
	_, addr := startTestProxy(t, broker, false)

	c := dialMySQLClient(t, addr)
	if reply := c.auth(t, "kks_test_token"); len(reply) == 0 || reply[0] != 0x00 {
		t.Fatalf("auth reply = %x", reply)
	}
	if !up.usedTLS() {
		t.Fatal("verify-ca must still perform a TLS handshake")
	}
}

// TestUpstreamTLSVerifyCARejectsUntrustedCA 断言 verify-ca 不会接受未知 CA。
func TestUpstreamTLSVerifyCARejectsUntrustedCA(t *testing.T) {
	_, cert := testTLSMaterialsNoSAN(t)
	otherCAPath, _ := testTLSMaterials(t)
	up := newFakeMySQL(t, "kkuser", "upstream-secret")
	up.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	broker := brokerFor(up)
	broker.upstreamCA = otherCAPath
	broker.upstreamTLSMode = UpstreamTLSVerifyCA
	_, addr := startTestProxy(t, broker, false)

	c := dialMySQLClient(t, addr)
	reply := c.auth(t, "kks_test_token")
	if len(reply) < 2 || reply[0] != 0xff {
		t.Fatalf("reply = %x, want an access-denied error", reply)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.authPackets != 0 || up.gotPassword != "" {
		t.Fatalf("the password was sent to an upstream with an untrusted certificate")
	}
}
