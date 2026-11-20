package dbproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"keykoi/internal/broker"
	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
	"keykoi/internal/secret"
)

// fakeUpstream 是内存实现的 pgwire 服务端：真实跑启动包、SCRAM/MD5/cleartext 认证、
// 简单查询与取消请求，用来验证代理两端握手而无须外部数据库。
type fakeUpstream struct {
	ln        net.Listener
	user      string
	password  string
	database  string
	authMode  string // scram | md5 | cleartext
	tlsConfig *tls.Config
	tlsOn     bool

	mu       sync.Mutex
	queries  []string
	cancels  [][2]uint32
	conns    int
	failures int
	lastErr  error

	cancelCh chan struct{}
	closed   chan struct{}
	closeOne sync.Once
}

func newFakeUpstream(t *testing.T, authMode string) *fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake upstream listen: %v", err)
	}
	f := &fakeUpstream{
		ln:       ln,
		user:     "keykoi_test",
		password: "upstream-secret",
		database: "keykoi_test",
		authMode: authMode,
		cancelCh: make(chan struct{}, 4),
		closed:   make(chan struct{}),
	}
	go f.acceptLoop()
	t.Cleanup(f.Close)
	return f
}

// withTLS 让 fake upstream 在 SSLRequest 后切换为 TLS。
func (f *fakeUpstream) withTLS(cert tls.Certificate) *fakeUpstream {
	f.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	return f
}

func (f *fakeUpstream) Addr() string { return f.ln.Addr().String() }

func (f *fakeUpstream) Close() {
	f.closeOne.Do(func() {
		close(f.closed)
		_ = f.ln.Close()
	})
}

func (f *fakeUpstream) acceptLoop() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeUpstream) handle(c net.Conn) {
	defer c.Close()
	f.mu.Lock()
	f.conns++
	f.mu.Unlock()

	br := bufio.NewReader(c)
	code, body, err := readStartupPacket(br)
	if err != nil {
		f.recordFailure(err)
		return
	}
	if code == codeSSLRequest {
		if f.tlsConfig != nil {
			if _, err := c.Write([]byte{'S'}); err != nil {
				f.recordFailure(err)
				return
			}
			tc := tls.Server(c, f.tlsConfig)
			tc.SetDeadline(time.Now().Add(5 * time.Second))
			if err := tc.Handshake(); err != nil {
				f.recordFailure(err)
				return
			}
			tc.SetDeadline(time.Time{})
			c = tc
			f.mu.Lock()
			f.tlsOn = true
			f.mu.Unlock()
		} else if _, err := c.Write([]byte{'N'}); err != nil {
			f.recordFailure(err)
			return
		}
		code, body, err = readStartupPacket(bufio.NewReader(c))
		if err != nil {
			f.recordFailure(err)
			return
		}
	}
	if code == codeCancelRequest {
		if len(body) >= 8 {
			f.mu.Lock()
			f.cancels = append(f.cancels, [2]uint32{
				binary.BigEndian.Uint32(body[:4]),
				binary.BigEndian.Uint32(body[4:8]),
			})
			f.mu.Unlock()
		}
		select {
		case f.cancelCh <- struct{}{}:
		default:
		}
		return
	}

	params, err := parseStartupParameters(body)
	if err != nil {
		f.recordFailure(err)
		return
	}
	if params["user"] != f.user || params["database"] != f.database {
		f.recordFailure(fmt.Errorf("unexpected startup user/database: %q/%q", params["user"], params["database"]))
		writeErrorFrame(c, "28P01", "fake upstream: bad user or database")
		return
	}

	br = bufio.NewReader(c)
	if err := f.authenticate(c, br); err != nil {
		f.recordFailure(err)
		writeErrorFrame(c, "28P01", "fake upstream: authentication failed")
		return
	}

	sendAll(c,
		&pgproto3.AuthenticationOk{},
		&pgproto3.ParameterStatus{Name: "server_version", Value: "18.0-fixture"},
		&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"},
		&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: []byte{0xde, 0xad, 0xbe, 0xef}},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	f.serveQueries(c, br)
}

func (f *fakeUpstream) authenticate(c net.Conn, br *bufio.Reader) error {
	switch f.authMode {
	case "cleartext":
		sendAll(c, &pgproto3.AuthenticationCleartextPassword{})
		typ, body, err := readTypedMessage(br)
		if err != nil {
			return err
		}
		if typ != 'p' || strings.TrimSuffix(string(body), "\x00") != f.password {
			return fmt.Errorf("cleartext password mismatch")
		}
	case "md5":
		var salt [4]byte = [4]byte{1, 2, 3, 4}
		sendAll(c, &pgproto3.AuthenticationMD5Password{Salt: salt})
		typ, body, err := readTypedMessage(br)
		if err != nil {
			return err
		}
		want := md5Password(f.user, f.password, salt[:])
		if typ != 'p' || strings.TrimSuffix(string(body), "\x00") != want {
			return fmt.Errorf("md5 password mismatch")
		}
	case "scram":
		if err := f.scramAuthenticate(c, br); err != nil {
			return err
		}
	default:
		return fmt.Errorf("fake upstream: unknown auth mode %q", f.authMode)
	}
	return nil
}

// scramAuthenticate 实现服务端 SCRAM-SHA-256，用于验证代理的客户端实现。
func (f *fakeUpstream) scramAuthenticate(c net.Conn, br *bufio.Reader) error {
	salt := []byte("keykoi-fixture-salt")
	const iterations = 4096
	serverNonce := "serverNonceABCDEF"

	sendAll(c, &pgproto3.AuthenticationSASL{AuthMechanisms: []string{scramSHA256}})
	typ, body, err := readTypedMessage(br)
	if err != nil {
		return err
	}
	if typ != 'p' {
		return fmt.Errorf("expected SASLInitialResponse, got %q", typ)
	}
	var initial pgproto3.SASLInitialResponse
	if err := initial.Decode(body); err != nil {
		return err
	}
	if initial.AuthMechanism != scramSHA256 {
		return fmt.Errorf("unexpected SASL mechanism %q", initial.AuthMechanism)
	}
	clientFirst := string(initial.Data)
	if !strings.HasPrefix(clientFirst, "n,,") {
		return fmt.Errorf("unexpected client-first-message %q", clientFirst)
	}
	clientFirstBare := strings.TrimPrefix(clientFirst, "n,,")
	attrs, err := parseSCRAMAttributes(clientFirstBare)
	if err != nil {
		return err
	}
	clientNonce := attrs["r"]
	if clientNonce == "" {
		return fmt.Errorf("client nonce missing")
	}
	combined := clientNonce + serverNonce
	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d", combined, base64.StdEncoding.EncodeToString(salt), iterations)
	sendAll(c, &pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})

	typ, body, err = readTypedMessage(br)
	if err != nil {
		return err
	}
	if typ != 'p' {
		return fmt.Errorf("expected SASLResponse, got %q", typ)
	}
	var final pgproto3.SASLResponse
	if err := final.Decode(body); err != nil {
		return err
	}
	clientFinal := string(final.Data)
	idx := strings.LastIndex(clientFinal, ",p=")
	if idx < 0 {
		return fmt.Errorf("client final message has no proof: %q", clientFinal)
	}
	finalWithoutProof := clientFinal[:idx]
	proof, err := base64.StdEncoding.DecodeString(clientFinal[idx+3:])
	if err != nil {
		return fmt.Errorf("client proof is not base64: %w", err)
	}
	authMessage := clientFirstBare + "," + serverFirst + "," + finalWithoutProof

	salted, err := pbkdf2.Key(sha256.New, f.password, salt, iterations, sha256.Size)
	if err != nil {
		return err
	}
	clientKey := hmacSHA256(salted, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientSignature := hmacSHA256(storedKey[:], []byte(authMessage))
	if len(proof) != len(clientSignature) {
		return fmt.Errorf("client proof length mismatch")
	}
	recovered := make([]byte, len(proof))
	for i := range proof {
		recovered[i] = proof[i] ^ clientSignature[i]
	}
	check := sha256.Sum256(recovered)
	if !hmac.Equal(check[:], storedKey[:]) {
		return fmt.Errorf("client proof does not verify")
	}
	serverKey := hmacSHA256(salted, []byte("Server Key"))
	serverSignature := hmacSHA256(serverKey, []byte(authMessage))
	sendAll(c, &pgproto3.AuthenticationSASLFinal{
		Data: []byte("v=" + base64.StdEncoding.EncodeToString(serverSignature)),
	})
	return nil
}

func (f *fakeUpstream) serveQueries(c net.Conn, br *bufio.Reader) {
	for {
		typ, body, err := readTypedMessage(br)
		if err != nil {
			return
		}
		switch typ {
		case 'Q':
			query := strings.TrimSuffix(string(body), "\x00")
			f.mu.Lock()
			f.queries = append(f.queries, query)
			f.mu.Unlock()
			if strings.Contains(query, "pg_sleep") {
				select {
				case <-f.cancelCh:
					sendAll(c,
						&pgproto3.ErrorResponse{Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: "57014", Message: "canceling statement due to user request"},
						&pgproto3.ReadyForQuery{TxStatus: 'I'},
					)
				case <-time.After(4 * time.Second):
					sendAll(c, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
				case <-f.closed:
					return
				}
				continue
			}
			sendAll(c, &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
		case 'X':
			return
		default:
			// 本包测试只用简单查询协议；扩展协议由 relay 原样转发，此处不模拟。
			return
		}
	}
}

func (f *fakeUpstream) recordFailure(err error) {
	f.mu.Lock()
	f.failures++
	f.lastErr = err
	f.mu.Unlock()
}

func (f *fakeUpstream) snapshot() (queries []string, cancels [][2]uint32, conns, failures int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...), append([][2]uint32(nil), f.cancels...), f.conns, f.failures
}

func (f *fakeUpstream) usedTLS() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tlsOn
}

func sendAll(c net.Conn, msgs ...pgproto3.BackendMessage) {
	var buf []byte
	for _, m := range msgs {
		encoded, err := m.Encode(nil)
		if err != nil {
			return
		}
		buf = append(buf, encoded...)
	}
	_, _ = c.Write(buf)
}

// testCertificates 生成一次性 CA 与服务端证书，返回 CA 文件路径与服务器证书。
func testCertificates(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	caKey, err := randomECKey()
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "keykoi dbproxy test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := randomECKey()
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
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	return caPath, cert
}

// fakeBroker 是后台运行面的内存替身：Resolve 返回凭证与同一次授权的 Binding 快照。
// Get 提供单条绑定详情（既有连接核对改绑用）与旧的绑定列表（断言代理不再读它）。
type fakeBroker struct {
	mu       sync.Mutex
	bindings []model.Binding
	// authorized 是 Resolve 返回的 Binding 快照；nil 表示用 bindings[0]。
	authorized *model.Binding
	fields     map[string]string
	valid      map[string]bool
	denial     error
	calls      int
	// getCalls 是单条绑定查询次数，listCalls 是旧的列表读取次数。
	getCalls  int
	listCalls int
	// getErr 非 nil 时单条绑定查询失败（模拟 daemon 暂时不可达）。
	getErr  error
	revoked []string
}

func newFakeBroker(bindingID string) *fakeBroker {
	return &fakeBroker{
		bindings: []model.Binding{{
			ID:             bindingID,
			CredentialID:   "cred_test",
			UpstreamOrigin: "http://127.0.0.1:5432",
			AuthScheme:     model.AuthBasic,
			UsernameField:  "username",
			PasswordField:  "password",
			Status:         model.StatusActive,
		}},
		fields: map[string]string{
			"username": "keykoi_test",
			"password": "upstream-secret",
			"database": "keykoi_test",
		},
		valid: map[string]bool{"kks_test_session_token": true},
	}
}

func (b *fakeBroker) setOrigin(origin string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bindings[0].UpstreamOrigin = origin
	if b.authorized != nil {
		b.authorized.UpstreamOrigin = origin
	}
}

// authorizeOrigin 只改 Resolve 返回的 Binding 快照（模拟授权时的目标），
// 不动 bindings 列表：后者只供已废弃的 /v1/bindings 读取路径使用。
func (b *fakeBroker) authorizeOrigin(origin string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	snapshot := b.bindings[0]
	snapshot.UpstreamOrigin = origin
	b.authorized = &snapshot
}

func (b *fakeBroker) rebind(origin string, revision int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bindings[0].UpstreamOrigin = origin
	b.bindings[0].Revision = revision
	if b.authorized != nil {
		b.authorized.UpstreamOrigin = origin
		b.authorized.Revision = revision
	}
}

// reviseLive 只改“当前已登记”的绑定，不动本次连接手里的授权快照：
// 这正是一条既有连接遇到改绑时 daemon 侧看到的差别。
func (b *fakeBroker) reviseLive(origin string, revision int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bindings[0].UpstreamOrigin = origin
	b.bindings[0].Revision = revision
}

// setLiveStatus 改当前登记的绑定状态。
func (b *fakeBroker) setLiveStatus(status model.EntityStatus) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bindings[0].Status = status
}

// failGets 让单条绑定查询按给定错误失败（nil 表示恢复）。
func (b *fakeBroker) failGets(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.getErr = err
}

func (b *fakeBroker) CheckLease(_ context.Context, _ secret.Value, lease model.UseLease) error {
	var binding model.Binding
	if err := b.Get("/v1/bindings/"+lease.BindingID, &binding); err != nil {
		return err
	}
	if (binding.Status != "" && binding.Status != model.StatusActive) ||
		binding.Revision != lease.BindingRevision || binding.UpstreamOrigin != lease.Target {
		return model.NewError(model.CodeBindingDisabled, "binding changed")
	}
	return nil
}

func (b *fakeBroker) ReleaseLease(leaseID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revoked = append(b.revoked, leaseID)
}

func (b *fakeBroker) leaseCounts() (resolved, revoked int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls, len(b.revoked)
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
			return fmt.Errorf("fake broker: unexpected output type %T", out)
		}
		target.Bindings = append([]model.Binding(nil), b.bindings...)
		return nil
	}
	b.getCalls++
	if b.getErr != nil {
		return b.getErr
	}
	id := strings.TrimPrefix(path, "/v1/bindings/")
	if id == path || id == "" {
		return fmt.Errorf("fake broker: unexpected path %q", path)
	}
	target, ok := out.(*model.Binding)
	if !ok {
		return fmt.Errorf("fake broker: unexpected output type %T", out)
	}
	for _, binding := range b.bindings {
		if binding.ID == id {
			*target = binding
			return nil
		}
	}
	return &ipcclient.APIError{Code: string(model.CodeBindingDisabled), Message: "binding is not registered"}
}

func (b *fakeBroker) Authorize(_ context.Context, req broker.Request) (*broker.Authorization, error) {
	token, mode := req.Token.RevealString(), string(req.Mode)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if mode != string(model.ModeProxy) {
		return nil, fmt.Errorf("fake broker: unexpected mode %q", mode)
	}
	if b.denial != nil {
		return nil, b.denial
	}
	if !b.valid[token] {
		return nil, &ipcclient.APIError{Code: string(model.CodeSessionInvalid), Message: "unknown session token"}
	}
	found := false
	for _, bd := range b.bindings {
		if bd.ID == req.BindingID {
			found = true
		}
	}
	if !found {
		return nil, &ipcclient.APIError{Code: string(model.CodeBindingDisabled), Message: "binding is not registered"}
	}
	fields := map[string]secret.Value{}
	for k, v := range b.fields {
		fields[k] = secret.New(v)
	}
	snapshot := b.bindings[0]
	if b.authorized != nil {
		snapshot = *b.authorized
	}
	return &broker.Authorization{
		Version: model.CredentialVersion{CredentialID: "cred_test", Version: 1, Fields: fields},
		Binding: &snapshot,
		Lease: model.UseLease{
			ID:              fmt.Sprintf("lease-%d", b.calls),
			BindingRevision: snapshot.Revision, BindingID: snapshot.ID, Target: snapshot.UpstreamOrigin, UseLeaseExpiresAt: time.Now().Add(time.Minute),
		},
	}, nil
}

// randomECKey 生成一次性 ECDSA 私钥。
func randomECKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
