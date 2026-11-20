package mongoproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"keykoi/internal/broker"
	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
	"keykoi/internal/secret"
)

// ---- BSON ----

func TestBSONRoundTrip(t *testing.T) {
	body := newBson().
		Int32("a", 7).
		String("b", "hello").
		Bool("c", true).
		Double("ok", 1).
		Int64("d", 1<<40).
		Binary("e", 0, []byte{1, 2, 3}).
		Document("f", newBson().String("g", "nested").Finish()).
		DateTime("h", 1700000000000).
		Finish()
	doc, err := document(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n, _ := bsonInt(doc["a"]); n != 7 {
		t.Fatalf("a = %v", doc["a"])
	}
	if s, _ := bsonStringValue(doc["b"]); s != "hello" {
		t.Fatalf("b = %v", doc["b"])
	}
	if b, ok := doc["c"].(bool); !ok || !b {
		t.Fatalf("c = %v", doc["c"])
	}
	if bin, ok := bsonBinaryValue(doc["e"]); !ok || !bytes.Equal(bin, []byte{1, 2, 3}) {
		t.Fatalf("e = %v", doc["e"])
	}
	nested, ok := doc["f"].(map[string]any)
	if !ok {
		t.Fatalf("f = %v", doc["f"])
	}
	if s, _ := bsonStringValue(nested["g"]); s != "nested" {
		t.Fatalf("f.g = %v", nested["g"])
	}
	if ms, _ := bsonInt(doc["h"]); ms != 1700000000000 {
		t.Fatalf("h = %v", doc["h"])
	}
	if _, err := document(append(body, 0)); err == nil {
		t.Fatalf("decoder accepted a length mismatch")
	}
}

func TestCommandName(t *testing.T) {
	body := newBson().Int32("hello", 1).String("$db", "admin").Finish()
	name, err := commandName(body)
	if err != nil || name != "hello" {
		t.Fatalf("commandName = %q err=%v", name, err)
	}
}

func TestHelloReplyBodyIncludesWireVersionRange(t *testing.T) {
	tests := []struct {
		name     string
		upstream map[string]any
		wantMin  int64
		wantMax  int64
	}{
		{name: "pre-auth safe defaults", wantMin: 0, wantMax: 17},
		{name: "upstream capabilities", upstream: map[string]any{"minWireVersion": int32(2), "maxWireVersion": int32(21)}, wantMin: 2, wantMax: 21},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := document(helloReplyBody(tt.upstream, 1700000000000))
			if err != nil {
				t.Fatalf("decode hello reply: %v", err)
			}
			if _, ok := doc["minWireVersion"]; !ok {
				t.Fatal("hello reply omitted minWireVersion")
			}
			if _, ok := doc["maxWireVersion"]; !ok {
				t.Fatal("hello reply omitted maxWireVersion")
			}
			if got, _ := bsonInt(doc["minWireVersion"]); got != tt.wantMin {
				t.Fatalf("minWireVersion = %d, want %d", got, tt.wantMin)
			}
			if got, _ := bsonInt(doc["maxWireVersion"]); got != tt.wantMax {
				t.Fatalf("maxWireVersion = %d, want %d", got, tt.wantMax)
			}
		})
	}
}

// ---- wire ----

func TestOPMsgRoundTrip(t *testing.T) {
	body := newBson().Int32("ping", 1).String("$db", "admin").Finish()
	var buf bytes.Buffer
	if err := writeOPMsg(&buf, 11, 22, body); err != nil {
		t.Fatalf("write: %v", err)
	}
	msg, err := readMessage(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if msg.requestID != 11 || msg.opCode != opMsg {
		t.Fatalf("message = %+v", msg)
	}
	if !bytes.Equal(msg.body, body) {
		t.Fatalf("body mismatch")
	}
	doc, err := msg.command()
	if err != nil {
		t.Fatalf("command: %v", err)
	}
	if n, _ := bsonInt(doc["ping"]); n != 1 {
		t.Fatalf("ping = %v", doc["ping"])
	}
}

func TestLegacyOPQueryAndReply(t *testing.T) {
	query := newBson().Int32("isMaster", 1).String("$db", "admin").Finish()
	var buf bytes.Buffer
	// 手工构造 OP_QUERY
	ns := "admin.$cmd"
	length := 16 + 4 + len(ns) + 1 + 4 + 4 + len(query)
	hdr := make([]byte, 0, length)
	hdr = append(hdr, byte(length), byte(length>>8), byte(length>>16), byte(length>>24))
	hdr = append(hdr, 1, 0, 0, 0)
	hdr = append(hdr, 0, 0, 0, 0)
	hdr = append(hdr, byte(opQuery&0xff), byte((opQuery>>8)&0xff), 0, 0)
	hdr = append(hdr, 0, 0, 0, 0)
	hdr = append(hdr, ns...)
	hdr = append(hdr, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff)
	hdr = append(hdr, query...)
	buf.Write(hdr)

	msg, err := readMessage(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("read OP_QUERY: %v", err)
	}
	if !msg.legacy {
		t.Fatalf("OP_QUERY was not marked legacy")
	}
	name, err := commandName(msg.body)
	if err != nil || name != "isMaster" {
		t.Fatalf("commandName = %q err=%v", name, err)
	}

	var out bytes.Buffer
	reply := newBson().Double("ok", 1).Finish()
	if err := writeOPReply(&out, 5, msg.requestID, reply); err != nil {
		t.Fatalf("write OP_REPLY: %v", err)
	}
	if out.Len() != 16+4+8+4+4+len(reply) {
		t.Fatalf("OP_REPLY length = %d", out.Len())
	}
	if got := int32(out.Bytes()[12]) | int32(out.Bytes()[13])<<8 | int32(out.Bytes()[14])<<16 | int32(out.Bytes()[15])<<24; got != opReply {
		t.Fatalf("opcode = %d", got)
	}
	garbage := append([]byte(nil), out.Bytes()...)
	garbage[0] = 0xff
	garbage[1] = 0xff
	if _, err := readMessage(bufio.NewReader(bytes.NewReader(garbage))); err == nil {
		t.Fatalf("oversized message accepted")
	}
}

// ---- SCRAM ----

// scrAMServer 是测试用的 SCRAM-SHA-256 服务端（只实现验证与签名）。
type scramServer struct {
	salt            []byte
	nonce           string
	iter            int
	password        string
	clientFirstBare string
	serverFirst     string
}

func newSCRAMServer(password string) *scramServer {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return &scramServer{salt: salt, iter: 15000, password: password, nonce: "srvnonce123456"}
}

func (s *scramServer) start(clientFirst string) (string, error) {
	rest := strings.TrimPrefix(clientFirst, "n,,")
	s.clientFirstBare = rest
	var cnonce string
	for _, part := range strings.Split(rest, ",") {
		if strings.HasPrefix(part, "r=") {
			cnonce = part[2:]
		}
	}
	if cnonce == "" {
		return "", errors.New("no client nonce")
	}
	s.serverFirst = fmt.Sprintf("r=%s%s,s=%s,i=%d", cnonce, s.nonce, base64.StdEncoding.EncodeToString(s.salt), s.iter)
	return s.serverFirst, nil
}

func (s *scramServer) finish(clientFinal string) (string, error) {
	withoutProof := clientFinal
	var proofB64 string
	idx := strings.LastIndex(clientFinal, ",p=")
	if idx < 0 {
		return "", errors.New("no proof")
	}
	withoutProof = clientFinal[:idx]
	proofB64 = clientFinal[idx+3:]
	proof, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		return "", err
	}
	salted := pbkdf2.Key([]byte(s.password), s.salt, s.iter, 32, sha256.New)
	clientKey := hmacSHA256(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	authMessage := s.clientFirstBare + "," + s.serverFirst + "," + withoutProof
	clientSig := hmacSHA256(storedKey[:], authMessage)
	recovered := make([]byte, len(proof))
	for i := range proof {
		recovered[i] = proof[i] ^ clientSig[i]
	}
	recoveredHash := sha256.Sum256(recovered)
	if subtle.ConstantTimeCompare(recoveredHash[:], storedKey[:]) != 1 {
		return "", errors.New("bad proof")
	}
	serverKey := hmacSHA256(salted, "Server Key")
	return "v=" + base64.StdEncoding.EncodeToString(hmacSHA256(serverKey, authMessage)), nil
}

func TestSCRAMClientAgainstServer(t *testing.T) {
	client, err := newSCRAMClient("kkuser", "s3cret-password")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	server := newSCRAMServer("s3cret-password")
	serverFirst, err := server.start(client.firstMessage())
	if err != nil {
		t.Fatalf("server start: %v", err)
	}
	if err := client.receiveServerFirst(serverFirst); err != nil {
		t.Fatalf("receive server first: %v", err)
	}
	final, err := client.finalMessage()
	if err != nil {
		t.Fatalf("final message: %v", err)
	}
	serverFinal, err := server.finish(final)
	if err != nil {
		t.Fatalf("server finish: %v", err)
	}
	if err := client.verifyServerFinal(serverFinal); err != nil {
		t.Fatalf("verify server final: %v", err)
	}

	// 错误口令必须验签失败。
	bad, _ := newSCRAMClient("kkuser", "wrong-password")
	server2 := newSCRAMServer("s3cret-password")
	sf2, _ := server2.start(bad.firstMessage())
	if err := bad.receiveServerFirst(sf2); err != nil {
		t.Fatalf("receive: %v", err)
	}
	bf, _ := bad.finalMessage()
	if _, err := server2.finish(bf); err == nil {
		t.Fatalf("server accepted a wrong password proof")
	}

	// nonce 不匹配必须拒绝。
	if err := client.receiveServerFirst("r=othernonce,s=" + base64.StdEncoding.EncodeToString(server.salt) + ",i=15000"); err == nil {
		t.Fatalf("client accepted a mismatched nonce")
	}
}

// ---- proxy end to end ----

type testBroker struct {
	mu         sync.Mutex
	fields     map[string]string
	resolveErr error
	binding    model.Binding
	// authorized 是 Resolve 返回的 Binding 快照；nil 表示用 binding。
	authorized         *model.Binding
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

func (b *testBroker) CheckLease(_ context.Context, _ secret.Value, lease model.UseLease) error {
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

func (b *testBroker) ReleaseLease(leaseID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revoked = append(b.revoked, leaseID)
}

func (b *testBroker) leaseCounts() (resolved, revoked int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls, len(b.revoked)
}

func (b *testBroker) Authorize(_ context.Context, req broker.Request) (*broker.Authorization, error) {
	token, mode := req.Token.RevealString(), string(req.Mode)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.resolveErr != nil {
		return nil, b.resolveErr
	}
	if token != "kks_test_token" {
		return nil, &ipcclient.APIError{Code: string(model.CodeSessionInvalid), Message: "invalid"}
	}
	if mode != string(model.ModeProxy) {
		return nil, &ipcclient.APIError{Code: string(model.CodeUseNotAllowed), Message: "mode"}
	}
	out := &broker.Authorization{Version: model.CredentialVersion{Fields: map[string]secret.Value{}}}
	for k, v := range b.fields {
		out.Version.Fields[k] = secret.New(v)
	}
	snapshot := b.binding
	if b.authorized != nil {
		snapshot = *b.authorized
	}
	out.Binding = &snapshot
	out.Lease = model.UseLease{ID: fmt.Sprintf("lease-%d", b.calls), BindingRevision: snapshot.Revision, BindingID: snapshot.ID, Target: snapshot.UpstreamOrigin, UseLeaseExpiresAt: time.Now().Add(time.Minute)}
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

// fakeMongo 是最小 mongod：hello + SCRAM-SHA-256 服务端 + ping。
type fakeMongo struct {
	ln       net.Listener
	user     string
	password string
	authDB   string
	mu       sync.Mutex
	authed   bool
	pings    int
	conns    int
}

func newFakeMongo(t *testing.T, user, password, authDB string) *fakeMongo {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeMongo{ln: ln, user: user, password: password, authDB: authDB}
	go f.accept()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeMongo) addr() string { return f.ln.Addr().String() }

func (f *fakeMongo) accept() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeMongo) connCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

func (f *fakeMongo) handle(c net.Conn) {
	defer c.Close()
	f.mu.Lock()
	f.conns++
	f.mu.Unlock()
	r := bufio.NewReader(c)
	server := newSCRAMServer(f.password)
	for {
		msg, err := readMessage(r)
		if err != nil {
			return
		}
		doc, err := msg.command()
		if err != nil {
			return
		}
		name, _ := commandName(msg.body)
		switch strings.ToLower(name) {
		case "hello", "ismaster":
			body := newBson().Bool("isWritablePrimary", true).Int32("maxWireVersion", 21).Int32("minWireVersion", 0).Double("ok", 1).Finish()
			_ = writeOPMsg(c, 100, msg.requestID, body)
		case "saslstart":
			payload, _ := bsonBinaryValue(doc["payload"])
			sf, err := server.start(string(payload))
			if err != nil {
				_ = writeOPMsg(c, 101, msg.requestID, newBson().String("errmsg", err.Error()).Double("ok", 0).Finish())
				return
			}
			body := newBson().Int32("conversationId", 1).Bool("done", false).Binary("payload", 0, []byte(sf)).Double("ok", 1).Finish()
			_ = writeOPMsg(c, 101, msg.requestID, body)
		case "saslcontinue":
			payload, _ := bsonBinaryValue(doc["payload"])
			if len(payload) == 0 {
				body := newBson().Int32("conversationId", 1).Bool("done", true).Binary("payload", 0, []byte{}).Double("ok", 1).Finish()
				_ = writeOPMsg(c, 102, msg.requestID, body)
				continue
			}
			sf, err := server.finish(string(payload))
			if err != nil {
				_ = writeOPMsg(c, 102, msg.requestID, newBson().String("errmsg", "Authentication failed.").Double("ok", 0).Finish())
				return
			}
			f.mu.Lock()
			f.authed = true
			f.mu.Unlock()
			body := newBson().Int32("conversationId", 1).Bool("done", false).Binary("payload", 0, []byte(sf)).Double("ok", 1).Finish()
			_ = writeOPMsg(c, 102, msg.requestID, body)
		case "ping":
			f.mu.Lock()
			f.pings++
			authed := f.authed
			f.mu.Unlock()
			if !authed {
				_ = writeOPMsg(c, 103, msg.requestID, newBson().String("errmsg", "unauthorized").Double("ok", 0).Finish())
				continue
			}
			body := newBson().String("marker", "upstream").Double("ok", 1).Finish()
			_ = writeOPMsg(c, 103, msg.requestID, body)
		default:
			_ = writeOPMsg(c, 104, msg.requestID, newBson().String("errmsg", "unsupported").Double("ok", 0).Finish())
		}
	}
}

func startMongoProxy(t *testing.T, broker *testBroker) (*Server, string) {
	t.Helper()
	srv, err := New(broker, Config{
		BindingID:          "bind_mongo_test",
		ListenAddr:         "127.0.0.1:0",
		AuthTimeout:        5 * time.Second,
		RevalidateInterval: broker.revalidateInterval,
		InsecureUpstream:   true,
		Logger:             log.New(io.Discard, "", 0),
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

func mongoBroker(addr string) *testBroker {
	return &testBroker{
		fields:  map[string]string{"username": "kkuser", "password": "mongo-secret", "database": "admin"},
		binding: model.Binding{ID: "bind_mongo_test", UpstreamOrigin: "http://" + addr, Status: model.StatusActive},
	}
}

type mongoTestClient struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialMongoClient(t *testing.T, addr string) *mongoTestClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &mongoTestClient{conn: conn, r: bufio.NewReader(conn)}
}

// legacyHello 用 OP_QUERY 发 isMaster，期望 OP_REPLY，返回解析后的 hello 文档。
func (c *mongoTestClient) legacyHello(t *testing.T, requestID int32) map[string]any {
	t.Helper()
	query := newBson().Int32("isMaster", 1).String("$db", "admin").Finish()
	ns := "admin.$cmd"
	length := 16 + 4 + len(ns) + 1 + 4 + 4 + len(query)
	buf := make([]byte, 0, length)
	buf = append(buf, byte(length), byte(length>>8), byte(length>>16), byte(length>>24))
	buf = append(buf, byte(requestID), 0, 0, 0, 0, 0, 0, 0)
	buf = append(buf, byte(opQuery&0xff), byte((opQuery>>8)&0xff), 0, 0)
	buf = append(buf, 0, 0, 0, 0)
	buf = append(buf, ns...)
	buf = append(buf, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff)
	buf = append(buf, query...)
	if _, err := c.conn.Write(buf); err != nil {
		t.Fatalf("write OP_QUERY: %v", err)
	}
	hdr := make([]byte, 36)
	if _, err := io.ReadFull(c.r, hdr); err != nil {
		t.Fatalf("read OP_REPLY header: %v", err)
	}
	opcode := int32(hdr[12]) | int32(hdr[13])<<8 | int32(hdr[14])<<16 | int32(hdr[15])<<24
	if opcode != opReply {
		t.Fatalf("handshake reply opcode = %d", opcode)
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(c.r, lenBuf[:]); err != nil {
		t.Fatalf("read OP_REPLY document length: %v", err)
	}
	docLen := int(int32(binary.LittleEndian.Uint32(lenBuf[:])))
	if docLen < 5 || docLen > 1<<20 {
		t.Fatalf("OP_REPLY document length = %d", docLen)
	}
	doc := make([]byte, docLen)
	copy(doc, lenBuf[:])
	if _, err := io.ReadFull(c.r, doc[4:]); err != nil {
		t.Fatalf("read OP_REPLY document: %v", err)
	}
	parsed, err := document(doc)
	if err != nil {
		t.Fatalf("parse handshake doc: %v", err)
	}
	return parsed
}

// hello 用现代 OP_MSG 发 hello，返回代理的回复文档（mongosh 2.x 的首个握手）。
func (c *mongoTestClient) hello(t *testing.T, requestID int32) map[string]any {
	t.Helper()
	body := newBson().Int32("hello", 1).Bool("helloOk", true).String("$db", "admin").Finish()
	if err := writeOPMsg(c.conn, requestID, 0, body); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	msg, err := readMessage(c.r)
	if err != nil {
		t.Fatalf("read hello reply: %v", err)
	}
	if msg.responseTo != requestID {
		t.Fatalf("hello responseTo = %d want %d", msg.responseTo, requestID)
	}
	doc, err := msg.command()
	if err != nil {
		t.Fatalf("parse hello reply: %v", err)
	}
	return doc
}

// assertWireVersionRange 断言认证前的 hello 回复同时给出 min/max wire version，
// 且 min ≤ max。缺 minWireVersion 时 mongosh 2.14 会在认证前报
// "minimum wire version undefined"。
func assertWireVersionRange(t *testing.T, doc map[string]any, what string) {
	t.Helper()
	if ok, _ := bsonInt(doc["ok"]); ok != 1 {
		t.Fatalf("%s ok = %v", what, doc["ok"])
	}
	min, hasMin := bsonInt(doc["minWireVersion"])
	if !hasMin {
		t.Fatalf("%s omitted minWireVersion: %v", what, doc)
	}
	max, hasMax := bsonInt(doc["maxWireVersion"])
	if !hasMax {
		t.Fatalf("%s omitted maxWireVersion: %v", what, doc)
	}
	if min > max {
		t.Fatalf("%s advertises minWireVersion %d > maxWireVersion %d", what, min, max)
	}
	// 取值与代理实际处理的初始握手能力一致：min 0（兼容 2.6+ 的握手）、max 17（6.0）。
	if min != 0 || max != 17 {
		t.Fatalf("%s wire version range = [%d,%d], want [0,17]", what, min, max)
	}
}

// legacyHandshake 用 OP_QUERY 发 isMaster，期望 OP_REPLY。
func (c *mongoTestClient) legacyHandshake(t *testing.T) {
	t.Helper()
	parsed := c.legacyHello(t, 7)
	assertWireVersionRange(t, parsed, "pre-auth legacy hello")
}

func (c *mongoTestClient) saslStart(t *testing.T, mechanism, payload string, requestID int32) map[string]any {
	t.Helper()
	body := newBson().
		Int32("saslStart", 1).
		String("mechanism", mechanism).
		Binary("payload", 0, []byte(payload)).
		String("$db", "$external").
		Finish()
	if err := writeOPMsg(c.conn, requestID, 0, body); err != nil {
		t.Fatalf("write saslStart: %v", err)
	}
	msg, err := readMessage(c.r)
	if err != nil {
		t.Fatalf("read saslStart reply: %v", err)
	}
	if msg.responseTo != requestID {
		t.Fatalf("responseTo = %d want %d", msg.responseTo, requestID)
	}
	doc, err := msg.command()
	if err != nil {
		t.Fatalf("parse saslStart reply: %v", err)
	}
	return doc
}

func (c *mongoTestClient) ping(t *testing.T, requestID int32) map[string]any {
	t.Helper()
	body := newBson().Int32("ping", 1).String("$db", "admin").Finish()
	if err := writeOPMsg(c.conn, requestID, 0, body); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	msg, err := readMessage(c.r)
	if err != nil {
		t.Fatalf("read ping reply: %v", err)
	}
	if msg.responseTo != requestID {
		t.Fatalf("ping responseTo = %d want %d", msg.responseTo, requestID)
	}
	doc, err := msg.command()
	if err != nil {
		t.Fatalf("parse ping reply: %v", err)
	}
	return doc
}

func TestProxyEndToEndPLAIN(t *testing.T) {
	up := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	_, addr := startMongoProxy(t, mongoBroker(up.addr()))
	c := dialMongoClient(t, addr)
	c.legacyHandshake(t)

	reply := c.saslStart(t, "PLAIN", "\x00kkuser\x00kks_test_token", 2)
	if ok, _ := bsonInt(reply["ok"]); ok != 1 {
		t.Fatalf("saslStart reply = %v", reply)
	}
	if done, _ := reply["done"].(bool); !done {
		t.Fatalf("saslStart did not complete the exchange: %v", reply)
	}
	ping := c.ping(t, 3)
	if ok, _ := bsonInt(ping["ok"]); ok != 1 {
		t.Fatalf("ping reply = %v", ping)
	}
	if marker, _ := bsonStringValue(ping["marker"]); marker != "upstream" {
		t.Fatalf("ping did not reach the upstream: %v", ping)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if !up.authed {
		t.Fatalf("upstream was never authenticated")
	}
}

func TestProxyRejectsSCRAMWithoutFakingIt(t *testing.T) {
	up := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	_, addr := startMongoProxy(t, mongoBroker(up.addr()))
	c := dialMongoClient(t, addr)
	c.legacyHandshake(t)
	reply := c.saslStart(t, "SCRAM-SHA-256", "n,,n=kkuser,r=abc", 2)
	if ok, _ := bsonInt(reply["ok"]); ok != 0 {
		t.Fatalf("SCRAM was accepted: %v", reply)
	}
	if code, _ := bsonInt(reply["code"]); code != 18 {
		t.Fatalf("auth failure code = %v", reply["code"])
	}
	msg, _ := bsonStringValue(reply["errmsg"])
	if !strings.Contains(msg, "PLAIN") {
		t.Fatalf("rejection does not explain the supported mechanism: %q", msg)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.authed {
		t.Fatalf("upstream was authenticated despite the rejected mechanism")
	}
}

func TestProxyWrongTokenRejected(t *testing.T) {
	up := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	_, addr := startMongoProxy(t, mongoBroker(up.addr()))
	c := dialMongoClient(t, addr)
	c.legacyHandshake(t)
	reply := c.saslStart(t, "PLAIN", "\x00kkuser\x00kks_wrong", 2)
	if ok, _ := bsonInt(reply["ok"]); ok != 0 {
		t.Fatalf("wrong token accepted: %v", reply)
	}
	if strings.Contains(fmt.Sprint(reply), "kks_wrong") {
		t.Fatalf("reply echoed the token: %v", reply)
	}
}

func TestProxyNoGrantRejected(t *testing.T) {
	up := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	broker := mongoBroker(up.addr())
	broker.resolveErr = &ipcclient.APIError{Code: string(model.CodeUseNotAllowed), Message: "no grant"}
	_, addr := startMongoProxy(t, broker)
	c := dialMongoClient(t, addr)
	c.legacyHandshake(t)
	reply := c.saslStart(t, "PLAIN", "\x00kkuser\x00kks_test_token", 2)
	if ok, _ := bsonInt(reply["ok"]); ok != 0 {
		t.Fatalf("no-grant auth accepted: %v", reply)
	}
}

func TestProxyUpstreamPasswordMismatch(t *testing.T) {
	up := newFakeMongo(t, "kkuser", "other-secret", "admin")
	_, addr := startMongoProxy(t, mongoBroker(up.addr()))
	c := dialMongoClient(t, addr)
	c.legacyHandshake(t)
	reply := c.saslStart(t, "PLAIN", "\x00kkuser\x00kks_test_token", 2)
	if ok, _ := bsonInt(reply["ok"]); ok != 0 {
		t.Fatalf("auth accepted with a wrong upstream password: %v", reply)
	}
	if strings.Contains(fmt.Sprint(reply), "other-secret") {
		t.Fatalf("reply leaked the upstream password: %v", reply)
	}
}

// TestProxyUsesAuthorizedBindingSnapshot 断言上游目标只来自授权快照：
// 旧的 /v1/bindings 读取路径（旧目标）不再参与，认证前也不接触上游。
func TestProxyUsesAuthorizedBindingSnapshot(t *testing.T) {
	legacy := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	authorized := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	broker := mongoBroker(authorized.addr())
	broker.binding.UpstreamOrigin = "http://" + legacy.addr()
	broker.authorize("http://" + authorized.addr())
	_, addr := startMongoProxy(t, broker)

	c := dialMongoClient(t, addr)
	c.legacyHandshake(t)
	if got := legacy.connCount(); got != 0 {
		t.Fatalf("the proxy contacted an upstream before authorization: %d connection(s)", got)
	}
	reply := c.saslStart(t, "PLAIN", "\x00kkuser\x00kks_test_token", 2)
	if ok, _ := bsonInt(reply["ok"]); ok != 1 {
		t.Fatalf("saslStart reply = %v", reply)
	}
	if authorized.connCount() != 1 {
		t.Fatalf("authorized upstream saw %d connection(s)", authorized.connCount())
	}
	if legacy.connCount() != 0 {
		t.Fatalf("the stale binding list target was used: %d connection(s)", legacy.connCount())
	}
	broker.mu.Lock()
	listCalls := broker.listCalls
	broker.mu.Unlock()
	if listCalls != 0 {
		t.Fatalf("proxy still listed /v1/bindings %d time(s)", listCalls)
	}
}

// pingErr 发 ping 并读回包；代理直接关闭连接时返回错误。
func (c *mongoTestClient) pingErr(requestID int32) (map[string]any, error) {
	body := newBson().Int32("ping", 1).String("$db", "admin").Finish()
	if err := writeOPMsg(c.conn, requestID, 0, body); err != nil {
		return nil, err
	}
	msg, err := readMessage(c.r)
	if err != nil {
		return nil, err
	}
	return msg.command()
}

// waitForClosed 轮询 ping，直到代理结束连接。
func waitForMongoClosed(t *testing.T, c *mongoTestClient) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	requestID := int32(100)
	for time.Now().Before(deadline) {
		requestID++
		if _, err := c.pingErr(requestID); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the existing connection was not ended after the binding changed")
}

func TestProxyEndsConnectionWhenBindingRevisionChanges(t *testing.T) {
	oldUpstream := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	newUpstream := newFakeMongo(t, "kkuser", "new-secret", "admin")
	broker := mongoBroker(oldUpstream.addr())
	broker.revalidateInterval = 20 * time.Millisecond
	_, addr := startMongoProxy(t, broker)
	c := dialMongoClient(t, addr)
	c.legacyHandshake(t)
	if reply := c.saslStart(t, "PLAIN", "\x00kkuser\x00kks_test_token", 2); func() bool { ok, _ := bsonInt(reply["ok"]); return ok != 1 }() {
		t.Fatalf("saslStart reply = %v", reply)
	}

	// 只改 daemon 侧登记的绑定：既有连接手里仍是旧快照。
	broker.reviseLive("http://"+newUpstream.addr(), 2)
	waitForMongoClosed(t, c)
	if newUpstream.connCount() != 0 {
		t.Fatal("the revised target was contacted on the old connection")
	}
	// 旧连接不做第二次授权：许可只在建立时创建并已经释放。
	deadline := time.Now().Add(time.Second)
	for {
		resolved, finished := broker.leaseCounts()
		if resolved == 1 && finished == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected one completed execution, got resolved=%d finished=%d", resolved, finished)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestExistingConnectionEndsWhenBindingStatusChanges 断言状态不再是 active 时结束连接。
func TestExistingConnectionEndsWhenBindingStatusChanges(t *testing.T) {
	up := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	broker := mongoBroker(up.addr())
	broker.revalidateInterval = 20 * time.Millisecond
	_, addr := startMongoProxy(t, broker)
	c := dialMongoClient(t, addr)
	c.legacyHandshake(t)
	if reply := c.saslStart(t, "PLAIN", "\x00kkuser\x00kks_test_token", 2); func() bool { ok, _ := bsonInt(reply["ok"]); return ok != 1 }() {
		t.Fatalf("saslStart reply = %v", reply)
	}
	broker.setLiveStatus(model.StatusDisabled)
	waitForMongoClosed(t, c)
}

// TestExistingConnectionEndsWhenUpstreamOriginChanges 断言 revision 不变但 origin
// 改绑时同样结束连接，旧连接不会被引导到新目标。
func TestExistingConnectionEndsWhenUpstreamOriginChanges(t *testing.T) {
	oldUpstream := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	newUpstream := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	broker := mongoBroker(oldUpstream.addr())
	broker.revalidateInterval = 20 * time.Millisecond
	_, addr := startMongoProxy(t, broker)
	c := dialMongoClient(t, addr)
	c.legacyHandshake(t)
	if reply := c.saslStart(t, "PLAIN", "\x00kkuser\x00kks_test_token", 2); func() bool { ok, _ := bsonInt(reply["ok"]); return ok != 1 }() {
		t.Fatalf("saslStart reply = %v", reply)
	}
	broker.reviseLive("http://"+newUpstream.addr(), 0)
	waitForMongoClosed(t, c)
	if newUpstream.connCount() != 0 {
		t.Fatalf("the moved target was contacted on the old connection: %d connection(s)", newUpstream.connCount())
	}
}

// TestBindingCheckFailureKeepsConnection 断言 daemon 暂时不可达时不断开连接，
// 恢复后仍能按新的 revision 结束连接（失败只记录并重试）。
func TestBindingCheckFailureKeepsConnection(t *testing.T) {
	up := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	broker := mongoBroker(up.addr())
	broker.revalidateInterval = 20 * time.Millisecond
	_, addr := startMongoProxy(t, broker)
	c := dialMongoClient(t, addr)
	c.legacyHandshake(t)
	if reply := c.saslStart(t, "PLAIN", "\x00kkuser\x00kks_test_token", 2); func() bool { ok, _ := bsonInt(reply["ok"]); return ok != 1 }() {
		t.Fatalf("saslStart reply = %v", reply)
	}

	broker.failGets(errors.New("keykoid is unreachable"))
	time.Sleep(120 * time.Millisecond)
	if ping := c.ping(t, 3); func() bool { ok, _ := bsonInt(ping["ok"]); return ok != 1 }() {
		t.Fatalf("a failed binding check closed the connection: %v", ping)
	}
	broker.mu.Lock()
	failedChecks := broker.getCalls
	broker.mu.Unlock()
	if failedChecks < 2 {
		t.Fatalf("binding checks were not retried: %d attempt(s)", failedChecks)
	}

	broker.failGets(nil)
	broker.reviseLive("http://127.0.0.1:1", 3)
	waitForMongoClosed(t, c)
}

// TestBindingCheckIsThrottledAndCoversIdleConnections 断言转发环里的核对既不是
// 逐消息触发、也不会因为连接空闲而停止。
func TestBindingCheckIsThrottledAndCoversIdleConnections(t *testing.T) {
	up := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	broker := mongoBroker(up.addr())
	broker.revalidateInterval = 100 * time.Millisecond
	_, addr := startMongoProxy(t, broker)
	c := dialMongoClient(t, addr)
	c.legacyHandshake(t)
	if reply := c.saslStart(t, "PLAIN", "\x00kkuser\x00kks_test_token", 2); func() bool { ok, _ := bsonInt(reply["ok"]); return ok != 1 }() {
		t.Fatalf("saslStart reply = %v", reply)
	}
	for i := 0; i < 30; i++ {
		if ping := c.ping(t, int32(10+i)); func() bool { ok, _ := bsonInt(ping["ok"]); return ok != 1 }() {
			t.Fatalf("ping %d reply = %v", i, ping)
		}
	}
	broker.mu.Lock()
	burstChecks := broker.getCalls
	broker.mu.Unlock()
	if burstChecks > 5 {
		t.Fatalf("binding checks followed every message: %d checks for 30 pings", burstChecks)
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

// TestPreAuthHelloAdvertisesWireVersionRange 走代理的真实握手顺序（hello → saslStart
// → ping）：认证前的现代 hello 与 legacy isMaster 都必须同时给出 min/max wire version。
func TestPreAuthHelloAdvertisesWireVersionRange(t *testing.T) {
	up := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	_, addr := startMongoProxy(t, mongoBroker(up.addr()))
	c := dialMongoClient(t, addr)

	assertWireVersionRange(t, c.hello(t, 1), "pre-auth hello")
	assertWireVersionRange(t, c.legacyHello(t, 2), "pre-auth legacy hello")

	reply := c.saslStart(t, "PLAIN", "\x00kkuser\x00kks_test_token", 3)
	if ok, _ := bsonInt(reply["ok"]); ok != 1 {
		t.Fatalf("saslStart after hello = %v", reply)
	}
	ping := c.ping(t, 4)
	if marker, _ := bsonStringValue(ping["marker"]); marker != "upstream" {
		t.Fatalf("ping did not reach the upstream: %v", ping)
	}
}

// TestShutdownCancelsIdleConnections 断言空闲连接不会让退出无限挂起。
func TestShutdownCancelsIdleConnections(t *testing.T) {
	up := newFakeMongo(t, "kkuser", "mongo-secret", "admin")
	srv, addr := startMongoProxy(t, mongoBroker(up.addr()))
	conn := dialMongoClient(t, addr)

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
	_ = conn.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("client connection was left open after shutdown")
	}
}
