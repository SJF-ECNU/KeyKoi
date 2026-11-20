// Package mongoproxy 实现 MongoDB 认证代理：客户端用 KeyKoi 会话令牌认证，
// 代理以登记的真实凭据向上游 MongoDB 完成 SCRAM-SHA-256 认证后转发命令。
//
// 支持范围（实测口径）：
//   - 客户端认证：SASL PLAIN（MongoDB 的 LDAP 式机制，payload 为
//     "\x00user\x00password"）。客户端必须显式选择该机制：
//     mongosh "mongodb://.../?authSource=%24external" --authenticationMechanism PLAIN。
//   - 上游认证：SCRAM-SHA-256 客户端实现（PBKDF2-HMAC-SHA256 + 口令证明 +
//     服务端签名校验），支持指定 authSource（默认 admin）。
//   - 命令阶段：OP_MSG 双向原样转发；认证前的 hello 由代理用自己的能力值应答。
//   - 目标与凭证来自同一次授权：上游地址只从 Resolve 返回的 Binding 快照取，
//     客户端提交令牌之前不接触上游。
//
// 为什么客户端侧不终结 SCRAM-SHA-256：
//
//	SCRAM 的服务端只需要保存验证器（StoredKey），而这里的“口令”就是 KeyKoi
//	会话令牌本身，代理不掌握令牌原文，因此无法校验客户端发来的 proof。
//	在不掌握口令的情况下终结 SCRAM 只能跳过校验，那会让任何字符串都通过认证，
//	属于假实现。因此客户端侧采用能真正读取令牌的 SASL PLAIN，并把 SCRAM 客户端
//	发起的认证明确拒绝（返回 AuthenticationFailed 与原因），不伪装成功。
//
// 不支持项：
//   - 客户端侧 SCRAM-SHA-1/SCRAM-SHA-256（原因见上）。
//   - OP_COMPRESSED、OP_QUERY 旧握手、客户端 TLS 与 X.509 证书认证。
//   - 多文档事务语义、读关注/写关注改写与副本集路由；权限由上游负责。
package mongoproxy

import (
	"bufio"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"keykoi/internal/model"
	"keykoi/internal/osruntime"
	"keykoi/internal/proxylease"
	"keykoi/internal/secret"
)

// Broker is the local authority used by the daemon-owned adapter.
type Broker = proxylease.Authority

// Config 配置代理。
type Config struct {
	BindingID     string
	ListenAddr    string
	ListenSocket  string
	UsernameField string
	PasswordField string
	DatabaseField string
	AuthTimeout   time.Duration
	DialTimeout   time.Duration
	// UpstreamCA appends a PEM bundle to the system trust store.
	UpstreamCA string
	// InsecureUpstream selects plaintext for a target without an explicit TLS scheme.
	InsecureUpstream bool
	// RevalidateInterval 是已认证连接核对绑定改绑的间隔：默认且最大 1 秒，
	// 转发环按时间戳节流，最多每秒查一次；测试可调小以加速。
	RevalidateInterval time.Duration
	MaxConnections     int
	// Logger 记录不含秘密的连接事件；nil 表示静默。
	Logger *log.Logger
}

func (c *Config) normalize() error {
	if c.BindingID == "" {
		return errors.New("mongoproxy: binding id is required")
	}
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:0"
	}
	if c.UsernameField == "" {
		c.UsernameField = "username"
	}
	if c.PasswordField == "" {
		c.PasswordField = "password"
	}
	if c.DatabaseField == "" {
		c.DatabaseField = "database"
	}
	if c.AuthTimeout <= 0 {
		c.AuthTimeout = 20 * time.Second
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.RevalidateInterval <= 0 || c.RevalidateInterval > proxylease.Interval {
		// 超过 1 秒的配置会削弱“改绑后最多 1 秒内被发现”的保证，统一收紧到上限。
		c.RevalidateInterval = proxylease.Interval
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = 64
	}
	return nil
}

// Server 是代理运行时。
type Server struct {
	broker Broker
	cfg    Config
	logger *log.Logger
	roots  *x509.CertPool

	requestID atomic.Int32

	mu    sync.Mutex
	lns   []net.Listener
	addrs []string
	stop  chan struct{}

	active atomic.Int64
	total  atomic.Int64
	denied atomic.Int64

	// conns 记录活跃客户端连接，Shutdown 用它取消在途连接而不是无限等待。
	conns map[net.Conn]struct{}

	wg sync.WaitGroup
}

const (
	// defaultDrainTimeout 是 Shutdown 在没有明确截止时间时等待在途连接的上限。
	defaultDrainTimeout = 5 * time.Second
)

// New 构造代理。它不监听端口，Listen 之后才对外可用。
func New(b Broker, cfg Config) (*Server, error) {
	if b == nil {
		return nil, errors.New("mongoproxy: broker client is required")
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	var roots *x509.CertPool
	if cfg.UpstreamCA != "" {
		pem, err := os.ReadFile(cfg.UpstreamCA)
		if err != nil {
			return nil, fmt.Errorf("read upstream CA file: %w", err)
		}
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("upstream CA file contains no usable certificate")
		}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{
		broker: b,
		cfg:    cfg,
		logger: logger,
		roots:  roots,
		stop:   make(chan struct{}),
		conns:  map[net.Conn]struct{}{},
	}, nil
}

// Config 返回生效配置（已归一化）。
func (s *Server) Config() Config { return s.cfg }

// Listen 绑定客户端监听地址。端口 0 时由系统分配，Addrs 给出实际地址。
func (s *Server) Listen() error {
	ln, err := osruntime.ListenLoopbackTCP(s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("mongoproxy: listen: %w", err)
	}
	s.mu.Lock()
	s.lns = append(s.lns, ln)
	s.addrs = append(s.addrs, ln.Addr().String())
	s.mu.Unlock()

	if s.cfg.ListenSocket != "" {
		_ = os.Remove(s.cfg.ListenSocket)
		sln, err := net.Listen("unix", s.cfg.ListenSocket)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("mongoproxy: listen unix socket: %w", err)
		}
		_ = os.Chmod(s.cfg.ListenSocket, 0o600)
		s.mu.Lock()
		s.lns = append(s.lns, sln)
		s.addrs = append(s.addrs, "unix:"+s.cfg.ListenSocket)
		s.mu.Unlock()
	}
	return nil
}

// Addrs 返回全部监听地址。
func (s *Server) Addrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.addrs))
	copy(out, s.addrs)
	return out
}

// Serve 接受连接直到 ctx 结束或 Shutdown 被调用。
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	lns := append([]net.Listener(nil), s.lns...)
	s.mu.Unlock()
	if len(lns) == 0 {
		select {
		case <-s.stop:
			return nil
		default:
		}
		return errors.New("mongoproxy: Listen must be called before Serve")
	}

	var acceptWG sync.WaitGroup
	go func() {
		<-ctx.Done()
		// 退出时用带截止时间的排空上下文：空闲连接不能无限拖住退出。
		drainCtx, cancel := context.WithTimeout(context.Background(), defaultDrainTimeout)
		defer cancel()
		_ = s.Shutdown(drainCtx)
	}()

	acceptWG.Add(len(lns))
	errCh := make(chan error, len(lns))
	for _, ln := range lns {
		go func(ln net.Listener) {
			defer acceptWG.Done()
			for {
				c, err := ln.Accept()
				if err != nil {
					select {
					case <-s.stop:
						return
					default:
					}
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					errCh <- err
					return
				}
				s.wg.Add(1)
				go func() {
					defer s.wg.Done()
					s.handle(ctx, c)
				}()
			}
		}(ln)
	}
	acceptWG.Wait()
	s.wg.Wait()
	select {
	case err := <-errCh:
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	default:
		return nil
	}
}

// Shutdown 关闭监听，取消全部活跃连接，并在时限内等待它们结束。
//
// 等待上限取 ctx 的截止时间；ctx 没有截止时间时用 defaultDrainTimeout。
func (s *Server) Shutdown(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(defaultDrainTimeout)
	}
	s.mu.Lock()
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	lns := s.lns
	s.lns = nil
	s.mu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}

	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.SetDeadline(time.Now())
		_ = c.Close()
	}

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		if len(conns) > 0 {
			s.logger.Printf("mongo-proxy shutdown: %d connection(s) still active after the drain timeout", len(conns))
		}
		return nil
	}
}

// trackConn / untrackConn 维护活跃客户端连接集合，供 Shutdown 取消。
func (s *Server) trackConn(c net.Conn) {
	s.mu.Lock()
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrackConn(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// Stats 返回不含秘密的运行计数。
func (s *Server) Stats() (active, total, denied int64) {
	return s.active.Load(), s.total.Load(), s.denied.Load()
}

// handle 处理一条客户端连接。
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	s.total.Add(1)
	remote := conn.RemoteAddr().String()
	if s.active.Add(1) > int64(s.cfg.MaxConnections) {
		s.active.Add(-1)
		s.denied.Add(1)
		_ = conn.Close()
		s.logger.Printf("mongo-proxy connection from %s rejected: connection limit %d", remote, s.cfg.MaxConnections)
		return
	}
	defer func() {
		s.active.Add(-1)
		s.untrackConn(conn)
		_ = conn.Close()
	}()
	s.trackConn(conn)

	_ = conn.SetDeadline(time.Now().Add(s.cfg.AuthTimeout))
	reader := bufio.NewReaderSize(conn, 32<<10)

	// 上游连接在拿到令牌之后才建立：目标必须来自那次授权。
	var up *upstream
	defer func() {
		if up != nil {
			_ = up.close()
		}
	}()

	authenticated := false
	for !authenticated {
		msg, err := readMessage(reader)
		if err != nil {
			s.denied.Add(1)
			s.logger.Printf("mongo-proxy connection from %s rejected: %v", remote, err)
			return
		}
		doc, err := msg.command()
		if err != nil {
			s.denied.Add(1)
			s.replyError(conn, s.nextRequestID(), msg.requestID, "malformed command document")
			s.logger.Printf("mongo-proxy connection from %s rejected: %v", remote, err)
			return
		}
		name, err := commandName(msg.body)
		if err != nil {
			s.denied.Add(1)
			s.replyError(conn, s.nextRequestID(), msg.requestID, "malformed command document")
			return
		}
		switch strings.ToLower(name) {
		case "hello", "ismaster":
			// 认证前不接触上游：用代理自己的能力值应答。
			body := helloReplyBody(nil, time.Now().UnixMilli())
			if err := s.reply(conn, msg, body); err != nil {
				return
			}
		case "saslstart":
			mechanism, _ := bsonStringValue(doc["mechanism"])
			if !strings.EqualFold(mechanism, "PLAIN") {
				s.denied.Add(1)
				s.replyAuthFailure(conn, msg.requestID,
					"this proxy terminates authentication with SASL PLAIN; start mongosh with --authenticationMechanism PLAIN and authSource=$external")
				s.logger.Printf("mongo-proxy connection from %s rejected: unsupported client mechanism %q", remote, mechanism)
				return
			}
			payload, _ := bsonBinaryValue(doc["payload"])
			token := plainPassword(payload)
			if token == "" {
				s.denied.Add(1)
				s.replyAuthFailure(conn, msg.requestID, "the password field must carry a KeyKoi session token")
				return
			}
			target, err := s.resolveTarget(ctx, token)
			if err != nil {
				s.denied.Add(1)
				s.replyAuthFailure(conn, msg.requestID, "Authentication failed.")
				s.logger.Printf("mongo-proxy connection from %s denied: %v", remote, err)
				return
			}
			defer target.use.Finish()
			defer target.use.Track(conn)()
			up, err = s.dialUpstream(target)
			if err != nil {
				s.denied.Add(1)
				s.replyAuthFailure(conn, msg.requestID, "Authentication failed.")
				s.logger.Printf("mongo-proxy connection from %s failed: %v (upstream %s)", remote, err, target)
				return
			}
			defer target.use.Track(up.conn)()
			if err := up.authenticate(target); err != nil {
				s.denied.Add(1)
				s.replyAuthFailure(conn, msg.requestID, "Authentication failed.")
				s.logger.Printf("mongo-proxy upstream authentication failed for %s: %v", target, err)
				return
			}
			body := newBson().
				Int32("conversationId", 1).
				Bool("done", true).
				Binary("payload", 0, []byte{}).
				Double("ok", 1).
				Finish()
			if err := s.reply(conn, msg, body); err != nil {
				return
			}
			authenticated = true
			s.logger.Printf("mongo-proxy connection from %s established (upstream %s)", remote, target)
		case "ping":
			body := newBson().Double("ok", 1).Finish()
			if err := s.reply(conn, msg, body); err != nil {
				return
			}
		default:
			s.denied.Add(1)
			s.replyAuthFailure(conn, msg.requestID, "not authenticated")
			s.logger.Printf("mongo-proxy connection from %s rejected: command %q before authentication", remote, name)
			return
		}
	}

	_ = conn.SetDeadline(time.Time{})
	s.relay(conn, reader, up)
	s.logger.Printf("mongo-proxy connection from %s closed", remote)
}

func (s *Server) nextRequestID() int32 { return s.requestID.Add(1) }

// reply 按客户端使用的协议（OP_MSG 或旧式 OP_QUERY）回包。
func (s *Server) reply(conn net.Conn, msg *message, body []byte) error {
	if msg.legacy {
		return writeOPReply(conn, s.nextRequestID(), msg.requestID, body)
	}
	return writeOPMsg(conn, s.nextRequestID(), msg.requestID, body)
}

// replyError 回复一个通用错误文档。
func (s *Server) replyError(conn net.Conn, requestID, responseTo int32, message string) {
	body := newBson().
		String("errmsg", message).
		Int32("code", 13).
		String("codeName", "Unauthorized").
		Double("ok", 0).
		Finish()
	_ = writeOPMsg(conn, requestID, responseTo, body)
}

// replyAuthFailure 回复认证失败（ERR 18 AuthenticationFailed）。
func (s *Server) replyAuthFailure(conn net.Conn, responseTo int32, message string) {
	body := newBson().
		String("errmsg", message).
		Int32("code", 18).
		String("codeName", "AuthenticationFailed").
		Double("ok", 0).
		Finish()
	_ = writeOPMsg(conn, s.nextRequestID(), responseTo, body)
}

// plainPassword 从 SASL PLAIN payload 中取出最后一个非空段（口令）。
func plainPassword(payload []byte) string {
	parts := strings.Split(string(payload), "\x00")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" {
			return parts[i]
		}
	}
	return ""
}

// helloReplyBody 用上游 hello 的能力值构造代理自己的 hello 回复。
func helloReplyBody(upstream map[string]any, nowMS int64) []byte {
	b := newBson()
	b.Bool("isWritablePrimary", true)
	b.Bool("helloOk", true)
	for _, key := range []string{"maxBsonObjectSize", "maxMessageSizeBytes", "maxWriteBatchSize", "logicalSessionTimeoutMinutes", "minWireVersion", "maxWireVersion"} {
		if v, ok := upstream[key]; ok {
			n, _ := bsonInt(v)
			b.Int32(key, int32(n))
		}
	}
	// 认证前不能连接上游；min=0/max=17 与代理实际处理的初始握手能力一致。
	// 有上游快照时则完整沿用其范围，不伪称支持更新或不兼容的协议。
	if _, ok := upstream["minWireVersion"]; !ok {
		b.Int32("minWireVersion", 0)
	}
	if _, ok := upstream["maxWireVersion"]; !ok {
		b.Int32("maxWireVersion", 17)
	}
	b.Int32("connectionId", 1)
	b.Bool("readOnly", false)
	b.DateTime("localTime", nowMS)
	b.Double("ok", 1)
	return b.Finish()
}

// resolveTarget 用一次授权换取目标与凭证：上游地址只从 resolved.Binding 取。
func (s *Server) resolveTarget(ctx context.Context, token string) (UpstreamTarget, error) {
	sessionToken := secret.New(token)
	resolved, err := proxylease.Authorize(ctx, s.broker, sessionToken, s.cfg.BindingID, s.cfg.AuthTimeout)
	if err != nil {
		return UpstreamTarget{}, proxylease.Denial(err)
	}
	use, err := proxylease.Begin(s.broker, sessionToken, resolved, s.cfg.RevalidateInterval)
	if err != nil {
		return UpstreamTarget{}, err
	}
	accepted := false
	defer func() {
		if !accepted {
			use.Finish()
		}
	}()
	binding, err := proxylease.Binding(resolved, s.cfg.BindingID)
	if err != nil {
		return UpstreamTarget{}, err
	}
	target, err := binding.DatabaseTarget(model.ProtocolMongo, "27017")
	if err != nil {
		return UpstreamTarget{}, err
	}

	userField := cmp.Or(s.cfg.UsernameField, binding.UsernameField, "username")
	passField := cmp.Or(s.cfg.PasswordField, binding.PasswordField, "password")
	user := resolved.Version.Fields[userField].RevealString()
	password := resolved.Version.Fields[passField]
	if user == "" || password.IsEmpty() {
		return UpstreamTarget{}, fmt.Errorf("credential is missing fields %q/%q for the mongodb adapter", userField, passField)
	}
	authDB := resolved.Version.Fields[s.cfg.DatabaseField].RevealString()
	if authDB == "" {
		authDB = "admin"
	}
	accepted = true
	return UpstreamTarget{
		Addr:     target.Address(),
		User:     user,
		Password: password,
		Database: authDB,
		host:     target.Host,
		tls:      target.TLS || !s.cfg.InsecureUpstream,
		use:      use,
	}, nil
}

// relay 认证完成后按字节双向转发 OP_MSG。
//
// 客户端→上游方向同时承担改绑核对：每一轮转发前后按时间戳判断是否到点，
// 到点用 Get 读一次绑定详情（最多每秒一次），不另起后台 goroutine。
func (s *Server) relay(conn net.Conn, clientReader *bufio.Reader, up *upstream) {
	watch := up.target.use

	done := make(chan struct{}, 2)
	go func() {
		s.copyClientToUpstream(conn, clientReader, up, watch)
		_ = up.conn.Close()
		done <- struct{}{}
	}()
	go func() {
		_, err := io.Copy(conn, up.reader)
		if err != nil && !isClosedErr(err) {
			s.logger.Printf("mongo-proxy upstream->client copy: %v", err)
		}
		_ = conn.Close()
		done <- struct{}{}
	}()
	<-done
	_ = up.conn.Close()
	_ = conn.Close()
	<-done
}

// copyClientToUpstream 把客户端字节转给上游，并在同一循环里做有界的改绑核对。
// MongoDB 没有可在任意时刻插入的异步错误包，改绑时直接结束连接。
//
// 读截止时间只用来按时唤醒核对：空闲连接按 RevalidateInterval 超时一次，
// 有数据时立即继续转发，字节流语义不变。
func (s *Server) copyClientToUpstream(conn net.Conn, clientReader *bufio.Reader, up *upstream, watch *proxylease.Use) {
	buf := make([]byte, 32<<10)
	for {
		if watch.Changed() {
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(watch.Interval)); err != nil {
			return
		}
		n, err := clientReader.Read(buf)
		if n > 0 {
			if _, werr := up.conn.Write(buf[:n]); werr != nil {
				if !isClosedErr(werr) {
					s.logger.Printf("mongo-proxy client->upstream copy: %v", werr)
				}
				return
			}
		}
		if err != nil {
			if isTimeoutErr(err) {
				continue
			}
			if !isClosedErr(err) {
				s.logger.Printf("mongo-proxy client->upstream copy: %v", err)
			}
			return
		}
	}
}

// UpstreamTarget 是经授权解析出的上游 MongoDB 连接参数。
type UpstreamTarget struct {
	Addr     string
	User     string
	Password secret.Value
	Database string
	host     string
	tls      bool
	use      *proxylease.Use
}

// String 只输出非秘密字段。
func (t UpstreamTarget) String() string {
	return fmt.Sprintf("addr=%s user=%s authdb=%s", t.Addr, t.User, t.Database)
}

// upstream 是代理到 MongoDB 的一条连接。
type upstream struct {
	conn      net.Conn
	reader    *bufio.Reader
	requestID int32
	// target 是这次授权解析出的上游参数；既有连接只把它当快照比较，不再用于取值。
	target UpstreamTarget
}

// dialUpstream 建立上游连接并完成 hello 握手（不认证）。
func (s *Server) dialUpstream(target UpstreamTarget) (*upstream, error) {
	d := &net.Dialer{Timeout: s.cfg.DialTimeout, KeepAlive: 30 * time.Second}
	ctx := target.use.Context()
	var conn net.Conn
	var err error
	if target.tls {
		td := tls.Dialer{
			NetDialer: d,
			Config: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: target.host,
				RootCAs:    s.roots,
			},
		}
		conn, err = td.DialContext(ctx, "tcp", target.Addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", target.Addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target.Addr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(s.cfg.DialTimeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	u := &upstream{conn: conn, reader: bufio.NewReaderSize(conn, 32<<10), target: target}
	hello := newBson().
		Int32("hello", 1).
		String("$db", "admin").
		Finish()
	reply, err := u.roundTrip(hello)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if ok, _ := bsonInt(reply["ok"]); ok != 1 {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream hello failed: %s", errmsgOf(reply))
	}
	_ = conn.SetDeadline(time.Time{})
	return u, nil
}

// roundTrip 发一条命令并读取对应回复。
func (u *upstream) roundTrip(body []byte) (map[string]any, error) {
	u.requestID++
	if err := writeOPMsg(u.conn, u.requestID, 0, body); err != nil {
		return nil, err
	}
	for i := 0; i < 4; i++ {
		msg, err := readMessage(u.reader)
		if err != nil {
			return nil, err
		}
		if msg.responseTo != u.requestID {
			continue
		}
		return msg.command()
	}
	return nil, errors.New("mongoproxy: upstream did not answer the request")
}

// authenticate 用真实凭据完成 SCRAM-SHA-256 认证。
func (u *upstream) authenticate(target UpstreamTarget) error {
	if err := u.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	defer func() { _ = u.conn.SetDeadline(time.Time{}) }()

	password := target.Password.RevealString()
	scram, err := newSCRAMClient(target.User, password)
	if err != nil {
		return err
	}
	start := newBson().
		Int32("saslStart", 1).
		String("mechanism", scramSHA256).
		Binary("payload", 0, []byte(scram.firstMessage())).
		Int32("autoAuthorize", 1).
		Document("options", newBson().Bool("skipEmptyExchange", true).Finish()).
		String("$db", target.Database).
		Finish()
	reply, err := u.roundTrip(start)
	if err != nil {
		return err
	}
	if ok, _ := bsonInt(reply["ok"]); ok != 1 {
		return fmt.Errorf("upstream saslStart failed: %s", errmsgOf(reply))
	}
	conversationID, _ := bsonInt(reply["conversationId"])
	payload, _ := bsonBinaryValue(reply["payload"])
	if err := scram.receiveServerFirst(string(payload)); err != nil {
		return err
	}
	final, err := scram.finalMessage()
	if err != nil {
		return err
	}

	// 标准流程是两轮：客户端 final → 服务端最终签名。未设置 skipEmptyExchange
	// 的服务端还会要求一次空 saslContinue，这里统一循环到 done=true。
	nextPayload := final
	verified := false
	for attempt := 0; attempt < 3; attempt++ {
		cont := newBson().
			Int32("saslContinue", 1).
			Int32("conversationId", int32(conversationID)).
			Binary("payload", 0, []byte(nextPayload)).
			String("$db", target.Database).
			Finish()
		reply, err = u.roundTrip(cont)
		if err != nil {
			return err
		}
		if ok, _ := bsonInt(reply["ok"]); ok != 1 {
			return fmt.Errorf("upstream saslContinue failed: %s", errmsgOf(reply))
		}
		payload, _ = bsonBinaryValue(reply["payload"])
		if len(payload) > 0 {
			if err := scram.verifyServerFinal(string(payload)); err != nil {
				return err
			}
			verified = true
		}
		if done, _ := reply["done"].(bool); done {
			if !verified {
				return errors.New("upstream SCRAM completed without a verifiable server signature")
			}
			return nil
		}
		nextPayload = ""
	}
	return errors.New("upstream SCRAM did not converge")
}

func (u *upstream) close() error { return u.conn.Close() }

func errmsgOf(doc map[string]any) string {
	if s, ok := bsonStringValue(doc["errmsg"]); ok {
		return s
	}
	return "unknown error"
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset by peer")
}

// isTimeoutErr 报告错误是否来自读截止时间。转发环用它区分“到点该核对”与真正断开。
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
