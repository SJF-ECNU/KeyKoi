// Package dbproxy 实现 PostgreSQL 协议代理：客户端用 KeyKoi 会话令牌认证，
// 代理经后台授权后以自己的身份向登记上游数据库完成认证，客户端不需要真实数据库密码。
//
// 支持范围（首版，实测口径）：
//   - 协议：PostgreSQL 3.0 前端/后端协议，认证阶段由代理终结，认证完成后按字节双向转发。
//   - 客户端认证：启动包 + AuthenticationCleartextPassword + PasswordMessage。
//     客户端口令位填 KeyKoi 会话令牌，用户名固定（默认 keykoi）。
//   - 上游认证：SCRAM-SHA-256（PostgreSQL 默认）、MD5、cleartext。
//   - 上游 TLS：sslmode=disable|prefer|require；require/prefer 都强制校验证书链与主机名，
//     可叠加 --upstream-ca 追加私有 CA。客户端侧 TLS 不提供（回 'N'）。
//   - 生命周期：取消请求（CancelRequest）转发到上游、连接关闭、错误语义（SQLSTATE）。
//   - 目标选择：上游地址取自同一次授权返回的 Binding 快照的 origin host:port，
//     数据库名取自同一批凭证的 database 字段；仅当凭证没有该字段时，才回落到
//     客户端启动包里的 dbname。代理不另行读取绑定列表，改绑不会把新凭证发到旧目标。
//
// 不支持项（显式声明，见 errors/日志与包文档）：
//   - 客户端侧 TLS / GSSAPI 加密：对 SSLRequest、GSSENCRequest 回 'N'。
//   - SCRAM-SHA-256-PLUS 通道绑定：上游只提供 -PLUS 时报错，不降级。
//   - SQL 语义、语句解析、表级/行级授权与只读强制：代理不做 SQL 解析，业务权限由上游数据库负责。
//   - 连接池复用与多路复用：一个客户端连接对应一条独立上游连接，不复用他人会话；
//     超过 --max-connections 时以 SQLSTATE 53300 拒绝。
//   - 复制协议、逻辑解码等长生命周期流：协议转发可行但未纳入验收，按不支持声明。
package dbproxy

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
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

	"github.com/jackc/pgx/v5/pgproto3"

	"keykoi/internal/model"
	"keykoi/internal/osruntime"
	"keykoi/internal/proxylease"
	"keykoi/internal/secret"
)

// SQLSTATE 常量。代理用它们表达拒绝原因，客户端驱动按标准错误处理。
const (
	codeInvalidPassword     = "28P01"
	codeInvalidAuthSpec     = "28000"
	codeCannotConnectNow    = "57P03"
	codeConnectionFailure   = "08006"
	codeProtocolViolation   = "08P01"
	codeTooManyConnections  = "53300"
	codeFeatureNotSupported = "0A000"
	codeAdminShutdown       = "57P01"
)

// Broker is the local authority used by the daemon-owned adapter.
type Broker = proxylease.Authority

// Config 配置代理。
type Config struct {
	// BindingID 是本代理代客户端使用的登记 Binding。
	BindingID string
	// ClientUser 是客户端必须使用的用户名。
	ClientUser string
	// ListenAddr 是客户端监听地址，必须是回环地址。
	ListenAddr string
	// ListenSocket 是可选的 Unix socket 监听路径（额外监听，便于测试驱动）。
	ListenSocket string
	// UpstreamTLS 是上游 TLS 策略。
	UpstreamTLS TLSMode
	// UpstreamCA 是可选的 PEM CA 文件；系统根证书始终参与校验。
	UpstreamCA string
	// DatabaseField 是凭证中数据库名字段名。
	DatabaseField string
	// UsernameField / PasswordField 覆盖 Binding 上的字段名缺省值。
	UsernameField string
	PasswordField string
	// AuthTimeout 限制客户端认证与解析耗时。
	AuthTimeout time.Duration
	// DialTimeout 限制上游连接与 TLS 握手耗时。
	DialTimeout time.Duration
	// RevalidateInterval 是已认证连接核对绑定改绑的间隔：默认且最大 1 秒，
	// 转发环按时间戳节流，最多每秒查一次；测试可调小以加速。
	RevalidateInterval time.Duration
	// MaxConnections 限制并发客户端连接数。
	MaxConnections int
	// Logger 记录不含秘密的连接事件；nil 表示静默。
	Logger *log.Logger
}

func (c *Config) normalize() error {
	if c.BindingID == "" {
		return errors.New("dbproxy: binding id is required")
	}
	if c.ClientUser == "" {
		c.ClientUser = "keykoi"
	}
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:0"
	}
	if c.DatabaseField == "" {
		c.DatabaseField = "database"
	}
	if c.UpstreamTLS == "" {
		c.UpstreamTLS = TLSRequire
	}
	if c.AuthTimeout <= 0 {
		c.AuthTimeout = 15 * time.Second
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

	mu    sync.Mutex
	lns   []net.Listener
	addrs []string
	stop  chan struct{}

	active atomic.Int64
	total  atomic.Int64
	denied atomic.Int64

	upstreamAddr atomic.Pointer[string]

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
		return nil, errors.New("dbproxy: broker client is required")
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{
		broker: b,
		cfg:    cfg,
		logger: logger,
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
		return fmt.Errorf("dbproxy: listen: %w", err)
	}
	s.mu.Lock()
	s.lns = append(s.lns, ln)
	s.addrs = append(s.addrs, ln.Addr().String())
	s.mu.Unlock()

	if s.cfg.ListenSocket != "" {
		_ = os.Remove(s.cfg.ListenSocket)
		sln, err := net.Listen("unix", s.cfg.ListenSocket)
		if err != nil {
			ln.Close()
			return fmt.Errorf("dbproxy: listen unix socket: %w", err)
		}
		_ = os.Chmod(s.cfg.ListenSocket, 0o600)
		s.mu.Lock()
		s.lns = append(s.lns, sln)
		s.addrs = append(s.addrs, "unix:"+s.cfg.ListenSocket)
		s.mu.Unlock()
	}
	return nil
}

// Addrs 返回全部监听地址。TCP 在前，unix socket 以 "unix:" 前缀标识。
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
		return errors.New("dbproxy: Listen must be called before Serve")
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
// 空闲连接不会再让退出无限挂起：先关监听器，再关客户端连接（relay 随之关闭上游）。
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

	// 取消活跃连接：关闭客户端 socket，relay 的两个方向都会随之结束。
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
			s.logger.Printf("db-proxy shutdown: %d connection(s) still active after the drain timeout", len(conns))
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

// WarmUp 用给定会话令牌做一次解析，缓存上游地址供取消请求转发使用。
// 解析失败不阻止代理启动：每个客户端连接仍会独立授权。
func (s *Server) WarmUp(ctx context.Context, token string) error {
	target, err := s.resolveTarget(ctx, token, s.cfg.ClientUser)
	if err != nil {
		return err
	}
	defer target.use.Finish()
	s.cacheUpstreamAddr(target.Addr)
	return nil
}

func (s *Server) cacheUpstreamAddr(addr string) {
	if addr == "" {
		return
	}
	s.upstreamAddr.Store(&addr)
}

func (s *Server) cachedUpstreamAddr() (string, bool) {
	p := s.upstreamAddr.Load()
	if p == nil {
		return "", false
	}
	return *p, true
}

// handle 处理一条客户端连接。
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	s.total.Add(1)
	remote := conn.RemoteAddr().String()
	if s.active.Add(1) > int64(s.cfg.MaxConnections) {
		s.active.Add(-1)
		s.denied.Add(1)
		writeErrorFrame(conn, codeTooManyConnections, "dbproxy: connection limit reached")
		_ = conn.Close()
		s.logger.Printf("db-proxy connection from %s rejected: connection limit %d", remote, s.cfg.MaxConnections)
		return
	}
	defer func() {
		s.active.Add(-1)
		s.untrackConn(conn)
		_ = conn.Close()
	}()
	s.trackConn(conn)

	// 认证阶段的硬超时；认证完成后取消超时，允许长事务与长查询。
	_ = conn.SetDeadline(time.Now().Add(s.cfg.AuthTimeout))
	reader := bufio.NewReaderSize(conn, 16<<10)

	startup, err := s.readClientStartup(conn, reader)
	if err != nil {
		s.denied.Add(1)
		var d *proxyDenial
		if errors.As(err, &d) {
			writeErrorFrame(conn, d.code, d.message)
		}
		s.logger.Printf("db-proxy connection from %s rejected: %v", remote, err)
		return
	}
	if startup.cancel != nil {
		s.forwardCancel(startup.cancel)
		return
	}

	token, err := s.requestToken(conn, reader)
	if err != nil {
		s.denied.Add(1)
		s.logger.Printf("db-proxy connection from %s rejected: %v", remote, err)
		return
	}

	target, err := s.resolveTarget(ctx, token, startup.database)
	if err != nil {
		s.denied.Add(1)
		writeErrorFrame(conn, errorCodeOf(err), err.Error())
		s.logger.Printf("db-proxy connection from %s denied: %v", remote, err)
		return
	}
	defer target.use.Finish()
	defer target.use.Track(conn)()
	s.cacheUpstreamAddr(target.Addr)

	up, err := dialUpstream(target.use.Context(), target, s.cfg.UpstreamTLS, s.cfg.UpstreamCA, s.cfg.DialTimeout)
	if err != nil {
		s.denied.Add(1)
		writeErrorFrame(conn, codeConnectionFailure, "dbproxy: upstream connection failed (TLS or network); details are in the keykoi db-proxy log")
		s.logger.Printf("db-proxy connection from %s failed: %v (upstream %s)", remote, err, target)
		return
	}
	defer up.close()
	defer target.use.Track(up.conn)()

	// 上游认证有独立截止时间：上游接受连接但不回包时，读取不会无限挂起。
	upCtx, cancelUp := context.WithTimeout(target.use.Context(), s.cfg.AuthTimeout)
	upDeadline, _ := upCtx.Deadline()
	_ = up.conn.SetDeadline(upDeadline)
	passthrough, err := up.startup(upCtx)
	cancelUp()
	_ = up.conn.SetDeadline(time.Time{})
	if err != nil {
		s.denied.Add(1)
		code := codeConnectionFailure
		message := "dbproxy: upstream authentication failed"
		var ue *upstreamError
		if errors.As(err, &ue) && !ue.AuthFailed {
			message = "dbproxy: upstream handshake failed; details are in the keykoi db-proxy log"
		}
		writeErrorFrame(conn, code, message)
		s.logger.Printf("db-proxy upstream authentication failed for %s: %v", target, err)
		return
	}

	// 客户端侧认证在这里终结：客户端只看到 AuthenticationOk 与其后的后端消息。
	ok, err := (&pgproto3.AuthenticationOk{}).Encode(nil)
	if err != nil {
		return
	}
	if _, err := conn.Write(ok); err != nil {
		return
	}
	for _, frame := range passthrough {
		if _, err := conn.Write(frame); err != nil {
			return
		}
	}
	_ = conn.SetDeadline(time.Time{})
	s.logger.Printf("db-proxy connection from %s established (upstream %s tls=%t)", remote, target, up.encrypted)

	s.relay(conn, reader, up)
	s.logger.Printf("db-proxy connection from %s closed", remote)
}

// startupInfo 是客户端启动包解析结果。
type startupInfo struct {
	database string
	user     string
	// cancel 非 nil 表示这是一个取消请求连接。
	cancel []byte
}

// readClientStartup 处理 SSLRequest/GSSENCRequest、CancelRequest 与 StartupMessage。
func (s *Server) readClientStartup(conn net.Conn, reader *bufio.Reader) (*startupInfo, error) {
	for attempt := 0; attempt < 4; attempt++ {
		code, body, err := readStartupPacket(reader)
		if err != nil {
			return nil, fmt.Errorf("read startup packet: %w", err)
		}
		switch code {
		case codeSSLRequest, codeGSSENCRequest:
			// 客户端侧 TLS/GSS 加密不在支持范围：明确回绝后继续明文握手。
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, err
			}
			continue
		case codeCancelRequest:
			if len(body) < 8 {
				return nil, errors.New("truncated cancel request")
			}
			packet := make([]byte, 0, 16)
			packet = append(packet, 0, 0, 0, 16)
			packet = binary.BigEndian.AppendUint32(packet, codeCancelRequest)
			packet = append(packet, body[:8]...)
			return &startupInfo{cancel: packet}, nil
		case 196608, 196610: // 3.0 / 3.2
			params, err := parseStartupParameters(body)
			if err != nil {
				return nil, err
			}
			user := params["user"]
			if user != s.cfg.ClientUser {
				return nil, &proxyDenial{
					code:    codeInvalidAuthSpec,
					message: fmt.Sprintf("role %q is not supported by this proxy; use %q with a KeyKoi session token as password", user, s.cfg.ClientUser),
				}
			}
			db := params["database"]
			if db == "" {
				db = user
			}
			return &startupInfo{user: user, database: db}, nil
		default:
			return nil, &proxyDenial{code: codeProtocolViolation, message: fmt.Sprintf("unsupported startup packet version/code %d", code)}
		}
	}
	return nil, errors.New("client did not complete the startup handshake")
}

// requestToken 用 cleartext password 请求取得客户端提交的会话令牌。
func (s *Server) requestToken(conn net.Conn, reader *bufio.Reader) (string, error) {
	frame, err := (&pgproto3.AuthenticationCleartextPassword{}).Encode(nil)
	if err != nil {
		return "", err
	}
	if _, err := conn.Write(frame); err != nil {
		return "", err
	}
	typ, body, err := readTypedMessage(reader)
	if err != nil {
		return "", fmt.Errorf("read password message: %w", err)
	}
	if typ != 'p' {
		return "", fmt.Errorf("expected password message, got message type %q", typ)
	}
	token := strings.TrimSuffix(string(body), "\x00")
	if token == "" {
		return "", errors.New("empty session token")
	}
	return token, nil
}

// resolveTarget 用一次授权换取目标与凭证：Binding 快照只从 resolved.Binding 取，
// 不再单独读取 /v1/bindings。这样改绑（origin 变更）时不会把新凭证发到旧目标。
// 授权先于取值：没有覆盖 proxy 的许可时不会读到凭证。
func (s *Server) resolveTarget(ctx context.Context, token, clientDatabase string) (UpstreamTarget, error) {
	sessionToken := secret.New(token)
	resolved, err := proxylease.Authorize(ctx, s.broker, sessionToken, s.cfg.BindingID, s.cfg.AuthTimeout)
	if err != nil {
		return UpstreamTarget{}, denialForResolveError(err)
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
		return UpstreamTarget{}, &proxyDenial{code: codeCannotConnectNow, message: err.Error()}
	}
	target, err := binding.DatabaseTarget(model.ProtocolPostgres, "5432")
	if err != nil {
		return UpstreamTarget{}, &proxyDenial{code: codeConnectionFailure, message: err.Error()}
	}

	userField := cmp.Or(s.cfg.UsernameField, binding.UsernameField, "username")
	passField := cmp.Or(s.cfg.PasswordField, binding.PasswordField, "password")
	user := resolved.Version.Fields[userField].RevealString()
	password := resolved.Version.Fields[passField]
	if user == "" || password.IsEmpty() {
		return UpstreamTarget{}, &proxyDenial{
			code:    codeCannotConnectNow,
			message: fmt.Sprintf("credential is missing fields %q/%q for the database adapter", userField, passField),
		}
	}
	database := resolved.Version.Fields[s.cfg.DatabaseField].RevealString()
	if database == "" {
		database = clientDatabase
	}
	if database == "" {
		database = user
	}
	accepted = true
	return UpstreamTarget{
		Host:     target.Host,
		Port:     target.Port,
		User:     user,
		Password: password,
		Database: database,
		Addr:     target.Address(),
		use:      use,
	}, nil
}

// forwardCancel 把取消请求转到上游。取消包只含上游的后端 PID 与密钥，
// 因此只需连到同一上游地址重发即可；数据库名与授权都不参与。
func (s *Server) forwardCancel(packet []byte) {
	addr, ok := s.cachedUpstreamAddr()
	if !ok {
		s.logger.Printf("db-proxy cancel request dropped: upstream address is not known yet")
		return
	}
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		s.logger.Printf("db-proxy cancel request forward failed: %v", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(packet); err != nil {
		s.logger.Printf("db-proxy cancel request write failed: %v", err)
		return
	}
	s.logger.Printf("db-proxy cancel request forwarded to %s", addr)
}

// relay 在认证完成后按字节双向转发。代理不解析 SQL，权限由上游数据库负责。
//
// 客户端→上游方向同时承担改绑核对：每一轮转发前后按时间戳判断是否到点，
// 到点用 Get 读一次绑定详情（最多每秒一次），不另起后台 goroutine。
func (s *Server) relay(conn net.Conn, clientReader *bufio.Reader, up *upstream) {
	watch := up.target.use

	done := make(chan struct{}, 2)
	go func() {
		s.copyClientToUpstream(conn, clientReader, up, watch)
		done <- struct{}{}
	}()
	go func() {
		_, err := io.Copy(conn, up.reader)
		if err != nil && !isClosedErr(err) {
			s.logger.Printf("db-proxy upstream->client copy: %v", err)
		}
		if tc, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	_ = up.conn.Close()
	_ = conn.Close()
	<-done
}

// copyClientToUpstream 把客户端字节转给上游，并在同一循环里做有界的改绑核对。
//
// 读截止时间只用来按时唤醒核对：空闲连接按 RevalidateInterval 超时一次，
// 有数据时立即继续转发，字节流语义不变。
func (s *Server) copyClientToUpstream(conn net.Conn, clientReader *bufio.Reader, up *upstream, watch *proxylease.Use) {
	buf := make([]byte, 32<<10)
	for {
		if watch.Changed() {
			// 协议层先回错误再断开：客户端能看到明确原因，不必等 socket 重置。
			writeErrorFrame(conn, codeAdminShutdown, "dbproxy: binding authorization changed; reconnect")
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(watch.Interval)); err != nil {
			return
		}
		n, err := clientReader.Read(buf)
		if n > 0 {
			if _, werr := up.conn.Write(buf[:n]); werr != nil {
				if !isClosedErr(werr) {
					s.logger.Printf("db-proxy client->upstream copy: %v", werr)
				}
				return
			}
		}
		if err != nil {
			if isTimeoutErr(err) {
				continue
			}
			if !isClosedErr(err) {
				s.logger.Printf("db-proxy client->upstream copy: %v", err)
			}
			// 客户端发 Terminate 或直接断开：只关上游写侧，让另一方向送完剩余响应。
			if tc, ok := up.conn.(interface{ CloseWrite() error }); ok {
				_ = tc.CloseWrite()
			} else {
				_ = up.conn.Close()
			}
			return
		}
	}
}

// proxyDenial 是代理主动拒绝，带 SQLSTATE。
type proxyDenial struct {
	code    string
	message string
}

func (e *proxyDenial) Error() string { return e.message }

func errorCodeOf(err error) string {
	var d *proxyDenial
	if errors.As(err, &d) {
		return d.code
	}
	return codeConnectionFailure
}

// writeErrorFrame 向客户端发送 FATAL 错误并结束。
func writeErrorFrame(w io.Writer, code, message string) {
	msg := &pgproto3.ErrorResponse{
		Severity:            "FATAL",
		SeverityUnlocalized: "FATAL",
		Code:                code,
		Message:             message,
	}
	frame, err := msg.Encode(nil)
	if err != nil {
		return
	}
	_, _ = w.Write(frame)
}

// 启动包代码。
const (
	codeSSLRequest    = 80877103
	codeGSSENCRequest = 80877104
	codeCancelRequest = 80877102
)

// readStartupPacket 读取启动包，返回版本/代码与包体（不含长度前缀与代码）。
func readStartupPacket(r *bufio.Reader) (uint32, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(int32(binary.BigEndian.Uint32(hdr[:])))
	if n < 8 || n > 10_000 {
		return 0, nil, fmt.Errorf("invalid startup packet length %d", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	code := binary.BigEndian.Uint32(body[:4])
	return code, body[4:], nil
}

// readTypedMessage 读取认证阶段的一条前端消息。
func readTypedMessage(r *bufio.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(int32(binary.BigEndian.Uint32(hdr[1:])))
	if n < 4 || n > 1<<20 {
		return 0, nil, fmt.Errorf("invalid message length %d", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return hdr[0], body, nil
}

// parseStartupParameters 解析启动包参数（NUL 分隔的 key/value）。
func parseStartupParameters(body []byte) (map[string]string, error) {
	params := map[string]string{}
	parts := strings.Split(string(body), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] == "" {
			continue
		}
		params[parts[i]] = parts[i+1]
	}
	return params, nil
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") || strings.Contains(s, "broken pipe")
}

// isTimeoutErr 报告错误是否来自读/写截止时间。转发环用它区分“到点该核对”与真正断开。
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// denialForResolveError 把后台稳定错误码映射为客户端可见的 PostgreSQL SQLSTATE。
// 授权不足或令牌无效统一表现为认证失败，避免向客户端泄漏授权细节。
func denialForResolveError(err error) error {
	switch proxylease.ErrorCode(err) {
	case model.CodeSessionInvalid, model.CodeUseNotAllowed, model.CodeLeaseExpired:
		return &proxyDenial{code: codeInvalidPassword, message: "session token is not authorized to use this binding"}
	case model.CodeBindingDisabled:
		return &proxyDenial{code: codeCannotConnectNow, message: "binding is not available"}
	case model.CodeVaultLocked:
		return &proxyDenial{code: codeCannotConnectNow, message: "keykoi vault is locked"}
	case model.CodeCredentialUnavailable:
		return &proxyDenial{code: codeCannotConnectNow, message: "credential is unavailable"}
	}
	return &proxyDenial{code: codeCannotConnectNow, message: "keykoid authorization failed"}
}
