// Package redisproxy 实现 Redis RESP 协议认证代理：客户端用 KeyKoi 会话令牌代替
// Redis 密码，代理经后台授权后以自己的身份向上游 Redis 完成 AUTH，之后转发命令。
//
// 支持范围（实测口径）：
//   - 协议：RESP2/RESP3 客户端命令与回复；AUTH <token> 与 AUTH <user> <token> 都在代理侧终结。
//     前端宣告的 RESP 版本以与上游实际协商的结果为准：只有上游接受 HELLO 3 时才回 RESP3。
//   - 客户端认证：令牌以 AUTH 的最后一个参数提交；认证成功后回 +OK，随后按消息原样转发。
//   - 上游认证：凭据有 username 字段时发 AUTH user password（Redis 6+ ACL），否则发 AUTH password
//     （requirepass）；上游未设密码时把 "no password is set" 视为无需认证。
//   - 上游传输：登记 origin 为 https:// 时对上游启用 TLS 并校验证书链与主机名（可叠加
//     UpstreamCA 追加私有 CA），AUTH 只在 TLS 握手与证书校验成功之后发送。http:// 明文上游
//     必须用 InsecureUpstream 显式声明，否则拒绝连接且不会发出任何 AUTH。
//   - 认证后的再次 AUTH / HELLO ... AUTH：代理把口令位替换为真实密码后转发，
//     客户端令牌不会到达上游。
//   - 透明转发：PING/SELECT/SET/GET/INFO 以及订阅、阻塞命令等都按 RESP 消息转发；
//     上游错误回复原样透传，连接关闭语义保持。
//   - 认证前的解析有硬上限（单行、bulk 长度、数组元素、嵌套深度、单条消息总量），
//     超限立即断开并记录，避免未认证连接按声明体积分配内存。
//
// 不支持项：
//   - 客户端侧 TLS（客户端与代理之间按回环明文连接）。
//   - Cluster 重定向（MOVED/ASK）由客户端自行处理，代理不做多节点路由。
//   - Redis 命令语义与 ACL 授权由上游负责，代理只做协议层转发。
package redisproxy

import (
	"bufio"
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

	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
	"keykoi/internal/secret"
)

// Broker 是代理访问后台运行面的最小接口。*ipcclient.Client 直接满足它。
//
// 目标与凭证来自同一次授权：Resolve 的返回同时带 Binding 快照与凭证字段，
// 代理不再列出 /v1/bindings；既有连接只用 Get 读单条元数据核对改绑。
type Broker interface {
	// Resolve 用会话令牌换取向上游认证所需的凭证字段与同一次授权的 Binding。
	Resolve(token, bindingID, mode string) (*ipcclient.Resolved, error)
	// Get 读取单条绑定元数据，供既有连接核对改绑；它不返回凭证，也不建立许可。
	Get(path string, out any) error
}

// Config 配置代理。
type Config struct {
	BindingID     string
	ListenAddr    string
	ListenSocket  string
	UsernameField string
	PasswordField string
	AuthTimeout   time.Duration
	DialTimeout   time.Duration
	// RevalidateInterval 是已认证连接核对绑定改绑的间隔：默认且最大 1 秒，
	// 转发环按时间戳节流，最多每秒查一次；测试可调小以加速。
	RevalidateInterval time.Duration
	MaxConnections     int
	// InsecureUpstream 显式允许明文（http://）上游。默认 false 时明文上游被拒绝，
	// 因为 AUTH 口令会在链路上明文传输。登记 origin 为 https:// 时始终走 TLS。
	InsecureUpstream bool
	// UpstreamCA 是追加的 PEM CA 文件；系统根证书始终参与校验。
	UpstreamCA string
	// Logger 记录不含秘密的连接事件；nil 表示静默。
	Logger *log.Logger
}

func (c *Config) normalize() error {
	if c.BindingID == "" {
		return errors.New("redisproxy: binding id is required")
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
	if c.AuthTimeout <= 0 {
		c.AuthTimeout = 15 * time.Second
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.RevalidateInterval <= 0 || c.RevalidateInterval > bindingCheckInterval {
		// 超过 1 秒的配置会削弱“改绑后最多 1 秒内被发现”的保证，统一收紧到上限。
		c.RevalidateInterval = bindingCheckInterval
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
		return nil, errors.New("redisproxy: broker client is required")
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
	host, _, err := net.SplitHostPort(s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("redisproxy: invalid listen address %q: %w", s.cfg.ListenAddr, err)
	}
	if host != "" && host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("redisproxy: listen address %q must be a loopback address", s.cfg.ListenAddr)
		}
	}
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("redisproxy: listen: %w", err)
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
			return fmt.Errorf("redisproxy: listen unix socket: %w", err)
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
		return errors.New("redisproxy: Listen must be called before Serve")
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
					s.handle(c)
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
// 空闲连接不会再让退出无限挂起：先关监听器，再关客户端连接（上游随之关闭）。
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
			s.logger.Printf("redis-proxy shutdown: %d connection(s) still active after the drain timeout", len(conns))
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
func (s *Server) handle(conn net.Conn) {
	s.total.Add(1)
	remote := conn.RemoteAddr().String()
	if s.active.Add(1) > int64(s.cfg.MaxConnections) {
		s.active.Add(-1)
		s.denied.Add(1)
		_, _ = conn.Write(errorString("ERR max number of clients reached"))
		_ = conn.Close()
		s.logger.Printf("redis-proxy connection from %s rejected: connection limit %d", remote, s.cfg.MaxConnections)
		return
	}
	defer func() {
		s.active.Add(-1)
		s.untrackConn(conn)
		_ = conn.Close()
	}()
	s.trackConn(conn)

	_ = conn.SetDeadline(time.Now().Add(s.cfg.AuthTimeout))
	reader := bufio.NewReaderSize(conn, 16<<10)

	token, helloProto, err := s.awaitAuth(conn, reader)
	if err != nil {
		s.denied.Add(1)
		_, _ = conn.Write(errorString("ERR " + err.Error()))
		s.logger.Printf("redis-proxy connection from %s rejected: %v", remote, err)
		return
	}

	target, err := s.resolveTarget(token)
	if err != nil {
		s.denied.Add(1)
		_, _ = conn.Write(errorString("NOAUTH " + err.Error()))
		s.logger.Printf("redis-proxy connection from %s denied: %v", remote, err)
		return
	}

	up, err := s.dialUpstream(target)
	if err != nil {
		s.denied.Add(1)
		_, _ = conn.Write(errorString("NOAUTH upstream authentication failed; details are in the keykoi redis-proxy log"))
		s.logger.Printf("redis-proxy connection from %s failed: %v (upstream %s)", remote, err, target)
		return
	}
	defer up.close()

	if err := up.authenticate(); err != nil {
		s.denied.Add(1)
		_, _ = conn.Write(errorString("NOAUTH upstream authentication failed; details are in the keykoi redis-proxy log"))
		s.logger.Printf("redis-proxy upstream authentication failed for %s: %v", target, err)
		return
	}

	if helloProto > 0 {
		// 只宣告真正协商到的版本：上游只支持 RESP2 时回 RESP2，避免依赖 RESP3 类型的
		// 客户端拿到错误语义。
		proto := up.respVersion(helloProto)
		if _, err := conn.Write(helloReply(proto)); err != nil {
			return
		}
	} else if _, err := conn.Write(simpleString("OK")); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	s.logger.Printf("redis-proxy connection from %s established (upstream %s)", remote, target)

	s.relay(conn, reader, up)
	s.logger.Printf("redis-proxy connection from %s closed", remote)
}

// awaitAuth 等待客户端把会话令牌作为 AUTH 的最后一个参数提交。
// 返回 helloProto>0 表示客户端用 HELLO <proto> AUTH ... 完成认证。
func (s *Server) awaitAuth(conn net.Conn, reader *bufio.Reader) (string, int, error) {
	for {
		raw, args, err := readCommandLimit(reader, authLimits)
		if err != nil {
			return "", 0, fmt.Errorf("read command: %w", err)
		}
		if len(args) == 0 {
			// 非命令值：协议上无意义，直接回错误并按原样丢弃。
			if _, err := conn.Write(errorString("ERR Protocol error: expected a command")); err != nil {
				return "", 0, err
			}
			_ = raw
			continue
		}
		switch strings.ToUpper(args[0]) {
		case "AUTH":
			if len(args) < 2 {
				if _, err := conn.Write(errorString("ERR wrong number of arguments for 'auth' command")); err != nil {
					return "", 0, err
				}
				continue
			}
			token := args[len(args)-1]
			if token == "" {
				return "", 0, errors.New("empty session token")
			}
			return token, 0, nil
		case "HELLO":
			proto := 2
			if len(args) > 1 {
				switch strings.TrimSpace(args[1]) {
				case "3":
					proto = 3
				case "2":
					proto = 2
				}
			}
			for i := 2; i < len(args); i++ {
				if strings.EqualFold(args[i], "AUTH") && i+2 < len(args) {
					return args[i+2], proto, nil
				}
			}
			if _, err := conn.Write(errorString("NOAUTH HELLO must be called with the client already authenticated, otherwise the HELLO <proto> AUTH <user> <pass> option can be used")); err != nil {
				return "", 0, err
			}
		case "QUIT":
			_, _ = conn.Write(simpleString("OK"))
			return "", 0, errors.New("client quit before authenticating")
		case "RESET":
			_, _ = conn.Write(simpleString("RESET"))
		default:
			if _, err := conn.Write(errorString("NOAUTH Authentication required.")); err != nil {
				return "", 0, err
			}
		}
	}
}

// helloReply 构造最小的 HELLO 回复（RESP2 数组或 RESP3 map），不向客户端暴露上游版本细节。
func helloReply(proto int) []byte {
	fields := []string{
		"server", "keykoi-redis",
		"version", "7.0.0",
		"proto", fmt.Sprintf("%d", proto),
		"id", "1",
		"mode", "standalone",
		"role", "master",
	}
	if proto == 3 {
		var b strings.Builder
		b.WriteString("%7\r\n")
		for i := 0; i < len(fields); i += 2 {
			b.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(fields[i]), fields[i]))
			b.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(fields[i+1]), fields[i+1]))
		}
		b.WriteString("$7\r\nmodules\r\n*0\r\n")
		return []byte(b.String())
	}
	var b strings.Builder
	b.WriteString("*14\r\n")
	for _, f := range fields {
		b.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(f), f))
	}
	b.WriteString("$7\r\nmodules\r\n*0\r\n")
	return []byte(b.String())
}

// registerUnauthorized 是 Redis 对未认证连接的回复；保留以便测试断言。
const unauthorizedReply = "-NOAUTH Authentication required.\r\n"

// resolveTarget 用一次授权换取目标与凭证：上游地址只从 resolved.Binding 取，
// 不再单独读取 /v1/bindings。改绑遇到在途请求时不会用旧目标配新密码。
//
// origin 的 scheme 决定上游传输：https 走 TLS（校验证书链与主机名），
// http 是明文，必须由 InsecureUpstream 显式允许。
func (s *Server) resolveTarget(token string) (UpstreamTarget, error) {
	resolved, err := s.broker.Resolve(token, s.cfg.BindingID, string(model.ModeRuntimeDelivery))
	if resolved != nil {
		defer s.releaseLease(resolved)
	}
	if err != nil {
		return UpstreamTarget{}, denialForResolveError(err)
	}
	binding, err := authorizedBinding(resolved, s.cfg.BindingID)
	if err != nil {
		return UpstreamTarget{}, err
	}
	origin, err := binding.Origin()
	if err != nil {
		return UpstreamTarget{}, errors.New("binding has an invalid upstream origin")
	}
	host := origin.Hostname()
	port := origin.Port()
	if port == "" {
		port = "6379"
	}
	if host == "" {
		return UpstreamTarget{}, errors.New("binding has no upstream host")
	}
	userField := firstNonEmpty(s.cfg.UsernameField, binding.UsernameField, "username")
	passField := firstNonEmpty(s.cfg.PasswordField, binding.PasswordField, "password")
	user := resolved.Fields[userField]
	password := resolved.Fields[passField]
	if password == "" {
		return UpstreamTarget{}, fmt.Errorf("credential is missing field %q for the redis adapter", passField)
	}
	return UpstreamTarget{
		Host:           host,
		User:           user,
		Password:       secret.New(password),
		Addr:           net.JoinHostPort(host, port),
		TLS:            strings.EqualFold(origin.Scheme, "https"),
		Revision:       binding.Revision,
		UpstreamOrigin: binding.UpstreamOrigin,
	}, nil
}

// authorizedBinding 取出这次授权校验过的 Binding 快照；缺失或指向别的绑定都拒绝，
// 绝不回落到另一次读取。
func authorizedBinding(resolved *ipcclient.Resolved, bindingID string) (*model.Binding, error) {
	if resolved == nil || resolved.Binding == nil {
		return nil, errors.New("authorization returned no binding snapshot")
	}
	binding := resolved.Binding
	if binding.ID != "" && binding.ID != bindingID {
		return nil, errors.New("authorization returned a binding snapshot for another binding")
	}
	if binding.Status != "" && binding.Status != model.StatusActive {
		return nil, errors.New("binding is " + string(binding.Status))
	}
	return binding, nil
}

// dialUpstream 建立到上游 Redis 的连接。
//
// 目标声明 https 时先完成 TLS 握手并校验证书，握手成功之后才返回可用的连接；
// 调用方随之发送 AUTH，所以口令永远不会在未加密链路上出去。http 目标只有
// 在 InsecureUpstream 显式声明时才被接受。
func (s *Server) dialUpstream(target UpstreamTarget) (*upstream, error) {
	d := &net.Dialer{Timeout: s.cfg.DialTimeout, KeepAlive: 30 * time.Second}
	conn, err := d.Dial("tcp", target.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target.Addr, err)
	}
	encrypted := false
	switch {
	case target.TLS:
		cfg, err := s.upstreamTLSConfig(target.Host)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		tlsConn := tls.Client(conn, cfg)
		_ = tlsConn.SetDeadline(time.Now().Add(s.cfg.DialTimeout))
		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("upstream TLS handshake with %s: %w", target.Addr, err)
		}
		conn = tlsConn
		encrypted = true
	case !s.cfg.InsecureUpstream:
		_ = conn.Close()
		return nil, fmt.Errorf("upstream %s is plaintext: register the binding origin as https:// for TLS, or declare insecure_upstream to allow a cleartext AUTH", target.Addr)
	}
	_ = conn.SetDeadline(time.Now().Add(s.cfg.AuthTimeout))
	return &upstream{
		conn:      conn,
		reader:    bufio.NewReaderSize(conn, 16<<10),
		target:    target,
		encrypted: encrypted,
	}, nil
}

// upstreamTLSConfig 构造校验上游证书的 TLS 配置：系统根证书 + 可选的追加 CA。
func (s *Server) upstreamTLSConfig(host string) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if s.cfg.UpstreamCA != "" {
		pemBytes, err := os.ReadFile(s.cfg.UpstreamCA)
		if err != nil {
			return nil, fmt.Errorf("read upstream CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("upstream CA file contains no usable certificate")
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		RootCAs:    pool,
	}, nil
}

// releaseLease 立即释放一次 Resolve 创建的许可；凭证与目标仍只使用同次返回的快照。
func (s *Server) releaseLease(resolved *ipcclient.Resolved) {
	if resolved == nil || resolved.Lease.ID == "" {
		return
	}
	revoker, ok := s.broker.(interface{ RevokeLease(string) error })
	if !ok {
		return
	}
	if err := revoker.RevokeLease(resolved.Lease.ID); err != nil {
		s.logger.Printf("redis-proxy revoke lease: %v", err)
	}
}

// relay 认证完成后双向转发。客户端方向按 RESP 消息重写 AUTH 口令，避免令牌流到上游；
// 同时在同一循环里做有界的改绑核对（最多每秒一次，不另起后台 goroutine）。
func (s *Server) relay(conn net.Conn, clientReader *bufio.Reader, up *upstream) {
	watch := s.newBindingWatch(up.target)

	done := make(chan struct{}, 2)
	go func() {
		_, err := io.Copy(conn, up.reader)
		if err != nil && !isClosedErr(err) {
			s.logger.Printf("redis-proxy upstream->client copy: %v", err)
		}
		_ = conn.Close()
		done <- struct{}{}
	}()
	go func() {
		s.copyClientToUpstream(conn, clientReader, up, watch)
		_ = up.conn.Close()
		done <- struct{}{}
	}()
	<-done
	_ = up.conn.Close()
	_ = conn.Close()
	<-done
}

// copyClientToUpstream 把客户端命令转发给上游，并在同一循环里做改绑核对。
//
// 空闲时用读截止时间按 RevalidateInterval 唤醒核对；Peek 不消费字节，
// 超时不会破坏 RESP 解析状态。一旦确认有数据，命令按完整消息读完再继续，
// 不会因为核对间隔把一条 RESP 消息截断。
func (s *Server) copyClientToUpstream(conn net.Conn, clientReader *bufio.Reader, up *upstream, watch *bindingWatch) {
	for {
		if watch.due(time.Now()) && watch.changed() {
			// 协议层先回错误再断开：沿用现有 -ERR 路径，客户端能看到明确原因。
			_, _ = conn.Write(errorString("ERR binding authorization changed; reconnect"))
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(watch.interval)); err != nil {
			return
		}
		if _, err := clientReader.Peek(1); err != nil {
			if isTimeoutErr(err) {
				continue
			}
			if !isClosedErr(err) {
				s.logger.Printf("redis-proxy client->upstream read: %v", err)
			}
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		raw, args, err := readCommandLimit(clientReader, relayLimits)
		if err != nil {
			if !isClosedErr(err) {
				s.logger.Printf("redis-proxy client->upstream read: %v", err)
			}
			return
		}
		if len(args) > 0 {
			raw = rewriteAuth(raw, args, up.target)
		}
		if _, err := up.conn.Write(raw); err != nil {
			if !isClosedErr(err) {
				s.logger.Printf("redis-proxy client->upstream write: %v", err)
			}
			return
		}
	}
}

// upstream 是代理到 Redis 服务器的一条连接。
type upstream struct {
	conn      net.Conn
	reader    *bufio.Reader
	target    UpstreamTarget
	encrypted bool
}

// respVersion 与上游协商 RESP 版本，返回可以向前端宣告的版本。
//
// 只有上游真的接受 HELLO <proto>（回 RESP3 map）时才宣告同一版本；上游是 RESP2
// 或拒绝 HELLO 时回落到 2，前端不会被承诺一个上游并不支持的协议。
func (u *upstream) respVersion(want int) int {
	if want != 3 {
		return 2
	}
	deadline := time.Now().Add(5 * time.Second)
	if err := u.conn.SetDeadline(deadline); err != nil {
		return 2
	}
	defer func() { _ = u.conn.SetDeadline(time.Time{}) }()
	if _, err := u.conn.Write(encodeCommand([]string{"HELLO", "3"})); err != nil {
		return 2
	}
	reply, err := readReply(u.reader)
	if err != nil || len(reply) == 0 || reply[0] != '%' {
		return 2
	}
	return 3
}

// authenticate 用真实密码向上游认证。上游未设密码时视为成功。
func (u *upstream) authenticate() error {
	password := u.target.Password.RevealString()
	var cmd []string
	if u.target.User != "" {
		cmd = []string{"AUTH", u.target.User, password}
	} else {
		cmd = []string{"AUTH", password}
	}
	if _, err := u.conn.Write(encodeCommand(cmd)); err != nil {
		return fmt.Errorf("send upstream AUTH: %w", err)
	}
	reply, err := readReply(u.reader)
	if err != nil {
		return fmt.Errorf("read upstream AUTH reply: %w", err)
	}
	if len(reply) == 0 {
		return errors.New("empty upstream AUTH reply")
	}
	switch reply[0] {
	case '+':
		_ = u.conn.SetDeadline(time.Time{})
		return nil
	case '-':
		msg := strings.ToLower(string(reply[1:]))
		if strings.Contains(msg, "no password is set") || strings.Contains(msg, "without any password configured") {
			// 上游未启用认证：代理仍以自己的身份连接，无需 AUTH。
			_ = u.conn.SetDeadline(time.Time{})
			return nil
		}
		return errors.New("upstream rejected the registered credential")
	}
	return fmt.Errorf("unexpected upstream AUTH reply %q", reply[0])
}

func (u *upstream) close() error { return u.conn.Close() }

// UpstreamTarget 是经授权解析出的上游连接参数。
type UpstreamTarget struct {
	Host     string
	User     string
	Password secret.Value
	Addr     string
	// TLS 表示登记 origin 声明了 https，上游必须先完成受验证的 TLS 握手。
	TLS bool
	// Revision 是同一次授权返回的 Binding revision，供在途连接检测改绑。
	Revision int64
	// UpstreamOrigin 是同一次授权返回的绑定 origin，用于发现改绑到别的目标。
	UpstreamOrigin string
}

// String 只输出非秘密字段。
func (t UpstreamTarget) String() string {
	return fmt.Sprintf("addr=%s user=%s", t.Addr, firstNonEmpty(t.User, "default"))
}

// rewriteAuth 把客户端再次发送的 AUTH / HELLO ... AUTH 口令替换为真实密码。
func rewriteAuth(raw []byte, args []string, target UpstreamTarget) []byte {
	password := target.Password.RevealString()
	if password == "" {
		return raw
	}
	switch strings.ToUpper(args[0]) {
	case "AUTH":
		if len(args) == 2 {
			return encodeCommand([]string{"AUTH", password})
		}
		if len(args) >= 3 {
			return encodeCommand([]string{"AUTH", args[1], password})
		}
	case "HELLO":
		out := append([]string(nil), args...)
		for i := 2; i+2 < len(out); i++ {
			if strings.EqualFold(out[i], "AUTH") {
				out[i+2] = password
				return encodeCommand(out)
			}
		}
	}
	return raw
}

// denialForResolveError 把后台稳定错误码映射为客户端可见的认证失败。
// 授权不足或令牌无效统一表现为 NOAUTH，避免泄漏授权细节。
func denialForResolveError(err error) error {
	var apiErr *ipcclient.APIError
	if errors.As(err, &apiErr) {
		switch model.Code(apiErr.Code) {
		case model.CodeSessionInvalid, model.CodeUseNotAllowed, model.CodeLeaseExpired:
			return errors.New("session token is not authorized to use this binding")
		case model.CodeBindingDisabled:
			return errors.New("binding is not available")
		case model.CodeVaultLocked:
			return errors.New("keykoi vault is locked")
		case model.CodeCredentialUnavailable:
			return errors.New("credential is unavailable")
		}
	}
	// 任何后台错误都不向客户端回显原文，避免带出内部细节。
	return errors.New("keykoid resolve failed")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
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

// isTimeoutErr 报告错误是否来自读截止时间。转发环用它区分“到点该核对”与真正断开。
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
