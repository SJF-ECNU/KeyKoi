// Package mysqlproxy 实现 MySQL 协议认证代理：客户端用任意用户名 + KeyKoi 会话令牌
// 作为密码连接，代理终结客户端认证，再以登记凭据向上游 MySQL 完成认证并转发命令。
//
// 支持范围（实测口径）：
//   - 客户端认证：Greeting 使用 caching_sha2_password；代理随后要求完整认证
//     （AuthMoreData 0x04）。客户端在 TLS 上直接提交明文口令（即会话令牌），
//     在明文连接上按 MySQL 约定索取代理 RSA 公钥并加密提交，代理用私钥解出令牌。
//   - 客户端侧 TLS：默认提供一张运行时生成的自签证书，客户端 ssl-mode=PREFERRED
//     即可协商；证书链与主机名由客户端策略决定，代理不做客户端证书校验。
//   - 上游认证：mysql_native_password 与 caching_sha2_password（含快路径与完整认证），
//     并用 AuthSwitchRequest 跟随服务端要求的插件。
//   - 上游传输：上游宣告 CLIENT_SSL 时先发 SSLRequest，再用 tls.Client 完成受验证的
//     TLS 握手（系统根证书 + 可选的追加 CA），完整认证的明文口令只在 TLS 上发送。
//     上游不宣告 TLS 时默认拒绝连接；显式声明 insecure_upstream 才继续明文，且明文链路上
//     的完整认证直接失败并报错，不再使用服务端临时下发、未经验证的 RSA 公钥。
//   - 认证后：按字节双向转发命令与结果集、错误包与 EOF/OK 语义；closing/QUIT 原样转发。
//
// 不支持项：
//   - 客户端证书认证、COM_CHANGE_USER 的重新认证（该命令会原样转发并被上游拒绝）。
//   - 多语句语义、结果集改写与连接池复用；业务权限由上游 MySQL 负责。
package mysqlproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
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
	DatabaseField string
	AuthTimeout   time.Duration
	DialTimeout   time.Duration
	// RevalidateInterval 是已认证连接核对绑定改绑的间隔：默认且最大 1 秒，
	// 转发环按时间戳节流，最多每秒查一次；测试可调小以加速。
	RevalidateInterval time.Duration
	MaxConnections     int
	// InsecureUpstream 显式允许明文上游。默认 false：上游不宣告 TLS 就拒绝连接；
	// 明文链路上的 caching_sha2_password 完整认证始终失败。
	InsecureUpstream bool
	// UpstreamCA 是追加的 PEM CA 文件；系统根证书始终参与校验。
	UpstreamCA string
	// UpstreamTLSMode 是上游 TLS 校验强度，默认 verify-full。
	UpstreamTLSMode UpstreamTLSMode
	// DisableClientTLS 关闭客户端侧 TLS 能力位；客户端随后只能用明文握手。
	DisableClientTLS bool
	// TLSConfig 覆盖默认的运行时自签证书配置。
	TLSConfig *tls.Config
	// Logger 记录不含秘密的连接事件；nil 表示静默。
	Logger *log.Logger
}

func (c *Config) normalize() error {
	if c.BindingID == "" {
		return errors.New("mysqlproxy: binding id is required")
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

	priv   *rsa.PrivateKey
	pubPEM []byte

	tlsOnce sync.Once
	tlsCfg  *tls.Config
	tlsErr  error

	connSeq atomic.Uint32

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
		return nil, errors.New("mysqlproxy: broker client is required")
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("mysqlproxy: generate client auth key: %w", err)
	}
	pubPEM, err := encodeRSAPublicKey(&key.PublicKey)
	if err != nil {
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
		priv:   key,
		pubPEM: pubPEM,
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
		return fmt.Errorf("mysqlproxy: invalid listen address %q: %w", s.cfg.ListenAddr, err)
	}
	if host != "" && host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("mysqlproxy: listen address %q must be a loopback address", s.cfg.ListenAddr)
		}
	}
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("mysqlproxy: listen: %w", err)
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
			return fmt.Errorf("mysqlproxy: listen unix socket: %w", err)
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
		return errors.New("mysqlproxy: Listen must be called before Serve")
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
			s.logger.Printf("mysql-proxy shutdown: %d connection(s) still active after the drain timeout", len(conns))
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

// tlsConfig 返回客户端侧 TLS 配置（首次调用时生成自签证书）。
func (s *Server) tlsConfig() (*tls.Config, error) {
	if s.cfg.TLSConfig != nil {
		return s.cfg.TLSConfig, nil
	}
	s.tlsOnce.Do(func() {
		cert, err := generateSelfSignedCert()
		if err != nil {
			s.tlsErr = err
			return
		}
		s.tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	})
	return s.tlsCfg, s.tlsErr
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "keykoi-mysql-proxy"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// handle 处理一条客户端连接。
func (s *Server) handle(rawConn net.Conn) {
	s.total.Add(1)
	remote := rawConn.RemoteAddr().String()
	if s.active.Add(1) > int64(s.cfg.MaxConnections) {
		s.active.Add(-1)
		s.denied.Add(1)
		_ = writePacket(rawConn, 0, errorPacket(1053, "08S01", "Too many connections"))
		_ = rawConn.Close()
		s.logger.Printf("mysql-proxy connection from %s rejected: connection limit %d", remote, s.cfg.MaxConnections)
		return
	}
	conn := rawConn
	// tracked 固定为登记的底层连接：TLS 升级后 conn 会变成 tls.Conn 包装，
	// 关闭它即关闭底层连接，取消集合里登记的仍是同一个 net.Conn。
	tracked := rawConn
	defer func() {
		s.active.Add(-1)
		s.untrackConn(tracked)
		_ = conn.Close()
	}()
	s.trackConn(tracked)

	_ = conn.SetDeadline(time.Now().Add(s.cfg.AuthTimeout))
	reader := bufio.NewReaderSize(conn, 16<<10)
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	id := s.connSeq.Add(1)
	if err := writeGreeting(conn, id, nonce, pluginCacheSha, !s.cfg.DisableClientTLS); err != nil {
		return
	}

	seq, payload, err := readPacket(reader)
	if err != nil {
		s.denied.Add(1)
		s.logger.Printf("mysql-proxy connection from %s rejected: %v", remote, err)
		return
	}

	secure := false
	// SSLRequest 恰好是 32 字节：能力位 + 最大包长 + 字符集 + 23 字节保留。
	// 只看长度和 CLIENT_SSL 位，不能看首字节（能力位低字节通常就是 0）。
	if len(payload) == 32 && binary.LittleEndian.Uint32(payload[:4])&clientSSL != 0 {
		if !s.cfg.DisableClientTLS {
			cfg, err := s.tlsConfig()
			if err == nil {
				// SSLRequest 与 ClientHello 可能一起到达：bufio 已把后面的字节预读进
				// reader。把它们作为前缀交给 TLS，避免握手丢掉已经缓冲的数据。
				tlsConn := tls.Server(&prefixedConn{Conn: conn, buffered: reader}, cfg)
				if err := tlsConn.Handshake(); err != nil {
					s.denied.Add(1)
					s.logger.Printf("mysql-proxy connection from %s TLS handshake failed: %v", remote, err)
					return
				}
				conn = tlsConn
				reader = bufio.NewReaderSize(conn, 16<<10)
				secure = true
				seq, payload, err = readPacket(reader)
				if err != nil {
					s.denied.Add(1)
					s.logger.Printf("mysql-proxy connection from %s rejected: %v", remote, err)
					return
				}
			}
		}
	}

	resp, err := parseClientResponse(payload)
	if err != nil {
		s.denied.Add(1)
		_ = writePacket(conn, seq+1, errorPacket(errAccessDenied, sqlStateAccess, "Access denied: malformed handshake response"))
		s.logger.Printf("mysql-proxy connection from %s rejected: %v", remote, err)
		return
	}
	resp.secure = secure

	token, outSeq, err := s.readToken(conn, reader, seq, secure, nonce)
	if err != nil {
		s.denied.Add(1)
		_ = writePacket(conn, outSeq, errorPacket(errAccessDenied, sqlStateAccess, "Access denied: the password field must carry a KeyKoi session token"))
		s.logger.Printf("mysql-proxy connection from %s rejected: %v", remote, err)
		return
	}

	target, err := s.resolveTarget(token, resp.database)
	if err != nil {
		s.denied.Add(1)
		_ = writePacket(conn, outSeq, errorPacket(errAccessDenied, sqlStateAccess, "Access denied: session token is not authorized to use this binding"))
		s.logger.Printf("mysql-proxy connection from %s denied: %v", remote, err)
		return
	}

	up, err := dialUpstream(target, upstreamOptions{
		timeout:  s.cfg.DialTimeout,
		insecure: s.cfg.InsecureUpstream,
		caFile:   s.cfg.UpstreamCA,
		tlsMode:  s.cfg.UpstreamTLSMode,
	})
	if err != nil {
		s.denied.Add(1)
		_ = writePacket(conn, outSeq, errorPacket(errAccessDenied, sqlStateAccess, "Access denied: upstream connection failed; details are in the keykoi mysql-proxy log"))
		s.logger.Printf("mysql-proxy connection from %s failed: %v (upstream %s)", remote, err, target)
		return
	}
	defer up.close()

	if err := up.handshake(); err != nil {
		s.denied.Add(1)
		_ = writePacket(conn, outSeq, errorPacket(errAccessDenied, sqlStateAccess, "Access denied: upstream authentication failed; details are in the keykoi mysql-proxy log"))
		s.logger.Printf("mysql-proxy upstream authentication failed for %s: %v", target, err)
		return
	}

	if err := writePacket(conn, outSeq, okPacket()); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	s.logger.Printf("mysql-proxy connection from %s established (upstream %s tls=%t)", remote, target, secure)

	s.relay(conn, reader, up)
	s.logger.Printf("mysql-proxy connection from %s closed", remote)
}

// readToken 通过完整认证流程取得客户端提交的会话令牌。
// 返回的 outSeq 是代理下一个应发送的包序号（入站序号 + 1）。
func (s *Server) readToken(conn net.Conn, reader *bufio.Reader, seq byte, secure bool, nonce []byte) (string, byte, error) {
	// 要求完整认证：客户端要么在 TLS 上直接给明文，要么索取 RSA 公钥加密提交。
	if err := writePacket(conn, seq+1, []byte{0x01, moreDataFullAuth}); err != nil {
		return "", seq + 1, err
	}
	seq, payload, err := readPacket(reader)
	if err != nil {
		return "", seq + 1, fmt.Errorf("read auth data: %w", err)
	}
	if len(payload) == 1 && payload[0] == 0x02 {
		pub := append([]byte{0x01}, s.pubPEM...)
		if err := writePacket(conn, seq+1, pub); err != nil {
			return "", seq + 1, err
		}
		seq, payload, err = readPacket(reader)
		if err != nil {
			return "", seq + 1, fmt.Errorf("read encrypted password: %w", err)
		}
	}
	outSeq := seq + 1
	if secure {
		token := string(trimNul(payload))
		if token == "" {
			return "", outSeq, errors.New("empty session token")
		}
		return token, outSeq, nil
	}
	token, err := rsaDecryptPassword(payload, s.priv, nonce)
	if err != nil {
		// 客户端可能自己缓存过公钥但未走 TLS；退化为按明文解析。
		token = string(trimNul(payload))
		if token == "" {
			return "", outSeq, fmt.Errorf("decrypt password: %w", err)
		}
	}
	if token == "" {
		return "", outSeq, errors.New("empty session token")
	}
	return token, outSeq, nil
}

// resolveTarget 用一次授权换取目标与凭证：上游地址只从 resolved.Binding 取。
// 不再单独读取 /v1/bindings，改绑时的在途请求不会用旧目标配新密码。
func (s *Server) resolveTarget(token, clientDatabase string) (UpstreamTarget, error) {
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
		port = "3306"
	}
	if host == "" {
		return UpstreamTarget{}, errors.New("binding has no upstream host")
	}
	userField := firstNonEmpty(s.cfg.UsernameField, binding.UsernameField, "username")
	passField := firstNonEmpty(s.cfg.PasswordField, binding.PasswordField, "password")
	user := resolved.Fields[userField]
	password := resolved.Fields[passField]
	if user == "" || password == "" {
		return UpstreamTarget{}, fmt.Errorf("credential is missing fields %q/%q for the mysql adapter", userField, passField)
	}
	database := resolved.Fields[s.cfg.DatabaseField]
	if database == "" {
		database = clientDatabase
	}
	return UpstreamTarget{
		Host:           host,
		Port:           port,
		User:           user,
		Password:       secret.New(password),
		Database:       database,
		Addr:           net.JoinHostPort(host, port),
		Revision:       binding.Revision,
		UpstreamOrigin: binding.UpstreamOrigin,
	}, nil
}

// authorizedBinding 取出这次授权校验过的 Binding 快照；缺失或指向别的绑定都拒绝。
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

// prefixedConn 让 TLS 层先读 bufio 已预读、但还没被消费的字节，再读底层连接。
// MySQL 客户端常在 SSLRequest 之后立刻发送 ClientHello，两者可能落在同一次读取里。
type prefixedConn struct {
	net.Conn
	buffered *bufio.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) { return c.buffered.Read(p) }

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
		s.logger.Printf("mysql-proxy revoke lease: %v", err)
	}
}

// relay 认证完成后双向按字节转发。
//
// 客户端→上游方向同时承担改绑核对：每一轮转发前后按时间戳判断是否到点，
// 到点用 Get 读一次绑定详情（最多每秒一次），不另起后台 goroutine。
func (s *Server) relay(conn net.Conn, clientReader *bufio.Reader, up *upstream) {
	watch := s.newBindingWatch(up.target)

	done := make(chan struct{}, 2)
	go func() {
		s.copyClientToUpstream(conn, clientReader, up, watch)
		_ = up.conn.Close()
		done <- struct{}{}
	}()
	go func() {
		_, err := io.Copy(conn, up.reader)
		if err != nil && !isClosedErr(err) {
			s.logger.Printf("mysql-proxy upstream->client copy: %v", err)
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
//
// 读截止时间只用来按时唤醒核对：空闲连接按 RevalidateInterval 超时一次，
// 有数据时立即继续转发，字节流语义不变。
func (s *Server) copyClientToUpstream(conn net.Conn, clientReader *bufio.Reader, up *upstream, watch *bindingWatch) {
	buf := make([]byte, 32<<10)
	for {
		if watch.due(time.Now()) && watch.changed() {
			// 协议层先回错误再断开：沿用现有 ERR 包路径，客户端能看到明确原因。
			_ = writePacket(conn, 0, errorPacket(errAccessDenied, sqlStateAccess,
				"Access denied: the binding authorization changed; reconnect"))
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(watch.interval)); err != nil {
			return
		}
		n, err := clientReader.Read(buf)
		if n > 0 {
			if _, werr := up.conn.Write(buf[:n]); werr != nil {
				if !isClosedErr(werr) {
					s.logger.Printf("mysql-proxy client->upstream copy: %v", werr)
				}
				return
			}
		}
		if err != nil {
			if isTimeoutErr(err) {
				continue
			}
			if !isClosedErr(err) {
				s.logger.Printf("mysql-proxy client->upstream copy: %v", err)
			}
			return
		}
	}
}

// denialForResolveError 把后台稳定错误码映射为客户端可见的认证失败。
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
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset by peer")
}

// isTimeoutErr 报告错误是否来自读截止时间。转发环用它区分“到点该核对”与真正断开。
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
