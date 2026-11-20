package mysqlproxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"keykoi/internal/secret"
)

// UpstreamTarget 是经授权解析出的上游 MySQL 连接参数。密码只在内存中停留。
type UpstreamTarget struct {
	Host     string
	Port     string
	User     string
	Password secret.Value
	Database string
	Addr     string
	// Revision 是同一次授权返回的 Binding revision，供在途连接检测改绑。
	Revision int64
	// UpstreamOrigin 是同一次授权返回的绑定 origin，用于发现改绑到别的目标。
	UpstreamOrigin string
}

// String 只输出非秘密字段，避免密码进入日志。
func (t UpstreamTarget) String() string {
	return fmt.Sprintf("addr=%s user=%s db=%s", t.Addr, t.User, t.Database)
}

// upstreamOptions 是上游传输策略。
type upstreamOptions struct {
	// timeout 限制连接、TLS 握手与整个认证阶段的耗时。
	timeout time.Duration
	// insecure 显式声明允许明文上游。默认 false：上游不支持 TLS 就拒绝连接。
	insecure bool
	// caFile 是可选的追加 PEM CA；系统根证书始终参与校验。
	caFile string
	// tlsMode 决定 TLS 的校验强度。
	tlsMode UpstreamTLSMode
}

// UpstreamTLSMode 是上游 TLS 的校验强度。
type UpstreamTLSMode string

const (
	// UpstreamTLSVerifyFull 校验证书链与主机名（默认）。
	UpstreamTLSVerifyFull UpstreamTLSMode = "verify-full"
	// UpstreamTLSVerifyCA 只校验证书链、不核对主机名。MySQL 自动生成的服务端
	// 证书通常没有 IP/主机名 SAN，需要这条显式降级但仍受 CA 约束的路径。
	UpstreamTLSVerifyCA UpstreamTLSMode = "verify-ca"
)

// ParseUpstreamTLSMode 解析上游 TLS 校验强度。
func ParseUpstreamTLSMode(s string) (UpstreamTLSMode, error) {
	switch UpstreamTLSMode(strings.ToLower(strings.TrimSpace(s))) {
	case "", UpstreamTLSVerifyFull:
		return UpstreamTLSVerifyFull, nil
	case UpstreamTLSVerifyCA:
		return UpstreamTLSVerifyCA, nil
	}
	return "", fmt.Errorf("mysqlproxy: unsupported upstream TLS mode %q (verify-full|verify-ca)", s)
}

// upstreamError 是上游认证阶段错误。AuthFailed 表示可以归因到认证失败。
type upstreamError struct {
	AuthFailed bool
	Errno      uint16
	Message    string
	Err        error
}

func (e *upstreamError) Error() string {
	if e.Message != "" {
		return "mysqlproxy: upstream: " + e.Message
	}
	if e.Err != nil {
		return "mysqlproxy: upstream: " + e.Err.Error()
	}
	return "mysqlproxy: upstream failure"
}

func (e *upstreamError) Unwrap() error { return e.Err }

// upstream 是代理到 MySQL 服务器的一条连接。
type upstream struct {
	conn   net.Conn
	reader *bufio.Reader
	target UpstreamTarget
	opts   upstreamOptions
	caps   uint32
	// encrypted 表示上游连接已通过 TLS 升级且证书校验通过。
	encrypted bool
}

// dialUpstream 建立上游 TCP 连接。TLS 在读到服务端 Greeting 之后协商
// （MySQL 的 SSLRequest 是握手的一部分）。
func dialUpstream(target UpstreamTarget, opts upstreamOptions) (*upstream, error) {
	d := &net.Dialer{Timeout: opts.timeout, KeepAlive: 30 * time.Second}
	conn, err := d.Dial("tcp", target.Addr)
	if err != nil {
		return nil, &upstreamError{Err: fmt.Errorf("dial %s: %w", target.Addr, err)}
	}
	if err := conn.SetDeadline(time.Now().Add(opts.timeout)); err != nil {
		_ = conn.Close()
		return nil, &upstreamError{Err: err}
	}
	return &upstream{
		conn:   conn,
		reader: bufio.NewReaderSize(conn, 16<<10),
		target: target,
		opts:   opts,
	}, nil
}

// handshake 完成上游认证：
//   - 服务端宣告 CLIENT_SSL 时先发 SSLRequest 再升级为受验证的 TLS，
//     后续认证（含 caching_sha2 的完整认证）都在 TLS 上完成；
//   - 服务端不宣告 TLS 时，只有显式 insecure 声明才继续明文；
//   - 明文链路上的 caching_sha2/sha256 完整认证直接失败：不再用服务端临时下发、
//     未经验证的 RSA 公钥加密口令。
func (u *upstream) handshake() error {
	seq, payload, err := readPacket(u.reader)
	if err != nil {
		return &upstreamError{Err: fmt.Errorf("read upstream greeting: %w", err)}
	}
	if seq != 0 {
		return &upstreamError{Err: fmt.Errorf("unexpected upstream greeting sequence %d", seq)}
	}
	greeting, err := parseGreeting(payload)
	if err != nil {
		return &upstreamError{Err: err}
	}
	if greeting.caps&clientProtocol41 == 0 || greeting.caps&clientSecureConnection == 0 {
		return &upstreamError{Err: errors.New("upstream does not support the 4.1 protocol")}
	}

	caps := keykoiCaps & greeting.caps
	caps |= clientProtocol41 | clientSecureConnection
	if u.target.Database != "" {
		caps |= clientConnectWithDB
	} else {
		caps &^= clientConnectWithDB
	}

	// seq 是上一条已收到/已发出的包序号；greeting 是 0。
	nextSeq := seq + 1
	switch {
	case greeting.caps&clientSSL != 0:
		if err := u.startTLS(caps, nextSeq); err != nil {
			return err
		}
		// SSLRequest 占用了 nextSeq，握手响应接着往下排；响应同样要带上
		// CLIENT_SSL，服务端据此确认链路已加密。
		nextSeq++
		caps |= clientSSL
	case !u.opts.insecure:
		return &upstreamError{Err: fmt.Errorf(
			"upstream %s does not offer TLS; the credential would be sent in cleartext. "+
				"Enable TLS on the upstream or declare insecure_upstream to allow it", u.target.Addr)}
	}

	plugin := greeting.plugin
	if !isSupportedPlugin(plugin) {
		plugin = pluginNative
	}
	password := u.target.Password.RevealString()
	auth, err := computeAuthResponse(plugin, password, greeting.nonce)
	if err != nil {
		return &upstreamError{Err: err}
	}
	u.caps = caps
	if err := writePacket(u.conn, nextSeq, buildClientResponse(caps, u.target.User, u.target.Database, plugin, auth)); err != nil {
		return &upstreamError{Err: fmt.Errorf("send upstream handshake response: %w", err)}
	}

	for attempt := 0; attempt < 8; attempt++ {
		seq, payload, err = readPacket(u.reader)
		if err != nil {
			return &upstreamError{Err: fmt.Errorf("read upstream auth packet: %w", err)}
		}
		if len(payload) == 0 {
			return &upstreamError{Err: errors.New("empty upstream auth packet")}
		}
		switch payload[0] {
		case 0x00:
			_ = u.conn.SetDeadline(time.Time{})
			return nil
		case 0xff:
			errno, message := parseErrPacket(payload)
			authFailed := errno == errAccessDenied || errno == 1044 || errno == 1698 || errno == 3118
			return &upstreamError{AuthFailed: authFailed, Errno: errno, Message: message}
		case 0xfe:
			rest := payload[1:]
			newPlugin, rest, ok := cutNul(rest)
			if !ok {
				return &upstreamError{Err: errors.New("truncated auth switch request")}
			}
			if !isSupportedPlugin(newPlugin) {
				return &upstreamError{Err: fmt.Errorf("unsupported upstream authentication plugin %q", newPlugin)}
			}
			switchPluginNonce := trimNul(rest)
			if len(switchPluginNonce) == 0 {
				switchPluginNonce = greeting.nonce
			}
			resp, err := computeAuthResponse(newPlugin, password, switchPluginNonce)
			if err != nil {
				return &upstreamError{Err: err}
			}
			plugin = newPlugin
			if err := writePacket(u.conn, seq+1, resp); err != nil {
				return &upstreamError{Err: fmt.Errorf("send auth switch response: %w", err)}
			}
		case 0x01:
			if err := u.handleAuthMoreData(payload[1:], seq, password); err != nil {
				return err
			}
		default:
			return &upstreamError{Err: fmt.Errorf("unexpected upstream auth packet type %#x", payload[0])}
		}
	}
	return &upstreamError{Err: errors.New("upstream authentication did not converge")}
}

// startTLS 用给定序号发送 SSLRequest，并把连接升级为已校验证书的 TLS。
func (u *upstream) startTLS(caps uint32, seq byte) error {
	// SSLRequest 是 32 字节：能力位（含 CLIENT_SSL）+ 最大包长 + 字符集 + 保留位。
	req := make([]byte, 32)
	binary.LittleEndian.PutUint32(req[0:4], caps|clientSSL)
	binary.LittleEndian.PutUint32(req[4:8], 32<<20)
	req[8] = 45
	if err := writePacket(u.conn, seq, req); err != nil {
		return &upstreamError{Err: fmt.Errorf("send upstream SSLRequest: %w", err)}
	}
	cfg, err := upstreamTLSConfig(u.target.Host, u.opts.caFile, u.opts.tlsMode)
	if err != nil {
		return err
	}
	tlsConn := tls.Client(u.conn, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(u.opts.timeout))
	if err := tlsConn.Handshake(); err != nil {
		return &upstreamError{Err: fmt.Errorf("upstream TLS handshake: %w", err)}
	}
	_ = tlsConn.SetDeadline(time.Now().Add(u.opts.timeout))
	u.conn = tlsConn
	u.reader = bufio.NewReaderSize(tlsConn, 16<<10)
	u.encrypted = true
	return nil
}

// upstreamTLSConfig 校验上游证书：系统根证书 + 可选的追加 CA。
// verify-full 还要求主机名匹配；verify-ca 只校验链，但仍然拒绝未知 CA。
func upstreamTLSConfig(host, caFile string, mode UpstreamTLSMode) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, &upstreamError{Err: fmt.Errorf("read upstream CA file: %w", err)}
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, &upstreamError{Err: errors.New("upstream CA file contains no usable certificate")}
		}
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		RootCAs:    pool,
	}
	if mode == UpstreamTLSVerifyCA {
		// InsecureSkipVerify 关掉的是“默认校验”，随后由 VerifyConnection 继续做
		// 证书链校验：只是不核对主机名。
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("upstream presented no certificate")
			}
			opts := x509.VerifyOptions{Roots: pool, Intermediates: x509.NewCertPool()}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		}
	}
	return cfg, nil
}

// handleAuthMoreData 处理 caching_sha2_password / sha256_password 的后续认证数据。
func (u *upstream) handleAuthMoreData(data []byte, seq byte, password string) error {
	if len(data) == 0 {
		return &upstreamError{Err: errors.New("empty auth more data")}
	}
	switch data[0] {
	case moreDataFastAuthOK:
		// 快路径已成功（挑战应答，不含明文口令），服务端随后发送 OK 包。
		return nil
	case moreDataFullAuth:
		if !u.encrypted {
			return &upstreamError{Err: fmt.Errorf(
				"upstream %s requires caching_sha2_password full authentication on a plaintext connection; "+
					"a verified TLS upstream is required to deliver the password", u.target.Addr)}
		}
		// TLS 上按协议直接提交明文口令（C 字符串，NUL 结尾）。
		if err := writePacket(u.conn, seq+1, append([]byte(password), 0)); err != nil {
			return &upstreamError{Err: fmt.Errorf("send password over TLS: %w", err)}
		}
		return nil
	}
	return &upstreamError{Err: fmt.Errorf("unexpected auth more data %#x", data[0])}
}

// parseErrPacket 解析 ERR 包，返回错误码与消息（消息不含口令）。
func parseErrPacket(payload []byte) (uint16, string) {
	if len(payload) < 3 {
		return 0, "malformed error packet"
	}
	errno := binary.LittleEndian.Uint16(payload[1:3])
	rest := payload[3:]
	if len(rest) > 6 && rest[0] == '#' {
		rest = rest[6:]
	}
	return errno, string(rest)
}

func (u *upstream) close() error { return u.conn.Close() }
