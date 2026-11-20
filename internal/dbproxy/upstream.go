package dbproxy

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"keykoi/internal/proxylease"
	"keykoi/internal/secret"
)

// TLSMode 是代理到上游数据库的 TLS 策略。
type TLSMode string

const (
	// TLSDisable 不尝试上游 TLS，直接明文握手。只适用于受控本机上游。
	TLSDisable TLSMode = "disable"
	// TLSPrefer 先请求 TLS；上游不支持时回落明文；上游支持则必须通过证书校验。
	TLSPrefer TLSMode = "prefer"
	// TLSRequire 必须使用 TLS，且必须通过证书链与主机名校验。
	TLSRequire TLSMode = "require"
)

// ParseTLSMode 解析 sslmode 取值。
func ParseTLSMode(s string) (TLSMode, error) {
	switch TLSMode(strings.ToLower(strings.TrimSpace(s))) {
	case TLSDisable:
		return TLSDisable, nil
	case TLSPrefer:
		return TLSPrefer, nil
	case "", TLSRequire:
		return TLSRequire, nil
	}
	return "", fmt.Errorf("dbproxy: unsupported upstream sslmode %q (disable|prefer|require)", s)
}

// UpstreamTarget 是经授权解析出的上游连接参数。密码只在内存中停留。
type UpstreamTarget struct {
	Host     string
	Port     string
	User     string
	Password secret.Value
	Database string
	// Addr 是 host:port，用于连接与取消请求转发。
	Addr string
	use  *proxylease.Use
}

// String 只输出非秘密字段，避免密码进入日志。
func (t UpstreamTarget) String() string {
	return fmt.Sprintf("host=%s db=%s user=%s", t.Addr, t.Database, t.User)
}

// upstreamError 是上游启动阶段错误。AuthFailed 表示可以归因到认证失败。
type upstreamError struct {
	AuthFailed bool
	SQLState   string
	Message    string
	Err        error
}

func (e *upstreamError) Error() string {
	if e.Message != "" {
		return "dbproxy: upstream: " + e.Message
	}
	if e.Err != nil {
		return "dbproxy: upstream: " + e.Err.Error()
	}
	return "dbproxy: upstream failure"
}

func (e *upstreamError) Unwrap() error { return e.Err }

// upstream 是代理到数据库服务器的一条连接。
type upstream struct {
	conn      net.Conn
	reader    *bufio.Reader
	target    UpstreamTarget
	encrypted bool
}

// dialUpstream 建立上游连接，并按 sslmode 完成 TLS 协商。
// caFile 非空时在系统根证书之外追加该 PEM 证书；校验从不关闭。
func dialUpstream(ctx context.Context, target UpstreamTarget, mode TLSMode, caFile string, timeout time.Duration) (*upstream, error) {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	return dialUpstreamWithDial(ctx, target, mode, caFile, timeout, d.DialContext)
}

func dialUpstreamWithDial(
	ctx context.Context,
	target UpstreamTarget,
	mode TLSMode,
	caFile string,
	timeout time.Duration,
	dial func(context.Context, string, string) (net.Conn, error),
) (*upstream, error) {
	raw, err := dial(ctx, "tcp", target.Addr)
	if err != nil {
		return nil, &upstreamError{Err: fmt.Errorf("dial %s: %w", target.Addr, err)}
	}
	conn := raw
	encrypted := false

	if mode != TLSDisable {
		// SSLRequest 的写与读都属于握手：写之前设置完整 deadline，避免对端不收数据时卡死。
		_ = conn.SetDeadline(time.Now().Add(timeout))
		// SSLRequest：长度 8，代码 80877103。
		if _, err := conn.Write([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
			conn.Close()
			return nil, &upstreamError{Err: fmt.Errorf("send SSLRequest: %w", err)}
		}
		var reply [1]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			conn.Close()
			return nil, &upstreamError{Err: fmt.Errorf("read SSLRequest reply: %w", err)}
		}
		_ = conn.SetDeadline(time.Time{})
		switch reply[0] {
		case 'S':
			cfg, err := upstreamTLSConfig(target.Host, caFile)
			if err != nil {
				conn.Close()
				return nil, err
			}
			tlsConn := tls.Client(conn, cfg)
			tlsConn.SetDeadline(time.Now().Add(timeout))
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, &upstreamError{Err: fmt.Errorf("upstream TLS handshake: %w", err)}
			}
			tlsConn.SetDeadline(time.Time{})
			conn = tlsConn
			encrypted = true
		case 'N':
			if mode != TLSPrefer {
				conn.Close()
				return nil, &upstreamError{Err: errors.New("upstream does not offer TLS while sslmode=require")}
			}
		case 'E':
			conn.Close()
			return nil, &upstreamError{Err: errors.New("upstream rejected the TLS request")}
		default:
			conn.Close()
			return nil, &upstreamError{Err: fmt.Errorf("unexpected SSLRequest reply %q", reply[0])}
		}
	}
	return &upstream{conn: conn, reader: bufio.NewReaderSize(conn, 16<<10), target: target, encrypted: encrypted}, nil
}

func upstreamTLSConfig(host, caFile string) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, &upstreamError{Err: fmt.Errorf("read upstream CA file: %w", err)}
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, &upstreamError{Err: errors.New("upstream CA file contains no usable certificate")}
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		RootCAs:    pool,
	}, nil
}

// startup 完成上游认证，返回需要原样转给客户端的后端消息（ParameterStatus、
// BackendKeyData、ReadyForQuery 等）。任何认证失败都返回 *upstreamError。
func (u *upstream) startup(ctx context.Context) (passthrough [][]byte, err error) {
	sm := &pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters: map[string]string{
			"user":             u.target.User,
			"database":         u.target.Database,
			"application_name": "keykoi-dbproxy",
		},
	}
	frame, err := sm.Encode(nil)
	if err != nil {
		return nil, &upstreamError{Err: err}
	}
	if _, err := u.conn.Write(frame); err != nil {
		return nil, &upstreamError{Err: fmt.Errorf("send startup: %w", err)}
	}

	password := u.target.Password.RevealString()
	var scram *scramClient

	for {
		if ctx.Err() != nil {
			return nil, &upstreamError{Err: ctx.Err()}
		}
		typ, frame, err := readFrame(u.reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, &upstreamError{Err: errors.New("upstream closed the connection during authentication")}
			}
			return nil, &upstreamError{Err: err}
		}
		switch typ {
		case 'R':
			if len(frame) < 9 {
				return nil, &upstreamError{Err: errors.New("truncated authentication message")}
			}
			code := binary.BigEndian.Uint32(frame[5:9])
			switch code {
			case pgproto3.AuthTypeOk: // 0
				// 认证完成；后续 ParameterStatus/BackendKeyData/ReadyForQuery 继续读。
			case pgproto3.AuthTypeCleartextPassword: // 3
				if err := u.sendPassword(password); err != nil {
					return nil, err
				}
			case pgproto3.AuthTypeMD5Password: // 5
				if len(frame) < 13 {
					return nil, &upstreamError{Err: errors.New("truncated MD5 salt")}
				}
				salt := frame[9:13]
				if err := u.sendPassword(md5Password(u.target.User, password, salt)); err != nil {
					return nil, err
				}
			case pgproto3.AuthTypeSASL: // 10
				var msg pgproto3.AuthenticationSASL
				if err := msg.Decode(frame[5:]); err != nil {
					return nil, &upstreamError{Err: err}
				}
				mechanism, err := chooseSASLMechanism(msg.AuthMechanisms)
				if err != nil {
					return nil, &upstreamError{Err: err}
				}
				if mechanism != scramSHA256 {
					return nil, &upstreamError{Err: fmt.Errorf("unsupported SASL mechanism %q", mechanism)}
				}
				scram, err = newSCRAMClient(password)
				if err != nil {
					return nil, &upstreamError{Err: err}
				}
				resp := &pgproto3.SASLInitialResponse{
					AuthMechanism: scramSHA256,
					Data:          scram.clientFirstMessage(),
				}
				if err := u.send(resp); err != nil {
					return nil, err
				}
			case pgproto3.AuthTypeSASLContinue: // 11
				if scram == nil {
					return nil, &upstreamError{Err: errors.New("unexpected SASL continue before SASL start")}
				}
				var msg pgproto3.AuthenticationSASLContinue
				if err := msg.Decode(frame[5:]); err != nil {
					return nil, &upstreamError{Err: err}
				}
				if err := scram.receiveServerFirst(msg.Data); err != nil {
					return nil, &upstreamError{Err: err}
				}
				final, err := scram.clientFinalMessage()
				if err != nil {
					return nil, &upstreamError{Err: err}
				}
				if err := u.send(&pgproto3.SASLResponse{Data: final}); err != nil {
					return nil, err
				}
			case pgproto3.AuthTypeSASLFinal: // 12
				if scram == nil {
					return nil, &upstreamError{Err: errors.New("unexpected SASL final before SASL start")}
				}
				var msg pgproto3.AuthenticationSASLFinal
				if err := msg.Decode(frame[5:]); err != nil {
					return nil, &upstreamError{Err: err}
				}
				if err := scram.verifyServerFinal(msg.Data); err != nil {
					return nil, &upstreamError{AuthFailed: true, Err: err}
				}
			default:
				return nil, &upstreamError{Err: fmt.Errorf("unsupported upstream authentication type %d (only scram-sha-256, md5 and cleartext are supported)", code)}
			}
		case 'E':
			var msg pgproto3.ErrorResponse
			if err := msg.Decode(frame[5:]); err != nil {
				return nil, &upstreamError{Err: err}
			}
			authFailed := msg.Code == "28P01" || msg.Code == "28000"
			return nil, &upstreamError{AuthFailed: authFailed, SQLState: msg.Code, Message: msg.Message}
		case 'S', 'K', 'N', 'v':
			passthrough = append(passthrough, frame)
		case 'Z':
			passthrough = append(passthrough, frame)
			return passthrough, nil
		default:
			return nil, &upstreamError{Err: fmt.Errorf("unexpected message %q during upstream startup", typ)}
		}
	}
}

// close 关闭上游连接。
func (u *upstream) close() error { return u.conn.Close() }

func (u *upstream) send(msg pgproto3.FrontendMessage) error {
	frame, err := msg.Encode(nil)
	if err != nil {
		return &upstreamError{Err: err}
	}
	if _, err := u.conn.Write(frame); err != nil {
		return &upstreamError{Err: fmt.Errorf("write to upstream: %w", err)}
	}
	return nil
}

func (u *upstream) sendPassword(password string) error {
	return u.send(&pgproto3.PasswordMessage{Password: password})
}

// chooseSASLMechanism 只接受 SCRAM-SHA-256。上游只提供带通道绑定的 -PLUS 时显式报错。
func chooseSASLMechanism(offered []string) (string, error) {
	for _, m := range offered {
		if m == scramSHA256 {
			return scramSHA256, nil
		}
	}
	for _, m := range offered {
		if m == scramSHA256Plus {
			return "", errors.New("upstream requires SCRAM-SHA-256-PLUS channel binding, which is outside this proxy's supported scope")
		}
	}
	return "", fmt.Errorf("upstream offers no supported SASL mechanism (offered %v)", offered)
}

// md5Password 计算 PostgreSQL 的 MD5 认证响应。
func md5Password(user, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	outer := md5.Sum(append([]byte(fmt.Sprintf("%x", inner)), salt...))
	return "md5" + fmt.Sprintf("%x", outer)
}

// readFrame 读取一条完整后端消息（类型字节 + 长度 + 体），返回原始帧。
// 原样返回便于把 ParameterStatus/BackendKeyData/ReadyForQuery 转给客户端。
func readFrame(r *bufio.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	typ := hdr[0]
	n := int(int32(binary.BigEndian.Uint32(hdr[1:])))
	if n < 4 || n > 16<<20 {
		return 0, nil, fmt.Errorf("dbproxy: invalid backend message length %d", n)
	}
	frame := make([]byte, 5+n-4)
	copy(frame, hdr[:])
	if _, err := io.ReadFull(r, frame[5:]); err != nil {
		return 0, nil, err
	}
	return typ, frame, nil
}
