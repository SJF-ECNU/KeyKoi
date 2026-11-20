package mysqlproxy

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// MySQL 协议常量。
const (
	protoVersion10 = 10

	clientLongPassword               uint32 = 0x00000001
	clientLongFlag                   uint32 = 0x00000004
	clientConnectWithDB              uint32 = 0x00000008
	clientProtocol41                 uint32 = 0x00000200
	clientSSL                        uint32 = 0x00000800
	clientTransactions               uint32 = 0x00002000
	clientSecureConnection           uint32 = 0x00008000
	clientMultiResults               uint32 = 0x00020000
	clientPluginAuth                 uint32 = 0x00080000
	clientConnectAttrs               uint32 = 0x00100000
	clientPluginAuthLenencClientData uint32 = 0x00200000

	serverStatusAutocommit uint16 = 0x0002

	// keykoiCaps 是代理向客户端宣告、并同样向上游声明的能力集合。
	// 两侧保持一致，结果集分帧（是否使用 EOF / session tracking）才不会错位。
	keykoiCaps = clientLongPassword | clientLongFlag | clientConnectWithDB |
		clientProtocol41 | clientTransactions | clientSecureConnection |
		clientMultiResults | clientPluginAuth |
		clientPluginAuthLenencClientData
	// 不声明 CLIENT_CONNECT_ATTRS：代理不转发连接属性，声明了就必须在握手响应里
	// 附带长度编码的属性块，否则上游会以 "Bad handshake" 拒绝。

	// clientFacingCaps 额外向客户端宣告 TLS 能力：客户端据此协商 TLS（sslmode=PREFERRED
	// 默认就会用），caching_sha2 的完整认证才有安全通道可走。
	clientFacingCaps = keykoiCaps | clientSSL

	errAccessDenied uint16 = 1045
	errHostBlocked  uint16 = 1129
	sqlStateAccess         = "28000"

	// MySQL 认证插件名。
	pluginNative   = "mysql_native_password"
	pluginCacheSha = "caching_sha2_password"
	pluginSha256   = "sha256_password"
	pluginClear    = "mysql_clear_password"

	// AuthMoreData 子代码。
	moreDataFullAuth   byte = 0x04
	moreDataFastAuthOK byte = 0x03
)

// readPacket 读取一个完整 MySQL 包，返回序号与负载。
func readPacket(r *bufio.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n < 0 || n > 32<<20 {
		return 0, nil, fmt.Errorf("mysqlproxy: invalid packet length %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[3], payload, nil
}

// writePacket 写出一个 MySQL 包。
func writePacket(w io.Writer, seq byte, payload []byte) error {
	n := len(payload)
	hdr := [4]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// serverGreeting 是解析后的服务端握手包。
type serverGreeting struct {
	version    string
	connection uint32
	caps       uint32
	charset    byte
	status     uint16
	plugin     string
	nonce      []byte
}

// parseGreeting 解析服务端 Greeting（protocol 10）。
func parseGreeting(payload []byte) (*serverGreeting, error) {
	if len(payload) == 0 {
		return nil, errors.New("mysqlproxy: empty greeting")
	}
	if payload[0] == 0xff {
		return nil, errors.New("mysqlproxy: server returned an error instead of a greeting")
	}
	if payload[0] != protoVersion10 {
		return nil, fmt.Errorf("mysqlproxy: unsupported protocol version %d", payload[0])
	}
	p := payload[1:]
	ver, rest, ok := cutNul(p)
	if !ok {
		return nil, errors.New("mysqlproxy: truncated greeting version")
	}
	g := &serverGreeting{version: ver}
	if len(rest) < 4 {
		return nil, errors.New("mysqlproxy: truncated greeting connection id")
	}
	g.connection = binary.LittleEndian.Uint32(rest[:4])
	rest = rest[4:]
	if len(rest) < 9 {
		return nil, errors.New("mysqlproxy: truncated greeting auth data")
	}
	g.nonce = append(g.nonce, rest[:8]...)
	rest = rest[9:] // 8 字节 auth data + 1 字节 filler
	if len(rest) < 2 {
		// 旧协议：没有扩展能力位。
		return g, nil
	}
	g.caps = uint32(binary.LittleEndian.Uint16(rest[:2]))
	rest = rest[2:]
	if len(rest) == 0 {
		return g, nil
	}
	if len(rest) < 16 {
		return nil, errors.New("mysqlproxy: truncated greeting capabilities")
	}
	g.charset = rest[0]
	g.status = binary.LittleEndian.Uint16(rest[1:3])
	g.caps |= uint32(binary.LittleEndian.Uint16(rest[3:5])) << 16
	authLen := int(rest[5])
	rest = rest[16:]
	part2 := authLen - 8
	if part2 < 13 {
		part2 = 13
	}
	if len(rest) < part2-1 {
		return nil, errors.New("mysqlproxy: truncated greeting auth data part 2")
	}
	take := part2 - 1
	if take > len(rest) {
		take = len(rest)
	}
	g.nonce = append(g.nonce, rest[:take]...)
	rest = rest[take:]
	if len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	if g.caps&clientPluginAuth != 0 && len(rest) > 0 {
		plugin, _, _ := cutNul(rest)
		g.plugin = plugin
	}
	if len(g.nonce) > 20 {
		g.nonce = g.nonce[:20]
	}
	return g, nil
}

// writeGreeting 写出代理自己的 Greeting。
func writeGreeting(w io.Writer, connection uint32, nonce []byte, plugin string, offerTLS bool) error {
	caps := keykoiCaps
	if offerTLS {
		caps = clientFacingCaps
	}
	if len(nonce) < 20 {
		return errors.New("mysqlproxy: nonce must be 20 bytes")
	}
	var b bytes.Buffer
	b.WriteByte(protoVersion10)
	b.WriteString("8.0.0-keykoi")
	b.WriteByte(0)
	_ = binary.Write(&b, binary.LittleEndian, connection)
	b.Write(nonce[:8])
	b.WriteByte(0)
	_ = binary.Write(&b, binary.LittleEndian, uint16(caps&0xffff))
	b.WriteByte(45) // utf8mb4_general_ci
	_ = binary.Write(&b, binary.LittleEndian, serverStatusAutocommit)
	_ = binary.Write(&b, binary.LittleEndian, uint16(caps>>16))
	b.WriteByte(21) // auth-plugin-data 总长
	b.Write(make([]byte, 10))
	b.Write(nonce[8:20])
	b.WriteByte(0)
	b.WriteString(plugin)
	b.WriteByte(0)
	return writePacket(w, 0, b.Bytes())
}

// clientResponse 是解析后的客户端握手响应。
type clientResponse struct {
	caps     uint32
	username string
	database string
	plugin   string
	auth     []byte
	secure   bool
}

// parseClientResponse 解析 HandshakeResponse41。
func parseClientResponse(payload []byte) (*clientResponse, error) {
	if len(payload) < 32 {
		if len(payload) > 0 && payload[0] == 0xff {
			return nil, errors.New("mysqlproxy: client reported an error during handshake")
		}
		return nil, errors.New("mysqlproxy: truncated handshake response")
	}
	caps := binary.LittleEndian.Uint32(payload[:4])
	rest := payload[32:]
	user, rest, ok := cutNul(rest)
	if !ok {
		return nil, errors.New("mysqlproxy: truncated username")
	}
	out := &clientResponse{caps: caps, username: user}
	switch {
	case caps&clientPluginAuthLenencClientData != 0:
		n, used, err := readLenEncInt(rest)
		if err != nil {
			return nil, err
		}
		rest = rest[used:]
		if int(n) > len(rest) {
			return nil, errors.New("mysqlproxy: truncated auth response")
		}
		out.auth = append([]byte(nil), rest[:n]...)
		rest = rest[n:]
	case caps&clientSecureConnection != 0:
		if len(rest) < 1 {
			return nil, errors.New("mysqlproxy: truncated auth response")
		}
		n := int(rest[0])
		rest = rest[1:]
		if n > len(rest) {
			return nil, errors.New("mysqlproxy: truncated auth response")
		}
		out.auth = append([]byte(nil), rest[:n]...)
		rest = rest[n:]
	default:
		val, r2, ok := cutNul(rest)
		if !ok {
			return nil, errors.New("mysqlproxy: truncated auth response")
		}
		out.auth = []byte(val)
		rest = r2
	}
	if caps&clientConnectWithDB != 0 {
		db, r2, ok := cutNul(rest)
		if !ok {
			return nil, errors.New("mysqlproxy: truncated database name")
		}
		out.database = db
		rest = r2
	}
	if caps&clientPluginAuth != 0 {
		plugin, _, _ := cutNul(rest)
		out.plugin = plugin
	}
	return out, nil
}

// buildClientResponse 构造发往上游的 HandshakeResponse41。
func buildClientResponse(caps uint32, user, database, plugin string, auth []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, caps)
	_ = binary.Write(&b, binary.LittleEndian, uint32(16<<20))
	b.WriteByte(45)
	b.Write(make([]byte, 23))
	b.WriteString(user)
	b.WriteByte(0)
	if caps&clientPluginAuthLenencClientData != 0 {
		b.Write(putLenEncInt(uint64(len(auth))))
	} else {
		b.WriteByte(byte(len(auth)))
	}
	b.Write(auth)
	if caps&clientConnectWithDB != 0 {
		b.WriteString(database)
		b.WriteByte(0)
	}
	if caps&clientPluginAuth != 0 {
		b.WriteString(plugin)
		b.WriteByte(0)
	}
	return b.Bytes()
}

// authSwitchRequest 构造 AuthSwitchRequest 包。
func authSwitchRequest(plugin string, nonce []byte) []byte {
	out := []byte{0xfe}
	out = append(out, plugin...)
	out = append(out, 0)
	out = append(out, nonce...)
	out = append(out, 0)
	return out
}

// okPacket 构造不带 session tracking 的 OK 包。
func okPacket() []byte {
	return []byte{0x00, 0x00, 0x00, byte(serverStatusAutocommit), 0x00, 0x00, 0x00}
}

// errorPacket 构造 ERR 包。message 不得包含秘密。
func errorPacket(errno uint16, sqlState, message string) []byte {
	var b bytes.Buffer
	b.WriteByte(0xff)
	_ = binary.Write(&b, binary.LittleEndian, errno)
	b.WriteByte('#')
	state := sqlState
	if len(state) != 5 {
		state = sqlStateAccess
	}
	b.WriteString(state)
	b.WriteString(message)
	return b.Bytes()
}

// nativePassword 计算 mysql_native_password 响应。
func nativePassword(password string, nonce []byte) []byte {
	if password == "" {
		return nil
	}
	st1 := sha1.Sum([]byte(password))
	st2 := sha1.Sum(st1[:])
	h := sha1.New()
	h.Write(nonce)
	h.Write(st2[:])
	scramble := h.Sum(nil)
	out := make([]byte, len(st1))
	for i := range st1 {
		out[i] = st1[i] ^ scramble[i]
	}
	return out
}

// cachingSha2Password 计算 caching_sha2_password 快路径响应。
func cachingSha2Password(password string, nonce []byte) []byte {
	if password == "" {
		return nil
	}
	st1 := sha256.Sum256([]byte(password))
	st2 := sha256.Sum256(st1[:])
	h := sha256.New()
	h.Write(st2[:])
	h.Write(nonce)
	scramble := h.Sum(nil)
	out := make([]byte, len(st1))
	for i := range st1 {
		out[i] = st1[i] ^ scramble[i]
	}
	return out
}

// computeAuthResponse 按插件计算初始认证响应。
func computeAuthResponse(plugin, password string, nonce []byte) ([]byte, error) {
	switch plugin {
	case "", pluginNative:
		return nativePassword(password, nonce), nil
	case pluginCacheSha:
		return cachingSha2Password(password, nonce), nil
	case pluginSha256:
		// sha256_password 先发空响应，服务端随后给出公钥或走 TLS 明文。
		return []byte{}, nil
	case pluginClear:
		return append([]byte(password), 0), nil
	}
	return nil, fmt.Errorf("mysqlproxy: unsupported authentication plugin %q", plugin)
}

// isSupportedPlugin 报告插件是否在支持范围内。
func isSupportedPlugin(plugin string) bool {
	switch plugin {
	case "", pluginNative, pluginCacheSha, pluginSha256, pluginClear:
		return true
	}
	return false
}

// xorNonce 按 MySQL 约定把口令与 nonce 循环异或。
func xorNonce(password, nonce []byte) []byte {
	if len(nonce) == 0 {
		return password
	}
	out := make([]byte, len(password))
	for i := range password {
		out[i] = password[i] ^ nonce[i%len(nonce)]
	}
	return out
}

// 说明：代理不再用服务端临时下发、未经验证的 RSA 公钥加密上游口令。
// 明文上游链路上的 caching_sha2_password / sha256_password 完整认证直接失败，
// 需要完整认证时由上游 TLS 承担（见 upstream.go 的 handleAuthMoreData）。
// 下面只保留客户端侧需要的解密：代理向自己的客户端提供公钥并解出会话令牌。

// rsaDecryptPassword 用代理自己的私钥解出客户端提交的口令。
// 客户端加密的是以 NUL 结尾的 C 字符串，解密后要去掉这个结尾。
func rsaDecryptPassword(enc []byte, priv *rsa.PrivateKey, nonce []byte) (string, error) {
	plain, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, enc, nil)
	if err != nil {
		return "", err
	}
	return string(trimNul(xorNonce(plain, nonce))), nil
}

// encodeRSAPublicKey 输出 PKIX PEM 公钥，用于回应客户端的公钥请求。
func encodeRSAPublicKey(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func cutNul(b []byte) (string, []byte, bool) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", nil, false
	}
	return string(b[:i]), b[i+1:], true
}

// readLenEncInt 读取 length-encoded 整数。
func readLenEncInt(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("mysqlproxy: truncated length-encoded integer")
	}
	switch b[0] {
	case 0xfc:
		if len(b) < 3 {
			return 0, 0, errors.New("mysqlproxy: truncated length-encoded integer")
		}
		return uint64(binary.LittleEndian.Uint16(b[1:3])), 3, nil
	case 0xfd:
		if len(b) < 4 {
			return 0, 0, errors.New("mysqlproxy: truncated length-encoded integer")
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4, nil
	case 0xfe:
		if len(b) < 9 {
			return 0, 0, errors.New("mysqlproxy: truncated length-encoded integer")
		}
		return binary.LittleEndian.Uint64(b[1:9]), 9, nil
	case 0xfb:
		return 0, 1, errors.New("mysqlproxy: unexpected NULL length-encoded integer")
	}
	return uint64(b[0]), 1, nil
}

// putLenEncInt 编码 length-encoded 整数。
func putLenEncInt(n uint64) []byte {
	switch {
	case n < 251:
		return []byte{byte(n)}
	case n < 1<<16:
		return []byte{0xfc, byte(n), byte(n >> 8)}
	case n < 1<<24:
		return []byte{0xfd, byte(n), byte(n >> 8), byte(n >> 16)}
	}
	out := []byte{0xfe, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint64(out[1:], n)
	return out
}

// trimNul 去掉尾部 NUL 填充。
func trimNul(b []byte) []byte { return bytes.TrimRight(b, "\x00") }
