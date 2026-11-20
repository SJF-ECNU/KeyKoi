package dbproxy

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// SCRAM-SHA-256 客户端（RFC 5802 / RFC 7677）与 PostgreSQL SASL 交换。
//
// 设计取舍：
//   - 只实现 SCRAM-SHA-256；SCRAM-SHA-256-PLUS（tls-server-end-point 通道绑定）
//     不在首版范围，上游只提供 -PLUS 时显式报错，不降级。
//   - 不做 SASLprep 归一化：上游密码来自钥库中的随机字符串（可打印 ASCII），
//     非 ASCII 密码由调用方避免。此限制记录在包文档的支持范围内。
//   - 服务端签名必须校验通过，否则视为认证失败，避免半途的伪上游。

const (
	scramSHA256     = "SCRAM-SHA-256"
	scramSHA256Plus = "SCRAM-SHA-256-PLUS"
	scramNonceLen   = 18
)

// scramClient 保存一次 SCRAM 交换的中间状态。它只在单次认证中使用一次。
type scramClient struct {
	password string
	// username 是 SCRAM n= 字段；PostgreSQL 以启动包里的 user 为准，取值总为空。
	username string

	clientNonce     string
	clientFirstBare string
	serverFirst     string
	clientFinalBare string

	saltedPassword []byte
	authMessage    []byte
}

// newSCRAMClient 用随机 nonce 构造客户端。
func newSCRAMClient(password string) (*scramClient, error) {
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	return newSCRAMClientWithNonce(password, nonce)
}

// newSCRAMClientWithNonce 便于测试注入固定 nonce。
func newSCRAMClientWithNonce(password, nonce string) (*scramClient, error) {
	return newSCRAMClientWithUser(password, nonce, "")
}

// newSCRAMClientWithUser 允许指定 SCRAM 用户名，仅用于对齐测试向量；
// 生产路径始终留空，由启动包的 user 参数携带用户名。
func newSCRAMClientWithUser(password, nonce, username string) (*scramClient, error) {
	if nonce == "" {
		return nil, errors.New("dbproxy: empty SCRAM nonce")
	}
	return &scramClient{password: password, clientNonce: nonce, username: username}, nil
}

func randomNonce() (string, error) {
	buf := make([]byte, scramNonceLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf), nil
}

// clientFirstMessage 返回 SASL 初始响应。用户名留空：PostgreSQL 以启动包里的 user 为准。
func (c *scramClient) clientFirstMessage() []byte {
	c.clientFirstBare = "n=" + c.username + ",r=" + c.clientNonce
	return []byte("n,," + c.clientFirstBare)
}

// receiveServerFirst 解析服务端首包，计算 salted password。
func (c *scramClient) receiveServerFirst(data []byte) error {
	c.serverFirst = string(data)
	attrs, err := parseSCRAMAttributes(c.serverFirst)
	if err != nil {
		return err
	}
	nonce := attrs["r"]
	if !strings.HasPrefix(nonce, c.clientNonce) || len(nonce) == len(c.clientNonce) {
		return errors.New("dbproxy: SCRAM server nonce does not extend client nonce")
	}
	saltB64 := attrs["s"]
	if saltB64 == "" {
		return errors.New("dbproxy: SCRAM server-first has no salt")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return fmt.Errorf("dbproxy: SCRAM salt is not valid base64: %w", err)
	}
	iter, err := strconv.Atoi(attrs["i"])
	if err != nil || iter < 4096 {
		return fmt.Errorf("dbproxy: SCRAM iteration count %q is not acceptable", attrs["i"])
	}
	salted, err := pbkdf2.Key(sha256.New, c.password, salt, iter, sha256.Size)
	if err != nil {
		return fmt.Errorf("dbproxy: derive SCRAM salted password: %w", err)
	}
	c.saltedPassword = salted
	c.clientFinalBare = "c=biws,r=" + nonce
	c.authMessage = []byte(c.clientFirstBare + "," + c.serverFirst + "," + c.clientFinalBare)
	return nil
}

// clientFinalMessage 返回带 proof 的客户端末包。
func (c *scramClient) clientFinalMessage() ([]byte, error) {
	if c.saltedPassword == nil {
		return nil, errors.New("dbproxy: SCRAM exchange is not initialized")
	}
	clientKey := hmacSHA256(c.saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientSignature := hmacSHA256(storedKey[:], c.authMessage)
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSignature[i]
	}
	final := c.clientFinalBare + ",p=" + base64.StdEncoding.EncodeToString(proof)
	return []byte(final), nil
}

// verifyServerFinal 校验服务端签名；失败即为认证失败。
func (c *scramClient) verifyServerFinal(data []byte) error {
	attrs, err := parseSCRAMAttributes(string(data))
	if err != nil {
		return err
	}
	if e := attrs["e"]; e != "" {
		return fmt.Errorf("dbproxy: SCRAM server reported error %q", e)
	}
	want := attrs["v"]
	if want == "" {
		return errors.New("dbproxy: SCRAM server-final has no verifier")
	}
	// RFC 5802：ServerSignature = HMAC(ServerKey, AuthMessage)，
	// ServerKey = HMAC(SaltedPassword, "Server Key")。
	serverKey := hmacSHA256(c.saltedPassword, []byte("Server Key"))
	serverSignature := hmacSHA256(serverKey, c.authMessage)
	if subtleCompareString(want, base64.StdEncoding.EncodeToString(serverSignature)) != 1 {
		return errors.New("dbproxy: SCRAM server signature mismatch")
	}
	return nil
}

// parseSCRAMAttributes 解析 "k=v,k=v" 形式，忽略扩展属性。
func parseSCRAMAttributes(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		if part == "" {
			continue
		}
		idx := strings.IndexByte(part, '=')
		if idx <= 0 {
			return nil, fmt.Errorf("dbproxy: malformed SCRAM attribute %q", part)
		}
		out[part[:idx]] = part[idx+1:]
	}
	return out, nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// subtleCompareString 用常量时间比较两个字符串。
func subtleCompareString(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}
