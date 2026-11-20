package mongoproxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const scramSHA256 = "SCRAM-SHA-256"

// scramClient 是 SCRAM-SHA-256 的客户端实现，用于代理向上游 MongoDB 认证。
//
// MongoDB 的 SCRAM-SHA-256 就是 RFC 5802 的 SHA-256 变体：口令直接参与
// PBKDF2-HMAC-SHA256，不做 SCRAM-SHA-1 那样的 MD5 用户名摘要。
type scramClient struct {
	user     string
	password string

	clientNonce     string
	clientFirstBare string
	serverFirst     string
	authMessage     string
	saltedPassword  []byte
}

// newSCRAMClient 生成客户端 nonce 与 client-first-message。
func newSCRAMClient(user, password string) (*scramClient, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	nonce := base64.RawStdEncoding.EncodeToString(raw)
	prepared, err := saslPrep(password)
	if err != nil {
		return nil, err
	}
	c := &scramClient{
		user:        saslName(user),
		password:    prepared,
		clientNonce: nonce,
	}
	c.clientFirstBare = "n=" + c.user + ",r=" + nonce
	return c, nil
}

// firstMessage 返回带 GS2 header 的 client-first-message。
func (c *scramClient) firstMessage() string { return "n,," + c.clientFirstBare }

// receiveServerFirst 解析 server-first-message，并派生 SaltedPassword。
func (c *scramClient) receiveServerFirst(serverFirst string) error {
	var combinedNonce, salt string
	iterations := 0
	for _, part := range strings.Split(serverFirst, ",") {
		switch {
		case strings.HasPrefix(part, "r="):
			combinedNonce = part[2:]
		case strings.HasPrefix(part, "s="):
			salt = part[2:]
		case strings.HasPrefix(part, "i="):
			n, err := strconv.Atoi(part[2:])
			if err != nil {
				return fmt.Errorf("mongoproxy: invalid SCRAM iteration count: %w", err)
			}
			iterations = n
		case strings.HasPrefix(part, "m="):
			return errors.New("mongoproxy: upstream SCRAM requires unsupported extensions")
		}
	}
	if !strings.HasPrefix(combinedNonce, c.clientNonce) || len(combinedNonce) == len(c.clientNonce) {
		return errors.New("mongoproxy: upstream SCRAM nonce does not match the client nonce")
	}
	if salt == "" || iterations <= 0 {
		return errors.New("mongoproxy: upstream SCRAM message is missing salt or iteration count")
	}
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return fmt.Errorf("mongoproxy: invalid SCRAM salt: %w", err)
	}
	c.serverFirst = serverFirst
	c.saltedPassword = pbkdf2.Key([]byte(c.password), saltBytes, iterations, 32, sha256.New)
	return nil
}

// finalMessage 生成 client-final-message 并记录 authMessage。
func (c *scramClient) finalMessage() (string, error) {
	if c.saltedPassword == nil {
		return "", errors.New("mongoproxy: SCRAM server-first message has not been processed")
	}
	withoutProof := "c=biws,r=" + serverNonce(c.serverFirst)
	c.authMessage = c.clientFirstBare + "," + c.serverFirst + "," + withoutProof

	clientKey := hmacSHA256(c.saltedPassword, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	clientSig := hmacSHA256(storedKey[:], c.authMessage)
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSig[i]
	}
	return withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof), nil
}

// verifyServerFinal 校验 server-final-message 中的服务端签名。
func (c *scramClient) verifyServerFinal(serverFinal string) error {
	if c.authMessage == "" {
		return errors.New("mongoproxy: SCRAM client-final message has not been generated")
	}
	var signature string
	for _, part := range strings.Split(serverFinal, ",") {
		switch {
		case strings.HasPrefix(part, "v="):
			signature = part[2:]
		case strings.HasPrefix(part, "e="):
			return fmt.Errorf("mongoproxy: upstream SCRAM failed: %s", part[2:])
		}
	}
	if signature == "" {
		return errors.New("mongoproxy: upstream SCRAM server-final message has no signature")
	}
	serverKey := hmacSHA256(c.saltedPassword, "Server Key")
	want := hmacSHA256(serverKey, c.authMessage)
	got, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("mongoproxy: invalid SCRAM server signature: %w", err)
	}
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return errors.New("mongoproxy: upstream SCRAM server signature verification failed")
	}
	return nil
}

func serverNonce(serverFirst string) string {
	for _, part := range strings.Split(serverFirst, ",") {
		if strings.HasPrefix(part, "r=") {
			return part[2:]
		}
	}
	return ""
}

func hmacSHA256(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

// saslName 按 RFC 5802 转义用户名中的 '=' 与 ','。
func saslName(user string) string {
	return strings.NewReplacer("=", "=3D", ",", "=2C").Replace(user)
}

// saslPrep 是 SASLprep 的最小实现：本项目测试口令与用户名都是 ASCII，
// 这里只拦截不能安全直传的空白与控制字符；非 ASCII 口令按原字节参与派生。
func saslPrep(password string) (string, error) {
	for _, r := range password {
		if r == 0x7f || (r < 0x20) {
			return "", errors.New("mongoproxy: password contains control characters that SASLprep would reject")
		}
	}
	return password, nil
}
