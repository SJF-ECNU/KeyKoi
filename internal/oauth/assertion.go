package oauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"time"

	"keykoi/internal/secret"
)

// MaxAssertionLifetime 是 JWT 断言允许的最长有效期。
// 服务账号断言的有效期不得超过 1 小时，超出的输入在此处被夹紧而不是把
// 非法断言发给上游。
const MaxAssertionLifetime = time.Hour

// minAssertionKeyBits 是断言签名可接受的最小 RSA 模数。
// 服务账号私钥通常是 2048 位；更短的密钥不应被用来代表服务身份。
const minAssertionKeyBits = 2048

// Assertion 是一次 RS256 JWT 断言的签名输入。
// 所有字段都来自凭证版本，本类型不读存储、不访问网络。
type Assertion struct {
	// Issuer 是断言签发者，即服务账号的 client_email。
	Issuer string
	// PrivateKey 是 PEM 编码的 RSA 私钥（PKCS#8 或 PKCS#1）。
	PrivateKey secret.Value
	// Scope 是请求的权限范围，写入 scope 声明。
	Scope string
	// Audience 是断言目标，通常是 token_uri。
	Audience string
	// IssuedAt 是签发时刻；零值表示使用当前时间。
	IssuedAt time.Time
	// Lifetime 是断言有效期；零值或超过 1 小时都按 1 小时处理。
	Lifetime time.Duration
}

// SignJWTAssertion 用 PEM RSA 私钥签一个 RS256 JWT 断言。
//
// 断言声明固定为 iss/aud/iat/exp（scope 非空时附带），不包含任何 secret 字段；
// 返回的错误只说明字段或格式问题，不包含私钥内容。
func SignJWTAssertion(a Assertion) (string, error) {
	if strings.TrimSpace(a.Issuer) == "" {
		return "", configError("jwt assertion: issuer is required")
	}
	if strings.TrimSpace(a.Audience) == "" {
		return "", configError("jwt assertion: audience is required")
	}
	key, err := parseRSAPrivateKey(a.PrivateKey.RevealString())
	if err != nil {
		return "", err
	}
	now := a.IssuedAt.UTC()
	if a.IssuedAt.IsZero() {
		now = time.Now().UTC()
	}
	lifetime := a.Lifetime
	if lifetime <= 0 || lifetime > MaxAssertionLifetime {
		lifetime = MaxAssertionLifetime
	}

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iss": a.Issuer,
		"aud": a.Audience,
		"iat": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
	}
	if scope := strings.TrimSpace(a.Scope); scope != "" {
		claims["scope"] = scope
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", localError("assertion", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", localError("assertion", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", localError("assertion", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// parseRSAPrivateKey 解析 PEM 私钥并校验它是可用的 RSA 密钥。
// 错误信息只描述形态问题，不回显密钥内容。
func parseRSAPrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return nil, configError("jwt assertion: private_key is not a PEM block")
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, configError("jwt assertion: private_key must not be encrypted")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, configError("jwt assertion: private_key is not a valid PKCS#1 RSA key")
		}
		key = parsed
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, configError("jwt assertion: private_key is not a valid PKCS#8 key")
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, configError("jwt assertion: private_key is not an RSA key")
		}
		key = rsaKey
	default:
		return nil, configError("jwt assertion: private_key must be a PKCS#1 or PKCS#8 RSA PEM block")
	}
	if key.N == nil || key.N.BitLen() < minAssertionKeyBits {
		return nil, configError("jwt assertion: private_key must be an RSA key of at least %d bits", minAssertionKeyBits)
	}
	if err := key.Validate(); err != nil {
		return nil, configError("jwt assertion: private_key is not a consistent RSA key")
	}
	return key, nil
}
