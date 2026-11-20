// Package ssha 实现受保护的本地 SSH Agent 服务端。
//
// 约束：agent 不持有长期私钥。每次签名都通过本机 IPC 向受信中介申请一次材料，
// 解析后立即清除明文缓冲，签名完成即丢弃引用。私钥、完整待签数据与签名材料
// 都不进入日志；可审计的只有会话、Binding、凭证与结果等元数据。
package ssha

import (
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"keykoi/internal/model"
)

// KeyInfo 描述一个当前会话可用的托管密钥。
// 它只含元数据与公钥；公钥不是秘密，私钥永不出现。
type KeyInfo struct {
	CredentialID string `json:"credential_id"`
	BindingID    string `json:"binding_id"`
	Label        string `json:"label"`
	Algorithm    string `json:"algorithm"`
	Fingerprint  string `json:"fingerprint"`
	// PublicKey 是 authorized_keys 格式的公钥行，供 SSH 客户端识别枚举结果。
	PublicKey string `json:"public_key"`
	// ErrorCode 记录该条目不完整的稳定原因（例如密钥库锁定）；此时 PublicKey 为空。
	ErrorCode string `json:"error_code,omitempty"`
}

// Provider 由受信中介提供密钥元数据与一次性签名材料。
type Provider interface {
	// ListKeys 只返回当前会话持有 sign 许可的托管密钥元数据。
	ListKeys(ctx context.Context) ([]KeyInfo, error)
	// ResolveMaterial 按 Binding 取得一次签名材料；调用方负责 Wipe。
	ResolveMaterial(ctx context.Context, bindingID string) (*Material, error)
}

// Material 是一次签名所需的私钥材料，生存期只覆盖一次签名。
type Material struct {
	PrivateKeyPEM []byte
	Passphrase    []byte
}

// Wipe 尽力清除明文缓冲并丢弃引用。
func (m *Material) Wipe() {
	if m == nil {
		return
	}
	zero(m.PrivateKeyPEM)
	zero(m.Passphrase)
	m.PrivateKeyPEM = nil
	m.Passphrase = nil
}

// Signer 解析材料并立即清除 PEM 与口令副本，随后只保留签名器引用。
func (m *Material) Signer() (ssh.Signer, error) {
	if m == nil {
		return nil, model.NewError(model.CodeCredentialUnavailable, "no private key material was resolved")
	}
	raw, err := parseRawPrivateKey(m.PrivateKeyPEM, m.Passphrase)
	// 无论解析成功与否，明文材料到此为止。
	m.Wipe()
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, model.NewError(model.CodeAdapterUnsupported, "key type is not supported for ssh signing")
	}
	return signer, nil
}

// PublicKeyInfo 是不含秘密的托管公钥描述。
type PublicKeyInfo struct {
	Algorithm     string
	Fingerprint   string
	AuthorizedKey string
}

// InspectPrivateKey 从 PEM/OpenSSH 私钥推导公钥元数据。调用方负责在返回后清除入参副本。
func InspectPrivateKey(pemBytes, passphrase []byte) (PublicKeyInfo, error) {
	raw, err := parseRawPrivateKey(pemBytes, passphrase)
	if err != nil {
		return PublicKeyInfo{}, err
	}
	pub, err := publicKeyOf(raw)
	if err != nil {
		return PublicKeyInfo{}, err
	}
	return PublicKeyInfo{
		Algorithm:     pub.Type(),
		Fingerprint:   ssh.FingerprintSHA256(pub),
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
	}, nil
}

// Sign 用一次取得的材料生成签名，并立即丢弃材料引用。
// flags 只用于 RSA 的 SHA-2 变体；其他算法按密钥自身类型签名。
func Sign(m *Material, data []byte, flags agent.SignatureFlags, rnd io.Reader) (*ssh.Signature, error) {
	signer, err := m.Signer()
	if err != nil {
		return nil, err
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	algo := ""
	switch {
	case flags&agent.SignatureFlagRsaSha256 != 0:
		algo = ssh.KeyAlgoRSASHA256
	case flags&agent.SignatureFlagRsaSha512 != 0:
		algo = ssh.KeyAlgoRSASHA512
	}
	if algo != "" && signer.PublicKey().Type() != ssh.KeyAlgoRSA {
		// RSA SHA-2 标志对其他算法没有意义，按默认算法签名。
		algo = ""
	}
	if algo != "" {
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, model.NewError(model.CodeAdapterUnsupported,
				"key type %s cannot produce %s signatures", signer.PublicKey().Type(), algo)
		}
		return as.SignWithAlgorithm(rnd, data, algo)
	}
	return signer.Sign(rnd, data)
}

func parseRawPrivateKey(pemBytes, passphrase []byte) (any, error) {
	if len(pemBytes) == 0 {
		return nil, model.NewError(model.CodeCredentialUnavailable, "credential has no private_key field")
	}
	var (
		raw any
		err error
	)
	if len(passphrase) > 0 {
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
	} else {
		raw, err = ssh.ParseRawPrivateKey(pemBytes)
	}
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, model.NewError(model.CodeCredentialUnavailable,
				"private key is encrypted; credential has no private_key_passphrase")
		}
		return nil, model.WrapError(model.CodeCredentialUnavailable, err, "private key could not be parsed")
	}
	return raw, nil
}

func publicKeyOf(raw any) (ssh.PublicKey, error) {
	switch k := raw.(type) {
	case ed25519.PrivateKey:
		return ssh.NewPublicKey(k.Public())
	case *ed25519.PrivateKey:
		return ssh.NewPublicKey(k.Public())
	case *rsa.PrivateKey:
		return ssh.NewPublicKey(&k.PublicKey)
	case *ecdsa.PrivateKey:
		return ssh.NewPublicKey(&k.PublicKey)
	case *dsa.PrivateKey:
		return ssh.NewPublicKey(&k.PublicKey)
	default:
		return nil, model.NewError(model.CodeAdapterUnsupported, "unsupported private key type %T", raw)
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
