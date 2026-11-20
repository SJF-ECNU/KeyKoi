// Package tlsproxy 实现工具级受信 HTTPS 代理：只对已登记 Binding 的域名终止
// 客户端 TLS、验证真实上游证书并注入认证头；未登记域名在 CONNECT 阶段拒绝。
package tlsproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	caCertFile = "ca.pem"
	caKeyFile  = "ca-key.pem"

	// caLifetime 是本机 CA 的有效期。它只用于本机工具级代理验收。
	caLifetime = 10 * 365 * 24 * time.Hour
	// leafLifetime 是动态签发叶子证书的有效期；短期限降低私钥暴露价值。
	leafLifetime = 7 * 24 * time.Hour
)

// CA 是本机受信代理的证书颁发机构。私钥只落在调用方指定的目录并限制为 0600；
// 公开证书交给客户端以 --cacert 信任。
type CA struct {
	dir     string
	now     func() time.Time
	cert    *x509.Certificate
	certDER []byte
	certPEM []byte
	key     *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// LoadOrCreateCA 加载目录中的 CA；不存在时生成并写出。目录权限固定为 0700。
func LoadOrCreateCA(dir string, now func() time.Time) (*CA, error) {
	if dir == "" {
		return nil, errors.New("tlsproxy: ca directory is required")
	}
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("tlsproxy: prepare ca directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("tlsproxy: restrict ca directory: %w", err)
	}
	ca := &CA{dir: dir, now: now, leaves: map[string]*tls.Certificate{}}
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		if err := ca.load(certPEM, keyPEM); err != nil {
			return nil, err
		}
		// 保证已有私钥仍然只有当前用户可读。
		if err := os.Chmod(keyPath, 0o600); err != nil {
			return nil, fmt.Errorf("tlsproxy: restrict ca key: %w", err)
		}
		return ca, nil
	case certErr == nil || keyErr == nil:
		return nil, fmt.Errorf("tlsproxy: incomplete CA material in %s (need both %s and %s)", dir, caCertFile, caKeyFile)
	}
	if !os.IsNotExist(certErr) {
		return nil, fmt.Errorf("tlsproxy: read ca certificate: %w", certErr)
	}
	if !os.IsNotExist(keyErr) {
		return nil, fmt.Errorf("tlsproxy: read ca key: %w", keyErr)
	}
	if err := ca.generate(); err != nil {
		return nil, err
	}
	// 私钥 0600；公开证书 0644。用 O_EXCL 避免并发生成互相覆盖。
	if err := writeFileExclusive(keyPath, ca.keyPEM(), 0o600); err != nil {
		return nil, fmt.Errorf("tlsproxy: write ca key: %w", err)
	}
	if err := writeFileExclusive(certPath, ca.certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("tlsproxy: write ca certificate: %w", err)
	}
	return ca, nil
}

// CertPath 返回公开 CA 证书的路径，供客户端 --cacert 使用。
func (c *CA) CertPath() string { return filepath.Join(c.dir, caCertFile) }

// CertPEM 返回公开 CA 证书字节。
func (c *CA) CertPEM() []byte {
	cp := make([]byte, len(c.certPEM))
	copy(cp, c.certPEM)
	return cp
}

// Pool 返回只含本机 CA 的信任池，便于测试与客户端配置。
func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

// CertificateForHost 为单个目标域名签发叶子证书。
func (c *CA) CertificateForHost(host string) (*tls.Certificate, error) {
	return c.CertificateForHosts(host)
}

// CertificateForHosts 为多个名称签发一张叶子证书（域名与 IP 自动区分）。
func (c *CA) CertificateForHosts(hosts ...string) (*tls.Certificate, error) {
	names := make([]string, 0, len(hosts))
	seen := map[string]bool{}
	for _, h := range hosts {
		h = normalizeHost(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		names = append(names, h)
	}
	if len(names) == 0 {
		return nil, errors.New("tlsproxy: no host name for certificate")
	}
	sort.Strings(names)
	key := strings.Join(names, ",")

	c.mu.Lock()
	if leaf, ok := c.leaves[key]; ok {
		cp := *leaf
		c.mu.Unlock()
		return &cp, nil
	}
	c.mu.Unlock()

	leaf, err := c.issue(names)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.leaves[key] = leaf
	cp := *leaf
	c.mu.Unlock()
	return &cp, nil
}

func (c *CA) generate() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("tlsproxy: generate ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := c.now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "KeyKoi Local TLS Proxy CA", Organization: []string{"KeyKoi"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("tlsproxy: create ca certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("tlsproxy: parse ca certificate: %w", err)
	}
	c.key = key
	c.cert = cert
	c.certDER = der
	c.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return nil
}

func (c *CA) load(certPEM, keyPEM []byte) error {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("tlsproxy: %s does not contain a certificate", caCertFile)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("tlsproxy: parse ca certificate: %w", err)
	}
	if !cert.IsCA {
		return fmt.Errorf("tlsproxy: %s is not a CA certificate", caCertFile)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("tlsproxy: %s does not contain a private key", caKeyFile)
	}
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("tlsproxy: parse ca key: %w", err)
		}
		c.key = key
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("tlsproxy: parse ca key: %w", err)
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("tlsproxy: ca key is not an EC private key")
		}
		c.key = key
	default:
		return fmt.Errorf("tlsproxy: unsupported ca key type %q", keyBlock.Type)
	}
	c.cert = cert
	c.certDER = cert.Raw
	c.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return nil
}

func (c *CA) keyPEM() []byte {
	der, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		// 生成路径上的 key 必然可序列化；这里只可能是内存损坏。
		panic("tlsproxy: marshal ca key: " + err.Error())
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func (c *CA) issue(names []string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsproxy: generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := c.now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{"KeyKoi"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("tlsproxy: issue leaf certificate for %s: %w", names[0], err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tlsproxy: parse leaf certificate: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("tlsproxy: generate certificate serial: %w", err)
	}
	return serial, nil
}

func writeFileExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}
