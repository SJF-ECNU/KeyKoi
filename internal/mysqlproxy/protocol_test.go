package mysqlproxy

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"testing"
)

func readerFor(b []byte) *bufio.Reader { return bufio.NewReader(bytes.NewReader(b)) }

func TestGreetingRoundTrip(t *testing.T) {
	nonce := make([]byte, 20)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	var buf bytes.Buffer
	if err := writeGreeting(&buf, 42, nonce, pluginCacheSha, true); err != nil {
		t.Fatalf("writeGreeting: %v", err)
	}
	seq, payload, err := readPacket(readerFor(buf.Bytes()))
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	if seq != 0 {
		t.Fatalf("greeting sequence = %d", seq)
	}
	g, err := parseGreeting(payload)
	if err != nil {
		t.Fatalf("parseGreeting: %v", err)
	}
	if g.version != "8.0.0-keykoi" || g.connection != 42 || g.plugin != pluginCacheSha {
		t.Fatalf("greeting = %+v", g)
	}
	if !bytes.Equal(g.nonce, nonce) {
		t.Fatalf("nonce = %x want %x", g.nonce, nonce)
	}
	if g.caps&clientSSL == 0 {
		t.Fatalf("client-facing greeting must offer TLS, caps = %#x", g.caps)
	}
	if g.caps&clientConnectAttrs != 0 {
		t.Fatalf("client-facing greeting must not advertise connect attrs, caps = %#x", g.caps)
	}
}

func TestGreetingWithTLSOffStillParses(t *testing.T) {
	nonce := make([]byte, 20)
	var buf bytes.Buffer
	if err := writeGreeting(&buf, 1, nonce, pluginCacheSha, false); err != nil {
		t.Fatalf("writeGreeting: %v", err)
	}
	_, payload, err := readPacket(readerFor(buf.Bytes()))
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	g, err := parseGreeting(payload)
	if err != nil {
		t.Fatalf("parseGreeting: %v", err)
	}
	if g.caps&clientSSL != 0 {
		t.Fatalf("TLS-off greeting still advertises SSL: caps=%#x", g.caps)
	}
}

func TestNativePasswordScramble(t *testing.T) {
	nonce := []byte("12345678901234567890")
	a := nativePassword("secret", nonce)
	b := nativePassword("secret", nonce)
	if !bytes.Equal(a, b) || len(a) != 20 {
		t.Fatalf("native scramble is not deterministic: %x vs %x", a, b)
	}
	if bytes.Equal(a, nativePassword("secret", []byte("abcdefghij0123456789"))) {
		t.Fatalf("native scramble ignores the nonce")
	}
	if bytes.Equal(a, nativePassword("Secret", nonce)) {
		t.Fatalf("native scramble ignores the password")
	}
	if nativePassword("", nonce) != nil {
		t.Fatalf("empty password must yield an empty response")
	}
	if nativePassword("secret", nonce)[0] == 's' {
		t.Fatalf("scramble must not leak plaintext")
	}
}

func TestCachingSha2Scramble(t *testing.T) {
	nonce := []byte("12345678901234567890")
	a := cachingSha2Password("secret", nonce)
	if len(a) != 32 {
		t.Fatalf("caching_sha2 scramble length = %d", len(a))
	}
	if !bytes.Equal(a, cachingSha2Password("secret", nonce)) {
		t.Fatalf("caching_sha2 scramble is not deterministic")
	}
	if bytes.Equal(a, cachingSha2Password("secret", []byte("abcdefghij0123456789"))) {
		t.Fatalf("caching_sha2 scramble ignores the nonce")
	}
	if cachingSha2Password("", nonce) != nil {
		t.Fatalf("empty password must yield an empty response")
	}
}

func TestRSAEncryptDecryptRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := encodeRSAPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(pubPEM) == 0 {
		t.Fatal("public key PEM is empty")
	}
	nonce := []byte("abcdefghij0123456789")
	// 客户端侧加密（代理只负责解密）：口令 + NUL 与 nonce 异或后 RSA-OAEP 加密。
	plain := xorNonce(append([]byte("token-123"), 0), nonce)
	enc, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, plain, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(enc) != 256 {
		t.Fatalf("ciphertext length = %d", len(enc))
	}
	got, err := rsaDecryptPassword(enc, key, nonce)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != "token-123" {
		t.Fatalf("decrypted token = %q", got)
	}
	// 用错 nonce 必须解出别的内容，而不是悄悄成功。
	other, err := rsaDecryptPassword(enc, key, []byte("0123456789abcdefghij"))
	if err == nil && other == "token-123" {
		t.Fatalf("decryption ignored the nonce")
	}
}

func TestParseClientResponseLenenc(t *testing.T) {
	caps := clientProtocol41 | clientSecureConnection | clientPluginAuth | clientPluginAuthLenencClientData | clientConnectWithDB
	payload := buildClientResponse(caps, "anyuser", "mydb", pluginCacheSha, []byte("0123456789abcdefghij"))
	got, err := parseClientResponse(payload)
	if err != nil {
		t.Fatalf("parseClientResponse: %v", err)
	}
	if got.username != "anyuser" || got.database != "mydb" || got.plugin != pluginCacheSha {
		t.Fatalf("parsed response = %+v", got)
	}
	if string(got.auth) != "0123456789abcdefghij" {
		t.Fatalf("auth = %q", got.auth)
	}
}

func TestParseClientResponseShortAuth(t *testing.T) {
	caps := clientProtocol41 | clientSecureConnection | clientPluginAuth | clientConnectWithDB
	payload := buildClientResponse(caps, "u", "db", pluginCacheSha, []byte("short"))
	got, err := parseClientResponse(payload)
	if err != nil {
		t.Fatalf("parseClientResponse: %v", err)
	}
	if string(got.auth) != "short" || got.database != "db" {
		t.Fatalf("parsed response = %+v", got)
	}
}

func TestOKAndErrorPackets(t *testing.T) {
	ok := okPacket()
	if len(ok) != 7 || ok[0] != 0x00 {
		t.Fatalf("ok packet = %x", ok)
	}
	errp := errorPacket(errAccessDenied, sqlStateAccess, "Access denied: test")
	if errp[0] != 0xff {
		t.Fatalf("error packet = %x", errp)
	}
	errno := uint16(errp[1]) | uint16(errp[2])<<8
	if errno != errAccessDenied {
		t.Fatalf("errno = %d", errno)
	}
	if errp[3] != '#' || string(errp[4:9]) != sqlStateAccess {
		t.Fatalf("sqlstate = %q", errp[3:9])
	}
	if string(errp[9:]) != "Access denied: test" {
		t.Fatalf("message = %q", errp[9:])
	}
}

func TestParseErrPacket(t *testing.T) {
	p := errorPacket(1045, "28000", "Access denied for user")
	errno, msg := parseErrPacket(p)
	if errno != 1045 || msg != "Access denied for user" {
		t.Fatalf("errno=%d msg=%q", errno, msg)
	}
}

func TestLenEncIntegerRoundTrip(t *testing.T) {
	for _, n := range []uint64{0, 1, 250, 251, 65535, 65536, 1 << 23, 1<<24 + 5} {
		enc := putLenEncInt(n)
		got, used, err := readLenEncInt(enc)
		if err != nil {
			t.Fatalf("readLenEncInt(%d): %v", n, err)
		}
		if got != n || used != len(enc) {
			t.Fatalf("roundtrip %d -> %d (used %d of %d)", n, got, used, len(enc))
		}
	}
}
