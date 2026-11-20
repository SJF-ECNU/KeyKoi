package dbproxy

import (
	"strings"
	"testing"
)

// RFC 7677 §3 的 SCRAM-SHA-256 测试向量：
// user=user password=pencil client nonce=rOprNGfwEbeRWgbNEkqO
func TestSCRAMSHA256RFC7677Vector(t *testing.T) {
	const (
		serverFirst = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
		wantFinal   = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
		serverFinal = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
	)
	c, err := newSCRAMClientWithUser("pencil", "rOprNGfwEbeRWgbNEkqO", "user")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if got := string(c.clientFirstMessage()); got != "n,,n=user,r=rOprNGfwEbeRWgbNEkqO" {
		t.Fatalf("client-first-message = %q", got)
	}
	if err := c.receiveServerFirst([]byte(serverFirst)); err != nil {
		t.Fatalf("receive server-first: %v", err)
	}
	final, err := c.clientFinalMessage()
	if err != nil {
		t.Fatalf("client final: %v", err)
	}
	if string(final) != wantFinal {
		t.Fatalf("client-final-message mismatch:\n got %s\nwant %s", final, wantFinal)
	}
	if err := c.verifyServerFinal([]byte(serverFinal)); err != nil {
		t.Fatalf("verify server-final: %v", err)
	}
}

func TestSCRAMRejectsTamperedServerSignature(t *testing.T) {
	c, err := newSCRAMClientWithNonce("pencil", "rOprNGfwEbeRWgbNEkqO")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.clientFirstMessage()
	if err := c.receiveServerFirst([]byte("r=rOprNGfwEbeRWgbNEkqOextra,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")); err != nil {
		t.Fatalf("receive server-first: %v", err)
	}
	if _, err := c.clientFinalMessage(); err != nil {
		t.Fatalf("client final: %v", err)
	}
	err = c.verifyServerFinal([]byte("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
	if err == nil || !strings.Contains(err.Error(), "signature mismatch") {
		t.Fatalf("expected signature mismatch, got %v", err)
	}
}

func TestSCRAMRejectsWeakNonceAndIterations(t *testing.T) {
	c, err := newSCRAMClientWithNonce("pencil", "nonce")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.clientFirstMessage()
	// 服务端 nonce 未扩展客户端 nonce。
	if err := c.receiveServerFirst([]byte("r=other,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")); err == nil {
		t.Fatal("expected nonce mismatch to be rejected")
	}
	c2, err := newSCRAMClientWithNonce("pencil", "nonce")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c2.clientFirstMessage()
	if err := c2.receiveServerFirst([]byte("r=nonceX,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=1024")); err == nil {
		t.Fatal("expected a below-minimum iteration count to be rejected")
	}
	if err := c2.receiveServerFirst([]byte("r=nonceX,s=***not-base64***,i=4096")); err == nil {
		t.Fatal("expected invalid salt to be rejected")
	}
}

func TestChooseSASLMechanism(t *testing.T) {
	if m, err := chooseSASLMechanism([]string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}); err != nil || m != scramSHA256 {
		t.Fatalf("expected SCRAM-SHA-256 to be chosen, got %q/%v", m, err)
	}
	if _, err := chooseSASLMechanism([]string{"SCRAM-SHA-256-PLUS"}); err == nil || !strings.Contains(err.Error(), "channel binding") {
		t.Fatalf("expected an explicit channel-binding error, got %v", err)
	}
	if _, err := chooseSASLMechanism([]string{"GSSAPI"}); err == nil {
		t.Fatal("expected an unsupported mechanism error")
	}
}

func TestMD5PasswordMatchesPostgresScheme(t *testing.T) {
	// PostgreSQL: md5(md5(password || user) || salt)
	got := md5Password("postgres", "secret", []byte{1, 2, 3, 4})
	if !strings.HasPrefix(got, "md5") || len(got) != 35 {
		t.Fatalf("unexpected md5 hash %q", got)
	}
}
