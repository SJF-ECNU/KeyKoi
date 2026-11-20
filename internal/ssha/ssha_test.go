package ssha

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"keykoi/internal/model"
)

// fakeProvider 是受控内存实现：它记录每次材料申请，便于断言"每次签名都重新取钥"。
type fakeProvider struct {
	mu sync.Mutex

	infos []KeyInfo
	pems  map[string][]byte
	pass  map[string][]byte

	listErr    error
	resolveErr map[string]error

	resolveCalls int
	handedOut    [][]byte
	passOut      [][]byte
}

func (p *fakeProvider) ListKeys(context.Context) ([]KeyInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listErr != nil {
		return nil, p.listErr
	}
	out := make([]KeyInfo, len(p.infos))
	copy(out, p.infos)
	return out, nil
}

func (p *fakeProvider) Sign(_ context.Context, bindingID string, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resolveCalls++
	if err, ok := p.resolveErr[bindingID]; ok {
		return nil, err
	}
	raw, ok := p.pems[bindingID]
	if !ok {
		return nil, model.NewError(model.CodeCredentialUnavailable, "no key for binding %s", bindingID)
	}
	buf := append([]byte(nil), raw...)
	m := &Material{PrivateKeyPEM: buf}
	p.handedOut = append(p.handedOut, buf)
	if pass, ok := p.pass[bindingID]; ok {
		m.Passphrase = append([]byte(nil), pass...)
		p.passOut = append(p.passOut, m.Passphrase)
	}
	return Sign(m, data, flags, nil)
}

func (p *fakeProvider) setInfos(infos ...KeyInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.infos = infos
}

func (p *fakeProvider) counts() (int, [][]byte, [][]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resolveCalls, p.handedOut, p.passOut
}

func (p *fakeProvider) setResolveError(bindingID string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resolveErr == nil {
		p.resolveErr = map[string]error{}
	}
	p.resolveErr[bindingID] = err
}

type keyFixture struct {
	info   KeyInfo
	pub    ssh.PublicKey
	pem    []byte
	pubKey string
}

func newProvider() *fakeProvider {
	return &fakeProvider{pems: map[string][]byte{}, pass: map[string][]byte{}, resolveErr: map[string]error{}}
}

func ed25519Fixture(t *testing.T, binding, label string) keyFixture {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return fixtureFromKey(t, binding, label, priv, nil)
}

func rsaFixture(t *testing.T, binding, label string) keyFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	return fixtureFromKey(t, binding, label, priv, nil)
}

func encryptedEd25519Fixture(t *testing.T, binding, label string, passphrase []byte) keyFixture {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return fixtureFromKey(t, binding, label, priv, passphrase)
}

func fixtureFromKey(t *testing.T, binding, label string, priv any, passphrase []byte) keyFixture {
	t.Helper()
	var (
		block *pem.Block
		err   error
	)
	if len(passphrase) > 0 {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "fixture", passphrase)
	} else {
		block, err = ssh.MarshalPrivateKey(priv, "fixture")
	}
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	pub := signer.PublicKey()
	authorized := string(ssh.MarshalAuthorizedKey(pub))
	info := KeyInfo{
		CredentialID: "cred_" + binding,
		BindingID:    binding,
		Label:        label,
		Algorithm:    pub.Type(),
		Fingerprint:  ssh.FingerprintSHA256(pub),
		PublicKey:    authorized,
	}
	return keyFixture{info: info, pub: pub, pem: pemBytes, pubKey: authorized}
}

func TestListOnlyExposesGrantedKeys(t *testing.T) {
	ed := ed25519Fixture(t, "bind_ed", "ed fixture")
	rsaKey := rsaFixture(t, "bind_rsa", "rsa fixture")
	p := newProvider()
	p.setInfos(ed.info, rsaKey.info)
	p.pems["bind_ed"] = ed.pem
	p.pems["bind_rsa"] = rsaKey.pem

	all := NewAgent(p, "")
	keys, err := all.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 enumerable keys, got %d", len(keys))
	}
	if keys[0].Format != ssh.KeyAlgoED25519 {
		t.Fatalf("expected ed25519 format, got %q", keys[0].Format)
	}
	if keys[0].Comment != "ed fixture" {
		t.Fatalf("expected label as comment, got %q", keys[0].Comment)
	}

	// 单个 Binding 的 agent 只能看到自己的钥匙。
	bound := NewAgent(p, "bind_ed")
	keys, err = bound.List()
	if err != nil {
		t.Fatalf("list bound: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key for the bound agent, got %d", len(keys))
	}

	// 无许可时枚举为空，而不是报错泄露内部状态。
	p.setInfos()
	empty, err := all.List()
	if err != nil {
		t.Fatalf("list without grants: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected no keys without grants, got %d", len(empty))
	}
}

func TestSignEd25519IsVerifiable(t *testing.T) {
	ed := ed25519Fixture(t, "bind_ed", "ed fixture")
	p := newProvider()
	p.setInfos(ed.info)
	p.pems["bind_ed"] = ed.pem
	ag := NewAgent(p, "bind_ed")

	data := []byte("keykoi p4 ssh agent payload")
	sig, err := ag.Sign(ed.pub, data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig.Format != ssh.KeyAlgoED25519 {
		t.Fatalf("expected ssh-ed25519 signature, got %q", sig.Format)
	}
	if err := ed.pub.Verify(data, sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
}

func TestSignRSAHonoursSHA2Flags(t *testing.T) {
	rsaKey := rsaFixture(t, "bind_rsa", "rsa fixture")
	p := newProvider()
	p.setInfos(rsaKey.info)
	p.pems["bind_rsa"] = rsaKey.pem
	ag := NewAgent(p, "bind_rsa")

	data := []byte("keykoi p4 ssh agent rsa payload")
	cases := []struct {
		name  string
		flags agent.SignatureFlags
		want  string
	}{
		{"default", 0, ssh.KeyAlgoRSA},
		{"sha256", agent.SignatureFlagRsaSha256, ssh.KeyAlgoRSASHA256},
		{"sha512", agent.SignatureFlagRsaSha512, ssh.KeyAlgoRSASHA512},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := ag.SignWithFlags(rsaKey.pub, data, tc.flags)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if sig.Format != tc.want {
				t.Fatalf("expected %q signature, got %q", tc.want, sig.Format)
			}
			if err := rsaKey.pub.Verify(data, sig); err != nil {
				t.Fatalf("signature did not verify: %v", err)
			}
		})
	}
}

func TestSignResolvesMaterialPerSignatureAndWipesIt(t *testing.T) {
	ed := ed25519Fixture(t, "bind_ed", "ed fixture")
	p := newProvider()
	p.setInfos(ed.info)
	p.pems["bind_ed"] = ed.pem
	ag := NewAgent(p, "bind_ed")

	for i := 0; i < 2; i++ {
		if _, err := ag.Sign(ed.pub, []byte("payload")); err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
	}
	calls, handedOut, _ := p.counts()
	if calls != 2 {
		t.Fatalf("expected one material resolution per signature, got %d", calls)
	}
	for i, buf := range handedOut {
		if len(buf) == 0 {
			t.Fatalf("material %d was not delivered", i)
		}
		for _, b := range buf {
			if b != 0 {
				t.Fatalf("material %d was not cleared after signing", i)
			}
		}
	}
}

func TestSignEncryptedKeyUsesPassphraseThenWipes(t *testing.T) {
	passphrase := []byte("fixture-passphrase")
	ed := encryptedEd25519Fixture(t, "bind_ed", "ed encrypted", passphrase)
	p := newProvider()
	p.setInfos(ed.info)
	p.pems["bind_ed"] = ed.pem
	p.pass["bind_ed"] = passphrase
	ag := NewAgent(p, "bind_ed")

	sig, err := ag.Sign(ed.pub, []byte("secret payload"))
	if err != nil {
		t.Fatalf("sign with passphrase: %v", err)
	}
	if err := ed.pub.Verify([]byte("secret payload"), sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
	_, _, passOut := p.counts()
	for i, buf := range passOut {
		for _, b := range buf {
			if b != 0 {
				t.Fatalf("passphrase copy %d was not cleared after signing", i)
			}
		}
	}

	// 缺少口令时必须拒绝，且错误码稳定。
	p2 := newProvider()
	p2.setInfos(ed.info)
	p2.pems["bind_ed"] = ed.pem
	if _, err := NewAgent(p2, "bind_ed").Sign(ed.pub, []byte("x")); err == nil {
		t.Fatal("expected encrypted key without passphrase to be rejected")
	} else if code := model.CodeOf(err); code != model.CodeCredentialUnavailable {
		t.Fatalf("expected CREDENTIAL_UNAVAILABLE, got %q", code)
	}
}

func TestSignDeniedAfterRevocation(t *testing.T) {
	ed := ed25519Fixture(t, "bind_ed", "ed fixture")
	p := newProvider()
	p.setInfos(ed.info)
	p.pems["bind_ed"] = ed.pem
	ag := NewAgent(p, "bind_ed")

	// 撤销后后台不再枚举该钥匙。
	p.setInfos()
	if keys, err := ag.List(); err != nil || len(keys) != 0 {
		t.Fatalf("expected no enumerated keys after revocation, got %d (err=%v)", len(keys), err)
	}
	_, err := ag.Sign(ed.pub, []byte("payload"))
	if err == nil {
		t.Fatal("expected signing to fail after revocation")
	}
	if code := model.CodeOf(err); code != model.CodeUseNotAllowed {
		t.Fatalf("expected USE_NOT_ALLOWED, got %q (%v)", code, err)
	}

	// 许可在枚举与签名之间被撤销：枚举仍列出，但取钥被拒。
	p.setInfos(ed.info)
	denied := model.NewError(model.CodeUseNotAllowed, "no active sign grant for binding bind_ed")
	p.setResolveError("bind_ed", denied)
	_, err = ag.Sign(ed.pub, []byte("payload"))
	if err == nil {
		t.Fatal("expected signing to fail when the grant is revoked")
	}
	if code := model.CodeOf(err); code != model.CodeUseNotAllowed {
		t.Fatalf("expected USE_NOT_ALLOWED from resolve, got %q (%v)", code, err)
	}
}

func TestSignRejectsUnknownKey(t *testing.T) {
	ed := ed25519Fixture(t, "bind_ed", "ed fixture")
	other := ed25519Fixture(t, "bind_other", "other fixture")
	p := newProvider()
	p.setInfos(ed.info)
	p.pems["bind_ed"] = ed.pem

	_, err := NewAgent(p, "bind_ed").Sign(other.pub, []byte("payload"))
	if err == nil {
		t.Fatal("expected signing with an unmanaged key to fail")
	}
	if code := model.CodeOf(err); code != model.CodeUseNotAllowed {
		t.Fatalf("expected USE_NOT_ALLOWED, got %q", code)
	}
	if calls, _, _ := p.counts(); calls != 0 {
		t.Fatalf("unmanaged key must not trigger a material resolution, got %d", calls)
	}
}

func TestSignersStayLazy(t *testing.T) {
	ed := ed25519Fixture(t, "bind_ed", "ed fixture")
	p := newProvider()
	p.setInfos(ed.info)
	p.pems["bind_ed"] = ed.pem
	ag := NewAgent(p, "bind_ed")

	signers, err := ag.Signers()
	if err != nil {
		t.Fatalf("signers: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}
	if calls, _, _ := p.counts(); calls != 0 {
		t.Fatalf("listing signers must not resolve key material, got %d calls", calls)
	}
	data := []byte("lazy signer payload")
	sig, err := signers[0].Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("signer sign: %v", err)
	}
	if err := ed.pub.Verify(data, sig); err != nil {
		t.Fatalf("signer signature did not verify: %v", err)
	}
}

func TestMutationOperationsRejected(t *testing.T) {
	p := newProvider()
	ag := NewAgent(p, "")

	ops := map[string]error{
		"add":        ag.Add(agent.AddedKey{}),
		"remove":     ag.Remove(nil),
		"remove_all": ag.RemoveAll(),
		"lock":       ag.Lock([]byte("x")),
		"unlock":     ag.Unlock([]byte("x")),
	}
	for name, err := range ops {
		if err == nil {
			t.Fatalf("%s should be rejected", name)
		}
		if code := model.CodeOf(err); code != model.CodeAdapterUnsupported {
			t.Fatalf("%s: expected ADAPTER_UNSUPPORTED, got %q", name, code)
		}
	}
	if _, err := ag.Extension("query", nil); err != agent.ErrExtensionUnsupported {
		t.Fatalf("expected extension unsupported, got %v", err)
	}
}

func TestServerServesAgentProtocolOverUnixSocket(t *testing.T) {
	ed := ed25519Fixture(t, "bind_ed", "ed fixture")
	p := newProvider()
	p.setInfos(ed.info)
	p.pems["bind_ed"] = ed.pem

	dir, err := os.MkdirTemp("", "ssha")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	sockPath := filepath.Join(dir, "agent.sock")

	srv := NewServer(sockPath, NewAgent(p, "bind_ed"))
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer func() { _ = srv.Close() }()

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected 0600 socket, got %o", perm)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial agent socket: %v", err)
	}
	defer conn.Close()
	client := agent.NewClient(conn)

	keys, err := client.List()
	if err != nil {
		t.Fatalf("client list: %v", err)
	}
	if len(keys) != 1 || keys[0].Comment != "ed fixture" {
		t.Fatalf("unexpected enumeration: %+v", keys)
	}

	data := []byte("over the socket")
	sig, err := client.Sign(ed.pub, data)
	if err != nil {
		t.Fatalf("client sign: %v", err)
	}
	if err := ed.pub.Verify(data, sig); err != nil {
		t.Fatalf("socket signature did not verify: %v", err)
	}

	// 撤销后同一 socket 上的枚举与签名都必须失败。
	p.setInfos()
	p.setResolveError("bind_ed", model.NewError(model.CodeUseNotAllowed, "revoked"))
	if keys, err := client.List(); err != nil || len(keys) != 0 {
		t.Fatalf("expected empty enumeration after revocation, got %d (err=%v)", len(keys), err)
	}
	if _, err := client.Sign(ed.pub, data); err == nil {
		t.Fatal("expected signing over the socket to fail after revocation")
	}
}

func TestInspectPrivateKeyDerivesPublicMetadata(t *testing.T) {
	ed := ed25519Fixture(t, "bind_ed", "ed fixture")
	info, err := InspectPrivateKey(ed.pem, nil)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if info.Algorithm != ssh.KeyAlgoED25519 {
		t.Fatalf("expected ssh-ed25519, got %q", info.Algorithm)
	}
	if info.Fingerprint != ssh.FingerprintSHA256(ed.pub) {
		t.Fatalf("fingerprint mismatch: %q", info.Fingerprint)
	}
	if strings.TrimSpace(info.AuthorizedKey) != strings.TrimSpace(ed.pubKey) {
		t.Fatalf("authorized key mismatch: %q", info.AuthorizedKey)
	}
	if bytes.Contains([]byte(info.AuthorizedKey), []byte("PRIVATE KEY")) {
		t.Fatal("public metadata must not contain private material")
	}
}
