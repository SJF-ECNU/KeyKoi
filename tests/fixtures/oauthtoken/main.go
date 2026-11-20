// Command oauthtoken 是受控 OAuth 2.0 token 端点，同时充当受控上游，用于
// oauth-client-credentials 验收：它按 client_credentials 与
// urn:ietf:params:oauth:grant-type:jwt-bearer 两种授予签发短期 token，
// 记录换取次数与客户端认证方式，并只接受自己签发的 Bearer 访问 /api/*。
//
// 它只监听 127.0.0.1，所有令牌在运行时生成，不接触任何真实服务商凭据。
// fixture 专用端点：/stats（计数）、/tokens（泄漏检查用，仅本地）、
// /control（切换失败模式与有效期）。
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type state struct {
	mu sync.Mutex

	clientID     string
	clientSecret string
	clientEmail  string
	publicKey    *rsa.PublicKey
	tokenURI     string
	scope        string
	expiresIn    int64

	failStatus int
	failCode   string

	tokens    map[string]time.Time
	issued    []string
	grantType map[string]int

	tokenRequests   int
	clientAuthBasic int
	clientAuthPost  int
	rejectedClient  int
	jwtRequests     int
	jwtVerified     int
	jwtBadSignature int
	jwtBadClaims    int
	lastScope       string

	upstreamRequests int
	upstreamMatched  int
	upstreamRejected int
	sessionTokens    int
}

func randomString(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (s *state) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "invalid_request"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	form := r.PostForm
	s.mu.Lock()
	s.tokenRequests++
	grant := form.Get("grant_type")
	if s.grantType == nil {
		s.grantType = map[string]int{}
	}
	s.grantType[grant]++
	failStatus, failCode := s.failStatus, s.failCode
	expiresIn := s.expiresIn
	s.mu.Unlock()

	if failStatus != 0 {
		if failCode == "" {
			failCode = "server_error"
		}
		writeJSON(w, failStatus, map[string]any{"error": failCode, "error_description": "controlled failure"})
		return
	}

	switch grant {
	case "client_credentials":
		user, pass, ok := r.BasicAuth()
		mode := "basic"
		if !ok {
			mode = "post"
			user, pass = form.Get("client_id"), form.Get("client_secret")
		}
		s.mu.Lock()
		if mode == "basic" {
			s.clientAuthBasic++
		} else {
			s.clientAuthPost++
		}
		wantID, wantSecret := s.clientID, s.clientSecret
		s.mu.Unlock()
		if user != wantID || pass != wantSecret {
			s.mu.Lock()
			s.rejectedClient++
			s.mu.Unlock()
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
			return
		}
		scope := form.Get("scope")
		s.mu.Lock()
		s.lastScope = scope
		wantScope := s.scope
		s.mu.Unlock()
		if wantScope != "" && scope != wantScope {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_scope"})
			return
		}
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		assertion := form.Get("assertion")
		s.mu.Lock()
		s.jwtRequests++
		s.mu.Unlock()
		if err := s.verifyAssertion(assertion); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": err.Error()})
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
		return
	}

	token := "at_" + randomString(24)
	s.mu.Lock()
	if s.tokens == nil {
		s.tokens = map[string]time.Time{}
	}
	s.tokens[token] = time.Now().Add(time.Duration(expiresIn) * time.Second)
	s.issued = append(s.issued, token)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
		"scope":        form.Get("scope"),
	})
}

// verifyAssertion 独立验证 RS256 签名与 GCP 服务账号断言的声明。
// 它不依赖 KeyKoi 的签名实现，确保验收校验的是真实签名结果。
func (s *state) verifyAssertion(assertion string) error {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return fmt.Errorf("assertion is not a compact JWT")
	}
	s.mu.Lock()
	pub := s.publicKey
	email := s.clientEmail
	audience := s.tokenURI
	wantScope := s.scope
	s.mu.Unlock()
	if pub == nil {
		return fmt.Errorf("fixture has no public key to verify the assertion")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("assertion signature is not base64url")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		s.mu.Lock()
		s.jwtBadSignature++
		s.mu.Unlock()
		return fmt.Errorf("assertion signature does not verify")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("assertion header is not base64url")
	}
	var header map[string]any
	if err := json.Unmarshal(rawHeader, &header); err != nil || header["alg"] != "RS256" {
		return fmt.Errorf("assertion must use RS256")
	}
	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("assertion claims are not base64url")
	}
	var claims struct {
		Issuer string `json:"iss"`
		Aud    string `json:"aud"`
		Scope  string `json:"scope"`
		Issued int64  `json:"iat"`
		Expiry int64  `json:"exp"`
	}
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return fmt.Errorf("assertion claims are not JSON")
	}
	now := time.Now().Unix()
	bad := ""
	switch {
	case claims.Issuer != email:
		bad = "iss does not match client_email"
	case claims.Aud != audience:
		bad = "aud does not match token_uri"
	case wantScope != "" && claims.Scope != wantScope:
		bad = "scope claim does not match the requested scope"
	case claims.Expiry <= now:
		bad = "assertion is expired"
	case claims.Issued > now+60:
		bad = "assertion iat is in the future"
	case claims.Expiry-claims.Issued > 3600:
		bad = "assertion lifetime exceeds 1h"
	}
	if bad != "" {
		s.mu.Lock()
		s.jwtBadClaims++
		s.mu.Unlock()
		return fmt.Errorf("%s", bad)
	}
	s.mu.Lock()
	s.jwtVerified++
	s.mu.Unlock()
	return nil
}

// handleAPI 是受控上游：只接受 fixture 自己签发且未过期的 Bearer token。
func (s *state) handleAPI(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.upstreamRequests++
	for _, values := range r.Header {
		for _, value := range values {
			if strings.Contains(value, "kks_") {
				s.sessionTokens++
			}
		}
	}
	s.mu.Unlock()

	auth := r.Header.Get("Authorization")
	matched := false
	if strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		s.mu.Lock()
		expiry, ok := s.tokens[token]
		matched = ok && time.Now().Before(expiry)
		if matched {
			s.upstreamMatched++
			s.mu.Unlock()
		} else {
			s.upstreamRejected++
			s.mu.Unlock()
		}
	} else {
		s.mu.Lock()
		s.upstreamRejected++
		s.mu.Unlock()
	}
	if !matched {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "reason": "bearer token is not a fixture-issued token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": r.URL.Path})
}

func (s *state) handleStats(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grants := map[string]int{}
	for k, v := range s.grantType {
		grants[k] = v
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token_requests":      s.tokenRequests,
		"grants":              grants,
		"client_auth_basic":   s.clientAuthBasic,
		"client_auth_post":    s.clientAuthPost,
		"rejected_client":     s.rejectedClient,
		"jwt_requests":        s.jwtRequests,
		"jwt_verified":        s.jwtVerified,
		"jwt_bad_signature":   s.jwtBadSignature,
		"jwt_bad_claims":      s.jwtBadClaims,
		"last_scope":          s.lastScope,
		"upstream_requests":   s.upstreamRequests,
		"upstream_matched":    s.upstreamMatched,
		"upstream_rejected":   s.upstreamRejected,
		"session_tokens_seen": s.sessionTokens,
		"expires_in":          s.expiresIn,
		"fail_status":         s.failStatus,
	})
}

func (s *state) handleTokens(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"tokens": s.issued})
}

func (s *state) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "use POST"})
		return
	}
	var body struct {
		ExpiresIn  *int64 `json:"expires_in"`
		FailStatus int    `json:"fail_status"`
		FailCode   string `json:"fail_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	s.mu.Lock()
	if body.ExpiresIn != nil {
		s.expiresIn = *body.ExpiresIn
	}
	s.failStatus, s.failCode = body.FailStatus, body.FailCode
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM file", path)
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s is not an RSA public key", path)
		}
		return rsaKey, nil
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not a usable RSA public key", path)
	}
	return key, nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address on loopback")
	addrFile := flag.String("addr-file", "", "write the actual listen address here")
	clientFile := flag.String("client-file", "", "write client registration (no secrets from real providers) here")
	clientID := flag.String("client-id", "", "expected client_id (generated when empty)")
	clientSecret := flag.String("client-secret", "", "expected client_secret (generated when empty)")
	clientEmail := flag.String("client-email", "", "expected service account email for jwt-bearer")
	publicKeyFile := flag.String("public-key", "", "PEM RSA public key used to verify jwt-bearer assertions")
	expiresIn := flag.Int64("expires-in", 3600, "access token lifetime in seconds")
	scope := flag.String("scope", "", "expected scope (empty accepts any)")
	flag.Parse()

	st := &state{
		clientID:     *clientID,
		clientSecret: *clientSecret,
		clientEmail:  *clientEmail,
		scope:        *scope,
		expiresIn:    *expiresIn,
		tokens:       map[string]time.Time{},
		grantType:    map[string]int{},
	}
	if st.clientID == "" {
		st.clientID = "keykoi-client-" + randomString(6)
	}
	if st.clientSecret == "" {
		st.clientSecret = "keykoi-secret-" + randomString(12)
	}
	if st.clientEmail == "" {
		st.clientEmail = "keykoi-test-" + randomString(4) + "@example.iam.gserviceaccount.com"
	}
	if *publicKeyFile != "" {
		pub, err := loadPublicKey(*publicKeyFile)
		if err != nil {
			log.Fatalf("oauth token fixture: %v", err)
		}
		st.publicKey = pub
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", st.handleToken)
	mux.HandleFunc("/api/", st.handleAPI)
	mux.HandleFunc("/stats", st.handleStats)
	mux.HandleFunc("/tokens", st.handleTokens)
	mux.HandleFunc("/control", st.handleControl)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("oauth token fixture: listen: %v", err)
	}
	actual := listener.Addr().String()
	st.tokenURI = "http://" + actual + "/token"
	if *addrFile != "" {
		if err := os.WriteFile(*addrFile, []byte(actual), 0o600); err != nil {
			log.Fatalf("oauth token fixture: write addr file: %v", err)
		}
	}
	if *clientFile != "" {
		registration := map[string]any{
			"client_id":       st.clientID,
			"client_secret":   st.clientSecret,
			"client_email":    st.clientEmail,
			"token_endpoint":  st.tokenURI,
			"upstream_origin": "http://" + actual,
			"addr":            actual,
			"expires_in":      st.expiresIn,
		}
		raw, err := json.MarshalIndent(registration, "", "  ")
		if err != nil {
			log.Fatalf("oauth token fixture: encode registration: %v", err)
		}
		if err := os.WriteFile(*clientFile, raw, 0o600); err != nil {
			log.Fatalf("oauth token fixture: write client file: %v", err)
		}
	}
	log.Printf("oauth token fixture on http://%s (token endpoint %s)", actual, st.tokenURI)
	if err := http.Serve(listener, mux); err != nil {
		log.Fatalf("oauth token fixture: serve: %v", err)
	}
}
