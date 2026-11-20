// Command oauthprovider 是受控 OAuth 2.0 提供方，用于 p4-oauth-refresh 的验收：
// 它实现授权码 + PKCE(S256) + refresh_token 轮换，并记录调用次数与失败模式。
//
// 它只在 127.0.0.1 上运行，所有 token 都是运行时生成的测试值，不接触任何真实凭证。
// 除验收需要外，它还提供两个 fixture 专用端点：/tokens（供脚本检查日志是否泄漏 token）
// 与 /control（切换撤销、网络失败、上游 5xx、token 有效期等故障模式）。
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type code struct {
	challenge string
	redirect  string
	used      bool
}

type tokens struct {
	access  string
	refresh string
}

type provider struct {
	mu          sync.Mutex
	clientID    string
	clientSec   string
	redirect    string
	expiresIn   int64
	codes       map[string]*code
	access      map[string]bool
	refresh     map[string]bool
	latest      tokens
	authorize   int
	tokenCode   int
	tokenRefr   int
	rejected    int
	revocations int
	failNet     bool
	failStatus  int
	delay       time.Duration
}

func randomString(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (p *provider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.mu.Lock()
	clientID := p.clientID
	p.authorize++
	p.mu.Unlock()
	if q.Get("response_type") != "code" {
		http.Error(w, "response_type=code is required", http.StatusBadRequest)
		return
	}
	if q.Get("client_id") != clientID {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "PKCE S256 is required", http.StatusBadRequest)
		return
	}
	if q.Get("state") == "" {
		http.Error(w, "state is required", http.StatusBadRequest)
		return
	}
	c := "code_" + randomString(18)
	p.mu.Lock()
	p.codes[c] = &code{challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	p.mu.Unlock()

	target, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "redirect_uri is invalid", http.StatusBadRequest)
		return
	}
	tq := target.Query()
	tq.Set("code", c)
	tq.Set("state", q.Get("state"))
	target.RawQuery = tq.Encode()
	// 受控提供方自动授权：直接 302 回受信入口，由脚本取出 code 再交给 keykoi callback。
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (p *provider) handleToken(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	failNet, failStatus, delay := p.failNet, p.failStatus, p.delay
	p.mu.Unlock()
	if failNet {
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		http.Error(w, "simulated network failure", http.StatusBadGateway)
		return
	}
	if failStatus != 0 {
		writeJSON(w, failStatus, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "form body required"})
		return
	}
	if !p.clientOK(r) {
		p.mu.Lock()
		p.rejected++
		p.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": "client authentication failed"})
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		p.exchangeCode(w, r)
	case "refresh_token":
		p.exchangeRefresh(w, r)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (p *provider) clientOK(r *http.Request) bool {
	p.mu.Lock()
	id, sec := p.clientID, p.clientSec
	p.mu.Unlock()
	if user, pass, ok := r.BasicAuth(); ok {
		return user == id && pass == sec
	}
	return r.PostForm.Get("client_id") == id && r.PostForm.Get("client_secret") == sec
}

func (p *provider) exchangeCode(w http.ResponseWriter, r *http.Request) {
	c := r.PostForm.Get("code")
	p.mu.Lock()
	entry, ok := p.codes[c]
	p.mu.Unlock()
	if !ok || entry.used {
		p.mu.Lock()
		p.rejected++
		p.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "authorization code is unknown or already used"})
		return
	}
	if entry.redirect != "" && r.PostForm.Get("redirect_uri") != entry.redirect {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != entry.challenge {
		p.mu.Lock()
		p.rejected++
		p.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
	}
	p.mu.Lock()
	entry.used = true
	p.tokenCode++
	ts := p.issueLocked()
	expires := p.expiresIn
	p.mu.Unlock()
	writeToken(w, ts, expires)
}

func (p *provider) exchangeRefresh(w http.ResponseWriter, r *http.Request) {
	rt := r.PostForm.Get("refresh_token")
	p.mu.Lock()
	valid := p.refresh[rt]
	p.mu.Unlock()
	if !valid {
		p.mu.Lock()
		p.rejected++
		p.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "refresh token is invalid, revoked, or already rotated"})
		return
	}
	p.mu.Lock()
	delete(p.refresh, rt)
	// 轮换：旧 access token 失效，调用方必须使用新组合。
	delete(p.access, p.latest.access)
	p.tokenRefr++
	ts := p.issueLocked()
	expires := p.expiresIn
	p.mu.Unlock()
	writeToken(w, ts, expires)
}

func (p *provider) issueLocked() tokens {
	n := len(p.access) + len(p.refresh) + 1
	ts := tokens{
		access:  fmt.Sprintf("at.%s.%d", randomString(12), n),
		refresh: fmt.Sprintf("rt.%s.%d", randomString(12), n),
	}
	p.access[ts.access] = true
	p.refresh[ts.refresh] = true
	p.latest = ts
	return ts
}

func (p *provider) handleResource(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.Lock()
	ok := p.access[token]
	p.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "reason": "access token is not current"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sub": "oauth-fixture-user"})
}

func (p *provider) handleStats(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"authorize_calls":     p.authorize,
		"token_code_calls":    p.tokenCode,
		"token_refresh_calls": p.tokenRefr,
		"rejected":            p.rejected,
		"revocations":         p.revocations,
		"live_access_tokens":  len(p.access),
		"live_refresh_tokens": len(p.refresh),
		"expires_in":          p.expiresIn,
		"fail_network":        p.failNet,
		"fail_status":         p.failStatus,
	})
}

// handleTokens 是 fixture 专用端点：让验收脚本拿到当前 token 值，用于确认
// KeyKoi 的日志与 CLI 输出里不出现 token 原文。
func (p *provider) handleTokens(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  p.latest.access,
		"refresh_token": p.latest.refresh,
	})
}

func (p *provider) handleControl(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action  string `json:"action"`
		Seconds int64  `json:"seconds"`
		Millis  int64  `json:"millis"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	p.mu.Lock()
	switch body.Action {
	case "revoke":
		p.access = map[string]bool{}
		p.refresh = map[string]bool{}
		p.revocations++
	case "fail_network":
		p.failNet = true
	case "fail_500":
		p.failStatus = http.StatusServiceUnavailable
	case "normal":
		p.failNet = false
		p.failStatus = 0
		p.delay = 0
	case "set_expires_in":
		if body.Seconds > 0 {
			p.expiresIn = body.Seconds
		}
	case "delay":
		p.delay = time.Duration(body.Millis) * time.Millisecond
	default:
		p.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown_action"})
		return
	}
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"action": body.Action})
}

func writeToken(w http.ResponseWriter, ts tokens, expiresIn int64) {
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  ts.access,
		"refresh_token": ts.refresh,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"scope":         "read write",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address on loopback")
	addrFile := flag.String("addr-file", "", "write the actual listen address here")
	clientFile := flag.String("client-file", "", "write generated client registration here")
	clientID := flag.String("client-id", "", "override generated client_id")
	clientSecret := flag.String("client-secret", "", "override generated client_secret")
	redirect := flag.String("redirect-uri", "http://127.0.0.1:9/keykoi-oauth-callback", "registered redirect URI")
	expiresIn := flag.Int64("expires-in", 900, "access token lifetime in seconds")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	base := "http://" + ln.Addr().String()

	p := &provider{
		clientID:  *clientID,
		clientSec: *clientSecret,
		redirect:  *redirect,
		expiresIn: *expiresIn,
		codes:     map[string]*code{},
		access:    map[string]bool{},
		refresh:   map[string]bool{},
	}
	if p.clientID == "" {
		p.clientID = "client_" + randomString(9)
	}
	if p.clientSec == "" {
		p.clientSec = "secret_" + randomString(18)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", p.handleAuthorize)
	mux.HandleFunc("/token", p.handleToken)
	mux.HandleFunc("/resource", p.handleResource)
	mux.HandleFunc("/stats", p.handleStats)
	mux.HandleFunc("/tokens", p.handleTokens)
	mux.HandleFunc("/control", p.handleControl)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	if *addrFile != "" {
		if err := os.WriteFile(*addrFile, []byte(ln.Addr().String()), 0o600); err != nil {
			log.Fatalf("write addr file: %v", err)
		}
	}
	if *clientFile != "" {
		reg := map[string]string{
			"client_id":          p.clientID,
			"client_secret":      p.clientSec,
			"authorize_endpoint": base + "/authorize",
			"token_endpoint":     base + "/token",
			"resource_endpoint":  base + "/resource",
			"redirect_uri":       p.redirect,
		}
		data, err := json.MarshalIndent(reg, "", "  ")
		if err != nil {
			log.Fatalf("encode client file: %v", err)
		}
		if err := os.WriteFile(*clientFile, data, 0o600); err != nil {
			log.Fatalf("write client file: %v", err)
		}
	}
	fmt.Println(ln.Addr().String())
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.Serve(ln))
}
