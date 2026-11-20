// Command sigv4verify 是 P4 专用签名验收的受控校验上游。
//
// 它用与签名器相同的 access_key_pair（通过环境变量注入，不落盘、不写日志）
// 独立重算 AWS Signature Version 4，并校验 Authorization、签名头、payload 摘要
// 与请求目标。它只返回校验结论与结构摘要，不回显 Authorization、会话令牌或密钥。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxBodyBytes  = 64 << 20
	maxSignedHdrs = 32
)

type config struct {
	accessID     string
	accessSecret []byte
	sessionToken string
	region       string
	service      string
}

type structure struct {
	Algorithm       string   `json:"algorithm"`
	CredentialScope string   `json:"credential_scope"`
	SignedHeaders   []string `json:"signed_headers"`
	SignatureLength int      `json:"signature_length"`
}

type stats struct {
	mu                sync.Mutex
	requests          int
	verified          int
	failed            int
	lastRawQuery      string
	lastCanonical     string
	lastFailure       string
	structures        map[string]structure
	verifiedByAgent   map[string]int
	unverifiedPayload int
}

var cfg config
var st = &stats{
	structures:      map[string]structure{},
	verifiedByAgent: map[string]int{},
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	addrFile := flag.String("addr-file", "", "write actual listen address to this file")
	flag.Parse()

	cfg = config{
		accessID:     os.Getenv("SIGV4_ACCESS_ID"),
		accessSecret: []byte(os.Getenv("SIGV4_ACCESS_SECRET")),
		sessionToken: os.Getenv("SIGV4_SESSION_TOKEN"),
		region:       envOr("SIGV4_REGION", "us-east-1"),
		service:      envOr("SIGV4_SERVICE", "s3"),
	}
	if cfg.accessID == "" || len(cfg.accessSecret) == 0 {
		log.Fatalf("SIGV4_ACCESS_ID and SIGV4_ACCESS_SECRET are required")
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	if *addrFile != "" {
		if err := os.WriteFile(*addrFile, []byte(ln.Addr().String()), 0o600); err != nil {
			log.Fatalf("write addr file: %v", err)
		}
	}
	srv := &http.Server{Handler: http.HandlerFunc(handle), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("sigv4verify listening on %s (region=%s service=%s)", ln.Addr(), cfg.region, cfg.service)
	if err := srv.Serve(ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/stats" {
		writeStats(w)
		return
	}
	st.mu.Lock()
	st.requests++
	st.mu.Unlock()

	agent := agentClass(r.UserAgent())
	structure, err := verify(r, agent)
	jsonResponse := strings.HasPrefix(r.URL.Path, "/kk/") || strings.Contains(r.Header.Get("Accept"), "application/json")
	if err != nil {
		st.mu.Lock()
		st.failed++
		st.lastFailure = err.Error()
		st.mu.Unlock()
		log.Printf("sigv4verify: %s %s agent=%s verified=false reason=%s", r.Method, r.URL.Path, agent, err)
		if jsonResponse {
			writeJSON(w, http.StatusForbidden, map[string]any{"verified": false, "reason": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `<Error><Code>SignatureDoesNotMatch</Code><Message>%s</Message></Error>`, xmlEscape(err.Error()))
		return
	}
	st.mu.Lock()
	st.verified++
	st.verifiedByAgent[agent]++
	if agent == "keykoi" {
		st.lastRawQuery = r.URL.RawQuery
		st.lastCanonical = structure.CanonicalQuery
	}
	public := structure.structure
	st.structures[agent] = public
	st.mu.Unlock()

	log.Printf("sigv4verify: %s %s agent=%s verified=true signed_headers=%d", r.Method, r.URL.Path, agent, len(public.SignedHeaders))
	if jsonResponse {
		writeJSON(w, http.StatusOK, map[string]any{
			"verified":        true,
			"agent":           agent,
			"raw_query":       r.URL.RawQuery,
			"canonical_query": structure.CanonicalQuery,
		})
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>kk-bucket</Name><Prefix>x</Prefix><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`)
}

func writeStats(w http.ResponseWriter) {
	st.mu.Lock()
	defer st.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"requests":             st.requests,
		"verified":             st.verified,
		"failed":               st.failed,
		"verified_by_agent":    st.verifiedByAgent,
		"structures":           st.structures,
		"last_raw_query":       st.lastRawQuery,
		"last_canonical_query": st.lastCanonical,
		"last_failure":         st.lastFailure,
		"secrets_logged":       false,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func headerNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func agentClass(ua string) string {
	switch {
	case strings.Contains(ua, "aws-cli"):
		return "aws-cli"
	case strings.Contains(ua, "keykoi-acceptance"):
		return "keykoi"
	default:
		return "other"
	}
}

type verifiedRequest struct {
	structure      structure
	CanonicalQuery string
}

// verify 独立重算 SigV4。失败原因只描述结构问题，不含任何签名材料或秘密。
func verify(r *http.Request, agent string) (*verifiedRequest, error) {
	auth := r.Header.Get("Authorization")
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(auth, prefix) {
		return nil, fmt.Errorf("missing AWS4-HMAC-SHA256 authorization header")
	}
	credential, signedHeaders, signature, err := parseAuthorization(strings.TrimPrefix(auth, prefix))
	if err != nil {
		return nil, err
	}
	parts := strings.Split(credential, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" {
		return nil, fmt.Errorf("credential scope is malformed")
	}
	if !constEq(parts[0], cfg.accessID) {
		return nil, fmt.Errorf("access key id does not match the registered credential")
	}
	if !constEq(parts[2], cfg.region) {
		return nil, fmt.Errorf("credential region does not match the registered region")
	}
	if !constEq(parts[3], cfg.service) {
		return nil, fmt.Errorf("credential service does not match the registered service")
	}
	amzDate := r.Header.Get("X-Amz-Date")
	if len(amzDate) != 16 || amzDate[8] != 'T' || amzDate[15] != 'Z' {
		return nil, fmt.Errorf("x-amz-date is missing or malformed")
	}
	if parts[1] != amzDate[:8] {
		return nil, fmt.Errorf("credential date does not match x-amz-date")
	}
	if _, err := time.Parse("20060102T150405Z", amzDate); err != nil {
		return nil, fmt.Errorf("x-amz-date is not a valid timestamp")
	}
	contentSHA := r.Header.Get("X-Amz-Content-Sha256")
	if contentSHA == "" {
		return nil, fmt.Errorf("x-amz-content-sha256 is required")
	}
	if cfg.sessionToken != "" && !constEq(r.Header.Get("X-Amz-Security-Token"), cfg.sessionToken) {
		return nil, fmt.Errorf("session token header does not match the registered credential")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read request body")
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("request body exceeds verifier limit")
	}
	if !strings.EqualFold(contentSHA, "UNSIGNED-PAYLOAD") && !strings.EqualFold(contentSHA, "STREAMING-UNSIGNED-PAYLOAD-TRAILER") {
		sum := sha256.Sum256(body)
		if !constEq(strings.ToLower(contentSHA), hex.EncodeToString(sum[:])) {
			return nil, fmt.Errorf("x-amz-content-sha256 does not match the request body")
		}
	} else {
		st.mu.Lock()
		st.unverifiedPayload++
		st.mu.Unlock()
	}

	names := strings.Split(signedHeaders, ";")
	if len(names) == 0 || len(names) > maxSignedHdrs {
		return nil, fmt.Errorf("signed header list is malformed")
	}
	seen := map[string]bool{}
	for i, name := range names {
		if name == "" || seen[name] {
			return nil, fmt.Errorf("signed header list is malformed")
		}
		if i > 0 && names[i-1] > name {
			return nil, fmt.Errorf("signed header list is not sorted")
		}
		seen[name] = true
	}
	for _, required := range []string{"host", "x-amz-date", "x-amz-content-sha256"} {
		if !seen[required] {
			return nil, fmt.Errorf("required header %q is not signed", required)
		}
	}
	if cfg.sessionToken != "" && !seen["x-amz-security-token"] {
		return nil, fmt.Errorf("session token header is not signed")
	}

	canonicalHeaders := strings.Builder{}
	for _, name := range names {
		var raw string
		if name == "host" {
			raw = r.Host
		} else {
			raw = r.Header.Get(name)
		}
		if raw == "" {
			if os.Getenv("SIGV4_DEBUG") != "" {
				log.Printf("debug: signed header %q missing; received=%v", name, headerNames(r.Header))
			}
			return nil, fmt.Errorf("signed header %q is missing from the request", name)
		}
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.Join(strings.Fields(raw), " "))
		canonicalHeaders.WriteByte('\n')
	}
	query, err := canonicalQuery(r.URL.RawQuery)
	if err != nil {
		return nil, err
	}
	uri := r.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	canonicalRequest := strings.Join([]string{
		r.Method, uri, query, canonicalHeaders.String(), signedHeaders, contentSHA,
	}, "\n")
	scope := strings.Join(parts[1:], "/")
	hash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(hash[:])}, "\n")
	expected := hex.EncodeToString(signingKey(cfg.accessSecret, parts[1], cfg.region, cfg.service, stringToSign))
	if !constEq(expected, signature) {
		return nil, fmt.Errorf("signature does not match the recomputed SigV4 value")
	}
	_ = agent
	return &verifiedRequest{
		structure: structure{
			Algorithm:       "AWS4-HMAC-SHA256",
			CredentialScope: scope,
			SignedHeaders:   names,
			SignatureLength: len(signature),
		},
		CanonicalQuery: query,
	}, nil
}

func parseAuthorization(rest string) (credential, signedHeaders, signature string, err error) {
	fields := strings.Split(rest, ", ")
	if len(fields) != 3 {
		return "", "", "", fmt.Errorf("authorization header is malformed")
	}
	credential = strings.TrimPrefix(fields[0], "Credential=")
	signedHeaders = strings.TrimPrefix(fields[1], "SignedHeaders=")
	signature = strings.TrimPrefix(fields[2], "Signature=")
	if credential == fields[0] || signedHeaders == fields[1] || signature == fields[2] {
		return "", "", "", fmt.Errorf("authorization header is malformed")
	}
	if len(signature) != 64 || !isHex(signature) {
		return "", "", "", fmt.Errorf("signature is not a hex SHA-256")
	}
	return credential, signedHeaders, signature, nil
}

func canonicalQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	type pair struct{ k, v string }
	pairs := make([]pair, 0, strings.Count(raw, "&")+1)
	for _, seg := range strings.Split(raw, "&") {
		if seg == "" {
			return "", fmt.Errorf("query has an empty parameter")
		}
		k, v, _ := strings.Cut(seg, "=")
		dk, err := url.QueryUnescape(k)
		if err != nil {
			return "", fmt.Errorf("query parameter name has invalid encoding")
		}
		dv, err := url.QueryUnescape(v)
		if err != nil {
			return "", fmt.Errorf("query parameter value has invalid encoding")
		}
		pairs = append(pairs, pair{k: uriEncode(dk, true), v: uriEncode(dv, true)})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&"), nil
}

func signingKey(secret []byte, date, region, service, stringToSign string) []byte {
	k := hmacSHA256(append([]byte("AWS4"), secret...), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	return hmacSHA256(k, stringToSign)
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func constEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}
