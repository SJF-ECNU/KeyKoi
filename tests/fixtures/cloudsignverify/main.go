// Command cloudsignverify 是腾讯云 TC3-HMAC-SHA256 与华为云 SDK-HMAC-SHA256
// 签名验收的受控校验上游。
//
// 它用与签名器相同的 access_key_pair（通过环境变量注入，不落盘、不写日志）
// 按各自云的公开规范独立重算签名，并校验 Authorization、签名头、payload 摘要与请求目标。
// 它只返回校验结论与结构摘要，不回显 Authorization、会话令牌或密钥。
//
// 用法：
//
//	--mode tc3     校验 tencent-tc3 签名（TC3 canonical URI 固定为 /）
//	--mode huawei  校验 huawei-aksk 签名（canonical URI 逐段编码并补 /）
//
// 环境变量（两种模式共用，按进程隔离）：CLOUDSIGN_ACCESS_ID、
// CLOUDSIGN_ACCESS_SECRET、CLOUDSIGN_SESSION_TOKEN、CLOUDSIGN_SERVICE、CLOUDSIGN_REGION。
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
	// maxBodyBytes 与签名器支持的“单个完整 body”模式一致。
	maxBodyBytes  = 64 << 20
	maxSignedHdrs = 32

	modeTC3    = "tc3"
	modeHuawei = "huawei"
)

type config struct {
	mode         string
	accessID     string
	accessSecret []byte
	sessionToken string
	service      string
	region       string
}

type structure struct {
	Algorithm       string   `json:"algorithm"`
	CredentialScope string   `json:"credential_scope,omitempty"`
	SignedHeaders   []string `json:"signed_headers"`
	SignatureLength int      `json:"signature_length"`
	Timestamp       string   `json:"timestamp"`
	CanonicalQuery  string   `json:"canonical_query"`
	CanonicalURI    string   `json:"canonical_uri"`
	PayloadSHA256   string   `json:"payload_sha256"`
}

type stats struct {
	mu         sync.Mutex
	requests   int
	verified   int
	failed     int
	lastFailed string
	last       structure
}

var cfg config
var st = &stats{}

func main() {
	mode := flag.String("mode", modeTC3, "signature mode to verify: tc3 or huawei")
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	addrFile := flag.String("addr-file", "", "write actual listen address to this file")
	flag.Parse()

	if *mode != modeTC3 && *mode != modeHuawei {
		log.Fatalf("unknown mode %q", *mode)
	}
	cfg = config{
		mode:         *mode,
		accessID:     os.Getenv("CLOUDSIGN_ACCESS_ID"),
		accessSecret: []byte(os.Getenv("CLOUDSIGN_ACCESS_SECRET")),
		sessionToken: os.Getenv("CLOUDSIGN_SESSION_TOKEN"),
		service:      envOr("CLOUDSIGN_SERVICE", "cvm"),
		region:       envOr("CLOUDSIGN_REGION", "ap-guangzhou"),
	}
	if cfg.accessID == "" || len(cfg.accessSecret) == 0 {
		log.Fatalf("CLOUDSIGN_ACCESS_ID and CLOUDSIGN_ACCESS_SECRET are required")
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
	log.Printf("cloudsignverify listening on %s (mode=%s service=%s)", ln.Addr(), cfg.mode, cfg.service)
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

	result, err := verify(r)
	if err != nil {
		st.mu.Lock()
		st.failed++
		st.lastFailed = err.Error()
		st.mu.Unlock()
		log.Printf("cloudsignverify: %s %s mode=%s verified=false reason=%s", r.Method, r.URL.Path, cfg.mode, err)
		writeJSON(w, http.StatusForbidden, map[string]any{"verified": false, "reason": err.Error()})
		return
	}
	st.mu.Lock()
	st.verified++
	st.last = result
	st.mu.Unlock()
	log.Printf("cloudsignverify: %s %s mode=%s verified=true signed_headers=%d",
		r.Method, r.URL.Path, cfg.mode, len(result.SignedHeaders))
	writeJSON(w, http.StatusOK, map[string]any{
		"verified":        true,
		"mode":            cfg.mode,
		"structure":       result,
		"canonical_uri":   result.CanonicalURI,
		"canonical_query": result.CanonicalQuery,
	})
}

func writeStats(w http.ResponseWriter) {
	st.mu.Lock()
	defer st.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":           cfg.mode,
		"requests":       st.requests,
		"verified":       st.verified,
		"failed":         st.failed,
		"last_failure":   st.lastFailed,
		"last_structure": st.last,
		"secrets_logged": false,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func verify(r *http.Request) (structure, error) {
	switch cfg.mode {
	case modeTC3:
		return verifyTC3(r)
	default:
		return verifyHuawei(r)
	}
}

// verifyTC3 独立重算 TC3-HMAC-SHA256。
func verifyTC3(r *http.Request) (structure, error) {
	auth := r.Header.Get("Authorization")
	const prefix = "TC3-HMAC-SHA256 "
	if !strings.HasPrefix(auth, prefix) {
		return structure{}, fmt.Errorf("missing TC3-HMAC-SHA256 authorization header")
	}
	credential, signedHeaders, signature, err := parseAuthorization(strings.TrimPrefix(auth, prefix))
	if err != nil {
		return structure{}, err
	}
	parts := strings.Split(credential, "/")
	if len(parts) != 4 || parts[3] != "tc3_request" {
		return structure{}, fmt.Errorf("credential scope is malformed")
	}
	if !constEq(parts[0], cfg.accessID) {
		return structure{}, fmt.Errorf("secret id does not match the registered credential")
	}
	if !constEq(parts[2], cfg.service) {
		return structure{}, fmt.Errorf("credential service does not match the registered service")
	}
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		return structure{}, fmt.Errorf("method %q is outside the TC3 signing model", r.Method)
	}
	timestamp := r.Header.Get("X-TC-Timestamp")
	if len(timestamp) < 10 || !digits(timestamp) {
		return structure{}, fmt.Errorf("x-tc-timestamp is missing or malformed")
	}
	seconds, err := time.ParseDuration(timestamp + "s")
	if err != nil {
		return structure{}, fmt.Errorf("x-tc-timestamp is not a valid unix time")
	}
	date := time.Unix(int64(seconds/time.Second), 0).UTC().Format("2006-01-02")
	if date != parts[1] {
		return structure{}, fmt.Errorf("credential date does not match x-tc-timestamp in UTC")
	}
	if cfg.sessionToken != "" && !constEq(r.Header.Get("X-TC-Token"), cfg.sessionToken) {
		return structure{}, fmt.Errorf("x-tc-token does not match the registered credential")
	}
	names, err := checkSignedHeaders(signedHeaders, signature)
	if err != nil {
		return structure{}, err
	}
	seen := map[string]bool{}
	for _, name := range names {
		seen[name] = true
	}
	if !seen["host"] || !seen["content-type"] {
		return structure{}, fmt.Errorf("host and content-type must be signed for TC3")
	}
	if r.Header.Get("X-TC-Action") != "" && !seen["x-tc-action"] {
		return structure{}, fmt.Errorf("x-tc-action header is present but not signed")
	}
	if r.URL.Path != "/" && r.URL.Path != "" {
		return structure{}, fmt.Errorf("TC3 canonical URI is fixed to /; request path is %q", r.URL.Path)
	}
	body, err := readBody(r)
	if err != nil {
		return structure{}, err
	}
	payloadHash := sha256Hex(body)
	query, err := canonicalQuery(r.URL.RawQuery)
	if err != nil {
		return structure{}, err
	}
	block, err := canonicalHeaderBlock(r, names, true)
	if err != nil {
		return structure{}, err
	}
	canonicalRequest := strings.Join([]string{
		r.Method, "/", query, block, signedHeaders, payloadHash,
	}, "\n")
	requestHash := sha256Hex([]byte(canonicalRequest))
	// TC3 的 CredentialScope 是 date/service/tc3_request，不含 SecretId。
	scope := strings.Join(parts[1:], "/")
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256", timestamp, scope, requestHash,
	}, "\n")
	secretDate := hmacSHA256(append([]byte("TC3"), cfg.accessSecret...), []byte(parts[1]))
	secretService := hmacSHA256(secretDate, []byte(parts[2]))
	secretSigning := hmacSHA256(secretService, []byte("tc3_request"))
	expected := hex.EncodeToString(hmacSHA256(secretSigning, []byte(stringToSign)))
	if !constEq(expected, signature) {
		return structure{}, fmt.Errorf("signature does not match the recomputed TC3 value")
	}
	return structure{
		Algorithm:       "TC3-HMAC-SHA256",
		CredentialScope: scope,
		SignedHeaders:   names,
		SignatureLength: len(signature),
		Timestamp:       timestamp,
		CanonicalQuery:  query,
		CanonicalURI:    "/",
		PayloadSHA256:   payloadHash,
	}, nil
}

// verifyHuawei 独立重算华为云 SDK-HMAC-SHA256。
func verifyHuawei(r *http.Request) (structure, error) {
	auth := r.Header.Get("Authorization")
	const prefix = "SDK-HMAC-SHA256 "
	if !strings.HasPrefix(auth, prefix) {
		return structure{}, fmt.Errorf("missing SDK-HMAC-SHA256 authorization header")
	}
	access, signedHeaders, signature, err := parseAuthorization(strings.TrimPrefix(auth, prefix))
	if err != nil {
		return structure{}, err
	}
	if !constEq(access, cfg.accessID) {
		return structure{}, fmt.Errorf("access key does not match the registered credential")
	}
	date := r.Header.Get("X-Sdk-Date")
	if _, err := time.Parse("20060102T150405Z", date); err != nil {
		return structure{}, fmt.Errorf("x-sdk-date is missing or malformed")
	}
	if cfg.sessionToken != "" && !constEq(r.Header.Get("X-Security-Token"), cfg.sessionToken) {
		return structure{}, fmt.Errorf("x-security-token does not match the registered credential")
	}
	names, err := checkSignedHeaders(signedHeaders, signature)
	if err != nil {
		return structure{}, err
	}
	seen := map[string]bool{}
	for _, name := range names {
		seen[name] = true
	}
	if !seen["host"] || !seen["x-sdk-date"] {
		return structure{}, fmt.Errorf("host and x-sdk-date must be signed for SDK-HMAC-SHA256")
	}
	if r.Header.Get("Content-Type") != "" && !seen["content-type"] {
		return structure{}, fmt.Errorf("content-type header is present but not signed")
	}
	body, err := readBody(r)
	if err != nil {
		return structure{}, err
	}
	payloadHash := sha256Hex(body)
	query, err := canonicalQuery(r.URL.RawQuery)
	if err != nil {
		return structure{}, err
	}
	block, err := canonicalHeaderBlock(r, names, false)
	if err != nil {
		return structure{}, err
	}
	uri := huaweiCanonicalURI(r.URL.Path)
	canonicalRequest := strings.Join([]string{
		r.Method, uri, query, block, signedHeaders, payloadHash,
	}, "\n")
	stringToSign := "SDK-HMAC-SHA256\n" + date + "\n" + sha256Hex([]byte(canonicalRequest))
	expected := hex.EncodeToString(hmacSHA256(cfg.accessSecret, []byte(stringToSign)))
	if !constEq(expected, signature) {
		return structure{}, fmt.Errorf("signature does not match the recomputed SDK-HMAC-SHA256 value")
	}
	return structure{
		Algorithm:       "SDK-HMAC-SHA256",
		SignedHeaders:   names,
		SignatureLength: len(signature),
		Timestamp:       date,
		CanonicalQuery:  query,
		CanonicalURI:    uri,
		PayloadSHA256:   payloadHash,
	}, nil
}

func readBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read request body")
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("request body exceeds verifier limit")
	}
	return body, nil
}

// parseAuthorization 解析 "Credential=../Access=/AK, SignedHeaders=..., Signature=..." 形式。
// 两种协议的键名不同，这里做统一处理。
func parseAuthorization(rest string) (credential, signedHeaders, signature string, err error) {
	fields := strings.Split(rest, ", ")
	if len(fields) != 3 {
		return "", "", "", fmt.Errorf("authorization header is malformed")
	}
	first := fields[0]
	switch {
	case strings.HasPrefix(first, "Credential="):
		credential = strings.TrimPrefix(first, "Credential=")
	case strings.HasPrefix(first, "Access="):
		credential = strings.TrimPrefix(first, "Access=")
	default:
		return "", "", "", fmt.Errorf("authorization header is malformed")
	}
	signedHeaders = strings.TrimPrefix(fields[1], "SignedHeaders=")
	signature = strings.TrimPrefix(fields[2], "Signature=")
	if signedHeaders == fields[1] || signature == fields[2] {
		return "", "", "", fmt.Errorf("authorization header is malformed")
	}
	if len(signature) != 64 || !isHex(signature) {
		return "", "", "", fmt.Errorf("signature is not a hex SHA-256")
	}
	return credential, signedHeaders, signature, nil
}

func checkSignedHeaders(joined, signature string) ([]string, error) {
	names := strings.Split(joined, ";")
	if len(names) == 0 || len(names) > maxSignedHdrs {
		return nil, fmt.Errorf("signed header list is malformed")
	}
	seen := map[string]bool{}
	for i, name := range names {
		if name == "" || seen[name] || name != strings.ToLower(name) {
			return nil, fmt.Errorf("signed header list is malformed")
		}
		if i > 0 && names[i-1] > name {
			return nil, fmt.Errorf("signed header list is not sorted")
		}
		seen[name] = true
	}
	if len(signature) != 64 {
		return nil, fmt.Errorf("signature is not a hex SHA-256")
	}
	return names, nil
}

// canonicalHeaderBlock 用收到的实际请求值重建规范 header 块。
// TC3 会把 header 值统一转小写；华为云保留原值，只折叠空白。
func canonicalHeaderBlock(r *http.Request, names []string, lowerValue bool) (string, error) {
	var b strings.Builder
	for _, name := range names {
		raw := ""
		if name == "host" {
			raw = r.Host
		} else {
			raw = r.Header.Get(name)
		}
		if raw == "" {
			return "", fmt.Errorf("signed header %q is missing from the request", name)
		}
		value := strings.Join(strings.Fields(raw), " ")
		if lowerValue {
			value = strings.ToLower(value)
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(value)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// huaweiCanonicalURI 逐段编码并以 / 结尾，与华为云规范一致。
func huaweiCanonicalURI(path string) string {
	if path == "" {
		path = "/"
	}
	segments := strings.Split(path, "/")
	encoded := make([]string, len(segments))
	for i, segment := range segments {
		encoded[i] = uriEncode(segment)
	}
	out := strings.Join(encoded, "/")
	if !strings.HasSuffix(out, "/") {
		out += "/"
	}
	return out
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
		pairs = append(pairs, pair{k: uriEncode(dk), v: uriEncode(dv)})
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

func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func constEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
