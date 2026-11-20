// Package signer 实现 KeyKoi 的专用协议签名，按 Binding.AdapterID 的协议前缀分派：
//
//   - aws-sigv4/：AWS Signature Version 4 的 Authorization 头签名（见本文件）。
//   - tencent-tc3/：腾讯云 API 3.0 的 TC3-HMAC-SHA256（见 tencent.go）。
//   - huawei-aksk/：华为云 AK/SK 的 SDK-HMAC-SHA256（见 huawei.go）。
//
// 下面先记录 aws-sigv4 的支持范围，另外两种协议的范围分别记录在各自文件与验收产物中：
//
//   - method：GET / HEAD / POST / PUT / DELETE / PATCH / OPTIONS。
//   - 请求目标：绝对 URL，scheme 只接受 http/https，host 必须与登记 Binding 的
//     upstream origin 一致，路径必须落在登记前缀内。
//   - canonical URI：使用调用方给出的已编码路径原样（S3 单编码语义），不做二次编码。
//     非 S3 服务只接受不含百分号编码与子分隔符的简单路径，避免静默产生服务端
//     不接受的“双编码”签名。
//   - canonical query：按编码后的 key/value 排序，重复参数全部保留。
//   - 参与签名的 header：host、x-amz-date、x-amz-security-token（有会话令牌时），
//     S3 另加 x-amz-content-sha256；调用方 header 只在白名单内参与签名。
//   - payload：只支持“单个完整 body 的 SHA-256”模式；分块/流式
//     （aws-chunked、STREAMING-*、UNSIGNED-PAYLOAD）与预签名（查询串签名）明确拒绝。
//   - 凭证：access_key_pair。签名器本身允许静态密钥（无 session_token），
//     便于复现 AWS 官方测试向量。/v1/signatures 同样只在凭证带临时会话
//     （session_token 字段存在且非空）时才要求并签署该令牌；静态 AccessKey
//     只要求 access_id/access_secret 在同一版本内完整。
//
// 本包不写日志、不持久化签名材料，也不返回 access_secret。
package signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ProtocolAWSSigV4 是当前实现的协议标识。
const ProtocolAWSSigV4 = "aws-sigv4"

// EmptyPayloadSHA256 是空 body 的 SHA-256，便于调用方与测试使用。
const EmptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// ErrorCode 是签名器稳定错误码。daemon 负责映射为 API 错误码。
type ErrorCode string

const (
	// CodeInvalidRequest 表示请求字段缺失、格式错误或不存在该签名语义。
	CodeInvalidRequest ErrorCode = "SIGN_INVALID_REQUEST"
	// CodeUnsupported 表示请求命中了明确不支持的签名模式。
	CodeUnsupported ErrorCode = "SIGN_UNSUPPORTED_PATTERN"
	// CodeTargetMismatch 表示请求目标越出登记 host/scheme/path。
	CodeTargetMismatch ErrorCode = "SIGN_TARGET_MISMATCH"
	// CodeConfigUnsupported 表示登记配置缺失或与请求的 service/region 不一致。
	CodeConfigUnsupported ErrorCode = "SIGN_CONFIG_UNSUPPORTED"
	// CodeCredentialIncomplete 表示凭证字段不完整或不可用于该协议。
	CodeCredentialIncomplete ErrorCode = "SIGN_CREDENTIAL_INCOMPLETE"
)

// Error 是签名器错误。
type Error struct {
	Code    ErrorCode
	Message string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

func errorf(code ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Registration 是登记在 Binding 上的签名目标与 adapter 配置。
// AdapterID 约定为 "<protocol>/<region>/<service>"，protocol 见 ParseAdapter。
type Registration struct {
	Service      string
	Region       string
	Scheme       string
	Host         string
	PathPrefixes []string
}

// ParseAdapterID 解析 Binding.AdapterID。未登记或格式不符时返回稳定错误。
func ParseAdapterID(adapterID string) (service, region string, err error) {
	id := strings.TrimSpace(adapterID)
	if id == "" {
		return "", "", errorf(CodeConfigUnsupported, "binding has no registered signer adapter")
	}
	if !strings.HasPrefix(id, ProtocolAWSSigV4+"/") {
		return "", "", errorf(CodeConfigUnsupported, "adapter %q is not a %s registration", id, ProtocolAWSSigV4)
	}
	parts := strings.Split(strings.TrimPrefix(id, ProtocolAWSSigV4+"/"), "/")
	if len(parts) != 2 {
		return "", "", errorf(CodeConfigUnsupported, "adapter %q must be %s/<region>/<service>", id, ProtocolAWSSigV4)
	}
	region, service = parts[0], parts[1]
	if !simpleIdent(region) || !simpleIdent(service) {
		return "", "", errorf(CodeConfigUnsupported, "adapter %q has invalid region or service", id)
	}
	return service, region, nil
}

// Credential 是一次签名需要的 access_key_pair 字段。SessionToken 为空表示静态密钥。
type Credential struct {
	AccessID     string
	AccessSecret []byte
	SessionToken string
}

// CredentialFromFields 由字段取值函数构造签名凭证：access_id 与 access_secret 必需，
// session_token 可选。只在凭证本身使用临时会话时才有 session_token；静态 AccessKey
// 缺该字段或为空都照常签名，签出的 Authorization 不含 Security-Token。
func CredentialFromFields(get func(name string) (string, bool)) (Credential, error) {
	accessID, ok := get("access_id")
	if !ok || accessID == "" {
		return Credential{}, errorf(CodeCredentialIncomplete, "credential version is missing access_id")
	}
	accessSecret, ok := get("access_secret")
	if !ok || accessSecret == "" {
		return Credential{}, errorf(CodeCredentialIncomplete, "credential version is missing access_secret")
	}
	cred := Credential{AccessID: accessID, AccessSecret: []byte(accessSecret)}
	if token, ok := get("session_token"); ok {
		cred.SessionToken = token
	}
	return cred, nil
}

// Request 是一个待签名请求。Service/Region 为空时使用登记值；给出时必须一致。
type Request struct {
	Method        string
	URL           string
	Headers       http.Header
	PayloadSHA256 string
	Service       string
	Region        string
	// Action 是腾讯云 API 3.0 的 X-TC-Action（接口名）；其他协议忽略该字段。
	Action string
	// Time 便于测试注入时钟；零值使用当前 UTC 时间。
	Time time.Time
}

// Result 是签名结果。Headers 只含签名头，不含调用方 header。
type Result struct {
	Headers         http.Header
	SignedHeaders   []string
	AmzDate         string
	CredentialScope string
	Region          string
	Service         string

	canonicalRequest string
	stringToSign     string
}

// CanonicalRequest 返回规范化请求，供测试与自校验使用；不含秘密。
func (r *Result) CanonicalRequest() string { return r.canonicalRequest }

// StringToSign 返回待签字符串，供测试与自校验使用；不含秘密。
func (r *Result) StringToSign() string { return r.stringToSign }

var supportedMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodDelete:  true,
	http.MethodPatch:   true,
	http.MethodOptions: true,
}

var presignQueryParams = map[string]bool{
	"x-amz-signature":     true,
	"x-amz-credential":    true,
	"x-amz-algorithm":     true,
	"x-amz-expires":       true,
	"x-amz-signedheaders": true,
}

var streamingHashValues = map[string]bool{
	"streaming-aws4-hmac-sha256-payload":         true,
	"streaming-aws4-hmac-sha256-payload-trailer": true,
	"streaming-unsigned-payload-trailer":         true,
	"unsigned-payload":                           true,
}

// managedHeaders 由签名器生成并校验的 header。
var managedHeaders = map[string]bool{
	"host":                 true,
	"x-amz-date":           true,
	"x-amz-content-sha256": true,
	"x-amz-security-token": true,
}

// allowedExtraHeaders 是允许参与签名的调用方 header（精确名）。
var allowedExtraHeaders = map[string]bool{
	"cache-control":                true,
	"content-disposition":          true,
	"content-encoding":             true,
	"content-language":             true,
	"content-md5":                  true,
	"content-type":                 true,
	"date":                         true,
	"expires":                      true,
	"if-match":                     true,
	"if-modified-since":            true,
	"if-none-match":                true,
	"if-unmodified-since":          true,
	"range":                        true,
	"x-amz-acl":                    true,
	"x-amz-server-side-encryption": true,
	"x-amz-server-side-encryption-aws-kms-key-id": true,
	"x-amz-storage-class":                         true,
	"x-amz-tagging":                               true,
	"x-amz-target":                                true,
	"x-amz-website-redirect-location":             true,
}

// allowedExtraHeaderPrefixes 是允许参与签名的调用方 header（前缀）。
var allowedExtraHeaderPrefixes = []string{
	"x-amz-checksum-",
	"x-amz-grant-",
	"x-amz-meta-",
}

// forbiddenHeaders 是会改变签名语义或属于 KeyKoi 内部状态的 header。
var forbiddenHeaders = map[string]bool{
	"authorization":                true,
	"connection":                   true,
	"content-length":               true,
	"cookie":                       true,
	"expect":                       true,
	"proxy-authorization":          true,
	"te":                           true,
	"trailer":                      true,
	"transfer-encoding":            true,
	"upgrade":                      true,
	"x-amz-decoded-content-length": true,
	"x-amz-trailer":                true,
}

// Sign 计算 AWS Signature Version 4 的 Authorization 头。
func Sign(reg Registration, cred Credential, req Request) (*Result, error) {
	if err := reg.validate(); err != nil {
		return nil, err
	}
	if err := cred.validate(); err != nil {
		return nil, err
	}
	method := strings.TrimSpace(req.Method)
	if method != strings.ToUpper(method) {
		return nil, errorf(CodeInvalidRequest, "method %q must be uppercase; the signature covers the exact request method", req.Method)
	}
	if !supportedMethods[method] {
		return nil, errorf(CodeInvalidRequest, "method %q is outside the supported set", req.Method)
	}
	payload, err := normalizePayloadHash(req.PayloadSHA256)
	if err != nil {
		return nil, err
	}
	u, err := parseTarget(reg, req.URL)
	if err != nil {
		return nil, err
	}
	service := reg.Service
	if req.Service != "" {
		if !strings.EqualFold(req.Service, reg.Service) {
			return nil, errorf(CodeConfigUnsupported, "service %q is not registered for this binding", req.Service)
		}
		service = reg.Service
	}
	region := reg.Region
	if req.Region != "" {
		if !strings.EqualFold(req.Region, reg.Region) {
			return nil, errorf(CodeConfigUnsupported, "region %q is not registered for this binding", req.Region)
		}
		region = reg.Region
	}
	now := req.Time
	if now.IsZero() {
		now = time.Now().UTC()
	}
	amzDate := now.UTC().Format("20060102T150405Z")

	query, err := canonicalQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}
	if err := rejectPresign(u.RawQuery); err != nil {
		return nil, err
	}
	canonicalURI, err := canonicalURI(reg.Service, u)
	if err != nil {
		return nil, err
	}
	headers, err := buildHeaders(service, u, amzDate, payload, cred, req.Headers)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, name := range names {
		canonHeaders.WriteString(name)
		canonHeaders.WriteByte(':')
		canonHeaders.WriteString(headers[name])
		canonHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")
	canonicalRequest := strings.Join([]string{
		method, canonicalURI, query, canonHeaders.String(), signedHeaders, payload,
	}, "\n")
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", amzDate[:8], region, service)
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(requestHash[:]),
	}, "\n")
	signature := hex.EncodeToString(signString(cred.AccessSecret, amzDate[:8], region, service, stringToSign))

	out := http.Header{}
	out.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		cred.AccessID, scope, signedHeaders, signature))
	out.Set("X-Amz-Date", amzDate)
	out.Set("X-Amz-Content-Sha256", payload)
	if cred.SessionToken != "" {
		out.Set("X-Amz-Security-Token", cred.SessionToken)
	}
	return &Result{
		Headers:          out,
		SignedHeaders:    names,
		AmzDate:          amzDate,
		CredentialScope:  scope,
		Region:           region,
		Service:          service,
		canonicalRequest: canonicalRequest,
		stringToSign:     stringToSign,
	}, nil
}

func (r Registration) validate() error {
	if !simpleIdent(r.Service) {
		return errorf(CodeConfigUnsupported, "registered service is missing or malformed")
	}
	if !simpleIdent(r.Region) {
		return errorf(CodeConfigUnsupported, "registered region is missing or malformed")
	}
	if r.Scheme != "http" && r.Scheme != "https" {
		return errorf(CodeConfigUnsupported, "registered origin scheme %q is unsupported", r.Scheme)
	}
	if !validHost(r.Host) {
		return errorf(CodeConfigUnsupported, "registered origin host is missing or malformed")
	}
	for _, p := range r.PathPrefixes {
		if p == "" || !strings.HasPrefix(p, "/") {
			return errorf(CodeConfigUnsupported, "registered path prefix %q must start with /", p)
		}
	}
	return nil
}

func (c Credential) validate() error {
	if c.AccessID == "" {
		return errorf(CodeCredentialIncomplete, "access_id is missing")
	}
	if len(c.AccessID) > 256 || hasControl(c.AccessID) || strings.ContainsAny(c.AccessID, " \t") {
		return errorf(CodeCredentialIncomplete, "access_id is malformed")
	}
	if len(c.AccessSecret) == 0 {
		return errorf(CodeCredentialIncomplete, "access_secret is missing")
	}
	for _, b := range c.AccessSecret {
		if b < 0x20 || b == 0x7f {
			return errorf(CodeCredentialIncomplete, "access_secret contains control characters")
		}
	}
	if strings.ContainsAny(c.SessionToken, "\r\n\t ") {
		return errorf(CodeCredentialIncomplete, "session_token contains whitespace")
	}
	return nil
}

func parseTarget(reg Registration, raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errorf(CodeInvalidRequest, "url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errorf(CodeInvalidRequest, "url cannot be parsed")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errorf(CodeInvalidRequest, "url scheme %q is outside the supported set", u.Scheme)
	}
	if u.Host == "" {
		return nil, errorf(CodeInvalidRequest, "url has no host")
	}
	if u.User != nil {
		return nil, errorf(CodeInvalidRequest, "url must not carry user information")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return nil, errorf(CodeInvalidRequest, "url must not carry a fragment; fragments are not part of a signed request")
	}
	if u.Scheme != reg.Scheme {
		return nil, errorf(CodeTargetMismatch, "url scheme %q does not match registered origin %q", u.Scheme, reg.Scheme)
	}
	want := canonicalHost(reg.Host, reg.Scheme)
	got := canonicalHost(u.Host, u.Scheme)
	if want != got {
		return nil, errorf(CodeTargetMismatch, "url host %q is not the registered target", u.Host)
	}
	decoded := u.Path
	if decoded == "" {
		decoded = "/"
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return nil, errorf(CodeTargetMismatch, "url path must not contain dot segments")
		}
	}
	if len(reg.PathPrefixes) > 0 {
		allowed := false
		for _, prefix := range reg.PathPrefixes {
			if strings.HasPrefix(decoded, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, errorf(CodeTargetMismatch, "url path %q is outside the registered path prefixes", decoded)
		}
	}
	return u, nil
}

// canonicalURI 保留调用方已编码路径。非 S3 服务避免误签双编码路径。
func canonicalURI(service string, u *url.URL) (string, error) {
	raw := u.EscapedPath()
	if raw == "" {
		raw = "/"
	}
	if !strings.HasPrefix(raw, "/") {
		return "", errorf(CodeInvalidRequest, "url path must be absolute")
	}
	if hasControl(raw) || strings.ContainsAny(raw, " \t") {
		return "", errorf(CodeInvalidRequest, "url path contains characters that are not encoded")
	}
	if !strings.EqualFold(service, "s3") {
		if strings.Contains(raw, "%") || !plainPath(raw) {
			return "", errorf(CodeUnsupported,
				"non-S3 canonical URI uses a different double-encoding model; only plain unreserved paths are supported")
		}
	}
	return raw, nil
}

func plainPath(p string) bool {
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/', c == '-', c == '_', c == '.', c == '~':
		default:
			return false
		}
	}
	return true
}

func rejectPresign(rawQuery string) error {
	if rawQuery == "" {
		return nil
	}
	for _, seg := range strings.Split(rawQuery, "&") {
		name, _, _ := strings.Cut(seg, "=")
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			return errorf(CodeInvalidRequest, "query parameter name has invalid encoding")
		}
		if presignQueryParams[strings.ToLower(decoded)] {
			return errorf(CodeUnsupported,
				"presigned URLs (query-string signatures) are not supported; KeyKoi only signs request headers")
		}
	}
	return nil
}

func canonicalQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	type pair struct{ key, value string }
	pairs := make([]pair, 0, strings.Count(raw, "&")+1)
	for _, seg := range strings.Split(raw, "&") {
		if seg == "" {
			return "", errorf(CodeInvalidRequest, "query contains an empty parameter")
		}
		k, v, _ := strings.Cut(seg, "=")
		dk, err := url.QueryUnescape(k)
		if err != nil {
			return "", errorf(CodeInvalidRequest, "query parameter name has invalid encoding")
		}
		dv, err := url.QueryUnescape(v)
		if err != nil {
			return "", errorf(CodeInvalidRequest, "query parameter value has invalid encoding")
		}
		pairs = append(pairs, pair{key: uriEncode(dk, true), value: uriEncode(dv, true)})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].key != pairs[j].key {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].value < pairs[j].value
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.key)
		b.WriteByte('=')
		b.WriteString(p.value)
	}
	return b.String(), nil
}

func buildHeaders(service string, u *url.URL, amzDate, payload string, cred Credential, extra http.Header) (map[string]string, error) {
	headers := map[string]string{
		"host":       canonicalHost(u.Host, u.Scheme),
		"x-amz-date": amzDate,
	}
	// x-amz-content-sha256 是 S3 的必需签名头；其他服务只在调用方显式给出时参与签名。
	if strings.EqualFold(service, "s3") {
		headers["x-amz-content-sha256"] = payload
	}
	if cred.SessionToken != "" {
		headers["x-amz-security-token"] = cred.SessionToken
	}
	names := make([]string, 0, len(extra))
	for name := range extra {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		lname := strings.ToLower(strings.TrimSpace(name))
		values := extra[name]
		if lname == "" {
			return nil, errorf(CodeInvalidRequest, "header name must not be empty")
		}
		if forbiddenHeaders[lname] || strings.HasPrefix(lname, "x-keykoi-") {
			return nil, errorf(CodeUnsupported, "header %q cannot participate in a signature", lname)
		}
		value, err := normalizeHeaderValue(values)
		if err != nil {
			return nil, err
		}
		if managedHeaders[lname] {
			if lname == "x-amz-content-sha256" {
				if streamingHashValues[strings.ToLower(value)] {
					return nil, errorf(CodeUnsupported, "streaming/unsigned payload markers are not supported")
				}
				if value != payload {
					return nil, errorf(CodeInvalidRequest, "x-amz-content-sha256 does not match payload_sha256")
				}
				headers[lname] = value
				continue
			}
			if err := checkManagedHeader(lname, value, headers); err != nil {
				return nil, err
			}
			continue
		}
		if !allowedExtraHeaders[lname] && !hasAllowedPrefix(lname) {
			return nil, errorf(CodeUnsupported, "header %q is outside the supported signing set", lname)
		}
		if strings.EqualFold(value, "aws-chunked") || strings.HasPrefix(strings.ToLower(value), "aws-chunked") {
			return nil, errorf(CodeUnsupported, "streaming/chunked payloads are not supported")
		}
		headers[lname] = value
	}
	return headers, nil
}

func checkManagedHeader(name, value string, headers map[string]string) error {
	want, ok := headers[name]
	if !ok {
		// 调用方提供了会话令牌头但凭证没有令牌：拒绝，避免半份签名材料。
		return errorf(CodeInvalidRequest, "header %q does not match the registered credential", name)
	}
	if name == "x-amz-date" {
		if value != want {
			return errorf(CodeInvalidRequest, "x-amz-date must be generated by the signer")
		}
		return nil
	}
	if name == "host" {
		if strings.ToLower(value) != want {
			return errorf(CodeTargetMismatch, "host header does not match the registered target")
		}
		return nil
	}
	if value != want {
		return errorf(CodeInvalidRequest, "header %q does not match the computed signing material", name)
	}
	return nil
}

func normalizeHeaderValue(values []string) (string, error) {
	if len(values) == 0 {
		return "", errorf(CodeInvalidRequest, "header value is missing")
	}
	parts := make([]string, 0, len(values))
	for _, raw := range values {
		if hasControl(raw) {
			return "", errorf(CodeInvalidRequest, "header value contains control characters")
		}
		parts = append(parts, strings.Join(strings.Fields(raw), " "))
	}
	return strings.Join(parts, ","), nil
}

func normalizePayloadHash(raw string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(raw))
	if h == "" {
		return "", errorf(CodeInvalidRequest, "payload_sha256 is required")
	}
	if streamingHashValues[h] {
		return "", errorf(CodeUnsupported, "payload mode %q is not supported; provide a complete SHA-256", raw)
	}
	if len(h) != 64 {
		return "", errorf(CodeInvalidRequest, "payload_sha256 must be 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", errorf(CodeInvalidRequest, "payload_sha256 must be hexadecimal")
	}
	return h, nil
}

func signString(secret []byte, date, region, service, stringToSign string) []byte {
	key := hmacSHA256([]byte("AWS4"+string(secret)), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	return hmacSHA256(key, stringToSign)
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// uriEncode 实现 SigV4 的 URI 编码：未保留字符之外全部大写百分号编码。
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

func canonicalHost(raw, scheme string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		return strings.TrimSuffix(host, ":")
	}
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return h
	}
	return net.JoinHostPort(h, port)
}

func validHost(host string) bool {
	if host == "" || strings.ContainsAny(host, "/ \t") {
		return false
	}
	return true
}

func simpleIdent(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func hasAllowedPrefix(lname string) bool {
	for _, prefix := range allowedExtraHeaderPrefixes {
		if strings.HasPrefix(lname, prefix) {
			return true
		}
	}
	return false
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
