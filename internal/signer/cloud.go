package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// 多云请求签名协议标识。Binding.AdapterID 以协议名开头，daemon 按前缀分派。
const (
	// ProtocolTencentTC3 是腾讯云 API 3.0 签名（TC3-HMAC-SHA256）。
	ProtocolTencentTC3 = "tencent-tc3"
	// ProtocolHuaweiAKSK 是华为云 AK/SK 头签名（SDK-HMAC-SHA256）。
	ProtocolHuaweiAKSK = "huawei-aksk"
)

// Adapter 是解析后的登记签名配置。
type Adapter struct {
	Protocol string
	Service  string
	Region   string
}

// ParseAdapter 按 <protocol>/<region>/<service> 解析 Binding.AdapterID。
// 未登记、协议不在支持范围或字段格式不符时返回稳定错误。
func ParseAdapter(adapterID string) (Adapter, error) {
	id := strings.TrimSpace(adapterID)
	if id == "" {
		return Adapter{}, errorf(CodeConfigUnsupported, "binding has no registered signer adapter")
	}
	protocol, rest, ok := strings.Cut(id, "/")
	if !ok {
		return Adapter{}, errorf(CodeConfigUnsupported, "adapter %q must be <protocol>/<region>/<service>", id)
	}
	switch protocol {
	case ProtocolAWSSigV4, ProtocolTencentTC3, ProtocolHuaweiAKSK:
	default:
		return Adapter{}, errorf(CodeConfigUnsupported, "adapter %q uses an unregistered signing protocol", id)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return Adapter{}, errorf(CodeConfigUnsupported, "adapter %q must be %s/<region>/<service>", id, protocol)
	}
	region, service := parts[0], parts[1]
	if !simpleIdent(region) || !simpleIdent(service) {
		return Adapter{}, errorf(CodeConfigUnsupported, "adapter %q has invalid region or service", id)
	}
	return Adapter{Protocol: protocol, Service: service, Region: region}, nil
}

// CloudResult 是 TC3 / 华为云 AK/SK 签名结果。Headers 只含签名头。
type CloudResult struct {
	Headers         http.Header
	SignedHeaders   []string
	Timestamp       string
	CredentialScope string
	Region          string
	Service         string

	canonicalRequest string
	stringToSign     string
	signature        string
}

// CanonicalRequest 返回规范化请求，供测试与自校验使用；不含秘密。
func (r *CloudResult) CanonicalRequest() string { return r.canonicalRequest }

// StringToSign 返回待签字符串，供测试与自校验使用；不含秘密。
func (r *CloudResult) StringToSign() string { return r.stringToSign }

// Header 取签名头。X-TC-* 这类固定大小写的头不经 http.Header.Set 规范化，
// 因此这里按 HTTP 语义做大小写不敏感查找。
func (r *CloudResult) Header(name string) string {
	if values, ok := r.Headers[name]; ok && len(values) > 0 {
		return values[0]
	}
	for key, values := range r.Headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// SignatureValue 返回十六进制签名值（公开材料，不包含 secret）。
func (r *CloudResult) SignatureValue() string { return r.signature }

// SignProtocol 按登记协议分派到对应签名器。钥匙与秘密只在本进程内使用。
func SignProtocol(adapter Adapter, reg Registration, cred Credential, req Request) (*CloudResult, error) {
	switch adapter.Protocol {
	case ProtocolAWSSigV4:
		res, err := Sign(reg, cred, req)
		if err != nil {
			return nil, err
		}
		return &CloudResult{
			Headers:          res.Headers,
			SignedHeaders:    res.SignedHeaders,
			Timestamp:        res.AmzDate,
			CredentialScope:  res.CredentialScope,
			Region:           res.Region,
			Service:          res.Service,
			canonicalRequest: res.canonicalRequest,
			stringToSign:     res.stringToSign,
			signature:        signatureFromAuthorization(res.Headers.Get("Authorization")),
		}, nil
	case ProtocolTencentTC3:
		return SignTC3(reg, cred, req)
	case ProtocolHuaweiAKSK:
		return SignHuawei(reg, cred, req)
	default:
		return nil, errorf(CodeConfigUnsupported, "protocol %q has no registered signer", adapter.Protocol)
	}
}

// signatureFromAuthorization 从 Authorization 头取出签名值，供响应结构复述。
func signatureFromAuthorization(auth string) string {
	const marker = "Signature="
	i := strings.LastIndex(auth, marker)
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(auth[i+len(marker):])
}

// cloudTarget 是各云签名器共享的请求校验结果。
type cloudTarget struct {
	method  string
	u       *url.URL
	payload string
	service string
	region  string
	now     time.Time
}

// prepareCloudRequest 复用 AWS 签名器的目标校验、method 与 payload 摘要规则。
// TC3 与 SDK-HMAC-SHA256 都只签名“单个完整 body 的 SHA-256”。
func prepareCloudRequest(reg Registration, cred Credential, req Request, methods map[string]bool, methodMessage string) (*cloudTarget, error) {
	if err := reg.validate(); err != nil {
		return nil, err
	}
	if err := cred.validate(); err != nil {
		return nil, err
	}
	method := strings.TrimSpace(req.Method)
	if method != strings.ToUpper(method) {
		return nil, errorf(CodeInvalidRequest,
			"method %q must be uppercase; the signature covers the exact request method", req.Method)
	}
	if !methods[method] {
		return nil, errorf(CodeUnsupported, "%s", methodMessage)
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
	}
	region := reg.Region
	if req.Region != "" {
		if !strings.EqualFold(req.Region, reg.Region) {
			return nil, errorf(CodeConfigUnsupported, "region %q is not registered for this binding", req.Region)
		}
	}
	now := req.Time
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return &cloudTarget{
		method:  method,
		u:       u,
		payload: payload,
		service: service,
		region:  region,
		now:     now.UTC(),
	}, nil
}

// sha256Hex 返回字符串的 SHA-256 十六进制摘要。
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// canonicalHeaderBlock 把 header 名/值映射拼成 "name:value\n" 升序块。
func canonicalHeaderBlock(headers map[string]string) (names []string, block string) {
	names = make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(headers[name])
		b.WriteByte('\n')
	}
	return names, b.String()
}

// cloudHeaderValue 归一化调用方 header 值：去控制字符、折叠空白。
func cloudHeaderValue(name string, values []string) (string, error) {
	if len(values) == 0 {
		return "", errorf(CodeInvalidRequest, "header %q has no value", name)
	}
	parts := make([]string, 0, len(values))
	for _, raw := range values {
		if hasControl(raw) {
			return "", errorf(CodeInvalidRequest, "header %q contains control characters", name)
		}
		parts = append(parts, strings.Join(strings.Fields(raw), " "))
	}
	return strings.Join(parts, ","), nil
}

// cloudCallerHeaders 收集调用方 header，供各签名器的白名单校验使用。
func cloudCallerHeaders(extra http.Header) (map[string]string, error) {
	out := make(map[string]string, len(extra))
	names := make([]string, 0, len(extra))
	for name := range extra {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		lname := strings.ToLower(strings.TrimSpace(name))
		if lname == "" {
			return nil, errorf(CodeInvalidRequest, "header name must not be empty")
		}
		if forbiddenHeaders[lname] || strings.HasPrefix(lname, "x-keykoi-") {
			return nil, errorf(CodeUnsupported, "header %q cannot participate in a signature", lname)
		}
		value, err := cloudHeaderValue(lname, extra[name])
		if err != nil {
			return nil, err
		}
		out[lname] = value
	}
	return out, nil
}
