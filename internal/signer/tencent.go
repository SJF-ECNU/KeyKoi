package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// TC3-HMAC-SHA256 是腾讯云 API 3.0 的请求头签名（签名方法 v3）。
//
// 支持范围记录在此，并由 docs/验收/artifacts/tencent-huawei-signer/result.json 复述：
//
//   - method：GET / POST（API 3.0 只接受这两种；其他 method 返回 SIGN_UNSUPPORTED_PATTERN）。
//   - 请求目标：绝对 URL，host 必须与登记 Binding 的 upstream origin 一致，路径必须落在
//     登记前缀内；TC3 的 CanonicalURI 固定为 “/”，因此路径不是 “/” 的请求直接拒绝，
//     避免签出一个云端永远无法验证的签名。
//   - CanonicalQueryString：GET 取 URL 查询串，按 RFC3986 编码后按 key、value 升序；
//     POST 的参数在 JSON body 中，带查询串的 POST 直接拒绝。
//   - CanonicalHeaders：content-type、host 必选，提供 X-TC-Action 时并入（值按规范转小写）；
//     调用方可额外签名 content-md5。其他 header 不在签名范围。
//   - HashedRequestPayload：只支持单个完整 body 的 SHA-256（与 aws-sigv4 相同规则）。
//   - 凭证：access_key_pair。存在 session_token 时以 X-TC-Token 头返回；
//     TC3 的 Token 不参与 CanonicalHeaders（与腾讯云官方 SDK 一致）。
//
// 签名值只由 SecretKey 派生，本包不写日志、不持久化签名材料。

const (
	tencentAlgorithm = "TC3-HMAC-SHA256"
	// TencentDocExamplePayload 是腾讯云文档示例使用的请求体（原始 JSON 文本）。
	TencentDocExamplePayload = `{"Limit": 1, "Filters": [{"Values": ["\u672a\u547d\u540d"], "Name": "instance-name"}]}`
)

var tencentMethods = map[string]bool{
	http.MethodGet:  true,
	http.MethodPost: true,
}

// tencentManagedHeaders 由签名器生成或从凭证取得，调用方不得覆盖。
var tencentManagedHeaders = map[string]bool{
	"authorization":  true,
	"content-length": true,
	"host":           true,
	"x-tc-timestamp": true,
	"x-tc-token":     true,
}

// tencentAllowedHeaders 是除 content-type/host/x-tc-action 外允许参与签名的调用方 header。
var tencentAllowedHeaders = map[string]bool{
	"content-md5": true,
}

// SignTC3 计算腾讯云 TC3-HMAC-SHA256 的 Authorization 头。
func SignTC3(reg Registration, cred Credential, req Request) (*CloudResult, error) {
	target, err := prepareCloudRequest(reg, cred, req,
		tencentMethods, "TC3-HMAC-SHA256 signs Tencent Cloud API 3.0 GET and POST requests only")
	if err != nil {
		return nil, err
	}
	if path := target.u.Path; path != "" && path != "/" {
		return nil, errorf(CodeUnsupported,
			"TC3 canonical URI is fixed to /; request path %q is outside the API 3.0 signing model", path)
	}
	query := ""
	if target.method == http.MethodGet {
		q, err := canonicalQuery(target.u.RawQuery)
		if err != nil {
			return nil, err
		}
		query = q
	} else if target.u.RawQuery != "" {
		return nil, errorf(CodeUnsupported,
			"TC3 POST parameters belong in the JSON body; a query string is not part of the signed request")
	}
	action, err := tencentAction(req)
	if err != nil {
		return nil, err
	}
	canonicalHeaders, err := tencentCanonicalHeaders(target, action, req.Headers)
	if err != nil {
		return nil, err
	}
	names, block := canonicalHeaderBlock(canonicalHeaders)
	signedHeaders := strings.Join(names, ";")
	canonicalRequest := strings.Join([]string{
		target.method, "/", query, block, signedHeaders, target.payload,
	}, "\n")

	timestamp := strconv.FormatInt(target.now.Unix(), 10)
	date := target.now.Format("2006-01-02")
	scope := fmt.Sprintf("%s/%s/tc3_request", date, target.service)
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		tencentAlgorithm, timestamp, scope, hex.EncodeToString(requestHash[:]),
	}, "\n")
	signature := hex.EncodeToString(tencentSignString(cred.AccessSecret, date, target.service, stringToSign))

	// 直接赋值而不是 Set：http.Header.Set 会把 "X-TC-Action" 规范成 "X-Tc-Action"，
	// 而腾讯云的公共参数名固定写作 X-TC-*，保留原样便于调用方照抄。
	out := http.Header{}
	out["Authorization"] = []string{fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		tencentAlgorithm, cred.AccessID, scope, signedHeaders, signature)}
	out["X-TC-Timestamp"] = []string{timestamp}
	if action != "" {
		out["X-TC-Action"] = []string{action}
	}
	if cred.SessionToken != "" {
		out["X-TC-Token"] = []string{cred.SessionToken}
	}
	return &CloudResult{
		Headers:          out,
		SignedHeaders:    names,
		Timestamp:        timestamp,
		CredentialScope:  scope,
		Region:           target.region,
		Service:          target.service,
		canonicalRequest: canonicalRequest,
		stringToSign:     stringToSign,
		signature:        signature,
	}, nil
}

// tencentCanonicalHeaders 构造 TC3 的规范 header 块。
//
// 值与 key 一律转小写（文档要求），因此 content-type 只接受已经小写的值，
// 避免“签名用的小写值与实际发送值不一致”导致云端验签失败。
func tencentCanonicalHeaders(target *cloudTarget, action string, extra http.Header) (map[string]string, error) {
	caller, err := cloudCallerHeaders(extra)
	if err != nil {
		return nil, err
	}
	if _, ok := caller["x-tc-action"]; ok {
		delete(caller, "x-tc-action")
	}
	headers := map[string]string{
		"host": canonicalHost(target.u.Host, target.u.Scheme),
	}
	for name, value := range caller {
		switch {
		case name == "content-type":
			if value != strings.ToLower(value) {
				return nil, errorf(CodeInvalidRequest,
					"content-type must be lowercase: TC3 signs the lowercased header value")
			}
			headers[name] = value
		case tencentAllowedHeaders[name]:
			headers[name] = strings.ToLower(value)
		case tencentManagedHeaders[name]:
			return nil, errorf(CodeInvalidRequest, "header %q is generated by the signer", name)
		default:
			return nil, errorf(CodeUnsupported, "header %q is outside the supported TC3 signing set", name)
		}
	}
	if _, ok := headers["content-type"]; !ok {
		return nil, errorf(CodeInvalidRequest, "content-type is required and must be signed for TC3")
	}
	if action != "" {
		headers["x-tc-action"] = strings.ToLower(action)
	}
	return headers, nil
}

// tencentAction 解析 X-TC-Action：优先取请求字段，其次取同名 header；两者必须一致。
// 返回的是调用方书写的原名（腾讯云在签名时统一转小写）。
func tencentAction(req Request) (string, error) {
	action := strings.TrimSpace(req.Action)
	headerValue := ""
	for name, values := range req.Headers {
		if strings.EqualFold(strings.TrimSpace(name), "x-tc-action") && len(values) > 0 {
			headerValue = strings.TrimSpace(values[0])
		}
	}
	if headerValue != "" {
		if action != "" && !strings.EqualFold(action, headerValue) {
			return "", errorf(CodeInvalidRequest, "action disagrees with the x-tc-action header")
		}
		action = headerValue
	}
	if action == "" {
		return "", nil
	}
	if hasControl(action) || strings.ContainsAny(action, " \t") {
		return "", errorf(CodeInvalidRequest, "x-tc-action contains whitespace or control characters")
	}
	return action, nil
}

// tencentSignString 执行 TC3 的 HMAC 链：SecretDate → SecretService → SecretSigning → Signature。
func tencentSignString(secret []byte, date, service, stringToSign string) []byte {
	secretDate := hmacSHA256(append([]byte("TC3"), secret...), date)
	secretService := hmacSHA256(secretDate, service)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	return hmacSHA256(secretSigning, stringToSign)
}
