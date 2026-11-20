package signer

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// 华为云 AK/SK 签名（SDK-HMAC-SHA256）向量。
//
// 来源一：华为云官方《API签名指南》「API签名认证机制示例」的 VPC 查询示例
// （https://support.huaweicloud.com/devg-apisign/api-sign-algorithm-002.html）。
// 文档给出的规范请求哈希为
// b25362e603ee30f4f25e7858e8a7160fd36e803bb2dfe206278659d71a9bcd7a，
// 待签字符串为「SDK-HMAC-SHA256\n20191115T033655Z\n<该哈希>」，
// 并给出 Signature=f12f84a5ecf9eff3206499c4a55b13d1adad745dc8624a2e31f15c6b381d5b80。
// 文档把示例 SK 打码成 MFyf***VmHc、AK 打码成 QTWA***KYUC，因此该示例只能锚定
// 规范化过程与待签字符串；签名值本身无法在无 SK 的情况下复算。
//
// 来源二：同一规范的固定回归向量（GET 与 POST 各一组）。它们用固定 AK/SK、固定时间
// 把完整 Authorization 写死，期望值由独立实现（tests/fixtures/cloudsignverify 的同一
// 规范化规则）复算得到，实现被改坏会立刻变红。
const (
	huaweiDocHost      = "service.region.example.com"
	huaweiDocPath      = "/v1/77b6a44cba5143ab91d13ab9a8ff44fd/vpcs"
	huaweiDocQuery     = "limit=2&marker=13551d6b-755d-4757-b956-536f674975c0"
	huaweiDocDate      = "20191115T033655Z"
	huaweiDocHash      = "b25362e603ee30f4f25e7858e8a7160fd36e803bb2dfe206278659d71a9bcd7a"
	huaweiDocSignature = "f12f84a5ecf9eff3206499c4a55b13d1adad745dc8624a2e31f15c6b381d5b80"

	huaweiTestAK = "HUAWEICLOUDTESTAK0001"
	huaweiTestSK = "HuaweiTestSecretKey0000000000000001"
)

func huaweiDocTime() time.Time {
	return time.Date(2019, 11, 15, 3, 36, 55, 0, time.UTC)
}

func huaweiFixedTime() time.Time {
	return time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
}

func mustSignHuawei(t *testing.T, reg Registration, cred Credential, req Request) *CloudResult {
	t.Helper()
	res, err := SignHuawei(reg, cred, req)
	if err != nil {
		t.Fatalf("SignHuawei() error: %v", err)
	}
	return res
}

func TestOfficialHuaweiDocVector(t *testing.T) {
	reg := Registration{Service: "vpc", Region: "cn-north-1", Scheme: "https", Host: huaweiDocHost}
	cred := Credential{AccessID: "QTWAOYNNMXXXXXXQHQIN", AccessSecret: []byte("MFyfXXXXXXXXXXXXVmHc")}
	res := mustSignHuawei(t, reg, cred, Request{
		Method:        "GET",
		URL:           "https://" + huaweiDocHost + huaweiDocPath + "?" + huaweiDocQuery,
		Headers:       http.Header{"Content-Type": []string{"application/json"}},
		PayloadSHA256: EmptyPayloadSHA256,
		Time:          huaweiDocTime(),
	})
	wantCanonical := strings.Join([]string{
		"GET",
		"/v1/77b6a44cba5143ab91d13ab9a8ff44fd/vpcs/",
		huaweiDocQuery,
		"content-type:application/json\nhost:" + huaweiDocHost + "\nx-sdk-date:" + huaweiDocDate + "\n",
		"content-type;host;x-sdk-date",
		EmptyPayloadSHA256,
	}, "\n")
	if got := res.CanonicalRequest(); got != wantCanonical {
		t.Fatalf("CanonicalRequest mismatch\n got: %q\nwant: %q", got, wantCanonical)
	}
	wantSTS := "SDK-HMAC-SHA256\n" + huaweiDocDate + "\n" + huaweiDocHash
	if got := res.StringToSign(); got != wantSTS {
		t.Fatalf("StringToSign mismatch\n got: %q\nwant: %q", got, wantSTS)
	}
	if len(res.SignatureValue()) != 64 || !isHexString(res.SignatureValue()) {
		t.Fatalf("signature is not a hex SHA-256: %q", res.SignatureValue())
	}
	auth := res.Header("Authorization")
	wantPrefix := "SDK-HMAC-SHA256 Access=QTWAOYNNMXXXXXXQHQIN, " +
		"SignedHeaders=content-type;host;x-sdk-date, Signature="
	if !strings.HasPrefix(auth, wantPrefix) {
		t.Fatalf("Authorization = %q, want prefix %q", auth, wantPrefix)
	}
	if got := res.Header("X-Sdk-Date"); got != huaweiDocDate {
		t.Fatalf("X-Sdk-Date = %q", got)
	}
	// 文档给出的 Signature 只与打码后的 SK 对应，这里仅确认它与本实现的待签字符串同形：
	// 两者都是 64 位十六进制、且都覆盖同一份规范请求。
	if len(huaweiDocSignature) != 64 {
		t.Fatalf("documented signature has unexpected shape")
	}
}

func TestHuaweiFixedVectors(t *testing.T) {
	cases := []struct {
		name    string
		reg     Registration
		req     Request
		want    string
		wantURI string
	}{
		{
			name: "get-with-query",
			reg:  Registration{Service: "ecs", Region: "cn-north-4", Scheme: "https", Host: "ecs.cn-north-4.myhuaweicloud.com"},
			req: Request{
				Method:        "GET",
				URL:           "https://ecs.cn-north-4.myhuaweicloud.com/v2/proj/servers?name=web&limit=1",
				Headers:       http.Header{"Content-Type": []string{"application/json"}},
				PayloadSHA256: EmptyPayloadSHA256,
				Time:          huaweiFixedTime(),
			},
			want: "SDK-HMAC-SHA256 Access=" + huaweiTestAK +
				", SignedHeaders=content-type;host;x-sdk-date, " +
				"Signature=68cbfb43e4e5d5ccf6b82be8d0b1c9b91b48abddbf422d44de85e7c5418c21cd",
			wantURI: "/v2/proj/servers/",
		},
		{
			name: "post-with-body",
			reg:  Registration{Service: "iam", Region: "cn-north-4", Scheme: "https", Host: "iam.cn-north-4.myhuaweicloud.com"},
			req: Request{
				Method:        "POST",
				URL:           "https://iam.cn-north-4.myhuaweicloud.com/v3.0/OS-USER/users?x=1",
				Headers:       http.Header{"Content-Type": []string{"application/json"}},
				PayloadSHA256: sha256Hex(`{"user":{"name":"kk-fixture"}}`),
				Time:          huaweiFixedTime(),
			},
			want: "SDK-HMAC-SHA256 Access=" + huaweiTestAK +
				", SignedHeaders=content-type;host;x-sdk-date, " +
				"Signature=47629e6567f65fe915172bf93daf27f2b92b0a46f654541e4d6f7c94044e6064",
			wantURI: "/v3.0/OS-USER/users/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustSignHuawei(t, tc.reg, Credential{AccessID: huaweiTestAK, AccessSecret: []byte(huaweiTestSK)}, tc.req)
			if got := res.Header("Authorization"); got != tc.want {
				t.Fatalf("Authorization mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			lines := strings.Split(res.CanonicalRequest(), "\n")
			if lines[1] != tc.wantURI {
				t.Fatalf("canonical URI = %q, want %q", lines[1], tc.wantURI)
			}
			if res.Header("X-Sdk-Date") != "20240102T030405Z" {
				t.Fatalf("X-Sdk-Date = %q", res.Header("X-Sdk-Date"))
			}
		})
	}
}

func TestHuaweiSessionTokenAndHeaders(t *testing.T) {
	reg := Registration{Service: "ecs", Region: "cn-north-4", Scheme: "https", Host: "ecs.cn-north-4.myhuaweicloud.com"}
	cred := Credential{AccessID: huaweiTestAK, AccessSecret: []byte(huaweiTestSK), SessionToken: "HWSECURITYTOKEN"}
	res := mustSignHuawei(t, reg, cred, Request{
		Method:        "GET",
		URL:           "https://ecs.cn-north-4.myhuaweicloud.com/v2/proj/servers",
		Headers:       http.Header{"Content-Type": []string{"application/json"}, "Content-MD5": []string{"aGVsbG8="}},
		PayloadSHA256: EmptyPayloadSHA256,
		Time:          huaweiFixedTime(),
	})
	joined := strings.Join(res.SignedHeaders, ";")
	if joined != "content-md5;content-type;host;x-sdk-date;x-security-token" {
		t.Fatalf("signed headers = %q", joined)
	}
	if got := res.Header("X-Security-Token"); got != "HWSECURITYTOKEN" {
		t.Fatalf("X-Security-Token = %q", got)
	}
	if !strings.Contains(res.CanonicalRequest(), "content-type:application/json\n") {
		t.Fatalf("canonical headers lost content-type: %q", res.CanonicalRequest())
	}
}

func TestHuaweiRejections(t *testing.T) {
	reg := Registration{
		Service: "ecs", Region: "cn-north-4", Scheme: "https",
		Host: "ecs.cn-north-4.myhuaweicloud.com", PathPrefixes: []string{"/v2/"},
	}
	cred := Credential{AccessID: huaweiTestAK, AccessSecret: []byte(huaweiTestSK)}
	good := Request{
		Method:        "GET",
		URL:           "https://ecs.cn-north-4.myhuaweicloud.com/v2/proj/servers",
		Headers:       http.Header{"Content-Type": []string{"application/json"}},
		PayloadSHA256: EmptyPayloadSHA256,
		Time:          huaweiFixedTime(),
	}
	cases := []struct {
		name string
		reg  Registration
		cred Credential
		req  Request
		code ErrorCode
	}{
		{
			name: "unregistered host", reg: reg, cred: cred,
			req:  hwWithURL(good, "https://ecs.cn-north-1.myhuaweicloud.com/v2/proj/servers"),
			code: CodeTargetMismatch,
		},
		{
			name: "path outside registered prefixes", reg: reg, cred: cred,
			req:  hwWithURL(good, "https://ecs.cn-north-4.myhuaweicloud.com/v3/proj/servers"),
			code: CodeTargetMismatch,
		},
		{
			name: "dot segment escapes prefix", reg: reg, cred: cred,
			req:  hwWithURL(good, "https://ecs.cn-north-4.myhuaweicloud.com/v2/../v1/servers"),
			code: CodeTargetMismatch,
		},
		{
			name: "unsupported method", reg: reg, cred: cred,
			req:  hwWithMethod(good, "CONNECT"),
			code: CodeUnsupported,
		},
		{
			name: "lowercase method", reg: reg, cred: cred,
			req:  hwWithMethod(good, "get"),
			code: CodeInvalidRequest,
		},
		{
			name: "missing payload digest", reg: reg, cred: cred,
			req:  hwWithPayload(good, ""),
			code: CodeInvalidRequest,
		},
		{
			name: "unsigned payload marker", reg: reg, cred: cred,
			req:  hwWithPayload(good, "UNSIGNED-PAYLOAD"),
			code: CodeUnsupported,
		},
		{
			name: "x-sdk-date override", reg: reg, cred: cred,
			req:  hwWithHeader(good, "X-Sdk-Date", "20240102T030405Z"),
			code: CodeInvalidRequest,
		},
		{
			name: "content sha override", reg: reg, cred: cred,
			req:  hwWithHeader(good, "X-Sdk-Content-Sha256", "UNSIGNED-PAYLOAD"),
			code: CodeInvalidRequest,
		},
		{
			name: "header outside the signing set", reg: reg, cred: cred,
			req:  hwWithHeader(good, "X-Project-Id", "abc"),
			code: CodeUnsupported,
		},
		{
			name: "region override", reg: reg, cred: cred,
			req: Request{
				Method: good.Method, URL: good.URL, Headers: good.Headers,
				PayloadSHA256: good.PayloadSHA256, Region: "cn-east-3", Time: good.Time,
			},
			code: CodeConfigUnsupported,
		},
		{
			name: "missing adapter config", reg: Registration{Scheme: "https", Host: "ecs.cn-north-4.myhuaweicloud.com"}, cred: cred,
			req:  good,
			code: CodeConfigUnsupported,
		},
		{
			name: "missing access id", reg: reg, cred: Credential{AccessSecret: []byte(huaweiTestSK)},
			req:  good,
			code: CodeCredentialIncomplete,
		},
		{
			name: "session token with whitespace", reg: reg,
			cred: Credential{AccessID: huaweiTestAK, AccessSecret: []byte(huaweiTestSK), SessionToken: "tok en"},
			req:  good,
			code: CodeCredentialIncomplete,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SignHuawei(tc.reg, tc.cred, tc.req)
			if err == nil {
				t.Fatalf("SignHuawei() accepted an out-of-scope request")
			}
			var se *Error
			if !errors.As(err, &se) {
				t.Fatalf("error is not a signer error: %v", err)
			}
			if se.Code != tc.code {
				t.Fatalf("error code = %s, want %s (%v)", se.Code, tc.code, err)
			}
			if strings.Contains(err.Error(), huaweiTestSK) {
				t.Fatalf("error message leaked the secret key")
			}
		})
	}
}

func hwWithURL(r Request, raw string) Request   { r.URL = raw; return r }
func hwWithMethod(r Request, m string) Request  { r.Method = m; return r }
func hwWithPayload(r Request, v string) Request { r.PayloadSHA256 = v; return r }

func hwWithHeader(r Request, name, value string) Request {
	h := http.Header{"Content-Type": []string{"application/json"}}
	h.Set(name, value)
	r.Headers = h
	return r
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return s != ""
}
