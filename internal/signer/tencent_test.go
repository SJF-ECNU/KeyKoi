package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// 腾讯云签名方法 v3（TC3-HMAC-SHA256）官方文档示例向量。
//
// 来源（公开文档，密钥为文档给出的示例密钥，非真实账户）：
//
//   - 中文文档「签名方法 v3」POST 示例：cvm / DescribeInstances / 时间戳 1551113065，
//     SignedHeaders=content-type;host;x-tc-action，
//     HashedCanonicalRequest=7019a55be8395899b900fb5564e4200d984910f34794a27cb3fb7d10ff6a1e84，
//     SecretSigning=b596b923aad85185e2d1f6659d2a062e0a86731226e021e61bfe06f7ed05f5af，
//     Signature=10b1a37a7301a02ca19a647ad722d5e43b4b3cff309d421d85b46093f6ab6c4f。
//   - 同一示例在 SignedHeaders=content-type;host 形态下的完整签名
//     （文档 curl 示例）：Signature=72e494ea809ad7a8c8f7a4507b9bddcbaa8e581f516e8da2f66e2c5a96525168，
//     示例 SecretId/SecretKey 取自文档示例；SecretId 在这里改成占位符，
//     避免被凭证扫描误判为真实 AKID（签名只取决于 SecretKey 与规范请求）。
//
// 文档在新版示例里把 SecretKey 打码，只公布派生密钥。第二组向量因此用文档公布的
// SecretSigning 复算文档公布的 Signature：只要本实现的 CanonicalRequest 与 StringToSign
// 有任何一个字节不同，这一步就会失败。
const (
	tencentDocSecretID  = "AKIDkeykoi-doc-example-secret-id"
	tencentDocSecretKey = "Gu5t9xGARNpq86cd98joQYCN3EXAMPLE"
	tencentDocTimestamp = 1551113065
	tencentDocScope     = "2019-02-25/cvm/tc3_request"
)

func tencentDocTime() time.Time {
	return time.Unix(tencentDocTimestamp, 0).UTC()
}

func tencentDocRegistration() Registration {
	return Registration{Service: "cvm", Region: "ap-guangzhou", Scheme: "https", Host: "cvm.tencentcloudapi.com"}
}

func tencentDocCredential() Credential {
	return Credential{AccessID: tencentDocSecretID, AccessSecret: []byte(tencentDocSecretKey)}
}

func tencentDocPayloadHash(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte(TencentDocExamplePayload))
	return hex.EncodeToString(sum[:])
}

func mustSignTC3(t *testing.T, reg Registration, cred Credential, req Request) *CloudResult {
	t.Helper()
	res, err := SignTC3(reg, cred, req)
	if err != nil {
		t.Fatalf("SignTC3() error: %v", err)
	}
	return res
}

// TestOfficialTC3Vectors 覆盖腾讯云文档示例：content-type;host 形态的完整签名，
// 以及加入 x-tc-action 后的规范化结果与文档公布的派生密钥。
func TestOfficialTC3Vectors(t *testing.T) {
	t.Run("post-content-type-host", func(t *testing.T) {
		res := mustSignTC3(t, tencentDocRegistration(), tencentDocCredential(), Request{
			Method:        "POST",
			URL:           "https://cvm.tencentcloudapi.com/",
			Headers:       http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
			PayloadSHA256: tencentDocPayloadHash(t),
			Time:          tencentDocTime(),
		})
		wantAuth := "TC3-HMAC-SHA256 Credential=" + tencentDocSecretID + "/" + tencentDocScope +
			", SignedHeaders=content-type;host, " +
			"Signature=72e494ea809ad7a8c8f7a4507b9bddcbaa8e581f516e8da2f66e2c5a96525168"
		if got := res.Header("Authorization"); got != wantAuth {
			t.Fatalf("Authorization mismatch\n got: %s\nwant: %s", got, wantAuth)
		}
		wantCanonical := strings.Join([]string{
			"POST", "/", "",
			"content-type:application/json; charset=utf-8\nhost:cvm.tencentcloudapi.com\n",
			"content-type;host",
			"35e9c5b0e3ae67532d3c9f17ead6c90222632e5b1ff7f6e89887f1398934f064",
		}, "\n")
		if got := res.CanonicalRequest(); got != wantCanonical {
			t.Fatalf("CanonicalRequest mismatch\n got: %q\nwant: %q", got, wantCanonical)
		}
		if got := res.Header("X-TC-Timestamp"); got != "1551113065" {
			t.Fatalf("X-TC-Timestamp = %q", got)
		}
		if got := res.Header("X-TC-Action"); got != "" {
			t.Fatalf("X-TC-Action should be absent when the caller gives no action, got %q", got)
		}
		if res.CredentialScope != tencentDocScope {
			t.Fatalf("credential scope = %q, want %q", res.CredentialScope, tencentDocScope)
		}
	})

	t.Run("post-with-x-tc-action", func(t *testing.T) {
		res := mustSignTC3(t, tencentDocRegistration(), tencentDocCredential(), Request{
			Method:        "POST",
			URL:           "https://cvm.tencentcloudapi.com/",
			Headers:       http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
			PayloadSHA256: tencentDocPayloadHash(t),
			Action:        "DescribeInstances",
			Time:          tencentDocTime(),
		})
		wantCanonical := strings.Join([]string{
			"POST", "/", "",
			"content-type:application/json; charset=utf-8\nhost:cvm.tencentcloudapi.com\nx-tc-action:describeinstances\n",
			"content-type;host;x-tc-action",
			"35e9c5b0e3ae67532d3c9f17ead6c90222632e5b1ff7f6e89887f1398934f064",
		}, "\n")
		if got := res.CanonicalRequest(); got != wantCanonical {
			t.Fatalf("CanonicalRequest mismatch\n got: %q\nwant: %q", got, wantCanonical)
		}
		requestHash := sha256.Sum256([]byte(wantCanonical))
		const documentedHash = "7019a55be8395899b900fb5564e4200d984910f34794a27cb3fb7d10ff6a1e84"
		if got := hex.EncodeToString(requestHash[:]); got != documentedHash {
			t.Fatalf("hashed canonical request = %s, want documented %s", got, documentedHash)
		}
		wantSTS := "TC3-HMAC-SHA256\n1551113065\n" + tencentDocScope + "\n" + documentedHash
		if got := res.StringToSign(); got != wantSTS {
			t.Fatalf("StringToSign mismatch\n got: %q\nwant: %q", got, wantSTS)
		}
		// 文档公布的派生签名密钥（SecretSigning）必须得到文档公布的 Signature。
		signingKey, err := hex.DecodeString("b596b923aad85185e2d1f6659d2a062e0a86731226e021e61bfe06f7ed05f5af")
		if err != nil {
			t.Fatalf("decode documented signing key: %v", err)
		}
		got := hex.EncodeToString(hmacSHA256(signingKey, wantSTS))
		const documentedSignature = "10b1a37a7301a02ca19a647ad722d5e43b4b3cff309d421d85b46093f6ab6c4f"
		if got != documentedSignature {
			t.Fatalf("signature from documented signing key = %s, want %s", got, documentedSignature)
		}
		if res.SignatureValue() != "644be983de9a8a3f00db8eadaba61467c3b429e2215758ba897b738ca469fd26" {
			t.Fatalf("signature with the documented example key pair = %s", res.SignatureValue())
		}
		if got := res.Header("X-TC-Action"); got != "DescribeInstances" {
			t.Fatalf("X-TC-Action = %q, want the caller-facing action name", got)
		}
	})
}

func TestTC3GetQueryAndSessionToken(t *testing.T) {
	reg := Registration{Service: "cvm", Region: "ap-guangzhou", Scheme: "https", Host: "cvm.tencentcloudapi.com"}
	cred := Credential{
		AccessID:     tencentDocSecretID,
		AccessSecret: []byte(tencentDocSecretKey),
		SessionToken: "TOKENEXAMPLE",
	}
	res := mustSignTC3(t, reg, cred, Request{
		Method:        "GET",
		URL:           "https://cvm.tencentcloudapi.com/?Offset=0&Limit=10&Filters.0.Name=zone",
		Headers:       http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
		PayloadSHA256: EmptyPayloadSHA256,
		Action:        "DescribeInstances",
		Time:          tencentDocTime(),
	})
	if got := res.Header("X-TC-Token"); got != "TOKENEXAMPLE" {
		t.Fatalf("X-TC-Token = %q", got)
	}
	if strings.Contains(strings.Join(res.SignedHeaders, ";"), "x-tc-token") {
		t.Fatalf("x-tc-token must not be part of TC3 signed headers: %v", res.SignedHeaders)
	}
	lines := strings.Split(res.CanonicalRequest(), "\n")
	if lines[1] != "/" {
		t.Fatalf("canonical URI = %q, want fixed /", lines[1])
	}
	if want := "Filters.0.Name=zone&Limit=10&Offset=0"; lines[2] != want {
		t.Fatalf("canonical query = %q, want %q", lines[2], want)
	}
	if lines[3] != "content-type:application/x-www-form-urlencoded" {
		t.Fatalf("canonical content-type line = %q", lines[3])
	}
	if got := res.Header("X-TC-Timestamp"); got != "1551113065" {
		t.Fatalf("X-TC-Timestamp = %q", got)
	}
}

func TestTC3Rejections(t *testing.T) {
	reg := Registration{
		Service: "cvm", Region: "ap-guangzhou", Scheme: "https",
		Host: "cvm.tencentcloudapi.com", PathPrefixes: []string{"/"},
	}
	cred := tencentDocCredential()
	good := Request{
		Method:        "POST",
		URL:           "https://cvm.tencentcloudapi.com/",
		Headers:       http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		PayloadSHA256: tencentDocPayloadHash(t),
		Action:        "DescribeInstances",
		Time:          tencentDocTime(),
	}
	cases := []struct {
		name string
		cred Credential
		req  Request
		code ErrorCode
	}{
		{
			name: "unregistered host", cred: cred,
			req:  tc3WithURL(good, "https://cvm.ap-shanghai.tencentcloudapi.com/"),
			code: CodeTargetMismatch,
		},
		{
			name: "path outside the fixed canonical URI", cred: cred,
			req:  tc3WithURL(good, "https://cvm.tencentcloudapi.com/v1/instances"),
			code: CodeUnsupported,
		},
		{
			name: "scheme mismatch", cred: cred,
			req:  tc3WithURL(good, "http://cvm.tencentcloudapi.com/"),
			code: CodeTargetMismatch,
		},
		{
			name: "unsupported method", cred: cred,
			req:  tc3WithMethod(good, "DELETE"),
			code: CodeUnsupported,
		},
		{
			name: "lowercase method", cred: cred,
			req:  tc3WithMethod(good, "post"),
			code: CodeInvalidRequest,
		},
		{
			name: "post with query string", cred: cred,
			req:  tc3WithURL(good, "https://cvm.tencentcloudapi.com/?Limit=10"),
			code: CodeUnsupported,
		},
		{
			name: "missing payload digest", cred: cred,
			req:  tc3WithPayload(good, ""),
			code: CodeInvalidRequest,
		},
		{
			name: "unsigned payload marker", cred: cred,
			req:  tc3WithPayload(good, "UNSIGNED-PAYLOAD"),
			code: CodeUnsupported,
		},
		{
			name: "missing content-type", cred: cred,
			req:  tc3WithoutHeader(good, "Content-Type"),
			code: CodeInvalidRequest,
		},
		{
			name: "uppercase content-type value", cred: cred,
			req:  tc3WithHeader(good, "Content-Type", "Application/JSON"),
			code: CodeInvalidRequest,
		},
		{
			name: "timestamp override", cred: cred,
			req:  tc3WithHeader(good, "X-TC-Timestamp", "1551113066"),
			code: CodeInvalidRequest,
		},
		{
			name: "token header without credential token", cred: cred,
			req:  tc3WithHeader(good, "X-TC-Token", "TOKENEXAMPLE"),
			code: CodeInvalidRequest,
		},
		{
			name: "header outside the signing set", cred: cred,
			req:  tc3WithHeader(good, "X-TC-Version", "2017-03-12"),
			code: CodeUnsupported,
		},
		{
			name: "regional override", cred: cred,
			req: Request{
				Method: good.Method, URL: good.URL, Headers: good.Headers,
				PayloadSHA256: good.PayloadSHA256, Action: good.Action,
				Region: "ap-beijing", Time: good.Time,
			},
			code: CodeConfigUnsupported,
		},
		{
			name: "action disagrees with header", cred: cred,
			req: Request{
				Method: good.Method, URL: good.URL,
				Headers:       http.Header{"Content-Type": []string{"application/json; charset=utf-8"}, "X-TC-Action": []string{"DescribeInstances"}},
				PayloadSHA256: good.PayloadSHA256, Action: "DescribeRegions", Time: good.Time,
			},
			code: CodeInvalidRequest,
		},
		{
			name: "missing access secret", cred: Credential{AccessID: tencentDocSecretID},
			req:  good,
			code: CodeCredentialIncomplete,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SignTC3(reg, tc.cred, tc.req)
			if err == nil {
				t.Fatalf("SignTC3() accepted an out-of-scope request")
			}
			var se *Error
			if !errors.As(err, &se) {
				t.Fatalf("error is not a signer error: %v", err)
			}
			if se.Code != tc.code {
				t.Fatalf("error code = %s, want %s (%v)", se.Code, tc.code, err)
			}
			if strings.Contains(err.Error(), tencentDocSecretKey) {
				t.Fatalf("error message leaked the secret key")
			}
		})
	}
}

func tc3WithURL(r Request, raw string) Request   { r.URL = raw; return r }
func tc3WithMethod(r Request, m string) Request  { r.Method = m; return r }
func tc3WithPayload(r Request, v string) Request { r.PayloadSHA256 = v; return r }

func tc3WithHeader(r Request, name, value string) Request {
	h := http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}
	h.Set(name, value)
	r.Headers = h
	return r
}

func tc3WithoutHeader(r Request, name string) Request {
	h := http.Header{}
	for k, vs := range r.Headers {
		if strings.EqualFold(k, name) {
			continue
		}
		h[k] = vs
	}
	r.Headers = h
	return r
}
