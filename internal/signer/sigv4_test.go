package signer

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	testAccessID     = "AKIDEXAMPLE"
	testAccessSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
)

func testTime() time.Time {
	return time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
}

func mustSign(t *testing.T, reg Registration, cred Credential, req Request) *Result {
	t.Helper()
	res, err := Sign(reg, cred, req)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	return res
}

func authHeader(signedHeaders, scope, signature string) string {
	return "AWS4-HMAC-SHA256 Credential=" + testAccessID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

// TestOfficialAWSVectors 使用 AWS 官方 SigV4 测试套件与官方文档示例向量。
// 这些签名不依赖网络与真实密钥。
func TestOfficialAWSVectors(t *testing.T) {
	tests := []struct {
		name    string
		reg     Registration
		cred    Credential
		req     Request
		headers http.Header
		want    string
	}{
		{
			name: "get-vanilla",
			reg:  Registration{Service: "service", Region: "us-east-1", Scheme: "http", Host: "example.amazonaws.com"},
			cred: Credential{AccessID: testAccessID, AccessSecret: []byte(testAccessSecret)},
			req: Request{
				Method: "GET", URL: "http://example.amazonaws.com/",
				PayloadSHA256: EmptyPayloadSHA256, Time: testTime(),
			},
			want: authHeader("host;x-amz-date", "20150830/us-east-1/service/aws4_request",
				"5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"),
		},
		{
			name: "get-vanilla-query-order-key-case",
			reg:  Registration{Service: "service", Region: "us-east-1", Scheme: "http", Host: "example.amazonaws.com"},
			cred: Credential{AccessID: testAccessID, AccessSecret: []byte(testAccessSecret)},
			req: Request{
				Method: "GET", URL: "http://example.amazonaws.com/?Param2=value2&Param1=value1",
				PayloadSHA256: EmptyPayloadSHA256, Time: testTime(),
			},
			want: authHeader("host;x-amz-date", "20150830/us-east-1/service/aws4_request",
				"b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"),
		},
		{
			name: "post-vanilla",
			reg:  Registration{Service: "service", Region: "us-east-1", Scheme: "http", Host: "example.amazonaws.com"},
			cred: Credential{AccessID: testAccessID, AccessSecret: []byte(testAccessSecret)},
			req: Request{
				Method: "POST", URL: "http://example.amazonaws.com/",
				PayloadSHA256: EmptyPayloadSHA256, Time: testTime(),
			},
			want: authHeader("host;x-amz-date", "20150830/us-east-1/service/aws4_request",
				"5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"),
		},
		{
			name: "s3-doc-get-object-range",
			reg:  Registration{Service: "s3", Region: "us-east-1", Scheme: "http", Host: "examplebucket.s3.amazonaws.com"},
			cred: Credential{AccessID: "AKIAIOSFODNN7EXAMPLE", AccessSecret: []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")},
			req: Request{
				Method: "GET", URL: "http://examplebucket.s3.amazonaws.com/test.txt",
				Headers:       http.Header{"Range": []string{"bytes=0-9"}},
				PayloadSHA256: EmptyPayloadSHA256,
				Time:          time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC),
			},
			want: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
				"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
				"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name: "s3-doc-put-object",
			reg:  Registration{Service: "s3", Region: "us-east-1", Scheme: "http", Host: "examplebucket.s3.amazonaws.com"},
			cred: Credential{AccessID: "AKIAIOSFODNN7EXAMPLE", AccessSecret: []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")},
			req: Request{
				Method: "PUT", URL: "http://examplebucket.s3.amazonaws.com/test%24file.text",
				Headers: http.Header{
					"Date":                []string{"Fri, 24 May 2013 00:00:00 GMT"},
					"X-Amz-Storage-Class": []string{"REDUCED_REDUNDANCY"},
				},
				PayloadSHA256: "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
				Time:          time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC),
			},
			want: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
				"SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, " +
				"Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		},
		{
			name: "s3-doc-list-objects",
			reg:  Registration{Service: "s3", Region: "us-east-1", Scheme: "http", Host: "examplebucket.s3.amazonaws.com"},
			cred: Credential{AccessID: "AKIAIOSFODNN7EXAMPLE", AccessSecret: []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")},
			req: Request{
				Method: "GET", URL: "http://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J",
				PayloadSHA256: EmptyPayloadSHA256,
				Time:          time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC),
			},
			want: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
				"SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
				"Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := mustSign(t, tc.reg, tc.cred, tc.req)
			if got := res.Headers.Get("Authorization"); got != tc.want {
				t.Fatalf("Authorization mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

func TestSessionTokenHeaderAndDuplicateQuery(t *testing.T) {
	reg := Registration{Service: "service", Region: "us-east-1", Scheme: "http", Host: "example.amazonaws.com"}
	cred := Credential{AccessID: testAccessID, AccessSecret: []byte(testAccessSecret), SessionToken: "SESSIONTOKENEXAMPLE"}
	res := mustSign(t, reg, cred, Request{
		Method: "GET", URL: "http://example.amazonaws.com/?a=2&a=1",
		PayloadSHA256: EmptyPayloadSHA256, Time: testTime(),
	})
	want := authHeader("host;x-amz-date;x-amz-security-token", "20150830/us-east-1/service/aws4_request",
		"d7e29ef8955744e1b4905a3573f0d4d9f6d2797787ef19d747750b9d98613e1a")
	if got := res.Headers.Get("Authorization"); got != want {
		t.Fatalf("Authorization mismatch\n got: %s\nwant: %s", got, want)
	}
	if got := res.Headers.Get("X-Amz-Security-Token"); got != "SESSIONTOKENEXAMPLE" {
		t.Fatalf("security token header = %q", got)
	}
	lines := strings.Split(res.CanonicalRequest(), "\n")
	if lines[2] != "a=1&a=2" {
		t.Fatalf("canonical query = %q, want duplicates preserved and sorted", lines[2])
	}
	if res.Headers.Get("X-Amz-Content-Sha256") != EmptyPayloadSHA256 {
		t.Fatalf("content sha header missing")
	}
	if res.Headers.Get("X-Amz-Date") != "20150830T123600Z" {
		t.Fatalf("amz date header = %q", res.Headers.Get("X-Amz-Date"))
	}
}

func TestHeaderNormalizationAndSignedSet(t *testing.T) {
	reg := Registration{Service: "s3", Region: "us-east-1", Scheme: "https", Host: "Bucket.Example.com"}
	res := mustSign(t, reg, Credential{AccessID: testAccessID, AccessSecret: []byte(testAccessSecret)}, Request{
		Method: "PUT", URL: "https://bucket.example.com:443/key.bin?a=1&a=2",
		Headers: http.Header{
			"X-Amz-Meta-Note": []string{"  spaced   value  "},
			"Content-Type":    []string{"text/plain"},
		},
		PayloadSHA256: EmptyPayloadSHA256, Time: testTime(),
	})
	joined := strings.Join(res.SignedHeaders, ";")
	want := "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-note"
	if joined != want {
		t.Fatalf("signed headers = %q, want %q", joined, want)
	}
	canonical := res.CanonicalRequest()
	if !strings.Contains(canonical, "x-amz-meta-note:spaced value\n") {
		t.Fatalf("header value was not trimmed/collapsed: %q", canonical)
	}
}

func TestParseAdapterID(t *testing.T) {
	service, region, err := ParseAdapterID("aws-sigv4/us-west-2/s3")
	if err != nil || service != "s3" || region != "us-west-2" {
		t.Fatalf("ParseAdapterID = %q,%q,%v", service, region, err)
	}
	for _, id := range []string{"", "sigv4/us-east-1/s3", "aws-sigv4/s3", "aws-sigv4/us-east-1/s3/extra", "aws-sigv4//s3"} {
		if _, _, err := ParseAdapterID(id); err == nil {
			t.Fatalf("ParseAdapterID(%q) accepted", id)
		}
	}
}

func TestRejections(t *testing.T) {
	baseReg := Registration{Service: "s3", Region: "us-east-1", Scheme: "http", Host: "127.0.0.1:9000", PathPrefixes: []string{"/bucket/"}}
	baseCred := Credential{AccessID: testAccessID, AccessSecret: []byte(testAccessSecret)}
	good := Request{
		Method: "GET", URL: "http://127.0.0.1:9000/bucket/key",
		PayloadSHA256: EmptyPayloadSHA256, Time: testTime(),
	}
	cases := []struct {
		name string
		reg  Registration
		cred Credential
		req  Request
		code ErrorCode
	}{
		{
			name: "unregistered host", reg: baseReg, cred: baseCred,
			req:  withURL(good, "http://127.0.0.1:9001/bucket/key"),
			code: CodeTargetMismatch,
		},
		{
			name: "path outside registered prefixes", reg: baseReg, cred: baseCred,
			req:  withURL(good, "http://127.0.0.1:9000/other/key"),
			code: CodeTargetMismatch,
		},
		{
			name: "dot segment escapes registered prefix", reg: baseReg, cred: baseCred,
			req:  withURL(good, "http://127.0.0.1:9000/bucket/../other/key"),
			code: CodeTargetMismatch,
		},
		{
			name: "fragment is not signable", reg: baseReg, cred: baseCred,
			req:  withURL(good, "http://127.0.0.1:9000/bucket/key#frag"),
			code: CodeInvalidRequest,
		},
		{
			name: "scheme mismatch", reg: baseReg, cred: baseCred,
			req:  withURL(good, "https://127.0.0.1:9000/bucket/key"),
			code: CodeTargetMismatch,
		},
		{
			name: "host header override", reg: baseReg, cred: baseCred,
			req:  withHeader(good, "Host", "evil.example.com"),
			code: CodeTargetMismatch,
		},
		{
			name: "wrong region override", reg: baseReg, cred: baseCred,
			req:  withRegion(good, "eu-west-1"),
			code: CodeConfigUnsupported,
		},
		{
			name: "wrong service override", reg: baseReg, cred: baseCred,
			req:  withService(good, "sqs"),
			code: CodeConfigUnsupported,
		},
		{
			name: "unregistered adapter config", reg: Registration{Scheme: "http", Host: "127.0.0.1:9000"}, cred: baseCred,
			req:  good,
			code: CodeConfigUnsupported,
		},
		{
			name: "chunked transfer encoding", reg: baseReg, cred: baseCred,
			req:  withHeader(good, "Transfer-Encoding", "chunked"),
			code: CodeUnsupported,
		},
		{
			name: "aws-chunked content encoding", reg: baseReg, cred: baseCred,
			req:  withHeader(good, "Content-Encoding", "aws-chunked"),
			code: CodeUnsupported,
		},
		{
			name: "decoded content length", reg: baseReg, cred: baseCred,
			req:  withHeader(good, "X-Amz-Decoded-Content-Length", "1024"),
			code: CodeUnsupported,
		},
		{
			name: "streaming payload hash header", reg: baseReg, cred: baseCred,
			req:  withHeader(good, "X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
			code: CodeUnsupported,
		},
		{
			name: "unsigned payload mode", reg: baseReg, cred: baseCred,
			req:  withPayload(good, "UNSIGNED-PAYLOAD"),
			code: CodeUnsupported,
		},
		{
			name: "presigned query", reg: baseReg, cred: baseCred,
			req:  withURL(good, "http://127.0.0.1:9000/bucket/key?X-Amz-Signature=abc"),
			code: CodeUnsupported,
		},
		{
			name: "missing payload hash", reg: baseReg, cred: baseCred,
			req:  withPayload(good, ""),
			code: CodeInvalidRequest,
		},
		{
			name: "malformed payload hash", reg: baseReg, cred: baseCred,
			req:  withPayload(good, "abc123"),
			code: CodeInvalidRequest,
		},
		{
			name: "missing access id", reg: baseReg, cred: Credential{AccessSecret: []byte(testAccessSecret)},
			req:  good,
			code: CodeCredentialIncomplete,
		},
		{
			name: "missing access secret", reg: baseReg, cred: Credential{AccessID: testAccessID},
			req:  good,
			code: CodeCredentialIncomplete,
		},
		{
			name: "unsupported method", reg: baseReg, cred: baseCred,
			req:  withMethod(good, "CONNECT"),
			code: CodeInvalidRequest,
		},
		{
			name: "lowercase method", reg: baseReg, cred: baseCred,
			req:  withMethod(good, "get"),
			code: CodeInvalidRequest,
		},
		{
			name: "unsignable header", reg: baseReg, cred: baseCred,
			req:  withHeader(good, "Authorization", "Bearer x"),
			code: CodeUnsupported,
		},
		{
			name: "internal header", reg: baseReg, cred: baseCred,
			req:  withHeader(good, "X-KeyKoi-Session", "kks_x"),
			code: CodeUnsupported,
		},
		{
			name: "non-s3 encoded path", reg: Registration{Service: "execute-api", Region: "us-east-1", Scheme: "http", Host: "127.0.0.1:9000"}, cred: baseCred,
			req:  withURL(good, "http://127.0.0.1:9000/a%20b"),
			code: CodeUnsupported,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Sign(tc.reg, tc.cred, tc.req)
			if err == nil {
				t.Fatalf("Sign() accepted an out-of-scope request")
			}
			var se *Error
			if !errors.As(err, &se) {
				t.Fatalf("error is not a signer error: %v", err)
			}
			if se.Code != tc.code {
				t.Fatalf("error code = %s, want %s (%v)", se.Code, tc.code, err)
			}
			if strings.Contains(err.Error(), testAccessSecret) {
				t.Fatalf("error message leaked the access secret")
			}
		})
	}
}

func TestDefaultPortEquivalence(t *testing.T) {
	reg := Registration{Service: "s3", Region: "us-east-1", Scheme: "http", Host: "example.amazonaws.com"}
	res := mustSign(t, reg, Credential{AccessID: testAccessID, AccessSecret: []byte(testAccessSecret)}, Request{
		Method: "GET", URL: "http://example.amazonaws.com:80/key",
		PayloadSHA256: EmptyPayloadSHA256, Time: testTime(),
	})
	if !strings.Contains(res.CanonicalRequest(), "host:example.amazonaws.com\n") {
		t.Fatalf("default port was not normalized: %q", res.CanonicalRequest())
	}
}

func withURL(r Request, raw string) Request   { r.URL = raw; return r }
func withMethod(r Request, m string) Request  { r.Method = m; return r }
func withRegion(r Request, v string) Request  { r.Region = v; return r }
func withService(r Request, v string) Request { r.Service = v; return r }
func withPayload(r Request, v string) Request { r.PayloadSHA256 = v; return r }

func withHeader(r Request, name, value string) Request {
	h := http.Header{}
	for k, vs := range r.Headers {
		h[k] = vs
	}
	h.Set(name, value)
	r.Headers = h
	return r
}

// TestCredentialFromFieldsStaticAccessKey 覆盖 33：静态 AccessKey 没有 session_token
// 字段时仍可构造凭证并签名，签出的头不含 Security-Token。
func TestCredentialFromFieldsStaticAccessKey(t *testing.T) {
	cred, err := CredentialFromFields(func(name string) (string, bool) {
		switch name {
		case "access_id":
			return testAccessID, true
		case "access_secret":
			return testAccessSecret, true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("static credential rejected: %v", err)
	}
	if cred.SessionToken != "" {
		t.Fatalf("static credential gained a session token: %q", cred.SessionToken)
	}
	reg := Registration{Service: "s3", Region: "us-east-1", Scheme: "https", Host: "bucket.example.com"}
	res := mustSign(t, reg, cred, Request{
		Method: "GET", URL: "https://bucket.example.com/key.bin",
		PayloadSHA256: EmptyPayloadSHA256, Time: testTime(),
	})
	if got := res.Headers.Get("X-Amz-Security-Token"); got != "" {
		t.Fatalf("static key signature carries a security token: %q", got)
	}
	if strings.Contains(strings.Join(res.SignedHeaders, ";"), "x-amz-security-token") {
		t.Fatalf("security token header signed for a static key: %v", res.SignedHeaders)
	}
	want := mustSign(t, reg, Credential{AccessID: testAccessID, AccessSecret: []byte(testAccessSecret)}, Request{
		Method: "GET", URL: "https://bucket.example.com/key.bin",
		PayloadSHA256: EmptyPayloadSHA256, Time: testTime(),
	})
	if res.Headers.Get("Authorization") != want.Headers.Get("Authorization") {
		t.Fatal("static credential mapping changed the signature")
	}
}

// TestCredentialFromFieldsSessionAndRequiredFields 确认临时会话令牌仍然被要求签署，
// access_id/access_secret 缺失或为空仍报字段不完整。
func TestCredentialFromFieldsSessionAndRequiredFields(t *testing.T) {
	fields := map[string]string{
		"access_id":     testAccessID,
		"access_secret": testAccessSecret,
		"session_token": "SESSIONTOKENEXAMPLE",
	}
	get := func(name string) (string, bool) {
		v, ok := fields[name]
		return v, ok
	}
	cred, err := CredentialFromFields(get)
	if err != nil {
		t.Fatalf("CredentialFromFields() error: %v", err)
	}
	if cred.SessionToken != "SESSIONTOKENEXAMPLE" {
		t.Fatalf("session token = %q", cred.SessionToken)
	}
	reg := Registration{Service: "service", Region: "us-east-1", Scheme: "http", Host: "example.amazonaws.com"}
	res := mustSign(t, reg, cred, Request{
		Method: "GET", URL: "http://example.amazonaws.com/",
		PayloadSHA256: EmptyPayloadSHA256, Time: testTime(),
	})
	if got := res.Headers.Get("X-Amz-Security-Token"); got != "SESSIONTOKENEXAMPLE" {
		t.Fatalf("security token header = %q", got)
	}

	for _, missing := range []string{"access_id", "access_secret"} {
		without := map[string]string{}
		for k, v := range fields {
			without[k] = v
		}
		delete(without, missing)
		_, err := CredentialFromFields(func(name string) (string, bool) {
			v, ok := without[name]
			return v, ok
		})
		var se *Error
		if !errors.As(err, &se) || se.Code != CodeCredentialIncomplete {
			t.Fatalf("missing %s: err = %v, want %s", missing, err, CodeCredentialIncomplete)
		}
	}
	// 字段存在但为空同样按不完整处理。
	if _, err := CredentialFromFields(func(name string) (string, bool) {
		return "", true
	}); err == nil {
		t.Fatal("empty access fields were accepted")
	}
}
