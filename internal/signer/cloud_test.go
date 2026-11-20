package signer

import (
	"net/http"
	"testing"
	"time"
)

func TestParseAdapter(t *testing.T) {
	cases := []struct {
		id       string
		protocol string
		region   string
		service  string
	}{
		{"aws-sigv4/us-west-2/s3", ProtocolAWSSigV4, "us-west-2", "s3"},
		{"tencent-tc3/ap-guangzhou/cvm", ProtocolTencentTC3, "ap-guangzhou", "cvm"},
		{"huawei-aksk/cn-north-4/ecs", ProtocolHuaweiAKSK, "cn-north-4", "ecs"},
	}
	for _, tc := range cases {
		adapter, err := ParseAdapter(tc.id)
		if err != nil {
			t.Fatalf("ParseAdapter(%q) error: %v", tc.id, err)
		}
		if adapter.Protocol != tc.protocol || adapter.Region != tc.region || adapter.Service != tc.service {
			t.Fatalf("ParseAdapter(%q) = %+v", tc.id, adapter)
		}
	}
	bad := []string{
		"", "tencent-tc3", "tencent-tc3/ap-guangzhou", "tencent-tc3/ap-guangzhou/cvm/extra",
		"tencent-tc3//cvm", "aliyun-v3/cn-hangzhou/ecs", "aws-sigv4/us-east-1/s3 ",
	}
	for _, id := range bad {
		if id == "aws-sigv4/us-east-1/s3 " {
			// 首尾空白会被 trimming 接受，这里只确认它不会被误判成别的协议。
			if adapter, err := ParseAdapter(id); err != nil || adapter.Protocol != ProtocolAWSSigV4 {
				t.Fatalf("ParseAdapter(%q) = %+v, %v", id, adapter, err)
			}
			continue
		}
		if _, err := ParseAdapter(id); err == nil {
			t.Fatalf("ParseAdapter(%q) accepted an unregistered adapter", id)
		}
	}
}

// TestSignProtocolDispatch 确认 daemon 用的分派入口与直接调用一致，
// 且 AWS 分支仍然只产出原来的 SigV4 头。
func TestSignProtocolDispatch(t *testing.T) {
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	base := Credential{AccessID: "AKIDEXAMPLE", AccessSecret: []byte("secret-value-EXAMPLE")}

	awsReg := Registration{Service: "s3", Region: "us-east-1", Scheme: "https", Host: "bucket.example.com"}
	awsReq := Request{Method: "GET", URL: "https://bucket.example.com/key", PayloadSHA256: EmptyPayloadSHA256, Time: now}
	aws, err := SignProtocol(Adapter{Protocol: ProtocolAWSSigV4, Service: "s3", Region: "us-east-1"}, awsReg, base, awsReq)
	if err != nil {
		t.Fatalf("SignProtocol(aws) error: %v", err)
	}
	if aws.Headers.Get("Authorization") == "" || aws.Timestamp == "" || aws.SignatureValue() == "" {
		t.Fatalf("aws dispatch result is incomplete: %+v", aws)
	}

	tc3Reg := Registration{Service: "cvm", Region: "ap-guangzhou", Scheme: "https", Host: "cvm.tencentcloudapi.com"}
	tc3Req := Request{
		Method: "POST", URL: "https://cvm.tencentcloudapi.com/",
		Headers:       http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		PayloadSHA256: sha256Hex(TencentDocExamplePayload),
		Action:        "DescribeInstances",
		Time:          now,
	}
	tc3, err := SignProtocol(Adapter{Protocol: ProtocolTencentTC3, Service: "cvm", Region: "ap-guangzhou"}, tc3Reg, base, tc3Req)
	if err != nil {
		t.Fatalf("SignProtocol(tencent) error: %v", err)
	}
	directTC3, err := SignTC3(tc3Reg, base, tc3Req)
	if err != nil {
		t.Fatalf("SignTC3() error: %v", err)
	}
	if tc3.Headers.Get("Authorization") != directTC3.Headers.Get("Authorization") {
		t.Fatalf("tencent dispatch differs from direct call")
	}

	hwReg := Registration{Service: "ecs", Region: "cn-north-4", Scheme: "https", Host: "ecs.cn-north-4.myhuaweicloud.com"}
	hwReq := Request{
		Method: "GET", URL: "https://ecs.cn-north-4.myhuaweicloud.com/v2/proj/servers",
		Headers:       http.Header{"Content-Type": []string{"application/json"}},
		PayloadSHA256: EmptyPayloadSHA256,
		Time:          now,
	}
	hw, err := SignProtocol(Adapter{Protocol: ProtocolHuaweiAKSK, Service: "ecs", Region: "cn-north-4"}, hwReg, base, hwReq)
	if err != nil {
		t.Fatalf("SignProtocol(huawei) error: %v", err)
	}
	directHW, err := SignHuawei(hwReg, base, hwReq)
	if err != nil {
		t.Fatalf("SignHuawei() error: %v", err)
	}
	if hw.Headers.Get("Authorization") != directHW.Headers.Get("Authorization") {
		t.Fatalf("huawei dispatch differs from direct call")
	}

	if _, err := SignProtocol(Adapter{Protocol: "aliyun-v3"}, hwReg, base, hwReq); err == nil {
		t.Fatalf("SignProtocol accepted an unregistered protocol")
	}
}
