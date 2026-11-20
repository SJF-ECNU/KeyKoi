package central

import (
	"net/http"
	"testing"
)

// 绑定级策略（未限定主体）继续按绑定授权，许可里记录请求声明的实际主体；
// 限定主体的策略只授权该主体。
func TestPolicyPrincipalScope(t *testing.T) {
	s, data := newTestServer(t)
	data.policies["binding_1"] = policyRecord{
		CredentialID: "cred_1", CredentialVersion: 3, Mode: "runtime_delivery", Status: "active",
	}
	h := s.Handler()

	// 未限定主体的策略：任意实际主体都可以申请，许可记录该主体。
	reqBody := leaseRequestBody{BindingID: "binding_1", PrincipalID: "principal_local_501", Mode: "runtime_delivery", Nonce: "n1"}
	rec, out := doJSON(t, h, http.MethodPost, "/v1/leases", reqBody, deviceHeaders(t, reqBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("binding-scoped policy must authorize any principal, got %d %v", rec.Code, out)
	}
	lease, _ := out["lease"].(map[string]any)
	if lease["principal_id"] != "principal_local_501" {
		t.Fatalf("the lease must record the actual principal, got %v", lease["principal_id"])
	}

	// 限定主体的策略：其他主体被拒绝。
	data.policies["binding_1"] = policyRecord{
		PrincipalID: "principal_local_501", CredentialID: "cred_1", CredentialVersion: 3,
		Mode: "runtime_delivery", Status: "active",
	}
	reqBody = leaseRequestBody{BindingID: "binding_1", PrincipalID: "principal_other", Mode: "runtime_delivery", Nonce: "n2"}
	rec, out = doJSON(t, h, http.MethodPost, "/v1/leases", reqBody, deviceHeaders(t, reqBody))
	if rec.Code != http.StatusForbidden || errorCodeOf(out) != "USE_NOT_ALLOWED" {
		t.Fatalf("a policy scoped to another principal must refuse, got %d %v", rec.Code, out)
	}

	// /v1/check 复核同一主体是否仍然匹配。
	reqBody = leaseRequestBody{BindingID: "binding_1", PrincipalID: "principal_local_501", Mode: "runtime_delivery", Nonce: "n3"}
	rec, out = doJSON(t, h, http.MethodPost, "/v1/leases", reqBody, deviceHeaders(t, reqBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("scoped policy must authorize its own principal, got %d %v", rec.Code, out)
	}
	lease, _ = out["lease"].(map[string]any)
	checkBody := map[string]string{"lease_id": lease["id"].(string), "device_id": testDeviceID}
	rec, out = doJSON(t, h, http.MethodPost, "/v1/check", checkBody, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("check of a matching principal must pass, got %d %v", rec.Code, out)
	}
	if out["principal_id"] != "principal_local_501" {
		t.Fatalf("check must echo the authorized principal, got %v", out["principal_id"])
	}

	// 策略改成另一个主体后，旧许可不能继续使用。
	data.policies["binding_1"] = policyRecord{
		PrincipalID: "principal_other", CredentialID: "cred_1", CredentialVersion: 3,
		Mode: "runtime_delivery", Status: "active",
	}
	rec, out = doJSON(t, h, http.MethodPost, "/v1/check", checkBody, nil)
	if rec.Code != http.StatusForbidden || errorCodeOf(out) != codeControlNone {
		t.Fatalf("a policy moved to another principal must invalidate the old lease, got %d %v", rec.Code, out)
	}
}
