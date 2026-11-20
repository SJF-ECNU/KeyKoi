package central

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
)

// fakeCenter 是只实现许可与确认两个接口的测试中心，用于验证客户端重试边界。
type fakeCenter struct {
	mu           sync.Mutex
	checkCodes   []string // 依次返回的 /v1/check 错误码，空字符串表示成功
	leaseCalls   int
	checkCalls   int
	lastLeaseReq leaseRequestBody
}

func (f *fakeCenter) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/leases", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body leaseRequestBody
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.leaseCalls++
		f.lastLeaseReq = body
		f.mu.Unlock()
		lease := Lease{
			ID: "lease_" + body.Nonce, DeviceID: testDeviceID, BindingID: body.BindingID,
			PrincipalID: body.PrincipalID, CredentialVersion: 7, Mode: body.Mode,
			Epoch: "epoch-new", IssuedAt: testNow, ExpiresAt: testNow.Add(90 * time.Second),
		}
		writeJSON(w, http.StatusOK, map[string]any{"lease": lease, "epoch": "epoch-new", "credential_id": "cred_1"})
	})
	mux.HandleFunc("/v1/check", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.checkCalls++
		code := ""
		if len(f.checkCodes) > 0 {
			code = f.checkCodes[0]
			f.checkCodes = f.checkCodes[1:]
		}
		f.mu.Unlock()
		if code == "" {
			writeJSON(w, http.StatusOK, map[string]any{"valid": true, "epoch": "epoch-new"})
			return
		}
		status := http.StatusConflict
		if code == codeControlNone {
			status = http.StatusForbidden
		}
		writeErr(w, status, code, "test center response")
	})
	return mux
}

func newTestClient(t *testing.T, fc *fakeCenter) *Client {
	t.Helper()
	srv := httptest.NewServer(fc.handler())
	t.Cleanup(srv.Close)
	return &Client{
		BaseURL: srv.URL, DeviceID: testDeviceID, Secret: testDeviceSecret, Mode: "online",
		HTTP: &http.Client{Timeout: 5 * time.Second}, Now: func() time.Time { return testNow },
		leases: map[leaseKey]Lease{},
	}
}

// TestCheckUseRetriesEpochStaleOnce 验证代次过期会重新取许可并确认一次。
func TestCheckUseRetriesEpochStaleOnce(t *testing.T) {
	fc := &fakeCenter{checkCodes: []string{codeLeaseEpochStale}}
	c := newTestClient(t, fc)
	permit, err := c.CheckUse(context.Background(), broker.UseQuery{
		PrincipalID: "principal_1", BindingID: "binding_1", Mode: model.ModeRuntimeDelivery,
		CredentialID: "cred_1", CredentialVersion: 7,
	})
	if err != nil {
		t.Fatalf("epoch rotation must be retried: %v", err)
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.checkCalls != 2 {
		t.Fatalf("expected exactly one retry, got %d checks", fc.checkCalls)
	}
	if fc.leaseCalls != 2 {
		t.Fatalf("retry must reissue the lease once, got %d lease calls", fc.leaseCalls)
	}
	if permit.CredentialVersion != 7 || permit.Mode != model.ModeRuntimeDelivery {
		t.Fatalf("permit must carry center version and mode: %+v", permit)
	}
	if permit.LeaseID == "" {
		t.Fatal("permit must reference the lease")
	}
	if fc.lastLeaseReq.PrincipalID != "principal_1" || fc.lastLeaseReq.Mode != string(model.ModeRuntimeDelivery) {
		t.Fatalf("lease request must carry principal and mode: %+v", fc.lastLeaseReq)
	}
}

// TestCheckUseDoesNotRetryRevocation 验证真正撤销立即拒绝且不重试。
func TestCheckUseDoesNotRetryRevocation(t *testing.T) {
	fc := &fakeCenter{checkCodes: []string{codeControlNone, codeControlNone}}
	c := newTestClient(t, fc)
	_, err := c.CheckUse(context.Background(), broker.UseQuery{BindingID: "binding_1", Mode: model.ModeProxy, CredentialVersion: 7})
	if err == nil {
		t.Fatal("revocation must stop the use")
	}
	if model.CodeOf(err) != model.CodeControlUnavailable {
		t.Fatalf("revocation must surface CONTROL_UNAVAILABLE, got %v", err)
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.checkCalls != 1 {
		t.Fatalf("revocation must not be retried, got %d checks", fc.checkCalls)
	}
	if fc.leaseCalls != 1 {
		t.Fatalf("revocation must not reissue the lease, got %d lease calls", fc.leaseCalls)
	}
}

// TestCheckUseRetryIsBounded 验证重试只有一次：连续代次过期必须失败。
func TestCheckUseRetryIsBounded(t *testing.T) {
	fc := &fakeCenter{checkCodes: []string{codeLeaseEpochStale, codeLeaseEpochStale, codeLeaseEpochStale}}
	c := newTestClient(t, fc)
	if _, err := c.CheckUse(context.Background(), broker.UseQuery{BindingID: "binding_1", Mode: model.ModeProxy, CredentialVersion: 7}); err == nil {
		t.Fatal("second epoch failure must stop the use")
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.checkCalls != 2 {
		t.Fatalf("retry must be bounded to one: %d checks", fc.checkCalls)
	}
}
