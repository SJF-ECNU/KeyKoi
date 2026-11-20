package central

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeData 是 dataStore 的内存实现，让处理器级测试不依赖 PostgreSQL。
type fakeData struct {
	devices     map[string]fakeDevice
	policies    map[string]policyRecord
	leases      map[string]leaseRecord
	revocations []Revocation
	seq         int64
}

type fakeDevice struct {
	secretHash string
	status     string
}

func newFakeData() *fakeData {
	return &fakeData{
		devices:  map[string]fakeDevice{},
		policies: map[string]policyRecord{},
		leases:   map[string]leaseRecord{},
	}
}

func (f *fakeData) RegisterDevice(_ context.Context, id, name, secretHash string, _ time.Time) error {
	f.devices[id] = fakeDevice{secretHash: secretHash, status: "active"}
	return nil
}

func (f *fakeData) Device(_ context.Context, id string) (string, string, error) {
	d, ok := f.devices[id]
	if !ok {
		return "", "", errFakeNotFound
	}
	return d.secretHash, d.status, nil
}

func (f *fakeData) DeviceStatus(_ context.Context, id string) (string, error) {
	d, ok := f.devices[id]
	if !ok {
		return "", errFakeNotFound
	}
	return d.status, nil
}

func (f *fakeData) UpsertPolicy(_ context.Context, bindingID string, p policyRecord) error {
	f.policies[bindingID] = p
	return nil
}

func (f *fakeData) Policy(_ context.Context, bindingID string) (policyRecord, error) {
	p, ok := f.policies[bindingID]
	if !ok {
		return policyRecord{}, errFakeNotFound
	}
	return p, nil
}

func (f *fakeData) BindingStatus(_ context.Context, bindingID string) (string, error) {
	p, ok := f.policies[bindingID]
	if !ok {
		return "", errFakeNotFound
	}
	return p.Status, nil
}

func (f *fakeData) InsertLease(_ context.Context, l Lease) error {
	f.leases[l.ID] = leaseRecord{
		Epoch: l.Epoch, Status: "active", BindingID: l.BindingID, PrincipalID: l.PrincipalID,
		Mode: l.Mode, CredentialVersion: l.CredentialVersion, ExpiresAt: l.ExpiresAt,
	}
	return nil
}

func (f *fakeData) Lease(_ context.Context, leaseID, deviceID string) (leaseRecord, error) {
	rec, ok := f.leases[leaseID]
	if !ok {
		return leaseRecord{}, errFakeNotFound
	}
	if _, ok := f.devices[deviceID]; !ok {
		return leaseRecord{}, errFakeNotFound
	}
	return rec, nil
}

func (f *fakeData) RevokeDevice(_ context.Context, target string, at time.Time, epoch string) error {
	d, ok := f.devices[target]
	if !ok {
		return errFakeNotFound
	}
	d.status = "revoked"
	f.devices[target] = d
	f.seq++
	f.revocations = append(f.revocations, Revocation{Sequence: f.seq, At: at, Kind: "device", Target: target, Epoch: epoch})
	return nil
}

func (f *fakeData) RevokeBinding(_ context.Context, target string, at time.Time, epoch string) error {
	p, ok := f.policies[target]
	if !ok {
		return errFakeNotFound
	}
	p.Status = "revoked"
	f.policies[target] = p
	f.seq++
	f.revocations = append(f.revocations, Revocation{Sequence: f.seq, At: at, Kind: "binding", Target: target, Epoch: epoch})
	return nil
}

func (f *fakeData) CountRevocations(_ context.Context, epoch, deviceID, bindingID string) (int, error) {
	n := 0
	for _, rev := range f.revocations {
		if rev.Epoch != epoch {
			continue
		}
		if (rev.Kind == "device" && rev.Target == deviceID) || (rev.Kind == "binding" && rev.Target == bindingID) {
			n++
		}
	}
	return n, nil
}

func (f *fakeData) Events(_ context.Context, since int64) ([]Revocation, error) {
	var out []Revocation
	for _, rev := range f.revocations {
		if rev.Sequence > since {
			out = append(out, rev)
		}
	}
	return out, nil
}

type fakeError string

func (e fakeError) Error() string { return string(e) }

const errFakeNotFound = fakeError("not found")

var testNow = time.Date(2026, 11, 20, 2, 0, 0, 0, time.UTC)

const (
	testAdminToken     = "admin-credential-xyz"
	testBootstrapToken = "bootstrap-credential-abc"
	testDeviceID       = "device_test"
	testDeviceSecret   = "device-secret-value"
)

func newTestServer(t *testing.T) (*Server, *fakeData) {
	t.Helper()
	data := newFakeData()
	sum := sha256.Sum256([]byte(testDeviceSecret))
	data.devices[testDeviceID] = fakeDevice{secretHash: hex.EncodeToString(sum[:]), status: "active"}
	s := &Server{
		AdminToken: testAdminToken, BootstrapToken: testBootstrapToken,
		Epoch: "epoch-current", SigningKey: []byte("signing-key"), LeaseTTL: 90 * time.Second,
		Now: func() time.Time { return testNow }, store: data,
	}
	return s, data
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any, headers map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = strings.NewReader(string(raw))
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func errorCodeOf(body map[string]any) string {
	if e, ok := body["error"].(map[string]any); ok {
		if code, ok := e["code"].(string); ok {
			return code
		}
	}
	return ""
}

func deviceHeaders(t *testing.T, body leaseRequestBody) map[string]string {
	t.Helper()
	sum := sha256.Sum256([]byte(testDeviceSecret))
	return map[string]string{
		"X-Device-ID":        testDeviceID,
		"X-Device-Signature": hmacSHA256([]byte(hex.EncodeToString(sum[:])), []byte(leaseSignaturePayload(body))),
	}
}

// TestRegisterUsesSeparateBootstrapCredential 验证设备注册只认注册凭据，
// 管理员凭据不能越权注册设备。
func TestRegisterUsesSeparateBootstrapCredential(t *testing.T) {
	s, data := newTestServer(t)
	h := s.Handler()

	rec, _ := doJSON(t, h, http.MethodPost, "/v1/devices/register", map[string]string{"name": "laptop"},
		map[string]string{"X-Central-Bootstrap": testAdminToken})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("administrator credential must not register devices, got %d", rec.Code)
	}
	if len(data.devices) != 1 {
		t.Fatal("rejected registration must not create a device")
	}

	rec, out := doJSON(t, h, http.MethodPost, "/v1/devices/register", map[string]string{"name": "laptop"},
		map[string]string{"X-Central-Bootstrap": testBootstrapToken})
	if rec.Code != http.StatusCreated {
		t.Fatalf("bootstrap credential must register devices, got %d body=%v", rec.Code, out)
	}
	if len(data.devices) != 2 {
		t.Fatalf("device was not persisted: %d", len(data.devices))
	}
}

// TestUnconfiguredCredentialsRejectEverything 验证「未配置就放行」不存在。
func TestUnconfiguredCredentialsRejectEverything(t *testing.T) {
	data := newFakeData()
	s := &Server{AdminToken: "", BootstrapToken: "", Epoch: "e", SigningKey: []byte("k"), LeaseTTL: time.Minute, Now: func() time.Time { return testNow }, store: data}
	h := s.Handler()

	rec, _ := doJSON(t, h, http.MethodPost, "/v1/devices/register", map[string]string{"name": "laptop"}, map[string]string{"X-Central-Bootstrap": ""})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured center must refuse registration, got %d", rec.Code)
	}
	rec, _ = doJSON(t, h, http.MethodPost, "/v1/admin/policy", map[string]any{"binding_id": "b", "credential_id": "c"},
		map[string]string{"X-Central-Admin": ""})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured center must refuse policy writes, got %d", rec.Code)
	}
	if err := ValidateCredentials("", ""); err == nil {
		t.Fatal("empty credentials must be rejected at startup")
	}
	if err := ValidateCredentials("same", "same"); err == nil {
		t.Fatal("bootstrap token equal to the administrator token must be rejected at startup")
	}
}

// TestAdminEndpointsRejectBootstrapCredential 验证注册凭据没有管理权限。
func TestAdminEndpointsRejectBootstrapCredential(t *testing.T) {
	s, data := newTestServer(t)
	h := s.Handler()
	body := map[string]any{"binding_id": "binding_1", "credential_id": "cred_1", "credential_version": 2, "mode": "proxy"}

	rec, _ := doJSON(t, h, http.MethodPost, "/v1/admin/policy", body, map[string]string{"X-Central-Admin": testBootstrapToken})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bootstrap credential must not write policy, got %d", rec.Code)
	}
	if len(data.policies) != 0 {
		t.Fatal("rejected policy write must not be stored")
	}
	rec, _ = doJSON(t, h, http.MethodPost, "/v1/admin/policy", body, map[string]string{"X-Central-Admin": testAdminToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("administrator credential must write policy, got %d", rec.Code)
	}
	rec, _ = doJSON(t, h, http.MethodPost, "/v1/admin/revoke", map[string]any{"kind": "binding", "target": "binding_1"},
		map[string]string{"X-Central-Admin": testBootstrapToken})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bootstrap credential must not revoke, got %d", rec.Code)
	}
	rec, _ = doJSON(t, h, http.MethodPost, "/v1/admin/revoke", map[string]any{"kind": "binding", "target": "binding_1"},
		map[string]string{"X-Central-Admin": testAdminToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("administrator credential must revoke, got %d", rec.Code)
	}
}

// TestLeaseHonorsModeAndVersion 验证许可按请求方式与版本裁定。
func TestLeaseHonorsModeAndVersion(t *testing.T) {
	s, data := newTestServer(t)
	data.policies["binding_1"] = policyRecord{CredentialID: "cred_1", CredentialVersion: 2, Mode: "runtime_delivery", Status: "active"}
	h := s.Handler()

	// 请求方式与策略不一致必须拒绝。
	reqBody := leaseRequestBody{BindingID: "binding_1", Mode: "proxy", Nonce: "n1"}
	rec, out := doJSON(t, h, http.MethodPost, "/v1/leases", reqBody, deviceHeaders(t, reqBody))
	if rec.Code != http.StatusForbidden || errorCodeOf(out) != "USE_NOT_ALLOWED" {
		t.Fatalf("mode mismatch must be refused, got %d %v", rec.Code, out)
	}

	// 请求版本与策略不一致：返回 LEASE_STALE，客户端会重新申请。
	reqBody = leaseRequestBody{BindingID: "binding_1", Mode: "runtime_delivery", Nonce: "n2", CredentialID: "cred_1", CredentialVersion: 1}
	rec, out = doJSON(t, h, http.MethodPost, "/v1/leases", reqBody, deviceHeaders(t, reqBody))
	if rec.Code != http.StatusConflict || errorCodeOf(out) != codeLeaseStale {
		t.Fatalf("stale version must return LEASE_STALE, got %d %v", rec.Code, out)
	}

	// 匹配时签发许可，并记录主体。
	reqBody = leaseRequestBody{BindingID: "binding_1", PrincipalID: "principal_1", Mode: "runtime_delivery", Nonce: "n3", CredentialID: "cred_1", CredentialVersion: 2}
	rec, out = doJSON(t, h, http.MethodPost, "/v1/leases", reqBody, deviceHeaders(t, reqBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("matching request must get a lease, got %d %v", rec.Code, out)
	}
	leaseRaw, ok := out["lease"].(map[string]any)
	if !ok {
		t.Fatalf("missing lease in response: %v", out)
	}
	if leaseRaw["principal_id"] != "principal_1" {
		t.Fatalf("lease must record the principal, got %v", leaseRaw["principal_id"])
	}
	if leaseRaw["mode"] != "runtime_delivery" {
		t.Fatalf("lease mode mismatch: %v", leaseRaw["mode"])
	}
	if leaseRaw["credential_version"].(float64) != 2 {
		t.Fatalf("lease must carry the policy version, got %v", leaseRaw["credential_version"])
	}
	if len(data.leases) != 1 {
		t.Fatalf("lease must be persisted once, got %d", len(data.leases))
	}
}

// TestCheckSeparatesEpochRotationFromRevocation 验证代次过期与真正撤销分开。
func TestCheckSeparatesEpochRotationFromRevocation(t *testing.T) {
	s, data := newTestServer(t)
	data.policies["binding_1"] = policyRecord{CredentialID: "cred_1", CredentialVersion: 2, Mode: "proxy", Status: "active"}
	data.leases["lease_old_epoch"] = leaseRecord{
		Epoch: "epoch-previous", Status: "active", BindingID: "binding_1", CredentialVersion: 2,
		Mode: "proxy", ExpiresAt: testNow.Add(time.Minute),
	}
	data.leases["lease_revoked"] = leaseRecord{
		Epoch: "epoch-current", Status: "revoked", BindingID: "binding_1", CredentialVersion: 2,
		Mode: "proxy", ExpiresAt: testNow.Add(time.Minute),
	}
	data.leases["lease_ok"] = leaseRecord{
		Epoch: "epoch-current", Status: "active", BindingID: "binding_1", CredentialVersion: 2,
		Mode: "proxy", ExpiresAt: testNow.Add(time.Minute),
	}
	h := s.Handler()

	rec, out := doJSON(t, h, http.MethodPost, "/v1/check", map[string]string{"lease_id": "lease_old_epoch", "device_id": testDeviceID}, nil)
	if rec.Code != http.StatusConflict || errorCodeOf(out) != codeLeaseEpochStale {
		t.Fatalf("epoch rotation must return LEASE_EPOCH_STALE, got %d %v", rec.Code, out)
	}
	rec, out = doJSON(t, h, http.MethodPost, "/v1/check", map[string]string{"lease_id": "lease_revoked", "device_id": testDeviceID}, nil)
	if rec.Code != http.StatusForbidden || errorCodeOf(out) != codeControlNone {
		t.Fatalf("revoked lease must return CONTROL_UNAVAILABLE, got %d %v", rec.Code, out)
	}

	// 策略版本前进后，旧版本的许可视为过期。
	data.policies["binding_1"] = policyRecord{CredentialID: "cred_1", CredentialVersion: 3, Mode: "proxy", Status: "active"}
	rec, out = doJSON(t, h, http.MethodPost, "/v1/check", map[string]string{"lease_id": "lease_ok", "device_id": testDeviceID}, nil)
	if rec.Code != http.StatusConflict || errorCodeOf(out) != codeLeaseStale {
		t.Fatalf("version drift must return LEASE_STALE, got %d %v", rec.Code, out)
	}

	// 版本一致时通过，并回显主体。
	data.policies["binding_1"] = policyRecord{CredentialID: "cred_1", CredentialVersion: 2, Mode: "proxy", Status: "active"}
	rec, out = doJSON(t, h, http.MethodPost, "/v1/check", map[string]string{"lease_id": "lease_ok", "device_id": testDeviceID}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid lease must pass, got %d %v", rec.Code, out)
	}

	// 设备撤销后，即使许可仍有效也返回 CONTROL_UNAVAILABLE。
	data.devices[testDeviceID] = fakeDevice{secretHash: data.devices[testDeviceID].secretHash, status: "revoked"}
	rec, out = doJSON(t, h, http.MethodPost, "/v1/check", map[string]string{"lease_id": "lease_ok", "device_id": testDeviceID}, nil)
	if rec.Code != http.StatusForbidden || errorCodeOf(out) != codeControlNone {
		t.Fatalf("revoked device must return CONTROL_UNAVAILABLE, got %d %v", rec.Code, out)
	}
}
