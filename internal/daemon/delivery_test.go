package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

// 通用解析接口只服务 runtime_delivery：签名许可不能取得整组原始凭证。
func TestResolveRejectsSignMode(t *testing.T) {
	f := newDaemonFixture(t)
	body := `{"token":"kks_x","binding_id":"bind_test","mode":"sign"}`
	rec := httptest.NewRecorder()
	f.d.handleResolve(rec, httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(body)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("sign mode must be rejected with 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), string(model.CodeUseNotAllowed)) {
		t.Fatalf("response must carry USE_NOT_ALLOWED: %s", rec.Body.String())
	}
}

// runtime_delivery 的解析结果必须带同一次授权的绑定快照，调用方不得另取目标。
func TestResolveReturnsBindingSnapshot(t *testing.T) {
	f := newDaemonFixture(t)
	ctx := context.Background()
	if err := f.st.PutGrant(ctx, &model.Grant{
		ID: "grant_runtime", PrincipalID: "principal_admin_local", BindingID: "bind_test",
		DeliveryMode: model.ModeRuntimeDelivery, MaxLeaseDuration: time.Minute,
		AuthRequirement: "permanent", Status: model.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	_, token, err := f.d.broker.CreateSession(ctx, "principal_admin_local", "test")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"token":"` + token.RevealString() + `","binding_id":"bind_test","mode":"runtime_delivery"}`
	rec := httptest.NewRecorder()
	f.d.handleResolve(rec, httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"binding"`) || !strings.Contains(rec.Body.String(), `"id":"bind_test"`) {
		t.Fatalf("resolve must return the authorized binding snapshot: %s", rec.Body.String())
	}
}

func TestResolveHonorsBindingRuntimeFields(t *testing.T) {
	f := newDaemonFixture(t)
	ctx := context.Background()
	f.b.material = model.CredentialVersion{Fields: map[string]secret.Value{
		"public_field":  secret.New("approved value"),
		"private_field": secret.New("restricted value"),
	}}
	binding, err := f.st.GetBinding(ctx, "bind_test")
	if err != nil {
		t.Fatal(err)
	}
	binding.RuntimeFields = []string{"public_field"}
	if err := f.st.PutBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := f.st.PutGrant(ctx, &model.Grant{
		ID: "runtime_selected", PrincipalID: "principal_admin_local", BindingID: binding.ID,
		DeliveryMode: model.ModeRuntimeDelivery, AuthRequirement: "permanent", Status: model.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	_, token, err := f.d.broker.CreateSession(ctx, "principal_admin_local", "test")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"token":"` + token.RevealString() + `","binding_id":"bind_test"}`
	w := httptest.NewRecorder()
	f.d.handleResolve(w, httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(body)))
	var result struct {
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || len(result.Fields) != 1 || result.Fields["public_field"] != "approved value" {
		t.Fatalf("runtime delivery must contain only the approved field, status=%d", w.Code)
	}
}

// SSH 签名接口只服务 ssh_key 凭证，其他类型不返回任何字段。
func TestSSHSignRejectsNonSSHKey(t *testing.T) {
	f := newDaemonFixture(t)
	ctx := context.Background()
	if err := f.st.PutGrant(ctx, &model.Grant{
		ID: "grant_sign", PrincipalID: "principal_admin_local", BindingID: "bind_test",
		DeliveryMode: model.ModeSign, MaxLeaseDuration: time.Minute,
		AuthRequirement: "permanent", Status: model.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	_, token, err := f.d.broker.CreateSession(ctx, "principal_admin_local", "test")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"token":"` + token.RevealString() + `","binding_id":"bind_test"}`
	rec := httptest.NewRecorder()
	f.d.handleSSHSign(rec, httptest.NewRequest(http.MethodPost, "/v1/ssh-sign", strings.NewReader(body)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("non ssh_key binding must be refused, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), string(model.CodeCredentialUnavailable)) {
		t.Fatalf("response must carry CREDENTIAL_UNAVAILABLE: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "fields") {
		t.Fatalf("refused request must not return fields: %s", rec.Body.String())
	}
}

// 同一（主体、绑定、方式）新建授权即取代旧授权，避免多份有效许可并存。
func TestGrantCreationSupersedesExisting(t *testing.T) {
	f := newDaemonFixture(t)
	ctx := context.Background()
	body := `{"principal_id":"principal_admin_local","binding_id":"bind_test","delivery_mode":"proxy","auth_requirement":"permanent"}`
	rec := httptest.NewRecorder()
	f.d.handleGrants(rec, adminRequest(http.MethodPost, "/v1/grants", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	grants, err := f.st.ListGrants(ctx, "principal_admin_local")
	if err != nil {
		t.Fatal(err)
	}
	active := 0
	for _, g := range grants {
		if g.Status == model.StatusActive && g.BindingID == "bind_test" && g.DeliveryMode == model.ModeProxy {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("exactly one active proxy grant must remain, got %d", active)
	}
}

// 重复路由必须被拒绝：否则按路由查找的结果取决于存储顺序。
func TestBindingRouteMustBeUnique(t *testing.T) {
	f := newDaemonFixture(t)
	ctx := context.Background()
	if err := f.st.PutBinding(ctx, &model.Binding{
		ID: "bind_other", CredentialID: "cred_test", UpstreamOrigin: "http://127.0.0.1:9",
		AuthScheme: model.AuthBearer, Status: model.StatusActive, Route: "shared",
	}); err != nil {
		t.Fatal(err)
	}
	body := `{"id":"bind_new","credential_id":"cred_test","upstream_origin":"http://127.0.0.1:8","auth_scheme":"bearer","route":"shared"}`
	rec := httptest.NewRecorder()
	f.d.handleBindings(rec, adminRequest(http.MethodPost, "/v1/bindings", body))
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate route must conflict, got %d: %s", rec.Code, rec.Body.String())
	}
}

// 元数据查询不是用钥：它建立的许可必须立刻释放。
func TestUseLeaseMetadataReleasesLease(t *testing.T) {
	f := newDaemonFixture(t)
	ctx := context.Background()
	_, token, err := f.d.broker.CreateSession(ctx, "principal_admin_local", "test")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"token":"` + token.RevealString() + `","binding_id":"bind_test","mode":"proxy"}`
	rec := httptest.NewRecorder()
	f.d.handleUseLeases(rec, httptest.NewRequest(http.MethodPost, "/v1/use-leases", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if n := f.d.broker.ActiveLeaseCount(); n != 0 {
		t.Fatalf("metadata lookup must not leave a live lease, got %d", n)
	}
}

func TestIPCExecutionControl(t *testing.T) {
	f := newDaemonFixture(t)
	ctx := context.Background()
	if err := f.d.bootstrapPrincipals(ctx); err != nil {
		t.Fatal(err)
	}
	router := f.d.ipcRouter()
	for _, tc := range []struct {
		name      string
		principal string
		admin     bool
	}{
		{"own", localPrincipalID(), false},
		{"managed", "principal_admin_local", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.st.PutGrant(ctx, &model.Grant{
				ID: "grant_control", PrincipalID: tc.principal, BindingID: "bind_test",
				DeliveryMode: model.ModeRuntimeDelivery, AuthRequirement: "permanent", Status: model.StatusActive,
			}); err != nil {
				t.Fatal(err)
			}
			session, token, err := f.d.broker.CreateSession(ctx, tc.principal, "control")
			if err != nil {
				t.Fatal(err)
			}
			auth, err := f.d.broker.Authorize(ctx, broker.Request{
				Token: token, BindingID: "bind_test", Mode: model.ModeRuntimeDelivery,
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, action := range []struct {
				path string
				body string
			}{
				{"/v1/use-leases/revoke", fmt.Sprintf(`{"lease_id":%q}`, auth.Lease.ID)},
				{"/v1/sessions/close", fmt.Sprintf(`{"session_id":%q}`, session.ID)},
			} {
				request := httptest.NewRequest(http.MethodPost, action.path, strings.NewReader(action.body))
				if tc.admin {
					reply := httptest.NewRecorder()
					router.ServeHTTP(reply, request)
					if reply.Code == http.StatusOK {
						t.Fatalf("%s accepted a mismatched subject", action.path)
					}
					request = httptest.NewRequest(http.MethodPost, action.path, strings.NewReader(action.body))
					request.Header.Set("X-KeyKoi-Admin", f.d.adminToken)
				}
				reply := httptest.NewRecorder()
				router.ServeHTTP(reply, request)
				if reply.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", action.path, reply.Code, reply.Body.String())
				}
			}
		})
	}

	ordinary := httptest.NewRecorder()
	router.ServeHTTP(ordinary, httptest.NewRequest(http.MethodGet, "/v1/audit-events", nil))
	if ordinary.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary requester audit status = %d", ordinary.Code)
	}

	request := adminRequest(http.MethodGet, "/v1/audit-events", "")
	reply := httptest.NewRecorder()
	router.ServeHTTP(reply, request)
	var audit struct{ Events []store.AuditEvent }
	if err := json.Unmarshal(reply.Body.Bytes(), &audit); err != nil {
		t.Fatal(err)
	}
	revoked := 0
	for _, event := range audit.Events {
		if event.Result == "revoked" {
			revoked++
		}
	}
	if reply.Code != http.StatusOK || revoked != 4 {
		t.Fatalf("administrator audit missing revocations: %d %s", reply.Code, reply.Body.String())
	}
}

// approve 只服务待复核授权：已撤销或被取代的记录不能借此复活。
func TestGrantApproveOnlyFromPendingReview(t *testing.T) {
	f := newDaemonFixture(t)
	ctx := context.Background()
	// 先新建一条授权，再用同一范围新建第二条，第一条会被取代为 revoked。
	for _, id := range []string{"grant_first", "grant_second"} {
		body := `{"principal_id":"principal_admin_local","binding_id":"bind_test","delivery_mode":"proxy","auth_requirement":"permanent"}`
		rec := httptest.NewRecorder()
		f.d.handleGrants(rec, adminRequest(http.MethodPost, "/v1/grants", body))
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", id, rec.Code, rec.Body.String())
		}
	}
	grants, err := f.st.ListGrants(ctx, "principal_admin_local")
	if err != nil {
		t.Fatal(err)
	}
	active, revoked := 0, 0
	for _, g := range grants {
		switch g.Status {
		case model.StatusActive:
			active++
		case model.StatusRevoked:
			revoked++
		}
	}
	if active != 1 || revoked < 1 {
		t.Fatalf("superseding must leave one active grant, got active=%d revoked=%d", active, revoked)
	}
	var supersededID string
	for _, g := range grants {
		if g.Status == model.StatusRevoked {
			supersededID = g.ID
			break
		}
	}
	rec := httptest.NewRecorder()
	f.d.handleGrantItem(rec, adminRequest(http.MethodPost, "/v1/grants/"+supersededID+"/approve", ""))
	if rec.Code != http.StatusConflict {
		t.Fatalf("approving a superseded grant must conflict, got %d: %s", rec.Code, rec.Body.String())
	}
	// 待复核授权可以批准。
	pending := &model.Grant{
		ID: "grant_pending", PrincipalID: "principal_admin_local", BindingID: "bind_test",
		DeliveryMode: model.ModeRuntimeDelivery, MaxLeaseDuration: time.Minute,
		AuthRequirement: "permanent", Status: model.StatusPending,
	}
	if err := f.st.PutGrant(ctx, pending); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	f.d.handleGrantItem(rec, adminRequest(http.MethodPost, "/v1/grants/grant_pending/approve", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("approving a pending grant must succeed, got %d: %s", rec.Code, rec.Body.String())
	}
}
