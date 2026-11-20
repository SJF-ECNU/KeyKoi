package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"keykoi/internal/model"
)

// TestStatusForErrorStableMapping 覆盖 27：每一类中间层错误都有确定的 HTTP 状态，
// 验证类失败不再落成 500。
func TestStatusForErrorStableMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"session invalid", model.NewError(model.CodeSessionInvalid, "x"), http.StatusUnauthorized},
		{"auth required", model.NewError(model.CodeAuthRequired, "x"), http.StatusUnauthorized},
		{"auth unavailable", model.NewError(model.CodeAuthUnavailable, "x"), http.StatusForbidden},
		{"vault unlock failed", model.NewError(model.CodeVaultUnlockFailed, "x"), http.StatusUnauthorized},
		{"vault locked", model.NewError(model.CodeVaultLocked, "x"), http.StatusServiceUnavailable},
		{"use not allowed", model.NewError(model.CodeUseNotAllowed, "x"), http.StatusForbidden},
		{"lease expired", model.NewError(model.CodeLeaseExpired, "x"), http.StatusForbidden},
		{"binding disabled", model.NewError(model.CodeBindingDisabled, "x"), http.StatusNotFound},
		{"credential unavailable", model.NewError(model.CodeCredentialUnavailable, "x"), http.StatusServiceUnavailable},
		{"adapter unsupported", model.NewError(model.CodeAdapterUnsupported, "x"), http.StatusNotImplemented},
		{"upstream unavailable", model.NewError(model.CodeUpstreamUnavailable, "x"), http.StatusBadGateway},
		{"control unavailable", model.NewError(model.CodeControlUnavailable, "x"), http.StatusServiceUnavailable},
		{"upstream auth failed", model.NewError(model.CodeUpstreamAuthFailed, "x"), http.StatusUnauthorized},
	}
	for _, tc := range cases {
		if got := statusForError(tc.err); got != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.name, got, tc.want)
		}
	}
	// 验证类失败与锁定/权限类失败都必须可处理，绝不能被映射成 500。
	for _, err := range []error{
		model.NewError(model.CodeAuthRequired, "x"),
		model.NewError(model.CodeAuthUnavailable, "x"),
		model.NewError(model.CodeSessionInvalid, "x"),
		model.NewError(model.CodeUseNotAllowed, "x"),
		model.NewError(model.CodeVaultLocked, "x"),
	} {
		if got := statusForError(err); got == http.StatusInternalServerError {
			t.Errorf("%s must not map to 500", model.CodeOf(err))
		}
	}
}

// TestWriteErrorKeepsJSONBody 确认新映射沿用原错误体结构与稳定错误码。
func TestWriteErrorKeepsJSONBody(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, model.NewError(model.CodeAuthUnavailable, "no verification provider is configured"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type = %q", ct)
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body.Error.Code != string(model.CodeAuthUnavailable) {
		t.Fatalf("error code = %q", body.Error.Code)
	}
	if !strings.Contains(body.Error.Message, "no verification provider is configured") {
		t.Fatalf("error message = %q", body.Error.Message)
	}
}

// TestWriteErrorUnauthorizedCarriesChallenge 确认 401 仍带 Basic 质询，便于 git 重试。
func TestWriteErrorUnauthorizedCarriesChallenge(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, model.NewError(model.CodeSessionInvalid, "missing intermediary session token"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="KeyKoi"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}
