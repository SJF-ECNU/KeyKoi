package daemon

import (
	"net/http"
	"sort"
	"time"

	"keykoi/internal/model"
	"keykoi/internal/store"
)

const activityAuditLimit = 500

// activityRow only exposes fields used by the local usage dashboard.
type activityRow struct {
	Time        time.Time `json:"time"`
	PrincipalID string    `json:"principal_id"`
	BindingID   string    `json:"binding_id"`
	Mode        string    `json:"mode"`
	Result      string    `json:"result"`
	ErrorCode   string    `json:"error_code,omitempty"`
	DurationMS  int64     `json:"duration_ms"`
	// AuthMethod / AuthResult 记录这次用钥前的验证方式与策略结果。
	AuthMethod string `json:"auth_method"`
	AuthResult string `json:"auth_result,omitempty"`
}

// auditAuthMethod 把空值统一成 none，避免界面出现空白列。
func auditAuthMethod(e *store.AuditEvent) string {
	if e.AuthMethod == "" {
		return "none"
	}
	return e.AuthMethod
}

func (d *Daemon) handleActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	events, err := d.store.ListAudit(r.Context(), activityAuditLimit)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	rows := make([]activityRow, 0, len(events))
	for _, e := range events {
		if !model.DeliveryMode(e.Mode).Valid() {
			continue
		}
		rows = append(rows, activityRow{
			Time: e.Time, PrincipalID: e.PrincipalID, BindingID: e.BindingID,
			Mode: e.Mode, Result: e.Result, ErrorCode: e.ErrorCode, DurationMS: e.DurationMS,
			AuthMethod: auditAuthMethod(e), AuthResult: e.AuthResult,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Time.After(rows[j].Time) })
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"events": rows, "audit_limit": activityAuditLimit})
}
