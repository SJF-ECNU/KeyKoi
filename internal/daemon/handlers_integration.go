package daemon

import (
	"net/http"
	"strings"

	"keykoi/internal/model"
)

// handleIntegrationPlan 返回脱敏预览，不写任何配置。
func (d *Daemon) handleIntegrationPlan(w http.ResponseWriter, r *http.Request) {
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		ProfileID string `json:"profile_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	plan, err := d.integration.Plan(r.Context(), body.ProfileID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

// handleIntegrationApply 执行已确定的接入变更。
func (d *Daemon) handleIntegrationApply(w http.ResponseWriter, r *http.Request) {
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		ProfileID string `json:"profile_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	rec, err := d.integration.Apply(r.Context(), body.ProfileID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (d *Daemon) handleIntegrationList(w http.ResponseWriter, r *http.Request) {
	recs, err := d.store.ListIntegrations(r.Context())
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"integrations": recs})
}

// handleIntegrationItem 处理 /v1/integrations/{id}[/verify|/detach|/status]。
func (d *Daemon) handleIntegrationItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/integrations/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	id := parts[0]
	if id == "" {
		writeAPIError(w, model.NewError("", "integration id is required"))
		return
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch action {
	case "verify":
		if _, err := d.requireAdmin(r); err != nil {
			writeAPIError(w, err)
			return
		}
		rec, err := d.integration.Verify(r.Context(), id)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rec)
	case "detach":
		if _, err := d.requireAdmin(r); err != nil {
			writeAPIError(w, err)
			return
		}
		rec, err := d.integration.Detach(r.Context(), id)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rec)
	case "status", "":
		rec, err := d.store.GetIntegration(r.Context(), id)
		if err != nil {
			writeAPIError(w, model.NewError(model.CodeAdapterUnsupported, "integration %q is not attached", id))
			return
		}
		drift, derr := d.integration.Drift(r.Context(), id)
		writeJSON(w, http.StatusOK, map[string]any{"integration": rec, "drift": drift, "drift_error": errString(derr)})
	default:
		writeAPIError(w, model.NewError("", "unsupported integration operation %q", action))
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
