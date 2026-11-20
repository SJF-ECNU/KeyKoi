package daemon

import (
	"context"
	"net/http"

	"keykoi/internal/model"
)

// Initializer 由加密密钥库实现；内存原型后端不具备初始化语义。
type Initializer interface {
	Init(ctx context.Context, password []byte) error
	Initialized() bool
}

// BackupRestorer 由加密密钥库实现密文备份与恢复。
type BackupRestorer interface {
	Backup(ctx context.Context, path string) error
	Restore(ctx context.Context, path string) (map[string]any, error)
}

func (d *Daemon) handleVaultInit(w http.ResponseWriter, r *http.Request) {
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	init, ok := d.backend.(Initializer)
	if !ok {
		writeAPIError(w, model.NewError(model.CodeAdapterUnsupported, "this backend has no initialization step"))
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if len(body.Password) < 8 {
		writeAPIError(w, model.NewError("", "master password must be at least 8 characters"))
		return
	}
	if err := init.Init(r.Context(), []byte(body.Password)); err != nil {
		writeAPIError(w, err)
		return
	}
	d.broker.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"initialized": true, "state": d.backend.State()})
}

func (d *Daemon) handleVaultBackup(w http.ResponseWriter, r *http.Request) {
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	br, ok := d.backend.(BackupRestorer)
	if !ok {
		writeAPIError(w, model.NewError(model.CodeAdapterUnsupported, "this backend has no encrypted backup support"))
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Path == "" {
		writeAPIError(w, model.NewError("", "backup path is required"))
		return
	}
	if err := br.Backup(r.Context(), body.Path); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backup": body.Path})
}

func (d *Daemon) handleVaultRestore(w http.ResponseWriter, r *http.Request) {
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	br, ok := d.backend.(BackupRestorer)
	if !ok {
		writeAPIError(w, model.NewError(model.CodeAdapterUnsupported, "this backend has no encrypted backup support"))
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	summary, err := br.Restore(r.Context(), body.Path)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	d.broker.Lock(r.Context())
	d.passwordProof.clear()
	if err := d.bootstrapPrincipals(r.Context()); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}
