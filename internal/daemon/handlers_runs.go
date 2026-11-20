package daemon

import (
	"net/http"

	"keykoi/internal/model"
)

func (d *Daemon) handleRuns(w http.ResponseWriter, r *http.Request) {
	writeAPIError(w, model.NewError(model.CodeAdapterUnsupported, "managed runs are delivered by p1-runtime-delivery; this build does not expose it"))
}

func (d *Daemon) handleRunItem(w http.ResponseWriter, r *http.Request) {
	writeAPIError(w, model.NewError(model.CodeAdapterUnsupported, "managed runs are delivered by p1-runtime-delivery; this build does not expose it"))
}
