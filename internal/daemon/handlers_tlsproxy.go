package daemon

import (
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"keykoi/internal/model"
	"keykoi/internal/osruntime"
	"keykoi/internal/tlsproxy"
)

// The control request owns the listener. Closing the CLI stream shuts down the
// listener and every hijacked tunnel, including when the launcher is killed.
func (d *Daemon) handleTLSProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	var cfg tlsproxy.ListenerConfig
	if err := decodeJSON(r, &cfg); err != nil {
		writeAPIError(w, err)
		return
	}
	if len(cfg.BindingIDs) == 0 || cfg.CADir == "" {
		writeAPIError(w, model.NewError("", "bindings and ca_dir are required"))
		return
	}
	for _, id := range cfg.BindingIDs {
		binding, err := d.store.GetBinding(r.Context(), id)
		if err != nil || binding.Status != model.StatusActive {
			writeAPIError(w, model.NewError(model.CodeBindingDisabled, "binding %s is unavailable", id))
			return
		}
		if origin, err := binding.Origin(); err != nil || origin.Scheme != "https" {
			writeAPIError(w, model.NewError(model.CodeBindingDisabled, "binding %s requires an HTTPS origin", id))
			return
		}
	}
	var roots *x509.CertPool
	if len(cfg.UpstreamCA) != 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(cfg.UpstreamCA) {
			writeAPIError(w, model.NewError("", "upstream CA contains no PEM certificates"))
			return
		}
	}
	proxy, err := tlsproxy.New(tlsproxy.Options{
		Authorizer: d.broker, Store: d.store, BindingIDs: cfg.BindingIDs,
		CADir: cfg.CADir, UpstreamRoots: roots, Resolve: cfg.Resolve, Logger: log.Default(),
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	defer proxy.Close()
	ln, err := osruntime.ListenLoopbackTCP(cfg.Listen)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	defer ln.Close()
	server := &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	defer server.Close()
	if err := json.NewEncoder(w).Encode(tlsproxy.ListenerInfo{Addr: ln.Addr().String(), CACertificate: proxy.CA().CertPath()}); err != nil {
		return
	}
	if err := http.NewResponseController(w).Flush(); err != nil {
		return
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()
	select {
	case <-r.Context().Done():
	case err := <-done:
		log.Printf("tls proxy stopped: %v", err)
	}
}
