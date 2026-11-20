package tlsproxy

// ListenerConfig carries administrator-supplied configuration to the daemon.
type ListenerConfig struct {
	BindingIDs []string          `json:"bindings"`
	Listen     string            `json:"listen"`
	CADir      string            `json:"ca_dir"`
	UpstreamCA []byte            `json:"upstream_ca"`
	Resolve    map[string]string `json:"resolve"`
}

// ListenerInfo is returned after the daemon has bound the loopback listener.
type ListenerInfo struct {
	Addr          string `json:"address"`
	CACertificate string `json:"ca_certificate"`
}
