package proxycontrol

import "time"

// DatabaseConfig configures a daemon-owned database listener.
type DatabaseConfig struct {
	Protocol, Binding, SessionToken             string
	Listen, ListenSocket, ClientUser            string
	UpstreamCA, SSLMode, MySQLTLS               string
	DatabaseField, UsernameField, PasswordField string
	AuthTimeout, DialTimeout                    time.Duration
	MaxConnections                              int
	InsecureUpstream, DisableClientTLS          bool
}

type DatabaseInfo struct {
	Addrs  []string `json:"addresses"`
	Warmup string   `json:"warmup"`
}
