package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"keykoi/internal/dbproxy"
	"keykoi/internal/mongoproxy"
	"keykoi/internal/mysqlproxy"
	"keykoi/internal/proxycontrol"
	"keykoi/internal/redisproxy"
)

// dbProxyServer 是各协议代理共有的运行面。
type dbProxyServer interface {
	Listen() error
	Addrs() []string
	Serve(ctx context.Context) error
	Shutdown(context.Context) error
}

// warmUpServer 是可选的预热解析（PostgreSQL 用它记录取消请求的上游地址）。
type warmUpServer interface {
	WarmUp(ctx context.Context, token string) error
}

func (d *Daemon) handleDBProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	var cfg proxycontrol.DatabaseConfig
	if err := decodeJSON(r, &cfg); err != nil {
		writeAPIError(w, err)
		return
	}
	server, err := d.databaseProxy(cfg)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if err := server.Listen(); err != nil {
		writeAPIError(w, err)
		return
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	warmup := "skipped"
	if warm, ok := server.(warmUpServer); ok {
		warmup = "ok"
		if err := warm.WarmUp(r.Context(), cfg.SessionToken); err != nil {
			warmup = "failed: " + err.Error()
		}
	}
	if err := json.NewEncoder(w).Encode(proxycontrol.DatabaseInfo{Addrs: server.Addrs(), Warmup: warmup}); err != nil {
		return
	}
	if err := http.NewResponseController(w).Flush(); err != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if err := server.Serve(ctx); err != nil {
		log.Printf("database proxy stopped: %v", err)
	}
}

func (d *Daemon) databaseProxy(cfg proxycontrol.DatabaseConfig) (dbProxyServer, error) {
	tlsMode, err := dbproxy.ParseTLSMode(cfg.SSLMode)
	if err != nil {
		return nil, err
	}
	mysqlTLS, err := mysqlproxy.ParseUpstreamTLSMode(cfg.MySQLTLS)
	if err != nil {
		return nil, err
	}
	switch cfg.Protocol {
	case "postgres", "postgresql", "pg":
		return dbproxy.New(d.broker, dbproxy.Config{
			BindingID:      cfg.Binding,
			ClientUser:     cfg.ClientUser,
			ListenAddr:     cfg.Listen,
			ListenSocket:   cfg.ListenSocket,
			UpstreamTLS:    tlsMode,
			UpstreamCA:     cfg.UpstreamCA,
			DatabaseField:  cfg.DatabaseField,
			UsernameField:  cfg.UsernameField,
			PasswordField:  cfg.PasswordField,
			AuthTimeout:    cfg.AuthTimeout,
			DialTimeout:    cfg.DialTimeout,
			MaxConnections: cfg.MaxConnections,
			Logger:         log.Default(),
		})
	case "redis":
		return redisproxy.New(d.broker, redisproxy.Config{
			BindingID:      cfg.Binding,
			ListenAddr:     cfg.Listen,
			ListenSocket:   cfg.ListenSocket,
			UsernameField:  cfg.UsernameField,
			PasswordField:  cfg.PasswordField,
			AuthTimeout:    cfg.AuthTimeout,
			DialTimeout:    cfg.DialTimeout,
			MaxConnections: cfg.MaxConnections,
			// 上游 TLS 由登记 origin 的 https:// 声明；明文必须显式登记。
			InsecureUpstream: cfg.InsecureUpstream,
			UpstreamCA:       cfg.UpstreamCA,
			Logger:           log.Default(),
		})
	case "mysql":
		return mysqlproxy.New(d.broker, mysqlproxy.Config{
			BindingID:        cfg.Binding,
			ListenAddr:       cfg.Listen,
			ListenSocket:     cfg.ListenSocket,
			UsernameField:    cfg.UsernameField,
			PasswordField:    cfg.PasswordField,
			DatabaseField:    cfg.DatabaseField,
			AuthTimeout:      cfg.AuthTimeout,
			DialTimeout:      cfg.DialTimeout,
			MaxConnections:   cfg.MaxConnections,
			DisableClientTLS: cfg.DisableClientTLS,
			InsecureUpstream: cfg.InsecureUpstream,
			UpstreamCA:       cfg.UpstreamCA,
			UpstreamTLSMode:  mysqlTLS,
			Logger:           log.Default(),
		})
	case "mongo", "mongodb":
		return mongoproxy.New(d.broker, mongoproxy.Config{
			BindingID:        cfg.Binding,
			ListenAddr:       cfg.Listen,
			ListenSocket:     cfg.ListenSocket,
			UsernameField:    cfg.UsernameField,
			PasswordField:    cfg.PasswordField,
			DatabaseField:    cfg.DatabaseField,
			AuthTimeout:      cfg.AuthTimeout,
			DialTimeout:      cfg.DialTimeout,
			UpstreamCA:       cfg.UpstreamCA,
			InsecureUpstream: cfg.InsecureUpstream,
			MaxConnections:   cfg.MaxConnections,
			Logger:           log.Default(),
		})
	default:
		return nil, fmt.Errorf("unsupported --protocol %q (postgres|redis|mysql|mongo)", cfg.Protocol)
	}

}
