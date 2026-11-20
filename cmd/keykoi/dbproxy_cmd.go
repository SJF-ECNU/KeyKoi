package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"keykoi/internal/dbproxy"
	"keykoi/internal/ipcclient"
	"keykoi/internal/mysqlproxy"
	"keykoi/internal/proxycontrol"
)

// cmdDBProxy 启动数据库协议代理：
//
//	keykoi db-proxy --protocol postgres|redis|mysql|mongo --binding ID --listen 127.0.0.1:PORT
//
// 管理权限启动监听器。每条数据库连接用客户端呈交的普通会话申请 proxy 授权。
// 全局 --socket 已被 main 处理为 keykoid 的 IPC socket，这里也接受同名参数以便单独调用。
func cmdDBProxy(args []string) error {
	fs := flag.NewFlagSet("db-proxy", flag.ContinueOnError)
	protocol := fs.String("protocol", "postgres", "database protocol: postgres|redis|mysql|mongo")
	binding := fs.String("binding", "", "binding id to proxy (required)")
	listen := fs.String("listen", "127.0.0.1:0", "client listen address on loopback")
	listenSocket := fs.String("listen-socket", "", "optional unix socket path for clients")
	socket := fs.String("socket", "", "keykoid IPC socket path (defaults to the global --socket)")
	clientUser := fs.String("client-user", "keykoi", "username PostgreSQL clients must present")
	sslmode := fs.String("upstream-sslmode", "require", "upstream TLS for postgres: disable|prefer|require")
	caFile := fs.String("upstream-ca", "", "extra PEM CA bundle for upstream TLS verification")
	insecureUpstream := fs.Bool("upstream-insecure", false,
		"explicitly allow a plaintext upstream (mysql, redis, mongo; default requires TLS)")
	mysqlTLSMode := fs.String("mysql-upstream-tls-mode", "verify-full",
		"upstream TLS verification strength for mysql: verify-full (chain+hostname) or verify-ca (chain only)")
	databaseField := fs.String("database-field", "database", "credential field holding the database/authSource name")
	usernameField := fs.String("username-field", "", "override credential username field")
	passwordField := fs.String("password-field", "", "override credential password field")
	authTimeout := fs.Duration("auth-timeout", 15*time.Second, "client authentication timeout")
	dialTimeout := fs.Duration("dial-timeout", 10*time.Second, "upstream connect timeout")
	maxConns := fs.Int("max-connections", 64, "maximum concurrent client connections")
	disableClientTLS := fs.Bool("mysql-disable-client-tls", false, "do not offer TLS to MySQL clients")
	printToken := fs.Bool("print-token", true, "print the session token once on startup")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *binding == "" {
		return fmt.Errorf("--binding is required")
	}
	// Unix socket 放在 flag 里会与全局 --socket 语义冲突，用别名统一到同一个覆盖。
	if *socket == "" {
		*socket = g.socket
	}

	tlsMode, err := dbproxy.ParseTLSMode(*sslmode)
	if err != nil {
		return err
	}
	mysqlTLS, err := mysqlproxy.ParseUpstreamTLSMode(*mysqlTLSMode)
	if err != nil {
		return err
	}

	proto := strings.ToLower(strings.TrimSpace(*protocol))
	switch proto {
	case "postgresql", "pg":
		proto = "postgres"
	case "mongodb":
		proto = "mongo"
	}
	adminToken, err := adminTokenFromDisk(g.dataDir)
	if err != nil {
		return err
	}
	ipc := ipcclient.New(*socket, "")
	session, err := ipc.CreateSession("db-proxy "+*binding, false)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	defer ipc.Post("/v1/sessions/close", map[string]string{"session_id": session.ID}, nil)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var info proxycontrol.DatabaseInfo
	admin := ipcclient.New(*socket, adminToken)
	body, err := admin.OpenStream(ctx, "/v1/db-proxy/listen", proxycontrol.DatabaseConfig{
		Protocol: proto, Binding: *binding, SessionToken: session.Token,
		Listen: *listen, ListenSocket: *listenSocket, ClientUser: *clientUser,
		UpstreamCA: *caFile, SSLMode: string(tlsMode), MySQLTLS: string(mysqlTLS),
		DatabaseField: *databaseField, UsernameField: *usernameField, PasswordField: *passwordField,
		AuthTimeout: *authTimeout, DialTimeout: *dialTimeout, MaxConnections: *maxConns,
		InsecureUpstream: *insecureUpstream, DisableClientTLS: *disableClientTLS,
	}, &info)
	if err != nil {
		return fmt.Errorf("start database proxy: %w", err)
	}
	defer body.Close()
	addrs, warmup := info.Addrs, info.Warmup
	if g.json {
		payload := map[string]any{
			"protocol":            proto,
			"binding":             *binding,
			"listen":              addrs,
			"client_user":         *clientUser,
			"upstream_sslmode":    string(tlsMode),
			"upstream_insecure":   *insecureUpstream,
			"upstream_tls_policy": upstreamTLSPolicy(proto),
			"mysql_upstream_mode": string(mysqlTLS),
			"session_id":          session.ID,
			"expires_at":          session.ExpiresAt,
			"warmup":              warmup,
		}
		if *printToken {
			payload["session_token"] = session.Token
		}
		if err := printJSON(payload); err != nil {
			return err
		}
	} else {
		for _, addr := range addrs {
			fmt.Printf("db-proxy: listening %s (protocol=%s binding=%s client_user=%s upstream=%s)\n",
				addr, proto, *binding, *clientUser, upstreamTLSPolicy(proto))
		}
		if warmup != "ok" && warmup != "skipped" {
			fmt.Printf("db-proxy: warm-up resolve %s\n", warmup)
		}
		if *printToken {
			// 令牌只在这里打印一次，不写入磁盘或日志。
			fmt.Printf("db-proxy: session-token %s\n", session.Token)
		}
	}

	_, err = io.Copy(io.Discard, body)
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("database proxy control connection: %w", err)
	}
	return fmt.Errorf("daemon stopped the database proxy")
}

// upstreamTLSPolicy 给出该协议当前的上游传输策略（写进启动输出，便于核对要求）。
func upstreamTLSPolicy(proto string) string {
	switch proto {
	case "postgres":
		return "sslmode flag"
	case "mysql", "redis":
		return "tls (https origin) or explicit --upstream-insecure"
	case "mongo":
		return "verified TLS by default; --upstream-insecure for plaintext"
	default:
		return "plaintext"
	}
}
