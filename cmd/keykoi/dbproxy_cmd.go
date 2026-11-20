package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"keykoi/internal/dbproxy"
	"keykoi/internal/ipcclient"
	"keykoi/internal/mongoproxy"
	"keykoi/internal/mysqlproxy"
	"keykoi/internal/redisproxy"
)

// dbProxyServer 是各协议代理共有的运行面。
type dbProxyServer interface {
	Listen() error
	Addrs() []string
	Serve(ctx context.Context) error
	Stats() (active, total, denied int64)
}

// warmUpServer 是可选的预热解析（PostgreSQL 用它记录取消请求的上游地址）。
type warmUpServer interface {
	WarmUp(token string) error
}

// cmdDBProxy 启动数据库协议代理：
//
//	keykoi db-proxy --protocol postgres|redis|mysql|mongo --binding ID --listen 127.0.0.1:PORT
//
// 代理只用普通（非管理员）会话：它向后台申请一次会话，把该令牌打印一次供客户端当口令使用，
// 之后每条客户端连接都独立经 /v1/resolve（runtime_delivery）授权后向上游数据库认证。
// 全局 --socket 已被 main 处理为 keykoid 的 IPC socket，这里也接受同名参数以便单独调用。
func cmdDBProxy(args []string) error {
	fs := flag.NewFlagSet("db-proxy", flag.ContinueOnError)
	protocol := fs.String("protocol", "postgres", "database protocol: postgres|redis|mysql|mongo")
	binding := fs.String("binding", "", "binding id to proxy (required)")
	listen := fs.String("listen", "127.0.0.1:0", "client listen address on loopback")
	listenSocket := fs.String("listen-socket", "", "optional unix socket path for clients")
	socket := fs.String("socket", "", "keykoid IPC socket path (defaults to the global --socket)")
	clientUser := fs.String("client-user", "keykoi", "username PostgreSQL clients must present")
	sslmode := fs.String("upstream-sslmode", "prefer", "upstream TLS for postgres: disable|prefer|require")
	caFile := fs.String("upstream-ca", "", "extra PEM CA bundle for upstream TLS verification (postgres, mysql, redis)")
	insecureUpstream := fs.Bool("upstream-insecure", false,
		"explicitly allow a plaintext upstream (mysql and redis only; default requires TLS on the upstream link)")
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

	// 非管理员客户端：不读取 admin.token，只申请普通会话与执行 resolve。
	ipc := ipcclient.New(*socket, "")
	session, err := ipc.CreateSession("db-proxy "+*binding, false)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	var srv dbProxyServer
	proto := strings.ToLower(strings.TrimSpace(*protocol))
	switch proto {
	case "postgres", "postgresql", "pg":
		proto = "postgres"
		s, err := dbproxy.New(ipc, dbproxy.Config{
			BindingID:      *binding,
			ClientUser:     *clientUser,
			ListenAddr:     *listen,
			ListenSocket:   *listenSocket,
			UpstreamTLS:    tlsMode,
			UpstreamCA:     *caFile,
			DatabaseField:  *databaseField,
			UsernameField:  *usernameField,
			PasswordField:  *passwordField,
			AuthTimeout:    *authTimeout,
			DialTimeout:    *dialTimeout,
			MaxConnections: *maxConns,
			Logger:         log.New(os.Stderr, "keykoi db-proxy: ", 0),
		})
		if err != nil {
			return err
		}
		srv = s
	case "redis":
		s, err := redisproxy.New(ipc, redisproxy.Config{
			BindingID:      *binding,
			ListenAddr:     *listen,
			ListenSocket:   *listenSocket,
			UsernameField:  *usernameField,
			PasswordField:  *passwordField,
			AuthTimeout:    *authTimeout,
			DialTimeout:    *dialTimeout,
			MaxConnections: *maxConns,
			// 上游 TLS 由登记 origin 的 https:// 声明；明文必须显式登记。
			InsecureUpstream: *insecureUpstream,
			UpstreamCA:       *caFile,
			Logger:           log.New(os.Stderr, "keykoi db-proxy: ", 0),
		})
		if err != nil {
			return err
		}
		srv = s
	case "mysql":
		s, err := mysqlproxy.New(ipc, mysqlproxy.Config{
			BindingID:        *binding,
			ListenAddr:       *listen,
			ListenSocket:     *listenSocket,
			UsernameField:    *usernameField,
			PasswordField:    *passwordField,
			DatabaseField:    *databaseField,
			AuthTimeout:      *authTimeout,
			DialTimeout:      *dialTimeout,
			MaxConnections:   *maxConns,
			DisableClientTLS: *disableClientTLS,
			InsecureUpstream: *insecureUpstream,
			UpstreamCA:       *caFile,
			UpstreamTLSMode:  mysqlTLS,
			Logger:           log.New(os.Stderr, "keykoi db-proxy: ", 0),
		})
		if err != nil {
			return err
		}
		srv = s
	case "mongo", "mongodb":
		proto = "mongo"
		s, err := mongoproxy.New(ipc, mongoproxy.Config{
			BindingID:      *binding,
			ListenAddr:     *listen,
			ListenSocket:   *listenSocket,
			UsernameField:  *usernameField,
			PasswordField:  *passwordField,
			DatabaseField:  *databaseField,
			AuthTimeout:    *authTimeout,
			DialTimeout:    *dialTimeout,
			MaxConnections: *maxConns,
			Logger:         log.New(os.Stderr, "keykoi db-proxy: ", 0),
		})
		if err != nil {
			return err
		}
		srv = s
	default:
		return fmt.Errorf("unsupported --protocol %q (postgres|redis|mysql|mongo)", *protocol)
	}

	if err := srv.Listen(); err != nil {
		return err
	}

	// 预热解析：PostgreSQL 用它为取消请求记录上游地址；失败不阻止启动。
	warmup := "skipped"
	if w, ok := srv.(warmUpServer); ok {
		warmup = "ok"
		if err := w.WarmUp(session.Token); err != nil {
			warmup = "failed: " + err.Error()
		}
	}

	addrs := srv.Addrs()
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Serve(ctx); err != nil {
		return err
	}
	active, total, denied := srv.Stats()
	if !g.json {
		fmt.Fprintf(os.Stderr, "db-proxy: stopped (protocol=%s connections total=%d denied=%d active=%d)\n", proto, total, denied, active)
	}
	return nil
}

// upstreamTLSPolicy 给出该协议当前的上游传输策略（写进启动输出，便于核对要求）。
func upstreamTLSPolicy(proto string) string {
	switch proto {
	case "postgres":
		return "sslmode flag"
	case "mysql", "redis":
		return "tls (https origin) or explicit --upstream-insecure"
	default:
		return "plaintext"
	}
}
