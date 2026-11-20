package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
	"keykoi/internal/osruntime"
	"keykoi/internal/remoteauth"
	"keykoi/internal/store"
	"keykoi/internal/tlsproxy"
)

// multiFlag 收集可重复的字符串参数。
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("empty value")
	}
	*m = append(*m, v)
	return nil
}

// resolveFlag 收集 host=address 覆盖，只用于受控验收环境。
type resolveFlag map[string]string

func (r *resolveFlag) String() string { return fmt.Sprint(map[string]string(*r)) }

func (r *resolveFlag) Set(v string) error {
	parts := strings.SplitN(v, "=", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return fmt.Errorf("expected host=address")
	}
	if *r == nil {
		*r = map[string]string{}
	}
	(*r)[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
	return nil
}

// cmdTLSProxy 启动工具级受信 HTTPS 代理。
//
// 代理只接受 CONNECT，并且只对 --binding 指定的已登记 Binding 域名终止 TLS。
// 上游证书始终验证；未登记域名在 CONNECT 阶段被拒绝，不注入任何凭证。
//
// 代理不再自行解锁密钥库，也不建立独立 Broker：每次用钥都通过本机 IPC 交给
// keykoid 授权，主库锁定、逐次验证与中心策略因此统一生效。后台不可达时直接报错，
// 不会静默降级成本地解锁。
func cmdTLSProxy(args []string) error {
	fs := flag.NewFlagSet("tls-proxy", flag.ContinueOnError)
	var bindings multiFlag
	var resolve resolveFlag
	fs.Var(&bindings, "binding", "registered binding id to serve (repeatable)")
	listen := fs.String("listen", "127.0.0.1:0", "loopback listen address")
	caDir := fs.String("ca-dir", "", "directory for the local CA (private key 0600)")
	upstreamCA := fs.String("upstream-ca", "", "PEM file with the upstream CA to trust instead of the system roots")
	fs.Var(&resolve, "resolve", "host=address override for controlled acceptance (repeatable; TLS still verifies host)")
	// 保留参数只为兼容既有调用：主密码不再由代理读取，解锁统一交给 keykoid。
	fs.Bool("password-stdin", false, "deprecated: ignored; unlock the vault through keykoid instead")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(bindings) == 0 {
		return errors.New("--binding is required")
	}
	if *caDir == "" {
		return errors.New("--ca-dir is required")
	}
	if err := requireLoopback(*listen); err != nil {
		return err
	}

	roots, err := loadUpstreamRoots(*upstreamCA)
	if err != nil {
		return err
	}
	logger := log.New(os.Stderr, "keykoi tls-proxy: ", 0)
	ctx := context.Background()

	// 用钥决定归主服务：先确认 keykoid 在跑，再经本机 IPC 申请授权。
	client := ipcclient.New(osruntime.SocketPath(g.dataDir), "")
	if _, err := client.Status(); err != nil {
		return fmt.Errorf("keykoid is not reachable at %s (%w); start keykoid first, tls-proxy does not unlock the vault on its own",
			client.Socket(), err)
	}
	authorizer := remoteauth.New(client, "tls-proxy listener")
	defer authorizer.Close(context.Background())

	dbPath := filepath.Join(g.dataDir, "vault.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("vault database %s is not readable; start keykoid and run keykoi init first", dbPath)
	}
	// 只读登记目标：是否允许用钥一律由 keykoid 在每次请求时判定。
	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		return fmt.Errorf("open vault database: %w", err)
	}
	defer st.Close()

	if err := validateTLSProxyBindings(ctx, st, bindings, logger); err != nil {
		return err
	}

	proxy, err := tlsproxy.New(tlsproxy.Options{
		Authorizer:    authorizer,
		Store:         st,
		BindingIDs:    bindings,
		UpstreamRoots: roots,
		Resolve:       resolve,
		CADir:         *caDir,
		Now:           time.Now,
		Logger:        logger,
	})
	if err != nil {
		return err
	}
	// CA 只公开证书路径；私钥留在 ca-dir 内 0600。
	fmt.Printf("ca_certificate=%s\n", proxy.CA().CertPath())

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listen, err)
	}
	addr := ln.Addr().String()
	if err := requireLoopback(addr); err != nil {
		_ = ln.Close()
		return err
	}
	fmt.Printf("listen=%s\n", addr)

	srv := &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	logger.Printf("ready: bindings=%v ca=%s", []string(bindings), proxy.CA().CertPath())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		logger.Printf("received %s; closing tunnels and closing the proxy session", s)
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			_ = proxy.Close()
			return fmt.Errorf("proxy listener stopped: %w", err)
		}
	}
	signal.Stop(sig)
	_ = srv.Close()
	_ = proxy.Close()
	stats := proxy.Stats()
	logger.Printf("stopped: connects=%d rejected=%d client_tls_failures=%d upstream_tls_invalid=%d binding_changed=%d injected=%d forwarded=%d",
		stats.ConnectsAccepted, stats.ConnectsRejected, stats.ClientTLSFailures, stats.UpstreamTLSInvalid,
		stats.TunnelsEndedByBindingChange, stats.RequestsInjected, stats.RequestsForwarded)
	return nil
}

// validateTLSProxyBindings 在监听前确认每个 --binding 已登记且使用 https origin。
// 域名白名单只来自登记 Binding；是否允许用钥由 keykoid 在每次请求时统一判定，
// 代理不在启动阶段自行批准或否决。
func validateTLSProxyBindings(ctx context.Context, st store.Store, ids []string, logger *log.Logger) error {
	for _, id := range ids {
		b, err := st.GetBinding(ctx, id)
		if err != nil {
			return fmt.Errorf("binding %s is not registered: %w", id, err)
		}
		if b.Status != model.StatusActive {
			return fmt.Errorf("binding %s is %s", id, b.Status)
		}
		origin, err := b.Origin()
		if err != nil {
			return err
		}
		if origin.Scheme != "https" {
			return fmt.Errorf("binding %s does not use an https origin", id)
		}
		logger.Printf("registered target: binding=%s host=%s auth=%s", id, origin.Hostname(), b.AuthScheme)
	}
	return nil
}

func loadUpstreamRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil // nil 表示系统信任根，不跳过任何校验。
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --upstream-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("--upstream-ca %s contains no PEM certificate", path)
	}
	return pool, nil
}

func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("tls-proxy only listens on loopback (got %q)", addr)
	}
	return nil
}
