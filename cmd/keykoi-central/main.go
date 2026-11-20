// Command keykoi-central 是多设备中心服务入口。它只发放短期许可与撤销事件，
// 不保存业务凭证内容。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"keykoi/internal/central"
)

func main() {
	var (
		dsn    = flag.String("dsn", "", "PostgreSQL DSN (required)")
		listen = flag.String("listen", "127.0.0.1:8390",
			"listen address; plaintext is only allowed on loopback, other addresses require TLS")
		adminToken = flag.String("admin-token", "",
			"administrator credential for policy and revocation (or KEYKOI_CENTRAL_ADMIN)")
		bootstrapToken = flag.String("bootstrap-token", "",
			"device registration credential; must differ from the administrator token (or KEYKOI_CENTRAL_BOOTSTRAP)")
		tlsCert  = flag.String("tls-cert", "", "TLS certificate for non-loopback listeners (or KEYKOI_CENTRAL_TLS_CERT)")
		tlsKey   = flag.String("tls-key", "", "TLS private key for non-loopback listeners (or KEYKOI_CENTRAL_TLS_KEY)")
		leaseTTL = flag.Duration("lease-ttl", 90*time.Second, "short-term lease duration")
	)
	flag.Parse()
	admin := firstNonEmpty(*adminToken, os.Getenv("KEYKOI_CENTRAL_ADMIN"))
	bootstrap := firstNonEmpty(*bootstrapToken, os.Getenv("KEYKOI_CENTRAL_BOOTSTRAP"))
	cert := firstNonEmpty(*tlsCert, os.Getenv("KEYKOI_CENTRAL_TLS_CERT"))
	key := firstNonEmpty(*tlsKey, os.Getenv("KEYKOI_CENTRAL_TLS_KEY"))

	if *dsn == "" {
		log.Fatal("--dsn is required")
	}
	// 两类凭据分别用于设备注册与管理操作，缺失或相同则拒绝启动。
	if err := central.ValidateCredentials(admin, bootstrap); err != nil {
		log.Fatalf("central credentials: %v", err)
	}
	// 明文监听只允许回环；跨机器部署必须显式提供证书与私钥。
	plan, err := central.ResolveListenPlan(*listen, cert, key)
	if err != nil {
		log.Fatalf("listen security: %v", err)
	}
	srv, err := central.OpenWithOptions(context.Background(), central.Options{
		DSN: *dsn, AdminToken: admin, BootstrapToken: bootstrap, LeaseTTL: *leaseTTL,
	})
	if err != nil {
		log.Fatalf("open center: %v", err)
	}
	httpSrv := &http.Server{Addr: plan.Addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		var serveErr error
		if plan.TLS {
			serveErr = httpSrv.ListenAndServeTLS(plan.CertFile, plan.KeyFile)
		} else {
			serveErr = httpSrv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatalf("serve: %v", serveErr)
		}
	}()
	// 只打印凭据指纹，不打印凭据本身。
	log.Printf("keykoi-central listening on %s epoch=%s transport=%s admin=%s bootstrap=%s",
		plan.Describe(), srv.Epoch, transportLabel(plan), fingerprint(admin), fingerprint(bootstrap))
	if !plan.TLS {
		log.Printf("keykoi-central: plaintext listener is restricted to loopback; use --tls-cert/--tls-key for remote clients")
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	_ = srv.DB.Close()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func transportLabel(plan central.ListenPlan) string {
	if plan.TLS {
		return "tls"
	}
	return "plaintext-loopback"
}

// fingerprint 返回凭据的短指纹，用于启动日志区分配置来源而不泄露秘密。
func fingerprint(token string) string {
	if token == "" {
		return "unset"
	}
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:4])
}
