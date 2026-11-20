package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"keykoi/internal/ipcclient"
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

// cmdTLSProxy asks the daemon to run an HTTPS proxy for authenticated callers.
func cmdTLSProxy(args []string) error {
	fs := flag.NewFlagSet("tls-proxy", flag.ContinueOnError)
	var bindings multiFlag
	var resolve resolveFlag
	fs.Var(&bindings, "binding", "registered binding id to serve (repeatable)")
	listen := fs.String("listen", "127.0.0.1:0", "loopback listen address")
	caDir := fs.String("ca-dir", "", "directory for the local CA (private key 0600)")
	sessionFile := fs.String("session-token-file", "", "caller session token file (default: create a local caller session)")
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
	cfg := tlsproxy.ListenerConfig{BindingIDs: bindings, Listen: *listen, CADir: *caDir, Resolve: resolve}
	if *upstreamCA != "" {
		pem, err := os.ReadFile(*upstreamCA)
		if err != nil {
			return fmt.Errorf("read --upstream-ca: %w", err)
		}
		cfg.UpstreamCA = pem
	}
	adminToken, err := adminTokenFromDisk(g.dataDir)
	if err != nil {
		return err
	}
	admin := ipcclient.New(g.socket, adminToken)
	client := ipcclient.New(g.socket, "")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var info tlsproxy.ListenerInfo
	body, err := admin.OpenStream(ctx, "/v1/tls-proxy/listen", cfg, &info)
	if err != nil {
		return fmt.Errorf("start TLS proxy: %w", err)
	}
	defer body.Close()

	var token string
	if *sessionFile != "" {
		data, err := os.ReadFile(*sessionFile)
		if err != nil {
			return fmt.Errorf("read --session-token-file: %w", err)
		}
		token = strings.TrimSpace(string(data))
		if token == "" {
			return errors.New("caller session token file is empty")
		}
	} else {
		session, err := client.CreateSessionContext(ctx, "tls-proxy caller", false, 0)
		if err != nil {
			return err
		}
		token = session.Token
		defer client.Post("/v1/sessions/close", map[string]string{"session_id": session.ID}, nil)
	}
	tokenFile, err := os.CreateTemp(g.dataDir, "tls-proxy-token-*")
	if err != nil {
		return fmt.Errorf("create proxy token file: %w", err)
	}
	defer os.Remove(tokenFile.Name())
	_, writeErr := fmt.Fprintln(tokenFile, token)
	if err := errors.Join(writeErr, tokenFile.Close()); err != nil {
		return fmt.Errorf("write proxy token file: %w", err)
	}
	fmt.Printf("ca_certificate=%s\nproxy_token_file=%s\nlisten=%s\n", info.CACertificate, tokenFile.Name(), info.Addr)

	_, err = io.Copy(io.Discard, body)
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("TLS proxy control connection: %w", err)
	}
	return errors.New("daemon stopped the TLS proxy")
}
