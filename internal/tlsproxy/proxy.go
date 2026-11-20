package tlsproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/httpforward"
	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

// Authorizer is the in-daemon authority for client sessions and per-request use.
type Authorizer interface {
	Authorize(ctx context.Context, req broker.Request) (*broker.Authorization, error)
	ReleaseLease(leaseID string)
	SessionByToken(secret.Value) (model.Session, error)
	Record(ctx context.Context, e store.AuditEvent)
}

// Options 配置工具级受信代理。
type Options struct {
	// Authorizer 与 Store 提供授权结果与登记目标；代理只按登记 Binding 发现目标，
	// 用钥决定一律来自 Authorizer。
	Authorizer Authorizer
	Store      store.Store
	// BindingIDs 限定本代理服务的登记 Binding；为空时允许全部 active Binding。
	BindingIDs []string
	// UpstreamRoots 是上游证书的信任池；nil 表示使用系统根。绝不跳过校验。
	UpstreamRoots *x509.CertPool
	// Resolve 只用于受控验收：把登记域名映射到本机地址，TLS 仍按登记域名校验。
	Resolve map[string]string
	// CADir 保存本机 CA；私钥 0600，公开证书交客户端 --cacert。
	CADir string
	// Now 便于测试注入时钟。
	Now func() time.Time
	// Logger 只记录域名、Binding 与错误码，不记录请求头或凭证。
	Logger logLike
	// MaxBodyBytes 限制隧道内请求体；0 表示不限制。
	MaxBodyBytes int64
}

// logLike 是 *log.Logger 的最小接口，便于测试注入。
type logLike interface {
	Printf(format string, args ...any)
}

// Stats 是代理运行计数，供验收与诊断使用。它不含任何秘密。
type Stats struct {
	ConnectsAccepted   int64 `json:"connects_accepted"`
	ConnectsRejected   int64 `json:"connects_rejected"`
	ClientTLSFailures  int64 `json:"client_tls_failures"`
	UpstreamTLSInvalid int64 `json:"upstream_tls_invalid"`
	UpstreamUnavail    int64 `json:"upstream_unavailable"`
	RequestsInjected   int64 `json:"requests_injected"`
	RequestsForwarded  int64 `json:"requests_forwarded"`
	// TunnelsEndedByBindingChange 记录因授权返回的绑定 revision 变化而结束的隧道数。
	TunnelsEndedByBindingChange int64 `json:"tunnels_ended_by_binding_change"`
}

// Proxy 是工具级受信 HTTPS 代理。它只接受 CONNECT，且只对已登记 Binding 的域名
// 终止 TLS、验证上游证书并注入认证头。
type Proxy struct {
	ca         *CA
	authorizer Authorizer
	store      store.Store
	allowed    map[string]bool
	roots      *x509.CertPool
	resolve    map[string]string
	now        func() time.Time
	log        logLike
	transport  *http.Transport
	maxBody    int64

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool

	stats struct {
		connectsAccepted            atomic.Int64
		connectsRejected            atomic.Int64
		clientTLSFailures           atomic.Int64
		upstreamTLSInvalid          atomic.Int64
		upstreamUnavail             atomic.Int64
		requestsInjected            atomic.Int64
		requestsForwarded           atomic.Int64
		tunnelsEndedByBindingChange atomic.Int64
	}
}

// New 构造代理并加载/生成本机 CA。它不建立任何监听。
func New(opts Options) (*Proxy, error) {
	if opts.Authorizer == nil || opts.Store == nil {
		return nil, errors.New("tlsproxy: authorizer and store are required")
	}
	ca, err := LoadOrCreateCA(opts.CADir, opts.Now)
	if err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	allowed := map[string]bool{}
	for _, id := range opts.BindingIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			allowed[id] = true
		}
	}
	p := &Proxy{
		ca:         ca,
		authorizer: opts.Authorizer,
		store:      opts.Store,
		allowed:    allowed,
		roots:      opts.UpstreamRoots,
		resolve:    opts.Resolve,
		now:        opts.Now,
		log:        opts.Logger,
		maxBody:    opts.MaxBodyBytes,
		conns:      map[net.Conn]struct{}{},
	}
	p.transport = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
			return d.DialContext(ctx, network, p.dialAddress(addr))
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.UpstreamRoots},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
	}
	return p, nil
}

// CA 返回本机 CA，供 CLI 打印公开证书路径。
func (p *Proxy) CA() *CA { return p.ca }

// Stats 返回当前计数快照。
func (p *Proxy) Stats() Stats {
	return Stats{
		ConnectsAccepted:            p.stats.connectsAccepted.Load(),
		ConnectsRejected:            p.stats.connectsRejected.Load(),
		ClientTLSFailures:           p.stats.clientTLSFailures.Load(),
		UpstreamTLSInvalid:          p.stats.upstreamTLSInvalid.Load(),
		UpstreamUnavail:             p.stats.upstreamUnavail.Load(),
		RequestsInjected:            p.stats.requestsInjected.Load(),
		RequestsForwarded:           p.stats.requestsForwarded.Load(),
		TunnelsEndedByBindingChange: p.stats.tunnelsEndedByBindingChange.Load(),
	}
}

// Close 关闭活动隧道与空闲上游连接。
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.conns = map[net.Conn]struct{}{}
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	p.transport.CloseIdleConnections()
	return nil
}

func (p *Proxy) validSession(token secret.Value) bool {
	_, err := p.authorizer.SessionByToken(token)
	return err == nil
}

// ServeHTTP 只接受 CONNECT。未登记域名在 CONNECT 阶段拒绝，不建立隧道，
// 也不发生任何凭证注入。
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// BasicAuth parses the standard Basic format, using the proxy header as its source.
	auth := http.Request{Header: http.Header{"Authorization": r.Header.Values("Proxy-Authorization")}}
	username, password, ok := auth.BasicAuth()
	token := secret.New(password)
	if !ok || username != "keykoi" || !p.validSession(token) {
		p.stats.connectsRejected.Add(1)
		w.Header().Set("Proxy-Authenticate", `Basic realm="KeyKoi"`)
		writeProxyError(w, http.StatusProxyAuthRequired, "proxy_auth_required", "valid proxy credentials are required")
		return
	}
	if r.Method != http.MethodConnect {
		p.stats.connectsRejected.Add(1)
		writeProxyError(w, http.StatusMethodNotAllowed, "method_not_allowed",
			"the KeyKoi tool-level proxy only supports CONNECT tunnels; point the tool's HTTPS proxy setting at this listener")
		return
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		p.stats.connectsRejected.Add(1)
		writeProxyError(w, http.StatusServiceUnavailable, "proxy_closed", "the trusted proxy is shutting down")
		return
	}
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	host, port, err := splitAuthority(authority)
	if err != nil {
		p.stats.connectsRejected.Add(1)
		writeProxyError(w, http.StatusBadRequest, "invalid_target", "CONNECT target must be host:port")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	binding, err := p.bindingForHost(ctx, host)
	if err != nil {
		cancel()
		p.stats.connectsRejected.Add(1)
		p.logf("CONNECT %s rejected: %v (no credential injected)", authority, err)
		writeProxyError(w, http.StatusForbidden, "target_not_registered",
			fmt.Sprintf("target %q is not a registered KeyKoi binding; no credential was injected", host))
		return
	}
	origin, err := binding.Origin()
	if err != nil || origin.Scheme != "https" {
		cancel()
		p.stats.connectsRejected.Add(1)
		p.logf("CONNECT %s rejected: binding %s origin is not https", authority, binding.ID)
		writeProxyError(w, http.StatusForbidden, "target_not_registered",
			fmt.Sprintf("binding %s does not register an https origin", binding.ID))
		return
	}
	// 在终止客户端 TLS 之前先验证真实上游证书：证书无效直接终止 CONNECT，
	// 凭证不会离开本进程，更不会写入任何请求。
	if err := p.verifyUpstream(ctx, origin); err != nil {
		cancel()
		code := "upstream_unavailable"
		var ue *upstreamError
		if errors.As(err, &ue) {
			code = ue.code
		}
		if code == "upstream_tls_invalid" {
			p.stats.upstreamTLSInvalid.Add(1)
		} else {
			p.stats.upstreamUnavail.Add(1)
		}
		p.stats.connectsRejected.Add(1)
		p.logf("CONNECT %s rejected: upstream %s verification failed with %s (no credential injected)", authority, origin.Host, code)
		writeProxyError(w, http.StatusBadGateway, code,
			fmt.Sprintf("upstream %s TLS certificate could not be verified; the connection was terminated and no credential was injected", origin.Host))
		return
	}
	cancel()

	hj, ok := w.(http.Hijacker)
	if !ok {
		p.stats.connectsRejected.Add(1)
		writeProxyError(w, http.StatusInternalServerError, "hijack_unsupported", "this listener cannot take over the connection")
		return
	}
	raw, brw, err := hj.Hijack()
	if err != nil {
		p.stats.connectsRejected.Add(1)
		p.logf("CONNECT %s hijack failed: %v", authority, err)
		return
	}
	if _, err := io.WriteString(brw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = raw.Close()
		return
	}
	if err := brw.Flush(); err != nil {
		_ = raw.Close()
		return
	}
	p.stats.connectsAccepted.Add(1)
	p.track(raw)
	go p.serveTunnel(raw, brw.Reader, &tunnel{binding: binding, host: host, port: port, token: token})
}

// tunnel 是同一条 CONNECT 连接的转发状态。
//
// binding 只是建连时读到的登记快照，用于 SNI 匹配和上游证书预检；真正决定转发目标与
// 凭证版本的是当次授权返回的 authz.Binding 与 authz.Lease。这样「新凭证发往旧目标」
// 不会发生：目标与版本来自同一次授权。
type tunnel struct {
	token   secret.Value
	binding *model.Binding
	host    string
	port    string
}

// serveTunnel 在已接管的连接上终止客户端 TLS，再以单连接 http.Server
// 处理隧道内请求。
func (p *Proxy) serveTunnel(raw net.Conn, r *bufio.Reader, tun *tunnel) {
	defer func() {
		p.untrack(raw)
		_ = raw.Close()
	}()
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" && normalizeHost(hello.ServerName) != tun.host {
				return nil, fmt.Errorf("tlsproxy: SNI %q does not match CONNECT target %q", hello.ServerName, tun.host)
			}
			return p.ca.CertificateForHost(tun.host)
		},
	}
	tlsConn := tls.Server(&bufferedConn{Conn: raw, r: r}, cfg)
	hsCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := tlsConn.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		p.stats.clientTLSFailures.Add(1)
		p.logf("client TLS handshake for %s:%s failed: %v; client does not trust the KeyKoi CA or pins certificates, which is recorded as unsupported", tun.host, tun.port, err)
		return
	}

	tracked := &trackedConn{Conn: tlsConn, closed: make(chan struct{})}
	one := &singleConnListener{conn: tracked, closed: tracked.closed}
	inner := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p.handleInner(w, r, tun) {
				return
			}
			// 隧道已失去授权（锁定、改绑或授权被拒）：把错误回完就结束连接，
			// 客户端必须重新建连并重新经过授权，不能在这条隧道上继续用钥。
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			_ = tracked.Close()
		}),
		ReadHeaderTimeout: 15 * time.Second,
		ErrorLog:          discardLogger,
	}
	_ = inner.Serve(one)
}

// handleInner 处理隧道内请求：先取得授权，再用同一次授权返回的绑定快照与凭证版本转发。
// 返回 false 表示这条隧道不能继续使用，调用方应结束连接。
func (p *Proxy) handleInner(w http.ResponseWriter, r *http.Request, tun *tunnel) bool {
	if r.Host != "" {
		if h, _, err := splitAuthority(r.Host); err == nil && h != tun.host {
			p.writeTunnelError(w, http.StatusMisdirectedRequest, "host_mismatch",
				"the request host does not match the CONNECT target")
			return true
		}
	}
	ctx := r.Context()
	// 用钥决定交给授权来源：主库锁定、逐次验证与中心策略都在主服务内统一生效。
	// 代理不再自建 Broker，也不复用主服务的启动会话。
	authz, err := p.authorizer.Authorize(ctx, broker.Request{
		Token:     tun.token,
		BindingID: tun.binding.ID,
		Mode:      model.ModeProxy,
		Purpose:   "tls proxy target=" + tun.host,
	})
	if err != nil {
		code := codeOf(err)
		if code == "" {
			code = "PROXY_ERROR"
		}
		p.logf("binding %s authorization denied: %s (no credential injected)", tun.binding.ID, code)
		// 只回稳定错误码与原因，不回请求内容或凭证。
		p.rejectTunnel(w, statusForCode(code), string(code), strings.TrimPrefix(err.Error(), string(code)+": "))
		return false
	}
	defer p.authorizer.ReleaseLease(authz.Lease.ID)
	ctx, cancel := authz.ExecutionContext(ctx)
	defer cancel()
	controller := http.NewResponseController(w)
	if controller.SetWriteDeadline(authz.Lease.UseLeaseExpiresAt) == nil {
		defer controller.SetWriteDeadline(time.Time{})
	}
	if authz.Binding == nil {
		p.rejectTunnel(w, http.StatusBadGateway, "PROXY_ERROR",
			"the authorization did not return a binding snapshot")
		return false
	}
	// 转发目标只来自这次授权：目标、认证方案与凭证版本必须是同一版本。
	binding := authz.Binding
	if binding.ID != tun.binding.ID {
		p.logf("binding %s authorization returned binding %s; ending the tunnel", tun.binding.ID, binding.ID)
		p.endStaleTunnel(w, ctx, authz, binding, "binding_changed")
		return false
	}
	origin, err := binding.Origin()
	if err != nil || origin.Scheme != "https" {
		p.rejectTunnel(w, http.StatusBadGateway, "target_not_registered", "the binding origin is invalid")
		return false
	}
	if normalizeHost(origin.Hostname()) != tun.host {
		p.logf("binding %s now targets %q; ending the tunnel established for %q", binding.ID, origin.Hostname(), tun.host)
		p.endStaleTunnel(w, ctx, authz, binding, "binding_target_changed")
		return false
	}
	// 同一隧道内的后续授权看到不同 revision：绑定已改，结束连接并要求重连。
	if rev := authz.Lease.BindingRevision; rev != tun.binding.Revision {
		p.logf("binding %s revision changed from %d to %d; ending the tunnel", binding.ID, tun.binding.Revision, rev)
		p.endStaleTunnel(w, ctx, authz, binding, "binding_revision_changed")
		return false
	}
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	if !binding.PathAllowed(path) {
		p.writeTunnelError(w, http.StatusForbidden, "path_not_allowed",
			fmt.Sprintf("path %q is not allowed for binding %s", path, binding.ID))
		return true
	}
	headerName, headerValue, err := buildAuthHeader(binding, authz.Version)
	if err != nil {
		p.logf("binding %s cannot build auth header: %s", binding.ID, model.CodeOf(err))
		p.writeTunnelError(w, http.StatusServiceUnavailable, string(model.CodeOf(err)), err.Error())
		return true
	}

	upstream := &url.URL{Scheme: origin.Scheme, Host: origin.Host, Path: path, RawQuery: r.URL.RawQuery}
	if raw := r.URL.RawPath; raw != "" {
		if decoded, derr := url.PathUnescape(raw); derr == nil && decoded == path {
			upstream.RawPath = raw
		}
	}

	body := r.Body
	if body != nil && p.maxBody > 0 {
		body = http.MaxBytesReader(w, r.Body, p.maxBody)
	}
	outReq, err := http.NewRequestWithContext(ctx, r.Method, upstream.String(), body)
	if err != nil {
		p.writeTunnelError(w, http.StatusBadGateway, "upstream_unavailable", "cannot build the upstream request")
		return true
	}
	outReq.URL = upstream
	outReq.Host = origin.Host
	outReq.ContentLength = r.ContentLength
	httpforward.CopyHeaders(outReq.Header, r.Header)
	removeClientCredentials(outReq.Header, headerName)
	outReq.Header.Set(headerName, headerValue)
	p.stats.requestsInjected.Add(1)

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		code := "upstream_unavailable"
		var ue *upstreamError
		if errors.As(err, &ue) {
			code = ue.code
		}
		if code == "upstream_tls_invalid" {
			p.stats.upstreamTLSInvalid.Add(1)
		} else {
			p.stats.upstreamUnavail.Add(1)
		}
		p.record(ctx, authz, binding, http.StatusBadGateway, code)
		p.logf("binding %s upstream %s failed: %s", binding.ID, origin.Host, code)
		w.Header().Set("Connection", "close")
		p.writeTunnelError(w, http.StatusBadGateway, code,
			fmt.Sprintf("upstream %s could not be reached with a verified TLS connection", origin.Host))
		return true
	}
	defer resp.Body.Close()

	p.stats.requestsForwarded.Add(1)
	httpforward.CopyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	readErr, writeErr := httpforward.StreamBody(w, resp.Body)
	if writeErr != nil {
		p.record(ctx, authz, binding, resp.StatusCode, "client_write_failed")
		return true
	}
	if readErr != nil {
		p.record(ctx, authz, binding, resp.StatusCode, "upstream_response_interrupted")
		panic(http.ErrAbortHandler)
	}
	p.record(ctx, authz, binding, resp.StatusCode, "")
	return true
}

// bindingForHost 在已登记的 active Binding 中按 origin 域名匹配 CONNECT 目标。
func (p *Proxy) bindingForHost(ctx context.Context, host string) (*model.Binding, error) {
	bindings, err := p.store.ListBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("read registered bindings: %w", err)
	}
	for _, b := range bindings {
		if len(p.allowed) > 0 && !p.allowed[b.ID] {
			continue
		}
		if b.Status != model.StatusActive {
			continue
		}
		origin, err := b.Origin()
		if err != nil || origin.Scheme != "https" {
			continue
		}
		if normalizeHost(origin.Hostname()) == host {
			return b, nil
		}
	}
	return nil, fmt.Errorf("target domain is not registered for this proxy")
}

// verifyUpstream 在 CONNECT 阶段验证上游证书链与域名，失败即终止。
func (p *Proxy) verifyUpstream(ctx context.Context, origin *url.URL) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	port := origin.Port()
	if port == "" {
		port = "443"
	}
	raw, err := dialer.DialContext(ctx, "tcp", p.dialAddress(net.JoinHostPort(origin.Hostname(), port)))
	if err != nil {
		return &upstreamError{code: "upstream_unavailable", err: err}
	}
	defer raw.Close()
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: origin.Hostname(), RootCAs: p.roots}
	tc := tls.Client(raw, cfg)
	hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hsCtx); err != nil {
		return &upstreamError{code: classifyTLSError(err), err: err}
	}
	return nil
}

func (p *Proxy) dialAddress(addr string) string {
	if p.resolve == nil {
		return addr
	}
	if v, ok := p.resolve[addr]; ok {
		return v
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if v, ok := p.resolve[normalizeHost(host)]; ok {
		if _, _, err := net.SplitHostPort(v); err == nil {
			return v
		}
		return net.JoinHostPort(v, port)
	}
	return addr
}

func (p *Proxy) track(c net.Conn) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = c.Close()
		return
	}
	p.conns[c] = struct{}{}
	p.mu.Unlock()
}

func (p *Proxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

// record 把一次转发的状态码与错误码写进授权来源的审计。
// 只上报编码与结果，不写请求头、令牌或凭证内容。
func (p *Proxy) record(ctx context.Context, authz *broker.Authorization, binding *model.Binding, status int, code string) {
	p.authorizer.Record(context.WithoutCancel(ctx), store.AuditEvent{
		SessionID:         authz.Session.ID,
		PrincipalID:       authz.Session.PrincipalID,
		BindingID:         binding.ID,
		CredentialID:      authz.Lease.CredentialID,
		CredentialVersion: authz.Lease.CredentialVersion,
		Mode:              string(authz.Lease.DeliveryMode),
		Result:            "tls_" + fmt.Sprint(status),
		ErrorCode:         code,
	})
}

// recordClosed 记录一次因为绑定变更而结束的隧道；不写任何凭证内容。
func (p *Proxy) recordClosed(ctx context.Context, authz *broker.Authorization, binding *model.Binding, code string) {
	p.authorizer.Record(context.WithoutCancel(ctx), store.AuditEvent{
		SessionID:         authz.Session.ID,
		PrincipalID:       authz.Session.PrincipalID,
		BindingID:         binding.ID,
		CredentialID:      authz.Lease.CredentialID,
		CredentialVersion: authz.Lease.CredentialVersion,
		Mode:              string(authz.Lease.DeliveryMode),
		Result:            "tls_closed",
		ErrorCode:         code,
	})
}

// rejectTunnel 回写一个「这条隧道不能再使用」的错误：先声明关闭连接，再写稳定错误体。
// 调用方在 handler 返回后立即结束底层连接，客户端必须重新建连并重新授权。
func (p *Proxy) rejectTunnel(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Connection", "close")
	writeProxyError(w, status, code, message)
}

// endStaleTunnel 结束因绑定变更而失效的隧道，并留下审计与计数。
func (p *Proxy) endStaleTunnel(w http.ResponseWriter, ctx context.Context, authz *broker.Authorization, binding *model.Binding, code string) {
	p.stats.tunnelsEndedByBindingChange.Add(1)
	p.recordClosed(ctx, authz, binding, code)
	p.rejectTunnel(w, http.StatusConflict, "binding_changed",
		"the binding changed while the tunnel was open; reconnect to authorize again")
}

func (p *Proxy) logf(format string, args ...any) {
	if p.log != nil {
		p.log.Printf(format, args...)
	}
}

func (p *Proxy) writeTunnelError(w http.ResponseWriter, status int, code, message string) {
	writeProxyError(w, status, code, message)
}

// buildAuthHeader 与显式网关保持同一注入语义：bearer / api_key / basic。
func buildAuthHeader(binding *model.Binding, version model.CredentialVersion) (string, string, error) {
	switch binding.AuthScheme {
	case model.AuthBearer:
		v, err := version.Field(defaultString(binding.TokenField, "token"))
		if err != nil {
			return "", "", model.WrapError(model.CodeCredentialUnavailable, err, "credential field for bearer injection is missing")
		}
		return "Authorization", "Bearer " + v.RevealString(), nil
	case model.AuthAPIKey:
		v, err := version.Field(defaultString(binding.TokenField, "token"))
		if err != nil {
			return "", "", model.WrapError(model.CodeCredentialUnavailable, err, "credential field for API key injection is missing")
		}
		return defaultString(binding.AuthHeader, "X-Api-Key"), v.RevealString(), nil
	case model.AuthBasic:
		user, err := version.Field(defaultString(binding.UsernameField, "username"))
		if err != nil {
			return "", "", model.WrapError(model.CodeCredentialUnavailable, err, "credential field for basic auth user is missing")
		}
		pw, err := version.Field(defaultString(binding.PasswordField, "password"))
		if err != nil {
			return "", "", model.WrapError(model.CodeCredentialUnavailable, err, "credential field for basic auth password is missing")
		}
		creds := user.RevealString() + ":" + pw.RevealString()
		return "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(creds)), nil
	}
	return "", "", model.NewError(model.CodeAdapterUnsupported, "unsupported auth scheme %q", binding.AuthScheme)
}

func splitAuthority(authority string) (host, port string, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", "", errors.New("empty authority")
	}
	h, p, err := net.SplitHostPort(authority)
	if err == nil {
		if normalizeHost(h) == "" || p == "" {
			return "", "", fmt.Errorf("invalid authority %q", authority)
		}
		return normalizeHost(h), p, nil
	}
	// 没有端口时按 https 默认端口处理。
	if strings.Contains(authority, ":") && !strings.HasPrefix(authority, "[") {
		return "", "", fmt.Errorf("invalid authority %q", authority)
	}
	return normalizeHost(authority), "443", nil
}

// codeOf 提取授权失败的错误码。注入内存 Broker 时返回 model.Error，经 keykoid 授权时
// 返回 IPC 客户端错误；两者都按同一套稳定错误码对待，不因入口不同而改变结果。
func codeOf(err error) model.Code {
	if code := model.CodeOf(err); code != "" {
		return code
	}
	var apiErr *ipcclient.APIError
	if errors.As(err, &apiErr) {
		return model.Code(apiErr.Code)
	}
	return ""
}

func statusForCode(code model.Code) int {
	switch code {
	case model.CodeVaultLocked, model.CodeAuthUnavailable:
		return http.StatusServiceUnavailable
	case model.CodeVaultUnlockFailed, model.CodeSessionInvalid:
		return http.StatusUnauthorized
	case model.CodeUseNotAllowed, model.CodeLeaseExpired:
		return http.StatusForbidden
	case model.CodeBindingDisabled:
		return http.StatusNotFound
	case model.CodeCredentialUnavailable:
		return http.StatusServiceUnavailable
	case model.CodeAdapterUnsupported:
		return http.StatusNotImplemented
	case model.CodeUpstreamUnavailable:
		return http.StatusBadGateway
	case model.CodeUpstreamAuthFailed:
		return http.StatusUnauthorized
	case "PROXY_ERROR":
		return http.StatusInternalServerError
	}
	return http.StatusForbidden
}

type upstreamError struct {
	code string
	err  error
}

func (e *upstreamError) Error() string { return e.code + ": " + e.err.Error() }
func (e *upstreamError) Unwrap() error { return e.err }

// classifyTLSError 区分证书问题与网络不可用；两类都不会继续注入。
func classifyTLSError(err error) string {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "upstream_tls_invalid"
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "upstream_tls_invalid"
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return "upstream_tls_invalid"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return "upstream_tls_invalid"
	}
	return "upstream_unavailable"
}

// removeClientCredentials 丢弃客户端自带认证头与中介控制头，再注入真实凭证。
func removeClientCredentials(h http.Header, injectHeader string) {
	for name := range h {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-keykoi-") {
			h.Del(name)
		}
	}
	h.Del("Authorization")
	h.Del("Proxy-Authorization")
	h.Del("X-Api-Key")
	if !strings.EqualFold(injectHeader, "Authorization") {
		h.Del(injectHeader)
	}
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// ErrorBody 是稳定错误封装，只含错误码与说明。
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeProxyError(w http.ResponseWriter, status int, code, message string) {
	body := ErrorBody{}
	body.Error.Code = code
	body.Error.Message = message
	// 显式给出长度：结束隧道时要能在回完整个错误体之后立即关闭连接，
	// 不留下残缺的分块帧。
	payload, err := json.Marshal(body)
	if err != nil {
		payload = []byte(`{"error":{"code":"` + code + `","message":"error response could not be encoded"}}`)
	}
	payload = append(payload, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-KeyKoi-Proxy-Result", code)
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

// bufferedConn 复用 hijack 返回的读缓冲，避免丢掉已预读的 ClientHello。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// trackedConn 在关闭时通知单连接监听器，使 Serve 能随隧道结束返回。
type trackedConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// singleConnListener 只交付一个连接；该连接关闭后 Accept 返回 io.EOF。
type singleConnListener struct {
	conn     net.Conn
	closed   <-chan struct{}
	accepted bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.closed
	return nil, io.EOF
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

var discardLogger = log.New(io.Discard, "", 0)
