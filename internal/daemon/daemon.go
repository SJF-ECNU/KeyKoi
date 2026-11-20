// Package daemon 组装 KeyKoi 后台：本机受认证 IPC、用钥 Broker、显式网关与运行器。
// 它不区分 P0/ P1 的对外语义；后端（内存或加密密钥库）通过 Backend 接口注入。
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/gateway"
	"keykoi/internal/integration"
	"keykoi/internal/model"
	"keykoi/internal/osruntime"
	"keykoi/internal/store"
)

// Backend 是密钥库后端：P0 使用内存实现，P1 使用 SQLite 加密密钥库。
type Backend interface {
	broker.Source
	// CreateCredential 写入凭证索引与首个完整版本。
	CreateCredential(ctx context.Context, meta model.Credential, version model.CredentialVersion) (*model.Credential, error)
	// AddVersion 原子写入新版本并切换当前版本。
	AddVersion(ctx context.Context, credentialID string, version model.CredentialVersion) (*model.Credential, error)
	// ActivateVersionCAS 只在凭证 revision 仍为 expectedRevision 时写入新版本，
	// 让 OAuth 刷新/回调的「记录未变」与「写入」成为一次原子决定。
	// 冲突返回 store.ErrConflict。
	ActivateVersionCAS(ctx context.Context, credentialID string, version model.CredentialVersion, expectedRevision int64) (*model.Credential, error)
	// Lock 停止取钥。
	Lock(ctx context.Context) error
	// Unlock 解除锁定；内存后端忽略参数。
	Unlock(ctx context.Context, password []byte) error
	// State 返回 locked/unlocked。
	State() string
	// Describe 返回不含秘密的状态摘要。
	Describe() string
	// Close 释放后端资源。
	Close() error
}

// Config 配置后台。
type Config struct {
	DataDir     string
	SocketPath  string
	GatewayAddr string
	AdminAddr   string
	UserLabel   string
	Broker      broker.Options
	// AdaptersDir 是受信适配声明的目录。
	AdaptersDir string
	// KeyKoiBin 是写入工具配置的助手入口绝对路径。
	KeyKoiBin string
	// Biometric 配置系统生物识别（Touch ID）助手的调用方式。
	Biometric BiometricConfig
}

// BiometricConfig 配置 macOS 生物识别助手。HelperPath 为空表示当前环境不支持，
// 此时依赖生物识别的请求会返回 AUTH_UNAVAILABLE 并提示回退主密码。
type BiometricConfig struct {
	HelperPath string
	Account    string
	Timeout    time.Duration
	// PasswordFallback 是主密码回退证明的有效期。
	PasswordFallback time.Duration
}

// Daemon 是运行中的后台实例。
type Daemon struct {
	cfg     Config
	store   store.Store
	backend Backend
	broker  *broker.Broker
	gateway *gateway.Gateway

	listener    net.Listener
	gwListener  net.Listener
	adminLn     net.Listener
	ipcServer   *http.Server
	gwServer    *http.Server
	adminServer *http.Server
	adminToken  string

	mu          sync.Mutex
	runners     *RunnerRegistry
	instances   *IntegrationRegistry
	oauth       *OAuthRegistry
	integration *integration.Manager
	startedAt   time.Time

	// authn 执行 Grant 的验证策略；passwordProof 保存一次性主密码回退证明。
	authn         *broker.Authenticator
	passwordProof *passwordProof
	authMu        sync.Mutex
	authProblem   string
}

// New 构造后台。调用方负责先准备好 store 与 backend。
func New(cfg Config, st store.Store, backend Backend) *Daemon {
	cfg.Broker.LocalPrincipalID = localPrincipalID()
	now := cfg.Broker.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	d := &Daemon{
		cfg:       cfg,
		store:     st,
		backend:   backend,
		startedAt: time.Now().UTC(),
		runners:   NewRunnerRegistry(),
		instances: NewIntegrationRegistry(),
		oauth:     NewOAuthRegistry(),
	}
	d.passwordProof = newPasswordProof(cfg.Biometric.PasswordFallback, now)
	d.authn = broker.NewAuthenticator(broker.VerifierFunc(d.verifyAuth), now)
	cfg.Broker.Auth = d.authn
	d.broker = broker.New(st, backend, cfg.Broker)
	d.integration = &integration.Manager{
		St: st, AdaptersDir: cfg.AdaptersDir, DataDir: cfg.DataDir, KeyKoiBin: cfg.KeyKoiBin,
	}
	d.gateway = gateway.New(d.broker, gateway.Options{})
	return d
}

// Broker 暴露内部 Broker，供运行器与 Helper 复用同一许可路径。
func (d *Daemon) Broker() *broker.Broker { return d.broker }

// Store 暴露存储，供管理接口使用。
func (d *Daemon) Store() store.Store { return d.store }

// Backend 暴露密钥库后端。
func (d *Daemon) Backend() Backend { return d.backend }

// Start 启动 IPC、网关与管理监听。
func (d *Daemon) Start() error {
	if d.cfg.SocketPath == "" {
		d.cfg.SocketPath = osruntime.SocketPath(d.cfg.DataDir)
	}
	ln, err := osruntime.ListenUnix(d.cfg.SocketPath)
	if err != nil {
		return err
	}
	d.listener = ln
	token, err := d.ensureAdminToken()
	if err != nil {
		_ = ln.Close()
		return err
	}
	d.adminToken = token
	if err := d.bootstrapPrincipals(context.Background()); err != nil {
		_ = ln.Close()
		return err
	}
	d.ipcServer = &http.Server{
		Handler: d.ipcRouter(), ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, ipcPeerKey{}, conn)
		},
	}
	go func() { _ = d.ipcServer.Serve(ln) }()

	if d.cfg.GatewayAddr != "" {
		gln, err := net.Listen("tcp", d.cfg.GatewayAddr)
		if err != nil {
			return fmt.Errorf("listen gateway: %w", err)
		}
		d.gwListener = gln
		d.gwServer = &http.Server{Handler: d.gateway, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = d.gwServer.Serve(gln) }()
	}
	if d.cfg.AdminAddr != "" {
		aln, err := net.Listen("tcp", d.cfg.AdminAddr)
		if err != nil {
			return fmt.Errorf("listen admin: %w", err)
		}
		d.adminLn = aln
		d.adminServer = &http.Server{Handler: d.adminRouter(), ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = d.adminServer.Serve(aln) }()
	}
	return nil
}

// SocketPath 返回实际 IPC 路径。
func (d *Daemon) SocketPath() string { return d.cfg.SocketPath }

// GatewayAddr 返回实际网关地址。
func (d *Daemon) GatewayAddr() string {
	if d.gwListener == nil {
		return ""
	}
	return d.gwListener.Addr().String()
}

// AdminAddr 返回实际管理界面地址。
func (d *Daemon) AdminAddr() string {
	if d.adminLn == nil {
		return ""
	}
	return d.adminLn.Addr().String()
}

// Stop 停止监听并撤销全部运行时状态。
func (d *Daemon) Stop() {
	ctx := context.Background()
	d.broker.CloseAll(ctx)
	if d.ipcServer != nil {
		_ = d.ipcServer.Close()
	}
	if d.gwServer != nil {
		_ = d.gwServer.Close()
	}
	if d.adminServer != nil {
		_ = d.adminServer.Close()
	}
	if d.listener != nil {
		_ = os.Remove(d.cfg.SocketPath)
	}
	d.runners.KillAll()
}

func (d *Daemon) ensureAdminToken() (string, error) {
	path := filepath.Join(d.cfg.DataDir, "admin.token")
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return string(b), nil
	}
	if err := os.MkdirAll(d.cfg.DataDir, 0o700); err != nil {
		return "", err
	}
	buf := make([]byte, 32)
	if _, err := cryptoRand(buf); err != nil {
		return "", err
	}
	token := fmt.Sprintf("%x", buf)
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		return "", err
	}
	return token, nil
}

// AdminToken 返回本机管理令牌，仅供 CLI 通过 0600 文件读取后使用。
func (d *Daemon) AdminToken() string { return d.adminToken }

func (d *Daemon) ipcRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", d.handleStatus)
	mux.HandleFunc("/v1/sessions", d.handleSessions)
	mux.HandleFunc("/v1/sessions/close", d.handleSessionClose)
	mux.HandleFunc("/v1/resolve", d.handleResolve)
	mux.HandleFunc("/v1/use-leases", d.handleUseLeases)
	mux.HandleFunc("/v1/use-leases/revoke", d.handleUseLeaseRevoke)
	mux.HandleFunc("/v1/credentials", d.handleCredentials)
	mux.HandleFunc("/v1/credentials/", d.handleCredentialItem)
	mux.HandleFunc("/v1/bindings", d.handleBindings)
	mux.HandleFunc("/v1/bindings/", d.handleBindingItem)
	mux.HandleFunc("/v1/subjects", d.handleSubjects)
	mux.HandleFunc("/v1/subjects/current", d.handleCurrentSubject)
	mux.HandleFunc("/v1/activity", d.handleActivity)
	mux.HandleFunc("/v1/grants", d.handleGrants)
	mux.HandleFunc("/v1/grants/", d.handleGrantItem)
	mux.HandleFunc("/v1/vault/init", d.handleVaultInit)
	mux.HandleFunc("/v1/vault/backup", d.handleVaultBackup)
	mux.HandleFunc("/v1/vault/restore", d.handleVaultRestore)
	mux.HandleFunc("/v1/vault/lock", d.handleLock)
	mux.HandleFunc("/v1/vault/unlock", d.handleUnlock)
	mux.HandleFunc("/v1/vault/enroll-biometric", d.handleVaultEnrollBiometric)
	mux.HandleFunc("/v1/vault/unlock-biometric", d.handleVaultUnlockBiometric)
	mux.HandleFunc("/v1/auth/status", d.handleAuthStatus)
	mux.HandleFunc("/v1/auth/verify", d.handleAuthVerify)
	mux.HandleFunc("/v1/audit-events", d.handleAudit)
	mux.HandleFunc("/v1/client-audit", d.handleClientAudit)
	mux.HandleFunc("/v1/support", d.handleSupport)
	mux.HandleFunc("/v1/runs", d.handleRuns)
	mux.HandleFunc("/v1/runs/", d.handleRunItem)
	mux.HandleFunc("/v1/integrations/plan", d.handleIntegrationPlan)
	mux.HandleFunc("/v1/integrations/apply", d.handleIntegrationApply)
	mux.HandleFunc("/v1/integrations", d.handleIntegrationList)
	mux.HandleFunc("/v1/integrations/", d.handleIntegrationItem)
	mux.HandleFunc("/v1/oauth/begin", d.handleOAuthBegin)
	mux.HandleFunc("/v1/oauth/callback", d.handleOAuthCallback)
	mux.HandleFunc("/v1/oauth/refresh", d.handleOAuthRefresh)
	mux.HandleFunc("/v1/signatures", d.handleSignatures)
	mux.HandleFunc("/v1/ssh-keys", d.handleSSHKeys)
	mux.HandleFunc("/v1/ssh-sign", d.handleSSHSign)
	mux.HandleFunc("/v1/tls-proxy/listen", d.handleTLSProxy)
	mux.HandleFunc("/v1/db-proxy/listen", d.handleDBProxy)
	return jsonMiddleware(mux)
}

func jsonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, err error) {
	code := model.CodeOf(err)
	status := http.StatusInternalServerError
	switch code {
	case model.CodeVaultLocked:
		status = http.StatusServiceUnavailable
	case model.CodeVaultUnlockFailed:
		status = http.StatusUnauthorized
	case model.CodeSessionInvalid, model.CodeAuthRequired:
		status = http.StatusUnauthorized
	case model.CodeAuthUnavailable:
		status = http.StatusServiceUnavailable
	case model.CodeUseNotAllowed, model.CodeLeaseExpired:
		status = http.StatusForbidden
	case model.CodeBindingDisabled:
		status = http.StatusNotFound
	case model.CodeCredentialUnavailable:
		status = http.StatusServiceUnavailable
	case model.CodeAdapterUnsupported:
		status = http.StatusNotImplemented
	case model.CodeConfigDrift:
		status = http.StatusConflict
	case "":
		status = http.StatusBadRequest
	}
	resp := errorResponse{}
	resp.Error.Code = string(code)
	if code == "" {
		resp.Error.Code = "BAD_REQUEST"
	}
	resp.Error.Message = err.Error()
	writeJSON(w, status, resp)
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	credCount := 0
	if creds, err := d.store.ListCredentials(r.Context()); err == nil {
		credCount = len(creds)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":       "keykoid",
		"locked":        d.backend.Locked(),
		"state":         d.backend.State(),
		"epoch":         d.broker.Epoch(),
		"gateway":       d.GatewayAddr(),
		"admin":         d.AdminAddr(),
		"credentials":   credCount,
		"active_leases": d.broker.ActiveLeaseCount(),
		"backend":       d.backend.Describe(),
		"started_at":    d.startedAt,
		"version":       Version,
	})
}
