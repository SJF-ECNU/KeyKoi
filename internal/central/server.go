// Package central 实现多设备中心：PostgreSQL 权威存储、设备注册、短期许可、
// 撤销事件与代次变化。它只发放许可，不接触业务凭证内容。
package central

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// 中心稳定错误码。LEASE_STALE 表示凭证版本冲突，LEASE_EPOCH_STALE 表示许可
// 属于旧授权代次；两者都可由客户端安全地重新申请。真正撤销仍只会返回
// CONTROL_UNAVAILABLE，客户端不得重试。
const (
	codeLeaseStale      = "LEASE_STALE"
	codeLeaseEpochStale = "LEASE_EPOCH_STALE"
	codeControlNone     = "CONTROL_UNAVAILABLE"
)

// Lease 是中心发放的短期使用许可。
type Lease struct {
	ID                string    `json:"id"`
	DeviceID          string    `json:"device_id"`
	BindingID         string    `json:"binding_id"`
	PrincipalID       string    `json:"principal_id,omitempty"`
	CredentialID      string    `json:"credential_id,omitempty"`
	CredentialVersion int       `json:"credential_version"`
	Mode              string    `json:"mode"`
	Epoch             string    `json:"epoch"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Signature         string    `json:"signature,omitempty"`
}

// Revocation 是一条撤销事件。
type Revocation struct {
	Sequence int64     `json:"sequence"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Target   string    `json:"target"`
	Epoch    string    `json:"epoch"`
}

// Server 是中心服务。设备注册凭据（BootstrapToken）与管理员凭据（AdminToken）
// 相互独立：注册令牌只能注册设备，管理操作只认管理员令牌。
type Server struct {
	DB *sql.DB
	// AdminToken 用于策略写入与撤销。
	AdminToken string
	// BootstrapToken 只用于设备注册；为空或等于 AdminToken 时拒绝服务。
	BootstrapToken string
	Epoch          string
	SigningKey     []byte
	LeaseTTL       time.Duration
	Now            func() time.Time

	// store 便于测试注入内存实现；生产为空时使用 DB。
	store dataStore
}

// Options 是启动中心的参数。
type Options struct {
	DSN            string
	AdminToken     string
	BootstrapToken string
	LeaseTTL       time.Duration
}

// ValidateCredentials 校验两类凭据都已配置且互不相同。
// 未配置时拒绝启动，避免「未配置就放行」，也避免注册凭据等于管理员凭据。
func ValidateCredentials(adminToken, bootstrapToken string) error {
	if adminToken == "" {
		return fmt.Errorf("administrator token is required")
	}
	if bootstrapToken == "" {
		return fmt.Errorf("device bootstrap token is required; device registration must not reuse the administrator credential")
	}
	if hmac.Equal([]byte(adminToken), []byte(bootstrapToken)) {
		return fmt.Errorf("device bootstrap token must differ from the administrator token")
	}
	return nil
}

// Open 连接 PostgreSQL 并迁移，启动时轮换授权代次。为保持旧调用可用，
// 它等价于 OpenWithOptions，只是不提供设备注册凭据；此时会因缺少注册凭据而
// 拒绝启动。
func Open(ctx context.Context, dsn, adminToken string, leaseTTL time.Duration) (*Server, error) {
	return OpenWithOptions(ctx, Options{DSN: dsn, AdminToken: adminToken, LeaseTTL: leaseTTL})
}

// OpenWithOptions 连接 PostgreSQL 并迁移，启动时轮换授权代次。
func OpenWithOptions(ctx context.Context, opts Options) (*Server, error) {
	if err := ValidateCredentials(opts.AdminToken, opts.BootstrapToken); err != nil {
		return nil, err
	}
	if opts.DSN == "" {
		return nil, fmt.Errorf("central database DSN is required")
	}
	db, err := sql.Open("pgx", opts.DSN)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect central database: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, migrations); err != nil {
		_ = db.Close()
		return nil, err
	}
	leaseTTL := opts.LeaseTTL
	if leaseTTL <= 0 {
		leaseTTL = 90 * time.Second
	}
	s := &Server{
		DB: db, AdminToken: opts.AdminToken, BootstrapToken: opts.BootstrapToken,
		LeaseTTL: leaseTTL, Now: func() time.Time { return time.Now().UTC() },
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	s.SigningKey = key
	// 每次启动生成新代次：备份恢复或重启后旧许可不能续期。
	s.Epoch = randomID()
	if _, err := db.ExecContext(ctx, `INSERT INTO central_meta(id, epoch, signing_key, created_at) VALUES(1,$1,$2,$3)
		ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch, signing_key=excluded.signing_key`, s.Epoch, key, s.Now()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Handler 返回中心 HTTP 路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/devices/register", s.handleRegister)
	mux.HandleFunc("/v1/leases", s.handleLease)
	mux.HandleFunc("/v1/check", s.handleCheck)
	mux.HandleFunc("/v1/events", s.handleEvents)
	mux.HandleFunc("/v1/admin/revoke", s.handleRevoke)
	mux.HandleFunc("/v1/admin/policy", s.handlePolicy)
	mux.HandleFunc("/v1/status", s.handleStatus)
	return mux
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": apiError{Code: code, Message: msg}})
}

// writeInternal 把数据访问层错误统一成 500，且不回显 SQL 细节。
func writeInternal(w http.ResponseWriter, msg string) {
	writeErr(w, http.StatusInternalServerError, "INTERNAL", msg)
}

// credentialsConfigured 检查两类凭据是否已配置且互不相同。
func (s *Server) credentialsConfigured() bool {
	return ValidateCredentials(s.AdminToken, s.BootstrapToken) == nil
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"service": "keykoi-central", "epoch": s.Epoch, "lease_ttl_seconds": int(s.LeaseTTL.Seconds())})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	data, err := s.data()
	if err != nil {
		writeInternal(w, "center storage is unavailable")
		return
	}
	if !s.credentialsConfigured() {
		writeErr(w, http.StatusServiceUnavailable, codeControlNone, "center credentials are not configured")
		return
	}
	// 注册只认设备注册凭据；管理员凭据不能注册设备。
	if !tokenEqual(r.Header.Get("X-Central-Bootstrap"), s.BootstrapToken) {
		writeErr(w, http.StatusUnauthorized, codeControlNone, "invalid bootstrap credential")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "device name is required")
		return
	}
	secret := randomToken()
	sum := sha256.Sum256([]byte(secret))
	deviceID := "device_" + randomID()
	if err := data.RegisterDevice(r.Context(), deviceID, body.Name, hex.EncodeToString(sum[:]), s.Now()); err != nil {
		writeInternal(w, "cannot register device")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"device_id": deviceID, "device_secret": secret, "epoch": s.Epoch})
}

// leaseRequestBody 是 /v1/leases 的请求体。主体、方式与凭证版本都是可选字段，
// 旧客户端只送 binding_id/mode/nonce 时仍可用。
type leaseRequestBody struct {
	BindingID         string `json:"binding_id"`
	PrincipalID       string `json:"principal_id,omitempty"`
	Mode              string `json:"mode"`
	CredentialID      string `json:"credential_id,omitempty"`
	CredentialVersion int    `json:"credential_version,omitempty"`
	Nonce             string `json:"nonce"`
}

// leaseSignaturePayload 是设备签名覆盖的内容。未携带主体与版本时保持旧格式，
// 携带时把它们一并签入，避免链路中被替换成其他主体或版本。
func leaseSignaturePayload(b leaseRequestBody) string {
	if b.PrincipalID == "" && b.CredentialID == "" && b.CredentialVersion == 0 {
		return fmt.Sprintf("%s|%s|%s", b.BindingID, b.Mode, b.Nonce)
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%d", b.BindingID, b.Mode, b.Nonce, b.PrincipalID, b.CredentialID, b.CredentialVersion)
}

func (s *Server) deviceFor(ctx context.Context, data dataStore, id, sig string, body []byte) error {
	secretHash, status, err := data.Device(ctx, id)
	if err != nil {
		return fmt.Errorf("unknown device")
	}
	if status != "active" {
		return fmt.Errorf("device is %s", status)
	}
	// 设备不发送明文秘密；双方都以 sha256(secret) 的十六进制串作为 HMAC 密钥。
	want := hmacSHA256([]byte(secretHash), body)
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return fmt.Errorf("device signature mismatch")
	}
	return nil
}

func (s *Server) handleLease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "BAD_REQUEST", "POST required")
		return
	}
	data, err := s.data()
	if err != nil {
		writeInternal(w, "center storage is unavailable")
		return
	}
	var body leaseRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "invalid body")
		return
	}
	if err := s.deviceFor(r.Context(), data, r.Header.Get("X-Device-ID"), r.Header.Get("X-Device-Signature"), []byte(leaseSignaturePayload(body))); err != nil {
		writeErr(w, http.StatusUnauthorized, "SESSION_INVALID", err.Error())
		return
	}
	policy, err := data.Policy(r.Context(), body.BindingID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "BINDING_DISABLED", "binding is not registered with the center")
		return
	}
	if policy.Status != "active" {
		writeErr(w, http.StatusForbidden, "BINDING_DISABLED", "binding is revoked at the center")
		return
	}
	// 策略带主体时只授权该主体；不带主体表示该绑定级策略未限定主体（旧策略），
	// 仍按绑定授权，但许可里记录调用方声明的实际主体，供 /v1/check 复核。
	if policy.PrincipalID != "" && body.PrincipalID != policy.PrincipalID {
		writeErr(w, http.StatusForbidden, "USE_NOT_ALLOWED", "principal is not permitted by the center policy")
		return
	}
	if body.PrincipalID == "" {
		body.PrincipalID = policy.PrincipalID
	}
	// 请求方式必须与中心策略一致；缺省时按策略方式签发，保持旧客户端可用。
	if body.Mode == "" {
		body.Mode = policy.Mode
	}
	if body.Mode != policy.Mode {
		writeErr(w, http.StatusForbidden, "USE_NOT_ALLOWED", "delivery mode is not permitted by the center policy")
		return
	}
	// 请求版本或凭证若与中心不一致，说明本机与中心的版本基准已分叉：
	// 返回 LEASE_STALE，客户端会重新申请。
	if body.CredentialVersion != 0 && body.CredentialVersion != policy.CredentialVersion {
		writeErr(w, http.StatusConflict, codeLeaseStale, "requested credential version differs from the center policy; request a new lease")
		return
	}
	if body.CredentialID != "" && body.CredentialID != policy.CredentialID {
		writeErr(w, http.StatusConflict, codeLeaseStale, "requested credential differs from the center policy; request a new lease")
		return
	}
	now := s.Now()
	lease := Lease{
		ID:                "lease_" + randomID(),
		DeviceID:          r.Header.Get("X-Device-ID"),
		BindingID:         body.BindingID,
		PrincipalID:       body.PrincipalID,
		CredentialID:      policy.CredentialID,
		CredentialVersion: policy.CredentialVersion,
		Mode:              body.Mode,
		Epoch:             s.Epoch,
		IssuedAt:          now,
		ExpiresAt:         now.Add(s.LeaseTTL),
	}
	lease.Signature = signLease(s.SigningKey, lease)
	if err := data.InsertLease(r.Context(), lease); err != nil {
		writeInternal(w, "cannot persist lease")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lease": lease, "epoch": s.Epoch, "credential_id": policy.CredentialID})
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	data, err := s.data()
	if err != nil {
		writeInternal(w, "center storage is unavailable")
		return
	}
	var body struct {
		LeaseID  string `json:"lease_id"`
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "invalid body")
		return
	}
	lease, err := data.Lease(r.Context(), body.LeaseID, body.DeviceID)
	if err != nil {
		writeErr(w, http.StatusForbidden, codeControlNone, "lease is unknown")
		return
	}
	// 代次变化（中心重启或授权代次轮换）只说明许可需要重签，不是撤销：
	// 用独立错误码告知客户端可以安全地重新申请。
	if lease.Epoch != s.Epoch {
		writeErr(w, http.StatusConflict, codeLeaseEpochStale, "lease belongs to an earlier authorization epoch; request a new lease")
		return
	}
	if lease.Status != "active" {
		writeErr(w, http.StatusForbidden, codeControlNone, "lease is revoked")
		return
	}
	if s.Now().After(lease.ExpiresAt) {
		writeErr(w, http.StatusForbidden, "LEASE_EXPIRED", "lease expired")
		return
	}
	policy, err := data.Policy(r.Context(), lease.BindingID)
	if err != nil {
		writeErr(w, http.StatusForbidden, codeControlNone, "binding is no longer registered with the center")
		return
	}
	if policy.CredentialVersion != lease.CredentialVersion {
		writeErr(w, http.StatusConflict, codeLeaseStale, "credential version changed; request a new lease")
		return
	}
	// 方式变化、或策略限定了主体但许可的主体不同，都不是可安全重签的版本漂移。
	if policy.Mode != lease.Mode || (policy.PrincipalID != "" && policy.PrincipalID != lease.PrincipalID) {
		writeErr(w, http.StatusForbidden, codeControlNone, "lease principal or mode no longer matches the center policy")
		return
	}
	if policy.Status != "active" {
		writeErr(w, http.StatusForbidden, codeControlNone, "binding is revoked at the center")
		return
	}
	devStatus, err := data.DeviceStatus(r.Context(), body.DeviceID)
	if err != nil || devStatus != "active" {
		writeErr(w, http.StatusForbidden, codeControlNone, "device was revoked")
		return
	}
	bindingStatus, err := data.BindingStatus(r.Context(), lease.BindingID)
	if err != nil || bindingStatus != "active" {
		writeErr(w, http.StatusForbidden, codeControlNone, "binding was revoked")
		return
	}
	revocations, err := data.CountRevocations(r.Context(), s.Epoch, body.DeviceID, lease.BindingID)
	if err != nil {
		writeErr(w, http.StatusForbidden, codeControlNone, "revocation state is unavailable")
		return
	}
	if revocations > 0 {
		writeErr(w, http.StatusForbidden, codeControlNone, "revocation event applies to this device or binding")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": true, "epoch": s.Epoch, "expires_at": lease.ExpiresAt,
		"principal_id": lease.PrincipalID, "binding_id": lease.BindingID,
		"credential_id": policy.CredentialID, "credential_version": lease.CredentialVersion, "mode": lease.Mode,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	data, err := s.data()
	if err != nil {
		writeInternal(w, "center storage is unavailable")
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	events, err := data.Events(r.Context(), since)
	if err != nil {
		writeInternal(w, "cannot read events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "epoch": s.Epoch})
}

// requireAdmin 校验管理凭据；未配置或不是管理员令牌时拒绝。
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !s.credentialsConfigured() {
		writeErr(w, http.StatusServiceUnavailable, codeControlNone, "center credentials are not configured")
		return false
	}
	// 管理操作只认管理员凭据；设备注册凭据没有管理权限。
	if !tokenEqual(r.Header.Get("X-Central-Admin"), s.AdminToken) {
		writeErr(w, http.StatusUnauthorized, codeControlNone, "administrator credential required")
		return false
	}
	return true
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	data, dataErr := s.data()
	if dataErr != nil {
		writeInternal(w, "center storage is unavailable")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var body struct {
		Kind   string `json:"kind"`
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Target == "" {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "kind and target are required")
		return
	}
	switch body.Kind {
	case "device":
		if err := data.RevokeDevice(r.Context(), body.Target, s.Now(), s.Epoch); err != nil {
			writeInternal(w, "cannot revoke device")
			return
		}
	case "binding":
		if err := data.RevokeBinding(r.Context(), body.Target, s.Now(), s.Epoch); err != nil {
			writeInternal(w, "cannot revoke binding")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "unsupported revocation kind")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": body.Target, "kind": body.Kind, "epoch": s.Epoch})
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	data, dataErr := s.data()
	if dataErr != nil {
		writeInternal(w, "center storage is unavailable")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var body struct {
		BindingID         string `json:"binding_id"`
		PrincipalID       string `json:"principal_id"`
		CredentialID      string `json:"credential_id"`
		CredentialVersion int    `json:"credential_version"`
		Mode              string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.BindingID == "" || body.CredentialID == "" {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "binding_id and credential_id are required")
		return
	}
	if body.Mode == "" {
		body.Mode = "proxy"
	}
	// 省略 principal_id 生成绑定级策略（不限主体）；给出时只授权该主体。
	policy := policyRecord{PrincipalID: body.PrincipalID, CredentialID: body.CredentialID, CredentialVersion: body.CredentialVersion, Mode: body.Mode, Status: "active"}
	if err := data.UpsertPolicy(r.Context(), body.BindingID, policy); err != nil {
		writeInternal(w, "cannot store policy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"binding_id": body.BindingID, "status": "active"})
}

func signLease(key []byte, l Lease) string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%d|%s|%s|%s|%s", l.ID, l.DeviceID, l.BindingID, l.CredentialID, l.CredentialVersion, l.Mode, l.Epoch, l.PrincipalID, l.ExpiresAt.UTC().Format(time.RFC3339Nano))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func hmacSHA256(key, msg []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

func randomID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func tokenEqual(a, b string) bool {
	if len(a) != len(b) || a == "" {
		return false
	}
	return hmac.Equal([]byte(a), []byte(b))
}

// SignRequest 计算设备请求签名，供客户端复用。
func SignRequest(secretHash, bindingID, mode, nonce string) string {
	return hmacSHA256([]byte(secretHash), []byte(fmt.Sprintf("%s|%s|%s", bindingID, mode, nonce)))
}
