// Package model 定义 KeyKoi 的四个核心对象、授权状态与稳定错误码。
//
// 四个核心对象回答同一个问题：这个已认证会话，能否通过此适配方式使用此组凭证，
// 并向这个登记目标完成认证？
//   - Credential：一组可原子更新的业务凭证。
//   - Binding：某组凭证对应的服务地址、认证方式和适配配置。
//   - Session：已通过中介认证的一次使用会话。
//   - UseLease：某会话在一段时间内经指定模式使用某个 Binding 的许可。
package model

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"keykoi/internal/secret"
)

// DeliveryMode 是凭证交付方式。它决定工具能否看到真实值。
type DeliveryMode string

const (
	// ModeProxy 由中介代为认证，原工具不接触业务凭证。
	ModeProxy DeliveryMode = "proxy"
	// ModeRuntimeDelivery 由受信组件把真实值交给原工具进程。
	ModeRuntimeDelivery DeliveryMode = "runtime_delivery"
	// ModeSign 由中介用托管密钥在注册协议内签名。
	ModeSign DeliveryMode = "sign"
)

// Valid 报告交付方式是否为已定义模式。
func (m DeliveryMode) Valid() bool {
	switch m {
	case ModeProxy, ModeRuntimeDelivery, ModeSign:
		return true
	}
	return false
}

// SupportStatus 记录支持模式与验证状态，二者分开记录。
type SupportStatus string

const (
	SupportPlanned      SupportStatus = "planned"
	SupportExperimental SupportStatus = "experimental"
	SupportVerified     SupportStatus = "verified"
)

// Valid 报告支持状态取值是否合法。
func (s SupportStatus) Valid() bool {
	switch s {
	case SupportPlanned, SupportExperimental, SupportVerified:
		return true
	}
	return false
}

// EntityStatus 是凭证、绑定、授权与接入的通用状态。
type EntityStatus string

const (
	StatusActive     EntityStatus = "active"
	StatusDisabled   EntityStatus = "disabled"
	StatusRevoked    EntityStatus = "revoked"
	StatusLocked     EntityStatus = "locked"
	StatusPending    EntityStatus = "pending_review"
	StatusRecovery   EntityStatus = "recovery_required"
	StatusUnverified EntityStatus = "unverified"
)

// CredentialKind 是一组业务凭证的类型。
type CredentialKind string

const (
	KindAPIKey        CredentialKind = "api_key"
	KindAccessKeyPair CredentialKind = "access_key_pair"
	KindOAuth         CredentialKind = "oauth"
	KindSSHKey        CredentialKind = "ssh_key"
	KindDatabase      CredentialKind = "database"
	KindClientCert    CredentialKind = "client_cert"
)

// Field describes one credential field without its value.
type Field struct {
	Name      string `json:"name"`
	Sensitive bool   `json:"sensitive"`
}

// FieldSpecs lists the field names expected by each credential kind.
// 只描述字段，不返回值。
func FieldSpecs(kind CredentialKind) []Field {
	switch kind {
	case KindAPIKey:
		return []Field{{"token", true}}
	case KindAccessKeyPair:
		return []Field{{"access_id", true}, {"access_secret", true}, {"session_token", true}}
	case KindOAuth:
		return []Field{{"access_token", true}, {"refresh_token", true}, {"client_id", false}, {"client_secret", true}, {"token_endpoint", false}}
	case KindSSHKey:
		return []Field{{"private_key", true}, {"private_key_passphrase", true}, {"public_key", false}}
	case KindDatabase:
		return []Field{{"username", false}, {"password", true}, {"database", false}}
	case KindClientCert:
		return []Field{{"certificate_chain", false}, {"private_key", true}}
	}
	return nil
}

// Credential 是凭证索引。它不含秘密。CurrentVersion 指向唯一权威版本。
type Credential struct {
	ID             string         `json:"id"`
	Kind           CredentialKind `json:"kind"`
	Label          string         `json:"label"`
	CurrentVersion int            `json:"current_version"`
	Status         EntityStatus   `json:"status"`
	Revision       int64          `json:"revision"`
	// ProviderExpiresAt 记录当前版本在原平台的真实到期时间；静态 key 为 nil。
	ProviderExpiresAt *time.Time `json:"provider_credential_expires_at,omitempty"`
}

// CredentialVersion 是一个完整凭证组合。Fields 的值是秘密，只存在于可信内存。
type CredentialVersion struct {
	CredentialID string
	Version      int
	Fields       map[string]secret.Value
	// ProviderExpiresAt 是原平台凭证自身的到期时间，不是中介许可期限。
	ProviderExpiresAt *time.Time
}

// Clone 复制字段映射（只复制引用，秘密值本身不可变）。
func (v CredentialVersion) Clone() CredentialVersion {
	out := CredentialVersion{CredentialID: v.CredentialID, Version: v.Version, ProviderExpiresAt: v.ProviderExpiresAt}
	out.Fields = make(map[string]secret.Value, len(v.Fields))
	for k, val := range v.Fields {
		out.Fields[k] = val
	}
	return out
}

// Field 返回字段秘密值；缺失返回错误，不返回空串冒充成功。
func (v CredentialVersion) Field(name string) (secret.Value, error) {
	val, ok := v.Fields[name]
	if !ok {
		return secret.Value{}, fmt.Errorf("credential %s version %d: field %q missing", v.CredentialID, v.Version, name)
	}
	return val, nil
}

// AuthScheme 是首版支持的 Header 注入方式。
type AuthScheme string

const (
	AuthBearer AuthScheme = "bearer"
	AuthAPIKey AuthScheme = "api_key"
	AuthBasic  AuthScheme = "basic"
	// AuthOAuthClientCredentials 用 client_credentials 流程换取 access token 后注入 Bearer。
	AuthOAuthClientCredentials AuthScheme = "oauth_client_credentials"
	// AuthOAuthJWTBearer 用服务账号私钥签 JWT 断言，走 jwt-bearer 流程换取 access token。
	AuthOAuthJWTBearer AuthScheme = "oauth_jwt_bearer"
)

// Valid 报告认证方式是否在首版支持范围。
func (a AuthScheme) Valid() bool {
	switch a {
	case AuthBearer, AuthAPIKey, AuthBasic, AuthOAuthClientCredentials, AuthOAuthJWTBearer:
		return true
	}
	return false
}

// Binding 将凭证绑定到认证目标与方式。登记 origin 由受信存储给出，调用者不可覆盖。
type Binding struct {
	ID           string `json:"id"`
	CredentialID string `json:"credential_id"`
	// UpstreamOrigin 固定 scheme://host:port，不含路径。
	UpstreamOrigin string `json:"upstream_origin"`
	// AllowedPaths 是允许转发的路径前缀；空前缀表示全部路径。
	AllowedPaths []string   `json:"allowed_paths,omitempty"`
	AuthScheme   AuthScheme `json:"auth_scheme"`
	// AuthHeader 是注入头名称；bearer 固定 Authorization，api_key 默认 X-Api-Key。
	AuthHeader string `json:"auth_header,omitempty"`
	// TokenField / UsernameField / PasswordField 指定取哪个凭证字段。
	TokenField    string       `json:"token_field,omitempty"`
	UsernameField string       `json:"username_field,omitempty"`
	PasswordField string       `json:"password_field,omitempty"`
	AdapterID     string       `json:"adapter_id,omitempty"`
	Route         string       `json:"route,omitempty"`
	Status        EntityStatus `json:"status"`
	Revision      int64        `json:"revision"`
}

// Origin 解析登记的 upstream origin。
func (b Binding) Origin() (*url.URL, error) {
	u, err := url.Parse(b.UpstreamOrigin)
	if err != nil {
		return nil, fmt.Errorf("binding %s: invalid upstream origin: %w", b.ID, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("binding %s: unsupported upstream scheme %q", b.ID, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("binding %s: upstream origin has no host", b.ID)
	}
	return u, nil
}

// NormalizePath 把路径规范化为比较用的形式：合并重复斜杠，消解 "." 与 ".." 段，
// 并保留结尾斜杠语义。百分号编码本身保持不变；非法百分号编码或含 NUL 的路径返回错误。
// 网关与 Binding 必须用同一函数判定范围，否则会规范化路径的上游会把请求带出登记前缀。
func NormalizePath(requestPath string) (string, error) {
	if requestPath == "" {
		return "/", nil
	}
	if strings.ContainsRune(requestPath, 0) {
		return "", fmt.Errorf("path contains a NUL byte")
	}
	if _, err := url.PathUnescape(requestPath); err != nil {
		return "", fmt.Errorf("path has an invalid percent-escape: %w", err)
	}
	return normalizeRawPath(requestPath), nil
}

// DecodedPath 返回“先解码百分号编码再规范化”的路径。会先解码再解析路径的上游
// （例如把 %2e%2e 当 dot segment 的服务器）看到的正是这个形式，因此判定范围时
// 两种解释都必须落在登记前缀内。
func DecodedPath(requestPath string) (string, error) {
	decoded, err := url.PathUnescape(requestPath)
	if err != nil {
		return "", fmt.Errorf("path has an invalid percent-escape: %w", err)
	}
	return normalizeRawPath(decoded), nil
}

// normalizeRawPath 只做路径结构规范化，不再校验百分号编码，因此可以重复调用。
func normalizeRawPath(p string) string {
	if p == "" {
		return "/"
	}
	trailing := strings.HasSuffix(p, "/") && p != "/"
	clean := path.Clean(p)
	if !strings.HasPrefix(clean, "/") {
		// 相对于根的路径补上前导斜杠后再清理，避免把 "../x" 当成普通文件段。
		clean = path.Clean("/" + clean)
	}
	if trailing && clean != "/" {
		clean += "/"
	}
	return clean
}

// PathAllowed 报告请求路径是否落在登记路径前缀内。
//
// 判定在规范化形式上进行：字面形式与“先解码再解析”两种解释都必须落在规范化后的
// 前缀内，因此 ".."、"//"、"%2e%2e/"、"..%2f" 之类无法逃出前缀。空前缀表示全部
// 路径；无法规范化的路径一律判为越界。
func (b Binding) PathAllowed(requestPath string) bool {
	if len(b.AllowedPaths) == 0 {
		return true
	}
	literal, err := NormalizePath(requestPath)
	if err != nil {
		return false
	}
	decoded, err := DecodedPath(requestPath)
	if err != nil {
		return false
	}
	for _, prefix := range b.AllowedPaths {
		wantLiteral, err := NormalizePath(prefix)
		if err != nil {
			continue
		}
		wantDecoded, err := DecodedPath(prefix)
		if err != nil {
			continue
		}
		if strings.HasPrefix(literal, wantLiteral) && strings.HasPrefix(decoded, wantDecoded) {
			return true
		}
	}
	return false
}

// Session 绑定已认证主体与到期时间。中介令牌只以哈希形式保存。
type Session struct {
	ID              string    `json:"id"`
	PrincipalID     string    `json:"principal_id"`
	IdentityType    string    `json:"identity_type"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	// AuthorizationEpoch 是授权代次；恢复或重新初始化会更换，使旧状态无法续期。
	AuthorizationEpoch string       `json:"authorization_epoch"`
	Status             EntityStatus `json:"status"`
	// TokenHash 只保存中介令牌的哈希，不保存令牌本身。
	TokenHash string `json:"-"`
}

// Grant 是主体对某个 Binding 的使用许可。
type Grant struct {
	ID           string       `json:"id"`
	PrincipalID  string       `json:"principal_id"`
	BindingID    string       `json:"binding_id"`
	DeliveryMode DeliveryMode `json:"delivery_mode"`
	// MaxLeaseDuration 是该许可允许的最长中介使用期限。
	MaxLeaseDuration time.Duration `json:"max_lease_duration"`
	// AuthRequirement 是该许可的额外验证策略：once（默认）/window:<秒>/per_use/permanent。
	// 它描述「用钥前是否再验一次人」，与 DeliveryMode 相互独立。
	AuthRequirement string       `json:"auth_requirement"`
	Status          EntityStatus `json:"status"`
	Revision        int64        `json:"revision"`
}

// UseLease 是某个会话经指定模式使用某个 Binding 的许可。
// 三种期限分别保存，避免混用。
type UseLease struct {
	ID                          string       `json:"id"`
	SessionID                   string       `json:"session_id"`
	AuthorizationEpoch          string       `json:"authorization_epoch"`
	BindingID                   string       `json:"binding_id"`
	CredentialID                string       `json:"credential_id"`
	CredentialVersion           int          `json:"credential_version"`
	GrantRevision               int64        `json:"grant_revision"`
	BindingRevision             int64        `json:"binding_revision"`
	DeliveryMode                DeliveryMode `json:"delivery_mode"`
	UseLeaseExpiresAt           time.Time    `json:"use_lease_expires_at"`
	CacheExpiresAt              time.Time    `json:"cache_expires_at"`
	ProviderCredentialExpiresAt *time.Time   `json:"provider_credential_expires_at,omitempty"`
	Status                      EntityStatus `json:"status"`
}

// Expired 报告中介使用许可是否到期。
func (l UseLease) Expired(now time.Time) bool {
	return !now.Before(l.UseLeaseExpiresAt)
}

// ValidateDelivery 检查许可是否覆盖所需模式。proxy 许可不能升级为 runtime_delivery。
func ValidateDelivery(leaseMode, required DeliveryMode) error {
	if leaseMode == required {
		return nil
	}
	return &Error{
		Code:    CodeUseNotAllowed,
		Message: fmt.Sprintf("delivery mode %q is not authorized for this request (lease %q)", leaseMode, required),
	}
}

// ErrNotAuthorized 是授权相关错误的包装起点。
var ErrNotAuthorized = errors.New("not authorized")
