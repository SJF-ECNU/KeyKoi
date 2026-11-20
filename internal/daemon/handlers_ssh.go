package daemon

import (
	"fmt"
	"net/http"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/ssha"
	"keykoi/internal/store"
)

// sshKeyView 是交给 SSH agent 的托管密钥元数据。
// 公钥不是秘密；私钥永不离开中介，因此本结构没有私钥字段。
type sshKeyView struct {
	CredentialID string `json:"credential_id"`
	BindingID    string `json:"binding_id"`
	Label        string `json:"label"`
	Algorithm    string `json:"algorithm"`
	Fingerprint  string `json:"fingerprint"`
	PublicKey    string `json:"public_key"`
	ErrorCode    string `json:"error_code,omitempty"`
}

// handleSSHKeys 返回当前会话主体拥有 sign 许可的 ssh_key 凭证元数据。
//
// 会话令牌来自 POST body 的 token 字段、Authorization Bearer 或
// X-KeyKoi-Session 头；仅本机管理令牌可以代替会话，且仍按管理员主体评估。
// 响应只含 id、label、算法、公钥指纹与公钥行，绝不含私钥。
func (d *Daemon) handleSSHKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	sess, principal, err := d.sshKeyRequester(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	grants, err := d.store.ListGrants(r.Context(), principal)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	// 枚举权限必须与用钥权限同源：Broker 允许本机 Agent 继承本机账户的授权，
	// 这里也要一并枚举，否则「可以签名」的密钥不会出现在 agent 列表中。
	if sess != nil && sess.IdentityType == "local_agent" {
		if local := localPrincipalID(); local != "" && local != principal {
			if inherited, ierr := d.store.ListGrants(r.Context(), local); ierr == nil {
				grants = append(grants, inherited...)
			}
		}
	}
	keys := make([]sshKeyView, 0, len(grants))
	seen := map[string]bool{}
	for _, g := range grants {
		if g.Status != model.StatusActive || g.DeliveryMode != model.ModeSign {
			continue
		}
		binding, err := d.store.GetBinding(r.Context(), g.BindingID)
		if err != nil || binding.Status != model.StatusActive {
			continue
		}
		if seen[binding.ID] {
			continue
		}
		cred, err := d.store.GetCredential(r.Context(), binding.CredentialID)
		if err != nil || cred.Status != model.StatusActive || cred.Kind != model.KindSSHKey {
			continue
		}
		seen[binding.ID] = true
		view := sshKeyView{CredentialID: cred.ID, BindingID: binding.ID, Label: cred.Label}
		// 指纹与算法必须由公钥推导；这里只在受信进程内解析一次并立即清除明文。
		version, err := d.backend.Materialize(r.Context(), cred.ID, cred.CurrentVersion)
		if err != nil {
			view.ErrorCode = sshKeyErrorCode(err)
			keys = append(keys, view)
			continue
		}
		info, err := sshKeyPublicInfo(version)
		if err != nil {
			view.ErrorCode = sshKeyErrorCode(err)
			keys = append(keys, view)
			continue
		}
		view.Algorithm = info.Algorithm
		view.Fingerprint = info.Fingerprint
		view.PublicKey = info.AuthorizedKey
		keys = append(keys, view)
	}
	if sess != nil {
		// 审计只记录枚举次数与主体，不记录密钥材料。
		d.broker.Record(r.Context(), store.AuditEvent{
			SessionID: sess.ID, PrincipalID: principal, Mode: "ssh-agent",
			Result: "enumerated", Detail: sshKeyCountDetail(len(keys)),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"principal_id": principal, "keys": keys})
}

// sshSignMaterialFields 是 SSH Agent 可取得的字段白名单。签名只需要私钥与可选口令，
// 其他字段（例如 access_secret 或会话令牌）不随响应离开后台。
var sshSignMaterialFields = []string{"private_key", "private_key_passphrase"}

// handleSSHSignMaterial 交付一次 SSH 签名材料。
//
// 它与通用解析接口分开：只有 sign 许可、ssh_key 类型凭证和字段白名单内的材料会返回，
// 因此「具备签名权限」不再等价于「可以取得整组原始凭证」。许可仍由 Broker 授权，
// 撤销、轮换与锁定在读值前后都会重新核对。
func (d *Daemon) handleSSHSignMaterial(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	var body struct {
		Token     string `json:"token"`
		BindingID string `json:"binding_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Token == "" || body.BindingID == "" {
		writeAPIError(w, model.NewError(model.CodeSessionInvalid, "token and binding_id are required"))
		return
	}
	authz, err := d.broker.Authorize(r.Context(), broker.Request{
		Token:     secret.New(body.Token),
		BindingID: body.BindingID,
		Mode:      model.ModeSign,
		Purpose:   "ssh sign material",
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	// 材料只在本次响应中交付；请求结束后立即释放许可，成功路径同样不驻留。
	defer d.broker.ReleaseLease(authz.Lease.ID)
	cred, err := d.store.GetCredential(r.Context(), authz.Lease.CredentialID)
	if err != nil || cred.Kind != model.KindSSHKey {
		// 签名材料接口只服务 ssh_key；失败时撤销刚建立的许可。
		_ = d.broker.RevokeLease(r.Context(), authz.Lease.ID)
		writeAPIError(w, model.NewError(model.CodeCredentialUnavailable,
			"binding %s is not an ssh_key binding", body.BindingID))
		return
	}
	fields := map[string]string{}
	for _, name := range sshSignMaterialFields {
		value, ferr := authz.Version.Field(name)
		if ferr != nil || value.IsEmpty() {
			continue
		}
		fields[name] = value.RevealString()
	}
	if fields["private_key"] == "" {
		_ = d.broker.RevokeLease(r.Context(), authz.Lease.ID)
		writeAPIError(w, model.NewError(model.CodeCredentialUnavailable,
			"credential %s has no private_key field", cred.ID))
		return
	}
	// 签名材料只被消费一次：交付后立即释放许可。
	d.broker.ReleaseLease(authz.Lease.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"lease":               authz.Lease,
		"credential_id":       authz.Lease.CredentialID,
		"credential_version":  authz.Lease.CredentialVersion,
		"fields":              fields,
		"binding":             authz.Binding,
		"provider_expires_at": authz.Lease.ProviderCredentialExpiresAt,
	})
}

// sshKeyRequester 解析调用主体。会话令牌优先；没有令牌时接受本机管理令牌。
func (d *Daemon) sshKeyRequester(r *http.Request) (*model.Session, string, error) {
	token := ""
	if r.Method == http.MethodPost {
		var body struct {
			Token string `json:"token"`
		}
		// 空 body 是合法调用：此时退回请求头。
		if err := decodeJSON(r, &body); err == nil {
			token = body.Token
		}
	} else {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		token = bearerToken(r)
	}
	if token != "" {
		sess, err := d.broker.SessionByToken(secret.New(token))
		if err != nil {
			return nil, "", err
		}
		return &sess, sess.PrincipalID, nil
	}
	if tok := r.Header.Get("X-KeyKoi-Admin"); tok != "" && subtleEqual(tok, d.adminToken) {
		return nil, d.adminPrincipalID(), nil
	}
	return nil, "", model.NewError(model.CodeSessionInvalid,
		"ssh key enumeration requires a local session token")
}

// sshKeyPublicInfo 从凭证版本推导公钥元数据，并清除私钥副本。
func sshKeyPublicInfo(version model.CredentialVersion) (ssha.PublicKeyInfo, error) {
	pemValue, err := version.Field("private_key")
	if err != nil {
		return ssha.PublicKeyInfo{}, model.NewError(model.CodeCredentialUnavailable,
			"credential %s has no private_key field", version.CredentialID)
	}
	var passphrase []byte
	if passValue, err := version.Field("private_key_passphrase"); err == nil {
		passphrase = passValue.Reveal()
	}
	pemBytes := pemValue.Reveal()
	defer wipeBytes(pemBytes)
	defer wipeBytes(passphrase)
	return ssha.InspectPrivateKey(pemBytes, passphrase)
}

func sshKeyErrorCode(err error) string {
	if code := model.CodeOf(err); code != "" {
		return string(code)
	}
	return string(model.CodeCredentialUnavailable)
}

func sshKeyCountDetail(n int) string {
	return fmt.Sprintf("ssh-agent enumerated %d keys", n)
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
