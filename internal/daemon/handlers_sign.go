package daemon

import (
	"errors"
	"net/http"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/secret"
	"keykoi/internal/signer"
)

// signatureRequestBody 是 POST /v1/signatures 的请求体。
//
// 协议由 Binding.AdapterID 决定：aws-sigv4/<region>/<service>、
// tencent-tc3/<region>/<service>、huawei-aksk/<region>/<service>。
// protocol 字段可以省略（默认取登记值）；给出时必须与登记协议一致。
// 请求体里的 token 是中继会话令牌，不作为响应回显。
type signatureRequestBody struct {
	Token         string            `json:"token"`
	BindingID     string            `json:"binding_id"`
	Protocol      string            `json:"protocol"`
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	Headers       map[string]string `json:"headers"`
	PayloadSHA256 string            `json:"payload_sha256"`
	Region        string            `json:"region"`
	Service       string            `json:"service"`
	// Action 是腾讯云 API 3.0 的接口名（X-TC-Action）；其他协议忽略。
	Action string `json:"action"`
}

// handleSignatures 用托管凭证在登记的 sign 许可内生成协议签名头。
//
// 流程：校验协议 → Authorize(ModeSign) → 校验凭证类型与同版本字段 →
// 用 Binding 登记的 adapter/target 构造签名器配置 → 按登记协议生成签名头。
// 任何一步失败都不返回签名材料，并撤销刚创建的许可；响应不含 access_secret 或会话令牌。
func (d *Daemon) handleSignatures(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	var body signatureRequestBody
	if err := decodeJSON(r, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Token == "" {
		writeAPIError(w, model.NewError(model.CodeSessionInvalid, "token is required"))
		return
	}
	if body.BindingID == "" || body.Method == "" || body.URL == "" || body.PayloadSHA256 == "" {
		writeAPIError(w, model.NewError("", "binding_id, method, url and payload_sha256 are required"))
		return
	}
	// 只有登记在案的协议名才进入授权流程，未知协议不创建许可。
	if body.Protocol != "" && !knownSignProtocol(body.Protocol) {
		writeAPIError(w, model.NewError(model.CodeAdapterUnsupported, "protocol %q is not registered", body.Protocol))
		return
	}

	authz, err := d.broker.Authorize(r.Context(), broker.Request{
		Token:     secret.New(body.Token),
		BindingID: body.BindingID,
		Mode:      model.ModeSign,
		Purpose:   "protocol signature: " + protocolForPurpose(body.Protocol),
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	// 签名请求结束即释放短期许可，成功路径也不能驻留到下一次 Authorize。
	defer d.broker.ReleaseLease(authz.Lease.ID)
	// 一旦进入签名阶段，失败要撤销刚建立的许可，避免留下没有产出的用钥记录。
	fail := func(err error) {
		_ = d.broker.RevokeLease(r.Context(), authz.Lease.ID)
		writeSignerFailure(w, err)
	}
	if authz.Binding == nil {
		fail(model.NewError(model.CodeBindingDisabled, "binding metadata is unavailable"))
		return
	}

	credMeta, err := d.store.GetCredential(r.Context(), authz.Lease.CredentialID)
	if err != nil || credMeta.Kind != model.KindAccessKeyPair {
		fail(model.NewError(model.CodeCredentialUnavailable,
			"signing requires an access_key_pair credential"))
		return
	}
	adapter, err := signer.ParseAdapter(authz.Binding.AdapterID)
	if err != nil {
		fail(err)
		return
	}
	if body.Protocol != "" && body.Protocol != adapter.Protocol {
		fail(model.NewError(model.CodeAdapterUnsupported,
			"binding is registered for protocol %q, not %q", adapter.Protocol, body.Protocol))
		return
	}
	origin, err := authz.Binding.Origin()
	if err != nil {
		fail(err)
		return
	}
	credential, err := signingCredential(authz.Version)
	if err != nil {
		// 签名器错误交给 writeSignerFailure：字段不完整映射为 CREDENTIAL_UNAVAILABLE。
		fail(err)
		return
	}
	headers := http.Header{}
	for name, value := range body.Headers {
		headers.Add(name, value)
	}
	result, err := signer.SignProtocol(
		adapter,
		signer.Registration{
			Service:      adapter.Service,
			Region:       adapter.Region,
			Scheme:       origin.Scheme,
			Host:         origin.Host,
			PathPrefixes: authz.Binding.AllowedPaths,
		},
		credential,
		signer.Request{
			Method:        body.Method,
			URL:           body.URL,
			Headers:       headers,
			PayloadSHA256: body.PayloadSHA256,
			Region:        body.Region,
			Service:       body.Service,
			Action:        body.Action,
			Time:          time.Now().UTC(),
		},
	)
	if err != nil {
		fail(err)
		return
	}

	// 只返回签名头和许可元数据；不返回 access_secret，也不回显会话令牌。
	outHeaders := map[string]string{}
	for name, values := range result.Headers {
		if len(values) == 0 {
			continue
		}
		outHeaders[name] = values[0]
	}
	// 一次签名就是一次用钥：结果产出后释放许可，不把它留到会话关闭。
	d.broker.ReleaseLease(authz.Lease.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol":         adapter.Protocol,
		"headers":          outHeaders,
		"signed_headers":   result.SignedHeaders,
		"region":           result.Region,
		"service":          result.Service,
		"credential_scope": result.CredentialScope,
		"timestamp":        result.Timestamp,
		"lease":            authz.Lease,
	})
}

// knownSignProtocol 报告协议名是否在签名器支持范围。
func knownSignProtocol(protocol string) bool {
	switch protocol {
	case signer.ProtocolAWSSigV4, signer.ProtocolTencentTC3, signer.ProtocolHuaweiAKSK:
		return true
	}
	return false
}

// protocolForPurpose 在未显式给出协议时保留原来的审计说明。
func protocolForPurpose(protocol string) string {
	if protocol == "" {
		return signer.ProtocolAWSSigV4
	}
	return protocol
}

// signingCredential 取同一版本的完整 access_key_pair 字段。缺 access_id/access_secret
// 不补默认值；session_token 只在凭证本身使用临时会话时存在，静态 AccessKey 没有
// 该字段也允许签名，此时签出的 Authorization 不含 Security-Token。
func signingCredential(v model.CredentialVersion) (signer.Credential, error) {
	return signer.CredentialFromFields(func(name string) (string, bool) {
		value, err := v.Field(name)
		if err != nil {
			return "", false
		}
		return value.RevealString(), true
	})
}

// writeSignerFailure 把签名器错误映射为稳定 API 错误码。
func writeSignerFailure(w http.ResponseWriter, err error) {
	var se *signer.Error
	if errors.As(err, &se) {
		code := model.Code("")
		switch se.Code {
		case signer.CodeTargetMismatch:
			code = model.CodeUseNotAllowed
		case signer.CodeUnsupported, signer.CodeConfigUnsupported:
			code = model.CodeAdapterUnsupported
		case signer.CodeCredentialIncomplete:
			code = model.CodeCredentialUnavailable
		}
		if code == "" {
			writeAPIError(w, model.NewError("", "%s", se.Message))
			return
		}
		writeAPIError(w, model.NewError(code, "%s", se.Message))
		return
	}
	writeAPIError(w, err)
}
