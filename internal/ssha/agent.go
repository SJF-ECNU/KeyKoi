package ssha

import (
	"bytes"
	"context"
	"io"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"keykoi/internal/model"
)

// Agent 实现 agent.ExtendedAgent。
//
// 语义：
//   - 枚举只返回当前会话持有 sign 许可、且属于本 agent 登记的 Binding 的托管密钥；
//   - 每次签名都重新向中介申请材料，许可被撤销后立即拒绝；
//   - 不支持 Add/Lock 等本地写入动作，钥匙管理走 keykoi 管理面。
type Agent struct {
	provider Provider
	// bindingID 非空时只服务这一个 Binding；这是 CLI 的最小权限边界。
	bindingID string
}

var _ agent.ExtendedAgent = (*Agent)(nil)

// NewAgent 构造 agent。bindingID 为空表示服务该会话可获得 sign 许可的全部密钥。
func NewAgent(p Provider, bindingID string) *Agent {
	return &Agent{provider: p, bindingID: bindingID}
}

// List 返回可枚举的托管公钥。任何条目解析失败都跳过，不输出错误材料。
func (a *Agent) List() ([]*agent.Key, error) {
	infos, err := a.keys(context.Background())
	if err != nil {
		return nil, err
	}
	keys := make([]*agent.Key, 0, len(infos))
	for _, info := range infos {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(info.PublicKey))
		if err != nil {
			continue
		}
		comment := info.Label
		if comment == "" {
			comment = info.Fingerprint
		}
		keys = append(keys, &agent.Key{Format: pub.Type(), Blob: pub.Marshal(), Comment: comment})
	}
	return keys, nil
}

// Sign 按默认算法签名。
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags 先校验密钥归属，再向中介申请一次材料并签名。
func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	info, err := a.lookup(key)
	if err != nil {
		return nil, err
	}
	mat, err := a.provider.ResolveMaterial(context.Background(), info.BindingID)
	if err != nil {
		if mat != nil {
			mat.Wipe()
		}
		return nil, err
	}
	return Sign(mat, data, flags, nil)
}

// Signers 返回惰性签名器：签名时仍然走一次中介授权，不缓存私钥。
func (a *Agent) Signers() ([]ssh.Signer, error) {
	infos, err := a.keys(context.Background())
	if err != nil {
		return nil, err
	}
	signers := make([]ssh.Signer, 0, len(infos))
	for _, info := range infos {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(info.PublicKey))
		if err != nil {
			continue
		}
		signers = append(signers, &lazySigner{agent: a, pub: pub})
	}
	return signers, nil
}

// Add 拒绝本地写入：管理动作只能通过 keykoi 管理接口完成。
func (a *Agent) Add(agent.AddedKey) error { return readOnly("add") }

// Remove 拒绝本地删除。
func (a *Agent) Remove(ssh.PublicKey) error { return readOnly("remove") }

// RemoveAll 拒绝本地清空。
func (a *Agent) RemoveAll() error { return readOnly("remove_all") }

// Lock 拒绝本地锁定；密钥库锁定走 keykoi lock。
func (a *Agent) Lock([]byte) error { return readOnly("lock") }

// Unlock 拒绝本地解锁。
func (a *Agent) Unlock([]byte) error { return readOnly("unlock") }

// Extension 不支持厂商扩展。
func (a *Agent) Extension(string, []byte) ([]byte, error) { return nil, agent.ErrExtensionUnsupported }

// keys 返回属于本 agent 且具备公钥材料的条目。
func (a *Agent) keys(ctx context.Context) ([]KeyInfo, error) {
	infos, err := a.provider.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]KeyInfo, 0, len(infos))
	for _, info := range infos {
		if a.bindingID != "" && info.BindingID != a.bindingID {
			continue
		}
		if info.PublicKey == "" {
			continue
		}
		out = append(out, info)
	}
	return out, nil
}

// lookup 找到请求公钥对应的托管条目；找不到即表示无 sign 许可。
func (a *Agent) lookup(key ssh.PublicKey) (KeyInfo, error) {
	if key == nil {
		return KeyInfo{}, model.NewError(model.CodeUseNotAllowed, "signature request carries no public key")
	}
	infos, err := a.keys(context.Background())
	if err != nil {
		return KeyInfo{}, err
	}
	blob := key.Marshal()
	for _, info := range infos {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(info.PublicKey))
		if err != nil {
			continue
		}
		if bytes.Equal(pub.Marshal(), blob) {
			return info, nil
		}
	}
	return KeyInfo{}, model.NewError(model.CodeUseNotAllowed,
		"no managed key with a sign grant matches this signature request")
}

func readOnly(op string) error {
	return model.NewError(model.CodeAdapterUnsupported,
		"managed ssh agent is read-only: %s is not supported; manage keys through keykoi", op)
}

// lazySigner 让 Go SSH 客户端复用 agent 的授权路径，自身不缓存私钥。
type lazySigner struct {
	agent *Agent
	pub   ssh.PublicKey
}

var _ ssh.AlgorithmSigner = (*lazySigner)(nil)

// PublicKey 返回托管公钥。
func (s *lazySigner) PublicKey() ssh.PublicKey { return s.pub }

// Sign 走一次中介授权后签名。
func (s *lazySigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.agent.Sign(s.pub, data)
}

// SignWithAlgorithm 把算法名映射为 agent 签名标志。
func (s *lazySigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if algorithm == "" || algorithm == s.pub.Type() {
		return s.agent.Sign(s.pub, data)
	}
	var flags agent.SignatureFlags
	switch algorithm {
	case ssh.KeyAlgoRSASHA256:
		flags = agent.SignatureFlagRsaSha256
	case ssh.KeyAlgoRSASHA512:
		flags = agent.SignatureFlagRsaSha512
	default:
		return nil, model.NewError(model.CodeAdapterUnsupported, "signature algorithm %q is not supported", algorithm)
	}
	return s.agent.SignWithFlags(s.pub, data, flags)
}
