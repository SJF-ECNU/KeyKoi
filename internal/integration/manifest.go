// Package integration 实现适配声明、工具探测、脱敏预览、受管配置写入、
// 真实验证、漂移识别与撤销恢复。
package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"keykoi/internal/model"
)

// Manifest 是受信任的适配器声明。它不包含真实凭证，也不执行任意脚本。
type Manifest struct {
	SchemaVersion  int             `yaml:"schema_version"`
	ID             string          `yaml:"id"`
	AdapterVersion int             `yaml:"adapter_version"`
	Status         string          `yaml:"status"`
	Tool           ToolSpec        `yaml:"tool"`
	Credential     CredentialSpec  `yaml:"credential"`
	Integration    IntegrationSpec `yaml:"integration"`
	Lifecycle      LifecycleSpec   `yaml:"lifecycle"`
}

// ToolSpec 描述原工具定位与已验证版本。
type ToolSpec struct {
	ExecutableRef    string   `yaml:"executable_ref"`
	Executable       string   `yaml:"executable"`
	SupportedOS      []string `yaml:"supported_os"`
	VerifiedVersions []string `yaml:"verified_versions"`
}

// CredentialSpec 描述绑定与交付模式。
type CredentialSpec struct {
	BindingRef   string `yaml:"binding_ref"`
	DeliveryMode string `yaml:"delivery_mode"`
}

// IntegrationSpec 描述配置写入方式。首版支持 helper_config 与 env_launcher。
type IntegrationSpec struct {
	Mechanism        string            `yaml:"mechanism"`
	ConfigPath       string            `yaml:"config_path"`
	Section          string            `yaml:"section"`
	ManagedKey       string            `yaml:"managed_key"`
	HelperExecutable string            `yaml:"helper_executable"`
	HelperArgs       []string          `yaml:"helper_args"`
	Env              map[string]string `yaml:"env"`
	VerifyArgs       []string          `yaml:"verify_args"`
	VerifySuccess    string            `yaml:"verify_success_contains"`
}

// LifecycleSpec 声明是否允许明文磁盘降级与持久令牌。
type LifecycleSpec struct {
	PlaintextDiskFallback bool `yaml:"plaintext_disk_fallback"`
	PersistSessionToken   bool `yaml:"persist_session_token"`
}

// LoadManifest 严格解析单个声明文件：未知字段视为错误。
func LoadManifest(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", filepath.Base(path), err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// LoadCatalog 读取目录内全部 *.yaml 声明。
func LoadCatalog(dir string) (map[string]*Manifest, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]*Manifest{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		m, err := LoadManifest(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[m.ID] = m
	}
	return out, nil
}

func (m *Manifest) validate() error {
	if m.SchemaVersion != 1 {
		return fmt.Errorf("unsupported manifest schema_version %d", m.SchemaVersion)
	}
	if m.ID == "" || m.Tool.Executable == "" {
		return fmt.Errorf("manifest id and tool.executable are required")
	}
	if !filepath.IsAbs(m.Tool.Executable) {
		return fmt.Errorf("tool.executable must be an absolute path")
	}
	switch m.Integration.Mechanism {
	case "helper_config":
		if m.Integration.ConfigPath == "" || m.Integration.Section == "" || m.Integration.ManagedKey == "" {
			return fmt.Errorf("helper_config requires config_path, section and managed_key")
		}
	case "env_launcher":
		if len(m.Integration.Env) == 0 {
			return fmt.Errorf("env_launcher requires env mappings")
		}
	default:
		return fmt.Errorf("unsupported integration mechanism %q", m.Integration.Mechanism)
	}
	switch m.Credential.DeliveryMode {
	case string(model.ModeRuntimeDelivery), string(model.ModeProxy):
	default:
		return fmt.Errorf("unsupported delivery_mode %q", m.Credential.DeliveryMode)
	}
	if m.Lifecycle.PlaintextDiskFallback {
		return fmt.Errorf("plaintext disk fallback is not permitted by this build")
	}
	return nil
}

// ExpandPath 把 ~ 展开到给定 HOME。
func ExpandPath(path, home string) string {
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	if path == "~" {
		return home
	}
	return path
}
