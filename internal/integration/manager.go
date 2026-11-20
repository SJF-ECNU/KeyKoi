package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"keykoi/internal/model"
	"keykoi/internal/store"
)

// Manager 执行探测、预览、应用、验证、漂移识别与撤销。
type Manager struct {
	St          store.Store
	AdaptersDir string
	DataDir     string
	// KeyKoiBin 是写入配置的助手入口绝对路径。
	KeyKoiBin string
	// Home 是用于展开 ~ 的家目录，默认当前用户家目录。
	Home string
	Now  func() time.Time
	// Exec 便于测试注入命令执行。
	Exec func(ctx context.Context, cmd *exec.Cmd) ([]byte, error)
}

func (m *Manager) home() string {
	if m.Home != "" {
		return m.Home
	}
	h, _ := os.UserHomeDir()
	return h
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now().UTC()
}

func (m *Manager) exec(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
	if m.Exec != nil {
		return m.Exec(ctx, cmd)
	}
	return cmd.CombinedOutput()
}

// Manifest 按 ID 读取声明。
func (m *Manager) Manifest(id string) (*Manifest, error) {
	catalog, err := LoadCatalog(m.AdaptersDir)
	if err != nil {
		return nil, model.WrapError(model.CodeAdapterUnsupported, err, "cannot read adapter catalog")
	}
	mf, ok := catalog[id]
	if !ok {
		return nil, model.NewError(model.CodeAdapterUnsupported, "adapter %q is not registered", id)
	}
	return mf, nil
}

// Detection 是工具探测结果。
type Detection struct {
	ProfileID       string `json:"profile_id"`
	Executable      string `json:"executable"`
	ToolVersion     string `json:"tool_version"`
	OS              string `json:"os"`
	OSSupported     bool   `json:"os_supported"`
	VersionVerified bool   `json:"version_verified"`
	Note            string `json:"note,omitempty"`
}

// Detect 定位二进制并取得真实版本。
func (m *Manager) Detect(ctx context.Context, id string) (*Detection, error) {
	mf, err := m.Manifest(id)
	if err != nil {
		return nil, err
	}
	det := &Detection{ProfileID: mf.ID, Executable: mf.Tool.Executable, OS: runtime.GOOS}
	for _, osName := range mf.Tool.SupportedOS {
		if osName == runtime.GOOS || (osName == "macos" && runtime.GOOS == "darwin") {
			det.OSSupported = true
		}
	}
	info, err := os.Stat(mf.Tool.Executable)
	if err != nil {
		return nil, model.NewError(model.CodeAdapterUnsupported, "tool executable %s is not installed", mf.Tool.Executable)
	}
	if info.Mode()&0o111 == 0 {
		return nil, model.NewError(model.CodeAdapterUnsupported, "tool executable %s is not executable", mf.Tool.Executable)
	}
	out, _ := m.exec(ctx, exec.CommandContext(ctx, mf.Tool.Executable, "--version"))
	det.ToolVersion = firstVersionLine(string(out))
	for _, v := range mf.Tool.VerifiedVersions {
		if v != "" && strings.Contains(det.ToolVersion, v) {
			det.VersionVerified = true
			break
		}
	}
	if !det.OSSupported {
		det.Note = "current OS is outside the adapter's declared range"
	} else if !det.VersionVerified {
		det.Note = "tool version is outside the verified range; integration will stay unverified until validated"
	}
	return det, nil
}

func firstVersionLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return "unknown"
}

// Change 是一项受管配置变更。
type Change struct {
	Action    string `json:"action"` // add | update | keep
	Key       string `json:"key"`
	Value     string `json:"value"`
	Masked    bool   `json:"masked"`
	Sensitive bool   `json:"sensitive"`
}

// Capability 是一项运行能力检查。
type Capability struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Note string `json:"note,omitempty"`
}

// Plan 是接入预览：只含受管字段与非敏感差异。
type Plan struct {
	ProfileID    string       `json:"profile_id"`
	Mechanism    string       `json:"mechanism"`
	ConfigPath   string       `json:"config_path"`
	Section      string       `json:"section"`
	ManagedKey   string       `json:"managed_key"`
	BindingID    string       `json:"binding_id"`
	DeliveryMode string       `json:"delivery_mode"`
	Changes      []Change     `json:"changes"`
	Capabilities []Capability `json:"capabilities"`
	Preview      string       `json:"preview"`
	PlanHash     string       `json:"plan_hash"`
	Detection    *Detection   `json:"detection"`
}

// Plan 计算受管字段差异与运行能力。
func (m *Manager) Plan(ctx context.Context, id string) (*Plan, error) {
	mf, err := m.Manifest(id)
	if err != nil {
		return nil, err
	}
	det, err := m.Detect(ctx, id)
	if err != nil {
		return nil, err
	}
	binding, err := m.St.GetBinding(ctx, mf.Credential.BindingRef)
	if err != nil {
		return nil, model.NewError(model.CodeBindingDisabled, "binding %q referenced by the adapter is not registered", mf.Credential.BindingRef)
	}
	if binding.Status != model.StatusActive {
		return nil, model.NewError(model.CodeBindingDisabled, "binding %s is %s", binding.ID, binding.Status)
	}
	configPath := ExpandPath(mf.Integration.ConfigPath, m.home())
	plan := &Plan{
		ProfileID: mf.ID, Mechanism: mf.Integration.Mechanism, ConfigPath: configPath,
		Section: mf.Integration.Section, ManagedKey: mf.Integration.ManagedKey,
		BindingID: binding.ID, DeliveryMode: mf.Credential.DeliveryMode, Detection: det,
	}
	plan.Capabilities = []Capability{
		{Name: "tool installed", OK: true, Note: mf.Tool.Executable},
		{Name: "os supported", OK: det.OSSupported, Note: runtime.GOOS},
		{Name: "delivery mode registered", OK: mf.Credential.DeliveryMode == string(model.ModeRuntimeDelivery), Note: mf.Credential.DeliveryMode},
		{Name: "binding active", OK: true, Note: binding.ID + " -> " + binding.UpstreamOrigin},
	}
	switch mf.Integration.Mechanism {
	case "helper_config":
		doc, err := parseINI(configPath)
		if err != nil {
			return nil, err
		}
		current, exists := doc.value(mf.Integration.Section, mf.Integration.ManagedKey)
		value := m.helperCommand(mf)
		action := "add"
		if exists {
			if current == value {
				action = "keep"
			} else {
				action = "update"
			}
		}
		plan.Changes = append(plan.Changes, Change{Action: action, Key: mf.Integration.Section + "." + mf.Integration.ManagedKey, Value: value})
		plan.Preview = previewINI(mf.Integration.Section, mf.Integration.ManagedKey, value)
	case "env_launcher":
		names := make([]string, 0, len(mf.Integration.Env))
		for k := range mf.Integration.Env {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			plan.Changes = append(plan.Changes, Change{Action: "runtime", Key: name, Value: mf.Integration.Env[name], Masked: true, Sensitive: true})
		}
		plan.Preview = "运行器按声明注入以下环境变量（真实值只在运行时存在，不写入配置）：" + strings.Join(names, ", ")
	}
	plan.PlanHash = hashStrings(mf.ID, configPath, mf.Integration.Section, mf.Integration.ManagedKey, mf.Integration.Mechanism)
	return plan, nil
}

// helperCommand 返回写入配置的助手命令行。
// 可执行文件与参数按 shell 引用规则拼接：macOS 默认安装路径含空格时
// （例如 /Applications/Key Koi.app/...）也能被 credential_process 正确执行。
func (m *Manager) helperCommand(mf *Manifest) string {
	bin := m.KeyKoiBin
	if bin == "" {
		bin = "keykoi"
	}
	parts := append([]string{bin}, mf.Integration.HelperArgs...)
	return ShellQuoteCommand(parts...)
}

func previewINI(section, key, value string) string {
	return fmt.Sprintf("[%s]\n%s = %s\n# 其它字段保持不变；预览不含真实凭证。", section, key, value)
}

// Apply 只修改受管字段，写入前创建恢复备份。
func (m *Manager) Apply(ctx context.Context, id string) (*store.IntegrationRecord, error) {
	plan, err := m.Plan(ctx, id)
	if err != nil {
		return nil, err
	}
	mf, _ := m.Manifest(id)
	rec := &store.IntegrationRecord{
		ID: mf.ID, ProfileID: mf.ID, ToolVersion: plan.Detection.ToolVersion, OS: runtime.GOOS,
		Mechanism: plan.Mechanism, ConfigPath: plan.ConfigPath, Section: plan.Section,
		ManagedKey: plan.ManagedKey, State: "applied", Detail: "",
	}
	if plan.Mechanism == "env_launcher" {
		// 不写普通配置，只记录运行方式与验证状态。
		rec.State = "applied"
		rec.ManagedFingerprint = hashStrings(mf.ID, "env_launcher")
		if err := m.St.PutIntegration(ctx, rec); err != nil {
			return nil, err
		}
		return rec, nil
	}
	doc, err := parseINI(plan.ConfigPath)
	if err != nil {
		return nil, err
	}
	// 并发修改检查：以计划时的受管值为准。
	change := plan.Changes[0]
	current, exists := doc.value(plan.Section, plan.ManagedKey)
	if (change.Action == "keep" || change.Action == "update") && !exists {
		return nil, model.NewError(model.CodeConfigDrift, "managed field disappeared between plan and apply")
	}
	// 只保存本次受管字段的原始值，并加密写入恢复材料；不复制整份配置。
	// 重复 apply 时保留首次接入记下的原始值，避免用自己写入的值覆盖它。
	if change.Action != "keep" || !m.snapshotExists(rec.ID) {
		snap := fieldSnapshot{Section: plan.Section, Key: plan.ManagedKey, Value: current, Existed: exists}
		if err := m.writeSnapshot(rec, snap); err != nil {
			return nil, err
		}
	} else {
		rec.BackupPath = m.snapshotPath(rec.ID)
	}
	doc.setValue(plan.Section, plan.ManagedKey, change.Value)
	if err := writeFileAtomic(plan.ConfigPath, []byte(doc.String())); err != nil {
		return nil, err
	}
	rec.ManagedFingerprint = fingerprint(change.Value)
	if err := m.St.PutIntegration(ctx, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// Verify 通过实际运行路径执行一次真实认证，验证受管配置是否生效。
func (m *Manager) Verify(ctx context.Context, id string) (*store.IntegrationRecord, error) {
	mf, err := m.Manifest(id)
	if err != nil {
		return nil, err
	}
	det, derr := m.Detect(ctx, id)
	if derr != nil {
		return nil, derr
	}
	if !det.VersionVerified {
		// 工具版本超出已验证范围时保留待验证状态，不冒充 verified。
		rec, err := m.St.GetIntegration(ctx, id)
		if err == nil {
			rec.State = "unverified"
			rec.Detail = "tool version " + det.ToolVersion + " is outside the adapter's verified range"
			_ = m.St.PutIntegration(ctx, rec)
		}
		return nil, model.NewError(model.CodeAdapterUnsupported,
			"tool version %s is outside the adapter's verified range; integration stays unverified", det.ToolVersion)
	}
	rec, err := m.St.GetIntegration(ctx, id)
	if err != nil {
		return nil, model.NewError(model.CodeAdapterUnsupported, "integration %q has not been applied", id)
	}
	if rec.State == "detached" {
		return nil, model.NewError(model.CodeAdapterUnsupported, "integration %q is detached", id)
	}
	if mf.Integration.Mechanism == "helper_config" {
		doc, err := parseINI(rec.ConfigPath)
		if err != nil {
			return nil, err
		}
		current, ok := doc.value(rec.Section, rec.ManagedKey)
		if !ok || fingerprint(current) != rec.ManagedFingerprint {
			rec.State = "unverified"
			rec.Detail = "managed field changed outside KeyKoi"
			_ = m.St.PutIntegration(ctx, rec)
			return rec, model.NewError(model.CodeConfigDrift, "managed field in %s was modified outside KeyKoi", rec.ConfigPath)
		}
	}
	binding, err := m.St.GetBinding(ctx, mf.Credential.BindingRef)
	if err != nil {
		return nil, model.NewError(model.CodeBindingDisabled, "binding is not registered")
	}
	args := expandVerifyArgs(mf.Integration.VerifyArgs, binding)
	// 按适配器声明的实际运行路径执行：env_launcher 经 KeyKoi 运行器解析并注入
	// 凭证，helper_config 由配置里的 credential_process 回到 KeyKoi。
	cmd := m.verifyCommand(ctx, mf, rec, binding, args)
	startedAt := m.now()
	out, execErr := m.exec(ctx, cmd)
	if execErr != nil {
		rec.State = "recovery_required"
		rec.Detail = "verification failed: " + strings.TrimSpace(lastLine(string(out)))
		_ = m.St.PutIntegration(ctx, rec)
		return rec, model.NewError(model.CodeUpstreamAuthFailed, "tool verification failed for %s; integration marked recovery_required", id)
	}
	if mf.Integration.VerifySuccess != "" && !strings.Contains(string(out), mf.Integration.VerifySuccess) {
		rec.State = "recovery_required"
		rec.Detail = "verification response did not contain the expected marker"
		_ = m.St.PutIntegration(ctx, rec)
		return rec, model.NewError(model.CodeUpstreamAuthFailed, "tool verification response mismatch; integration marked recovery_required")
	}
	// 命令成功不等于走了 KeyKoi：必须看到本次请求对应的成功用钥记录，
	// 否则可能是主机已有凭证生效，不能标记为已验证。
	used, uerr := m.hasUseRecord(ctx, binding.ID, startedAt)
	if uerr != nil {
		rec.State = "recovery_required"
		rec.Detail = "verification could not confirm a key-use record: " + uerr.Error()
		_ = m.St.PutIntegration(ctx, rec)
		return rec, model.NewError(model.CodeControlUnavailable, "cannot confirm that verification used a KeyKoi-resolved credential: %v", uerr)
	}
	if !used {
		rec.State = "recovery_required"
		rec.Detail = "verification ran without a KeyKoi key-use record; the tool may have used ambient host credentials"
		_ = m.St.PutIntegration(ctx, rec)
		return rec, model.NewError(model.CodeControlUnavailable,
			"verification produced no key-use record for binding %s; check that the tool runs through KeyKoi", binding.ID)
	}
	rec.State = "verified"
	rec.VerifiedVersion = rec.ToolVersion
	rec.Detail = "verified against " + binding.UpstreamOrigin
	if err := m.St.PutIntegration(ctx, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// expandVerifyArgs 替换验证参数中的上游占位符。
func expandVerifyArgs(template []string, binding *model.Binding) []string {
	args := make([]string, 0, len(template))
	for _, a := range template {
		args = append(args, strings.ReplaceAll(a, "{{upstream}}", binding.UpstreamOrigin))
	}
	return args
}

// verifyCommand 构造验证命令，确保走适配器声明的实际运行路径。
func (m *Manager) verifyCommand(ctx context.Context, mf *Manifest, rec *store.IntegrationRecord, binding *model.Binding, args []string) *exec.Cmd {
	if mf.Integration.Mechanism == "env_launcher" {
		// 运行器负责经 KeyKoi 解析并注入凭证；这里只是用同一个入口执行工具。
		runArgs := runnerArgs(mf, binding.ID, args)
		cmd := exec.CommandContext(ctx, m.keykoiBin(), runArgs...)
		cmd.Env = append(sanitizedEnv(), "HOME="+m.home())
		return cmd
	}
	cmd := exec.CommandContext(ctx, mf.Tool.Executable, args...)
	cmd.Env = m.verifyEnv(rec)
	return cmd
}

// keykoiBin 返回运行器入口；未配置时回退到 PATH 上的 keykoi。
func (m *Manager) keykoiBin() string {
	if m.KeyKoiBin != "" {
		return m.KeyKoiBin
	}
	return "keykoi"
}

// runnerArgs 生成 `keykoi run` 的参数：声明里的环境映射原样交给运行器解析。
func runnerArgs(mf *Manifest, bindingID string, args []string) []string {
	out := []string{"run", "--binding", bindingID, "--mode", "runtime", "--exe", mf.Tool.Executable}
	names := make([]string, 0, len(mf.Integration.Env))
	for name := range mf.Integration.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, "--env", name+"="+mf.Integration.Env[name])
	}
	out = append(out, "--")
	return append(out, args...)
}

// credentialEnvNames 是验证时不得从主机继承的凭证来源变量。留下它们会让工具
// 直接用主机已有凭证通过验证，掩盖接入配置本身的问题。
var credentialEnvNames = map[string]bool{
	"AWS_ACCESS_KEY_ID":                      true,
	"AWS_SECRET_ACCESS_KEY":                  true,
	"AWS_SESSION_TOKEN":                      true,
	"AWS_SECURITY_TOKEN":                     true,
	"AWS_PROFILE":                            true,
	"AWS_DEFAULT_PROFILE":                    true,
	"AWS_ROLE_ARN":                           true,
	"AWS_ROLE_SESSION_NAME":                  true,
	"AWS_WEB_IDENTITY_TOKEN_FILE":            true,
	"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": true,
	"AWS_CONTAINER_CREDENTIALS_FULL_URI":     true,
	"AWS_CONTAINER_AUTHORIZATION_TOKEN":      true,
	"AWS_CONFIG_FILE":                        true,
	"AWS_SHARED_CREDENTIALS_FILE":            true,
	"AWS_EC2_METADATA_SERVICE_ENDPOINT":      true,
	"GOOGLE_APPLICATION_CREDENTIALS":         true,
	"AZURE_CLIENT_SECRET":                    true,
	"AZURE_CLIENT_ID":                        true,
	"AZURE_TENANT_ID":                        true,
}

// sanitizedEnv 返回去掉主机凭证来源后的环境变量。
func sanitizedEnv() []string {
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if credentialEnvNames[name] {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// verifyEnv 构造 helper_config 验证环境：只读本次写入的受管配置，并且不指向
// 主机已有的凭证文件，避免「用主机凭证验证通过」。
func (m *Manager) verifyEnv(rec *store.IntegrationRecord) []string {
	env := append(sanitizedEnv(), "HOME="+m.home(), "AWS_PAGER=", "AWS_EC2_METADATA_DISABLED=true")
	if rec.ConfigPath != "" {
		env = append(env, "AWS_CONFIG_FILE="+rec.ConfigPath)
	}
	env = append(env, "AWS_SHARED_CREDENTIALS_FILE="+m.emptyCredentialsPath(rec.ID))
	return env
}

// emptyCredentialsPath 返回一个不会存在的占位凭证文件路径；它不会被创建，
// 也不会覆盖用户的 ~/.aws/credentials。
func (m *Manager) emptyCredentialsPath(id string) string {
	if m.DataDir != "" {
		return filepath.Join(m.snapshotDir(), id+".credentials.none")
	}
	return filepath.Join(m.home(), ".keykoi", id+".credentials.none")
}

// hasUseRecord 核对本次验证期间是否产生了绑定的成功用钥记录。
func (m *Manager) hasUseRecord(ctx context.Context, bindingID string, since time.Time) (bool, error) {
	events, err := m.St.ListAudit(ctx, 200)
	if err != nil {
		return false, err
	}
	// 审计时间来自 Broker 时钟，留一点余量避免时钟抖动误判。
	cutoff := since.Add(-5 * time.Second)
	for _, e := range events {
		if e == nil || e.BindingID != bindingID {
			continue
		}
		if e.Result != "allowed" {
			continue
		}
		if e.Time.Before(cutoff) {
			continue
		}
		return true, nil
	}
	return false, nil
}

// Detach 撤销接入：只还原本次受管的字段，保留其他账号、其他 section 以及
// 接入前已存在的助手设置。
func (m *Manager) Detach(ctx context.Context, id string) (*store.IntegrationRecord, error) {
	rec, err := m.St.GetIntegration(ctx, id)
	if err != nil {
		return nil, model.NewError(model.CodeAdapterUnsupported, "integration %q is not attached", id)
	}
	if rec.Mechanism == "helper_config" {
		doc, err := parseINI(rec.ConfigPath)
		if err != nil {
			return nil, err
		}
		switch {
		case rec.BackupPath == "":
			// 没有恢复材料（例如历史记录或未启用数据目录）：只在当前值仍是
			// KeyKoi 写入的值时移除，用户后续编辑一律保留。
			if m.managedValueUnchanged(doc, rec) {
				doc.removeValue(rec.Section, rec.ManagedKey)
				if err := writeFileAtomic(rec.ConfigPath, []byte(doc.String())); err != nil {
					return nil, err
				}
			}
		default:
			snap, serr := m.readSnapshot(rec)
			if serr != nil {
				// 无法确定原始值就不要动配置。
				return nil, model.NewError(model.CodeConfigDrift,
					"recovery material for %s is unavailable (%v); managed field was left untouched", id, serr)
			}
			if snap.Existed {
				doc.setValue(snap.Section, snap.Key, snap.Value)
			} else {
				doc.removeValue(snap.Section, snap.Key)
			}
			if err := writeFileAtomic(rec.ConfigPath, []byte(doc.String())); err != nil {
				return nil, err
			}
			m.removeSnapshot(rec)
		}
	}
	rec.State = "detached"
	if err := m.St.PutIntegration(ctx, rec); err != nil {
		return nil, err
	}
	if err := m.St.DeleteIntegration(ctx, id); err != nil {
		return nil, err
	}
	return rec, nil
}

// managedValueUnchanged 判断配置中的受管字段是否仍是 KeyKoi 写入的值。
func (m *Manager) managedValueUnchanged(doc *iniDocument, rec *store.IntegrationRecord) bool {
	current, ok := doc.value(rec.Section, rec.ManagedKey)
	if !ok || rec.ManagedFingerprint == "" {
		return false
	}
	return fingerprint(current) == rec.ManagedFingerprint
}

// Drift 检查受管字段是否被外部修改。
func (m *Manager) Drift(ctx context.Context, id string) (bool, error) {
	rec, err := m.St.GetIntegration(ctx, id)
	if err != nil {
		return false, err
	}
	if rec.Mechanism != "helper_config" {
		return false, nil
	}
	doc, err := parseINI(rec.ConfigPath)
	if err != nil {
		return true, err
	}
	current, ok := doc.Value(rec.Section, rec.ManagedKey)
	if !ok {
		return true, nil
	}
	return fingerprint(current) != rec.ManagedFingerprint, nil
}

// Value 是 Section 值读取的导出包装。
func (d *iniDocument) Value(section, key string) (string, bool) { return d.value(section, key) }

func fingerprint(v string) string { return hashStrings(v)[:32] }

func hashStrings(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".keykoi-config-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

var _ = errors.Is
var _ = strconv.Itoa
