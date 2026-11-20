package integration_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keykoi/internal/integration"
	"keykoi/internal/model"
	"keykoi/internal/store"
)

const testBindingID = "binding_test"

func writeManifest(t *testing.T, dir, bindingID string) {
	t.Helper()
	path := filepath.Join(dir, "test-adapter.yaml")
	content := `schema_version: 1
id: test-adapter
adapter_version: 1
status: verified
tool:
  executable_ref: installations.test
  executable: /bin/sh
  supported_os: [darwin, macos, linux]
  verified_versions: ["test-1.0"]
credential:
  binding_ref: ` + bindingID + `
  delivery_mode: runtime_delivery
integration:
  mechanism: helper_config
  config_path: "~/.testtool/config.ini"
  section: "profile keykoi"
  managed_key: credential_process
  helper_args: ["helper", "aws", "--binding", "` + bindingID + `"]
  verify_args: ["-c", "exit 0"]
lifecycle:
  plaintext_disk_fallback: false
  persist_session_token: false
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeEnvManifest(t *testing.T, dir, bindingID string) {
	t.Helper()
	path := filepath.Join(dir, "test-env.yaml")
	content := `schema_version: 1
id: test-env
adapter_version: 1
status: verified
tool:
  executable_ref: installations.test
  executable: /bin/sh
  supported_os: [darwin, macos, linux]
  verified_versions: ["test-1.0"]
credential:
  binding_ref: ` + bindingID + `
  delivery_mode: runtime_delivery
integration:
  mechanism: env_launcher
  env:
    AWS_ACCESS_KEY_ID: "field:access_id"
    AWS_SECRET_ACCESS_KEY: "field:access_secret"
  verify_args: ["-c", "exit 0"]
lifecycle:
  plaintext_disk_fallback: false
  persist_session_token: false
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// setup 构造测试用 Manager。Exec 默认模拟「实际运行路径产生了一次用钥记录」，
// 需要验证缺失用钥记录的场景由各测试自行替换。
func setup(t *testing.T) (*integration.Manager, *store.Memory, string) {
	t.Helper()
	home := t.TempDir()
	adaptersDir := filepath.Join(home, "adapters")
	if err := os.MkdirAll(adaptersDir, 0o700); err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.PutBinding(ctx, &model.Binding{
		ID: testBindingID, CredentialID: "cred_test", UpstreamOrigin: "http://127.0.0.1:9",
		AuthScheme: model.AuthBearer, Route: "r", Status: model.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	writeManifest(t, adaptersDir, testBindingID)
	writeEnvManifest(t, adaptersDir, testBindingID)
	m := &integration.Manager{
		St: st, AdaptersDir: adaptersDir, DataDir: filepath.Join(home, "data"),
		KeyKoiBin: "/usr/local/bin/keykoi", Home: home,
		Exec: func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
			for _, a := range cmd.Args {
				if a == "--version" {
					return []byte("test-1.0\n"), nil
				}
			}
			// 走实际运行路径时，Broker 会写入一条成功用钥记录。
			_ = st.AppendAudit(ctx, &store.AuditEvent{
				BindingID: testBindingID, Result: "allowed", Mode: "runtime_delivery", Time: time.Now().UTC(),
			})
			return []byte("ok"), nil
		},
	}
	return m, st, home
}

func writeConfig(t *testing.T, home, content string) string {
	t.Helper()
	dir := filepath.Join(home, ".testtool")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestManifestStrictParsing(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("schema_version: 1\nid: x\ntool:\n  executable: /bin/sh\nunexpected: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := integration.LoadManifest(bad); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
}

func TestPlanIsMaskedAndScoped(t *testing.T) {
	m, _, _ := setup(t)
	plan, err := m.Plan(context.Background(), "test-adapter")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 1 || plan.Changes[0].Key != "profile keykoi.credential_process" {
		t.Fatalf("unexpected changes: %+v", plan.Changes)
	}
	if strings.Contains(plan.Preview, "secret") && !strings.Contains(plan.Preview, "不含真实凭证") {
		t.Fatal("preview must not include credential values")
	}
	if !strings.Contains(plan.Preview, "/usr/local/bin/keykoi helper aws --binding binding_test") {
		t.Fatalf("preview must show managed helper path: %s", plan.Preview)
	}
}

func TestApplyPreservesUnrelatedFieldsAndIsIdempotent(t *testing.T) {
	m, st, home := setup(t)
	cfgPath := writeConfig(t, home, "[profile keykoi]\nregion = us-east-1\ncredential_process = old-command\n\n[profile other]\nregion = eu-west-1\n")
	ctx := context.Background()
	rec, err := m.Apply(ctx, "test-adapter")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "region = us-east-1") || !strings.Contains(string(data), "region = eu-west-1") {
		t.Fatalf("unrelated fields were overwritten:\n%s", data)
	}
	if !strings.Contains(string(data), "credential_process = /usr/local/bin/keykoi helper aws --binding binding_test") {
		t.Fatalf("managed field not written:\n%s", data)
	}
	info, _ := os.Stat(cfgPath)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions must be 0600, got %v", info.Mode().Perm())
	}
	if rec.BackupPath == "" {
		t.Fatal("recovery material must be recorded")
	}
	// 幂等：再次 apply 不改变内容，也不覆盖首次记录的原始值。
	before := string(data)
	if _, err := m.Apply(ctx, "test-adapter"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(cfgPath)
	if string(after) != before {
		t.Fatal("apply must be idempotent")
	}
	rec2, err := st.GetIntegration(ctx, "test-adapter")
	if err != nil || rec2.State != "applied" {
		t.Fatalf("record state: %+v err=%v", rec2, err)
	}
}

// TestBackupIsEncryptedAndFieldScoped 验证恢复材料只含受管字段且加密保存。
func TestBackupIsEncryptedAndFieldScoped(t *testing.T) {
	m, _, home := setup(t)
	cfgPath := writeConfig(t, home, "[profile keykoi]\nregion = us-east-1\ncredential_process = old-command\n\n[profile other]\nregion = eu-west-1\naws_secret_access_key = other-account-secret\n")
	ctx := context.Background()
	rec, err := m.Apply(ctx, "test-adapter")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(rec.BackupPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, secret := range []string{"old-command", "other-account-secret", "us-east-1", "credential_process"} {
		if strings.Contains(text, secret) {
			t.Fatalf("recovery material must not contain plaintext %q", secret)
		}
	}
	info, _ := os.Stat(rec.BackupPath)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("recovery material must be 0600, got %v", info.Mode().Perm())
	}
	_ = cfgPath
}

// TestDetachRestoresOnlyManagedField 验证撤销只还原受管字段。
func TestDetachRestoresOnlyManagedField(t *testing.T) {
	m, _, home := setup(t)
	cfgPath := writeConfig(t, home, "[profile keykoi]\nregion = us-east-1\ncredential_process = old-command\n\n[profile other]\nregion = eu-west-1\n")
	ctx := context.Background()
	if _, err := m.Apply(ctx, "test-adapter"); err != nil {
		t.Fatal(err)
	}
	// 接入之后用户又做了与本次接入无关的编辑。
	edited := strings.Replace(readFile(t, cfgPath), "[profile other]\nregion = eu-west-1\n",
		"[profile other]\nregion = eu-west-1\nextra = kept\n\n[profile later]\nregion = ap-south-1\n", 1)
	edited = strings.Replace(edited, "[profile keykoi]\nregion = us-east-1\n",
		"[profile keykoi]\nregion = us-east-1\nassistant_setting = pre-existing\n", 1)
	if err := os.WriteFile(cfgPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Detach(ctx, "test-adapter"); err != nil {
		t.Fatal(err)
	}
	final := readFile(t, cfgPath)
	checks := []string{
		"credential_process = old-command", "region = us-east-1", "assistant_setting = pre-existing",
		"extra = kept", "[profile later]", "region = ap-south-1", "region = eu-west-1",
	}
	for _, want := range checks {
		if !strings.Contains(final, want) {
			t.Fatalf("detach lost %q:\n%s", want, final)
		}
	}
	if strings.Contains(final, "/usr/local/bin/keykoi helper") {
		t.Fatalf("detach must remove the KeyKoi helper entry:\n%s", final)
	}
}

// TestDetachRemovesManagedFieldWhenItDidNotExist 验证接入前不存在该字段时撤销
// 只删除自己新增的字段。
func TestDetachRemovesManagedFieldWhenItDidNotExist(t *testing.T) {
	m, _, home := setup(t)
	cfgPath := writeConfig(t, home, "[profile keykoi]\nregion = us-east-1\n[profile other]\nregion = eu-west-1\n")
	ctx := context.Background()
	if _, err := m.Apply(ctx, "test-adapter"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Detach(ctx, "test-adapter"); err != nil {
		t.Fatal(err)
	}
	final := readFile(t, cfgPath)
	if strings.Contains(final, "credential_process") {
		t.Fatalf("managed field must be removed:\n%s", final)
	}
	if !strings.Contains(final, "region = us-east-1") || !strings.Contains(final, "region = eu-west-1") {
		t.Fatalf("unrelated fields must survive detach:\n%s", final)
	}
}

// TestDetachRefusesWhenSnapshotIsUnreadable 验证无法确定原始值时不动配置。
func TestDetachRefusesWhenSnapshotIsUnreadable(t *testing.T) {
	m, st, home := setup(t)
	cfgPath := writeConfig(t, home, "[profile keykoi]\nregion = us-east-1\n")
	ctx := context.Background()
	rec, err := m.Apply(ctx, "test-adapter")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rec.BackupPath, []byte("corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, cfgPath)
	if _, err := m.Detach(ctx, "test-adapter"); err == nil {
		t.Fatal("unreadable recovery material must stop detach")
	} else if model.CodeOf(err) != model.CodeConfigDrift {
		t.Fatalf("expected CONFIG_DRIFT, got %v", err)
	}
	if after := readFile(t, cfgPath); after != before {
		t.Fatalf("config must be untouched when recovery material is unusable:\n%s", after)
	}
	if _, err := st.GetIntegration(ctx, "test-adapter"); err != nil {
		t.Fatal("integration record must stay attached")
	}
}

func TestVerifyAndRecoveryState(t *testing.T) {
	m, st, _ := setup(t)
	if _, err := m.Apply(context.Background(), "test-adapter"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(context.Background(), "test-adapter"); err != nil {
		t.Fatal(err)
	}
	rec, _ := st.GetIntegration(context.Background(), "test-adapter")
	if rec.State != "verified" {
		t.Fatalf("expected verified, got %s", rec.State)
	}
	// 验证失败进入 recovery_required。
	m.Exec = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		for _, a := range cmd.Args {
			if a == "--version" {
				return []byte("test-1.0\n"), nil
			}
		}
		return []byte("auth failed"), exec.ErrWaitDelay
	}
	if _, err := m.Verify(context.Background(), "test-adapter"); err == nil {
		t.Fatal("verification failure must be reported")
	}
	rec, _ = st.GetIntegration(context.Background(), "test-adapter")
	if rec.State != "recovery_required" {
		t.Fatalf("expected recovery_required, got %s", rec.State)
	}
}

// TestVerifyRequiresKeyUseRecord 验证没有用钥记录时验证失败，而不是「通过」。
func TestVerifyRequiresKeyUseRecord(t *testing.T) {
	m, st, _ := setup(t)
	if _, err := m.Apply(context.Background(), "test-adapter"); err != nil {
		t.Fatal(err)
	}
	m.Exec = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		for _, a := range cmd.Args {
			if a == "--version" {
				return []byte("test-1.0\n"), nil
			}
		}
		// 工具用主机已有凭证执行成功，但没有经过 KeyKoi。
		return []byte("ok"), nil
	}
	_, err := m.Verify(context.Background(), "test-adapter")
	if err == nil {
		t.Fatal("verification without a key-use record must fail")
	}
	if model.CodeOf(err) != model.CodeControlUnavailable {
		t.Fatalf("expected CONTROL_UNAVAILABLE, got %v", err)
	}
	rec, _ := st.GetIntegration(context.Background(), "test-adapter")
	if rec.State != "recovery_required" {
		t.Fatalf("state must move to recovery_required, got %s", rec.State)
	}
}

// TestVerifyEnvIgnoresHostCredentials 验证验证环境不继承主机凭证，也不指向
// 用户的真实凭证文件。
func TestVerifyEnvIgnoresHostCredentials(t *testing.T) {
	m, _, home := setup(t)
	cfgPath := writeConfig(t, home, "[profile keykoi]\nregion = us-east-1\n")
	if _, err := m.Apply(context.Background(), "test-adapter"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "host-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "host-secret")
	var captured []string
	m.Exec = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		for _, a := range cmd.Args {
			if a == "--version" {
				return []byte("test-1.0\n"), nil
			}
		}
		captured = append([]string(nil), cmd.Env...)
		_ = m.St.AppendAudit(ctx, &store.AuditEvent{BindingID: testBindingID, Result: "allowed", Time: time.Now().UTC()})
		return []byte("ok"), nil
	}
	if _, err := m.Verify(context.Background(), "test-adapter"); err != nil {
		t.Fatal(err)
	}
	env := strings.Join(captured, "\n")
	if strings.Contains(env, "AWS_ACCESS_KEY_ID=host-key") || strings.Contains(env, "AWS_SECRET_ACCESS_KEY=host-secret") {
		t.Fatal("verification must not inherit host credentials")
	}
	if !strings.Contains(env, "AWS_CONFIG_FILE="+cfgPath) {
		t.Fatalf("verification must read the managed config: %s", env)
	}
	hostCreds := filepath.Join(home, ".aws", "credentials")
	if strings.Contains(env, "AWS_SHARED_CREDENTIALS_FILE="+hostCreds) {
		t.Fatal("verification must not point at the host credentials file")
	}
	if !strings.Contains(env, "HOME="+home) {
		t.Fatalf("verification HOME must be the managed home: %s", env)
	}
}

// TestEnvLauncherVerifyUsesRunner 验证 env_launcher 的验证经 KeyKoi 运行器执行。
func TestEnvLauncherVerifyUsesRunner(t *testing.T) {
	m, st, home := setup(t)
	ctx := context.Background()
	if _, err := m.Apply(ctx, "test-env"); err != nil {
		t.Fatal(err)
	}
	var captured *exec.Cmd
	m.Exec = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		for _, a := range cmd.Args {
			if a == "--version" {
				return []byte("test-1.0\n"), nil
			}
		}
		captured = cmd
		_ = st.AppendAudit(ctx, &store.AuditEvent{BindingID: testBindingID, Result: "allowed", Time: time.Now().UTC()})
		return []byte("ok"), nil
	}
	if _, err := m.Verify(ctx, "test-env"); err != nil {
		t.Fatal(err)
	}
	if captured == nil {
		t.Fatal("verification command was not executed")
	}
	if captured.Path != "/usr/local/bin/keykoi" {
		t.Fatalf("env_launcher verification must run through KeyKoi, got %s", captured.Path)
	}
	joined := strings.Join(captured.Args, " ")
	for _, want := range []string{" run ", "--binding " + testBindingID, "--exe /bin/sh", "AWS_ACCESS_KEY_ID=field:access_id"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("runner command missing %q: %s", want, joined)
		}
	}
	_ = home
}

// TestHelperCommandQuotesSpacedPath 验证含空格的可执行文件路径被正确引用。
func TestHelperCommandQuotesSpacedPath(t *testing.T) {
	m, _, home := setup(t)
	m.KeyKoiBin = "/Applications/Key Koi.app/Contents/MacOS/keykoi"
	plan, err := m.Plan(context.Background(), "test-adapter")
	if err != nil {
		t.Fatal(err)
	}
	want := `'/Applications/Key Koi.app/Contents/MacOS/keykoi' helper aws --binding binding_test`
	if plan.Changes[0].Value != want {
		t.Fatalf("managed value must quote the spaced path:\n got %q\nwant %q", plan.Changes[0].Value, want)
	}
	cfgPath := writeConfig(t, home, "[profile keykoi]\n")
	if _, err := m.Apply(context.Background(), "test-adapter"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, cfgPath), "credential_process = "+want) {
		t.Fatalf("config must carry the quoted command: %s", readFile(t, cfgPath))
	}
}

// TestShellQuoteCommand 验证引用规则本身。
func TestShellQuoteCommand(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{args: []string{"/usr/local/bin/keykoi", "helper"}, want: "/usr/local/bin/keykoi helper"},
		{args: []string{"/Applications/Key Koi/keykoi", "--binding", "b1"}, want: `'/Applications/Key Koi/keykoi' --binding b1`},
		{args: []string{"it's", "x"}, want: `'it'\''s' x`},
		{args: []string{""}, want: "''"},
		{args: []string{"a&b"}, want: "'a&b'"},
	}
	for _, tc := range cases {
		if got := integration.ShellQuoteCommand(tc.args...); got != tc.want {
			t.Fatalf("ShellQuoteCommand(%q) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

// TestGitCredentialHelperQuotesSpacedPath 验证 git credential helper 值按 sh
// 语法引用含空格路径。
func TestGitCredentialHelperQuotesSpacedPath(t *testing.T) {
	got := integration.GitCredentialHelper("/Applications/Key Koi.app/Contents/MacOS/keykoi", "binding_test")
	want := `!'/Applications/Key Koi.app/Contents/MacOS/keykoi' helper git-token --binding binding_test`
	if got != want {
		t.Fatalf("git helper value = %q, want %q", got, want)
	}
	// 简单路径保持可读，不额外加引号。
	if plain := integration.GitCredentialHelper("/usr/local/bin/keykoi", "b"); plain != "!/usr/local/bin/keykoi helper git-token --binding b" {
		t.Fatalf("plain path must stay unquoted: %q", plain)
	}
}

func TestDriftDetectionAndDetach(t *testing.T) {
	m, st, home := setup(t)
	cfgPath := writeConfig(t, home, "[profile keykoi]\nregion = us-east-1\n[profile other]\nregion = eu-west-1\n")
	ctx := context.Background()
	if _, err := m.Apply(ctx, "test-adapter"); err != nil {
		t.Fatal(err)
	}
	if drift, err := m.Drift(ctx, "test-adapter"); err != nil || drift {
		t.Fatalf("unexpected initial drift: %v %v", drift, err)
	}
	// 用户手工修改受管字段。
	modified := strings.Replace(readFile(t, cfgPath), "credential_process = /usr/local/bin/keykoi helper aws --binding binding_test", "credential_process = user-command", 1)
	if err := os.WriteFile(cfgPath, []byte(modified), 0o600); err != nil {
		t.Fatal(err)
	}
	if drift, _ := m.Drift(ctx, "test-adapter"); !drift {
		t.Fatal("drift must be detected")
	}
	if _, err := m.Verify(ctx, "test-adapter"); err == nil || model.CodeOf(err) != model.CodeConfigDrift {
		t.Fatalf("verify must refuse on drift, got %v", err)
	}
	rec, _ := st.GetIntegration(ctx, "test-adapter")
	if rec.State != "unverified" {
		t.Fatalf("drift must move state to unverified, got %s", rec.State)
	}
	// 撤销：只还原受管字段并删除记录。
	if _, err := m.Detach(ctx, "test-adapter"); err != nil {
		t.Fatal(err)
	}
	final := readFile(t, cfgPath)
	if !strings.Contains(final, "region = eu-west-1") {
		t.Fatalf("detach must preserve unrelated config: %s", final)
	}
	if _, err := st.GetIntegration(ctx, "test-adapter"); err == nil {
		t.Fatal("integration record must be removed after detach")
	}
}

func TestPlanRejectsMissingBinding(t *testing.T) {
	m, _, _ := setup(t)
	ctx := context.Background()
	if err := m.St.DeleteIntegration(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if err := deleteBinding(ctx, m); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Plan(ctx, "test-adapter"); err == nil {
		t.Fatal("missing binding must be rejected")
	}
}

func deleteBinding(ctx context.Context, m *integration.Manager) error {
	return m.St.UpdateBindingStatus(ctx, testBindingID, model.StatusDisabled, 0)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
