package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"keykoi/internal/ipcclient"
)

func readPasswordNoEcho() ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return term.ReadPassword(int(os.Stdin.Fd()))
	}
	var pw string
	_, err := fmt.Fscanln(os.Stdin, &pw)
	return []byte(pw), err
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fromStdin := fs.Bool("password-stdin", false, "read master password from stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pw, err := readPassword(*fromStdin)
	if err != nil {
		return err
	}
	var out map[string]any
	if err := client().Post("/v1/vault/init", map[string]any{"password": string(pw)}, &out); err != nil {
		return err
	}
	if g.json {
		return printJSON(out)
	}
	fmt.Printf("vault initialized; state=%v\n", out["state"])
	return nil
}

func cmdUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
	fromStdin := fs.Bool("password-stdin", false, "read master password from stdin")
	biometric := fs.Bool("biometric", false, "unlock with Touch ID; fall back to the master password when unavailable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *biometric {
		bioErr := unlockBiometric()
		if bioErr == nil {
			return nil
		}
		if !fallbackAllowed(bioErr) {
			return bioErr
		}
		fmt.Fprintf(os.Stderr, "Touch ID 不可用（%s）；回退主密码。\n", apiMessage(bioErr))
	}
	pw, err := readPassword(*fromStdin)
	if err != nil {
		if *biometric {
			return fmt.Errorf("AUTH_UNAVAILABLE: Touch ID is unavailable and the master password fallback is not usable here: %w", err)
		}
		return err
	}
	var out map[string]any
	if err := client().Post("/v1/vault/unlock", map[string]any{"password": string(pw)}, &out); err != nil {
		return err
	}
	if g.json {
		return printJSON(out)
	}
	fmt.Println("vault unlocked (master password)")
	return nil
}

// unlockBiometric 尝试用 Touch ID 解锁。
func unlockBiometric() error {
	var out map[string]any
	if err := client().Post("/v1/vault/unlock-biometric", map[string]any{}, &out); err != nil {
		return err
	}
	if g.json {
		return printJSON(out)
	}
	fmt.Println("vault unlocked (Touch ID)")
	return nil
}

// apiMessage 去掉稳定错误码的重复前缀，只保留可读原因。
func apiMessage(err error) string {
	var apiErr *ipcclient.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Message
	}
	return err.Error()
}

// fallbackAllowed 只有「环境无法完成验证」或「需要重新验证」才回退主密码；
// 其它错误（例如服务未启动）原样返回。
func fallbackAllowed(err error) bool {
	var apiErr *ipcclient.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Code == "AUTH_UNAVAILABLE" || apiErr.Code == "AUTH_REQUIRED"
}

func cmdLock() error {
	var out map[string]any
	if err := client().Post("/v1/vault/lock", map[string]any{}, &out); err != nil {
		return err
	}
	if g.json {
		return printJSON(out)
	}
	fmt.Printf("vault locked; epoch=%v\n", out["epoch"])
	return nil
}

func cmdCredential(sub string, args []string) error {
	switch sub {
	case "", "list":
		var out struct {
			Credentials []map[string]any `json:"credentials"`
		}
		if err := client().Get("/v1/credentials", &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out.Credentials)
		}
		if len(out.Credentials) == 0 {
			fmt.Println("no credentials")
			return nil
		}
		for _, c := range out.Credentials {
			fmt.Printf("%s  kind=%-18s status=%-8s v%v  %s\n", c["id"], c["kind"], c["status"], c["current_version"], c["label"])
		}
		return nil
	case "add":
		fs := flag.NewFlagSet("credential add", flag.ContinueOnError)
		kind := fs.String("kind", "api_key", "credential kind")
		label := fs.String("label", "", "human label (no secrets)")
		expires := fs.String("expires", "", "provider expiry RFC3339 (optional)")
		fields := kvFlag{}
		fieldFiles := kvFlag{}
		fieldStdin := false
		fs.Var(&fields, "field", "field name=value, or just name to read it hidden / from stdin (repeatable)")
		fs.Var(&fieldFiles, "field-file", "field name=path (repeatable; read the secret from a 0600 file)")
		fs.BoolVar(&fieldStdin, "field-stdin", false, "read the value of every name-only --field from stdin instead of prompting")
		if err := fs.Parse(args); err != nil {
			return err
		}
		prompted, err := fields.Resolve(fieldStdin)
		if err != nil {
			return err
		}
		merged, err := mergeFieldFiles(prompted, fieldFiles.Map())
		if err != nil {
			return err
		}
		if *label == "" || len(merged) == 0 {
			return fmt.Errorf("--label and at least one --field or --field-file are required")
		}
		body := map[string]any{"kind": *kind, "label": *label, "fields": merged}
		if *expires != "" {
			body["provider_expires_at"] = *expires
		}
		var out map[string]any
		if err := client().Post("/v1/credentials", body, &out); err != nil {
			return err
		}
		if g.json {
			fmt.Println(out["id"])
			return nil
		}
		fmt.Printf("created %v (kind=%v)\n", out["id"], out["kind"])
		return nil
	case "rotate":
		fs := flag.NewFlagSet("credential rotate", flag.ContinueOnError)
		id := fs.String("id", "", "credential id")
		fields := kvFlag{}
		fieldFiles := kvFlag{}
		fieldStdin := false
		fs.Var(&fields, "field", "field name=value, or just name to read it hidden / from stdin (repeatable)")
		fs.Var(&fieldFiles, "field-file", "field name=path (repeatable; read from a 0600 file)")
		fs.BoolVar(&fieldStdin, "field-stdin", false, "read the value of every name-only --field from stdin instead of prompting")
		if err := fs.Parse(args); err != nil {
			return err
		}
		prompted, err := fields.Resolve(fieldStdin)
		if err != nil {
			return err
		}
		merged, err := mergeFieldFiles(prompted, fieldFiles.Map())
		if err != nil {
			return err
		}
		if *id == "" || len(merged) == 0 {
			return fmt.Errorf("--id and at least one --field or --field-file are required")
		}
		var out map[string]any
		if err := client().Post("/v1/credentials/"+*id+"/versions", map[string]any{"fields": merged}, &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out)
		}
		fmt.Printf("rotated %s to version %v\n", *id, out["current_version"])
		return nil
	case "disable":
		fs := flag.NewFlagSet("credential disable", flag.ContinueOnError)
		id := fs.String("id", "", "credential id")
		if err := fs.Parse(args); err != nil {
			return err
		}
		var out map[string]any
		if err := client().Post("/v1/credentials/"+*id+"/disable", map[string]any{}, &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out)
		}
		fmt.Printf("disabled %s\n", *id)
		return nil
	}
	return fmt.Errorf("unknown credential subcommand %q", sub)
}

func cmdBinding(sub string, args []string) error {
	switch sub {
	case "", "list":
		var out struct {
			Bindings []map[string]any `json:"bindings"`
		}
		if err := client().Get("/v1/bindings", &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out.Bindings)
		}
		for _, b := range out.Bindings {
			fmt.Printf("%s  route=%-20v %s -> %s (%v)\n", b["id"], b["route"], b["upstream_origin"], b["auth_scheme"], b["status"])
		}
		return nil
	case "add":
		fs := flag.NewFlagSet("binding add", flag.ContinueOnError)
		id := fs.String("id", "", "binding id")
		cred := fs.String("credential", "", "credential id")
		origin := fs.String("origin", "", "upstream origin, e.g. https://api.example.com")
		route := fs.String("route", "", "gateway route name")
		scheme := fs.String("scheme", "bearer", "bearer|api_key|basic")
		header := fs.String("header", "", "auth header override")
		tokenField := fs.String("token-field", "", "credential field for token")
		userField := fs.String("username-field", "", "credential field for basic username")
		passField := fs.String("password-field", "", "credential field for basic password")
		paths := fs.String("paths", "", "comma separated allowed path prefixes")
		if err := fs.Parse(args); err != nil {
			return err
		}
		body := map[string]any{
			"id": *id, "credential_id": *cred, "upstream_origin": *origin, "route": *route,
			"auth_scheme": *scheme, "auth_header": *header, "token_field": *tokenField,
			"username_field": *userField, "password_field": *passField,
		}
		if *paths != "" {
			body["allowed_paths"] = strings.Split(*paths, ",")
		}
		var out map[string]any
		if err := client().Post("/v1/bindings", body, &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out)
		}
		fmt.Printf("binding %s registered for route %s\n", *id, *route)
		return nil
	}
	return fmt.Errorf("unknown binding subcommand %q", sub)
}

func cmdGrant(sub string, args []string) error {
	switch sub {
	case "", "list":
		var out struct {
			Grants []map[string]any `json:"grants"`
		}
		if err := client().Get("/v1/grants", &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out.Grants)
		}
		for _, gr := range out.Grants {
			fmt.Printf("%s  principal=%v binding=%v mode=%v auth=%v status=%v\n",
				gr["id"], gr["principal_id"], gr["binding_id"], gr["delivery_mode"], gr["auth_requirement"], gr["status"])
		}
		return nil
	case "subjects":
		var out struct {
			Subjects []map[string]any `json:"subjects"`
		}
		if err := client().Get("/v1/subjects", &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out.Subjects)
		}
		for _, subject := range out.Subjects {
			fmt.Printf("%-16s %s\n", subject["key"], subject["label"])
		}
		return nil
	case "register-agent":
		fs := flag.NewFlagSet("grant register-agent", flag.ContinueOnError)
		key := fs.String("key", "", "stable lowercase agent key")
		label := fs.String("label", "", "display name")
		executable := fs.String("executable", "", "absolute native executable path")
		if err := fs.Parse(args); err != nil {
			return err
		}
		var out map[string]any
		if err := client().Post("/v1/subjects", map[string]string{
			"key": *key, "label": *label, "executable": *executable,
		}, &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out)
		}
		fmt.Printf("registered %s (%s)\n", out["label"], out["key"])
		return nil
	case "add":
		fs := flag.NewFlagSet("grant add", flag.ContinueOnError)
		principal := fs.String("principal", "me", "me | codex-app | codex-cli | principal id")
		binding := fs.String("binding", "", "binding id")
		mode := fs.String("mode", "proxy", "proxy|runtime_delivery|sign")
		maxLease := fs.Int64("max-lease-seconds", 600, "max lease duration in seconds")
		auth := fs.String("auth", "once", "verification policy: once|window:300|per-use|permanent")
		if err := fs.Parse(args); err != nil {
			return err
		}
		var out map[string]any
		if err := client().Post("/v1/grants", map[string]any{
			"principal_id": *principal, "binding_id": *binding, "delivery_mode": *mode,
			"max_lease_seconds": *maxLease, "auth_requirement": *auth,
		}, &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out)
		}
		fmt.Printf("granted %v for %v on %v (auth=%v)\n", out["delivery_mode"], *principal, *binding, out["auth_requirement"])
		return nil
	case "revoke", "approve":
		fs := flag.NewFlagSet("grant "+sub, flag.ContinueOnError)
		id := fs.String("id", "", "grant id")
		if err := fs.Parse(args); err != nil {
			return err
		}
		// 先取元数据以撤销关联的运行时许可。
		var out map[string]any
		if err := client().Post("/v1/grants/"+*id+"/"+sub, map[string]any{}, &out); err != nil {
			return err
		}
		if g.json {
			return printJSON(out)
		}
		fmt.Printf("%s %s\n", sub+"d", *id)
		return nil
	}
	return fmt.Errorf("unknown grant subcommand %q", sub)
}

func cmdAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	limit := fs.Int("limit", 50, "max events")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var out struct {
		Events []map[string]any `json:"events"`
	}
	if err := client().Get(fmt.Sprintf("/v1/audit-events?limit=%d", *limit), &out); err != nil {
		return err
	}
	if g.json {
		return printJSON(out.Events)
	}
	for _, e := range out.Events {
		fmt.Printf("%-30v %-10v %-8v %-8v %-20v %v\n", e["Time"], e["Mode"], e["Result"], e["ErrorCode"], e["BindingID"], e["Detail"])
	}
	return nil
}

func cmdLease(sub string, args []string) error {
	if sub != "revoke" {
		return fmt.Errorf("unknown lease subcommand %q", sub)
	}
	fs := flag.NewFlagSet("lease revoke", flag.ContinueOnError)
	id := fs.String("id", "", "lease id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var out map[string]any
	if err := client().Post("/v1/use-leases/revoke", map[string]any{"lease_id": *id}, &out); err != nil {
		return err
	}
	fmt.Println("lease revoked")
	return nil
}

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	path := fs.String("out", "", "backup file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" && fs.NArg() > 0 {
		*path = fs.Arg(0)
	}
	if *path == "" {
		*path = filepath.Join(g.dataDir, "backup-"+timestamp()+".json")
	}
	var out map[string]any
	if err := client().Post("/v1/vault/backup", map[string]any{"path": *path}, &out); err != nil {
		return err
	}
	if g.json {
		return printJSON(out)
	}
	fmt.Printf("encrypted backup written to %s\n", *path)
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	path := fs.String("in", "", "backup file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" && fs.NArg() > 0 {
		*path = fs.Arg(0)
	}
	if *path == "" {
		return fmt.Errorf("backup path is required")
	}
	var out map[string]any
	if err := client().Post("/v1/vault/restore", map[string]any{"path": *path}, &out); err != nil {
		return err
	}
	if g.json {
		return printJSON(out)
	}
	fmt.Printf("restored: credentials=%v versions=%v grants_pending=%v locked=%v\n", out["credentials"], out["versions"], out["grants_pending"], out["locked_after"])
	return nil
}

func cmdDoctor() error {
	st, err := client().Status()
	if err != nil {
		return err
	}
	checks := []struct {
		name string
		ok   bool
		note string
	}{
		{"daemon reachable", true, g.socket},
		{"vault state", st["state"] != "uninitialized", fmt.Sprint(st["state"])},
		{"gateway listening", st["gateway"] != "", fmt.Sprint(st["gateway"])},
		{"admin listening", st["admin"] != "", fmt.Sprint(st["admin"])},
	}
	var authStatus struct {
		Biometric map[string]any `json:"biometric"`
	}
	authErr := client().Get("/v1/auth/status", &authStatus)
	if authErr == nil {
		available, _ := authStatus.Biometric["available"].(bool)
		enrolled, _ := authStatus.Biometric["enrolled"].(bool)
		note := fmt.Sprintf("available=%v enrolled=%v", available, enrolled)
		if reason, ok := authStatus.Biometric["reason"].(string); ok && reason != "" {
			note += " · " + reason
		}
		checks = append(checks, struct {
			name string
			ok   bool
			note string
		}{"biometric (Touch ID)", available, note})
	}
	sockInfo, err := os.Stat(g.socket)
	if err == nil {
		checks = append(checks, struct {
			name string
			ok   bool
			note string
		}{"socket permissions 0600", sockInfo.Mode().Perm() == 0o600, sockInfo.Mode().Perm().String()})
	}
	if g.json {
		items := []map[string]any{}
		for _, c := range checks {
			items = append(items, map[string]any{"check": c.name, "ok": c.ok, "note": c.note})
		}
		return printJSON(items)
	}
	for _, c := range checks {
		mark := "ok"
		if !c.ok {
			mark = "FAIL"
		}
		fmt.Printf("[%s] %-28s %s\n", mark, c.name, c.note)
	}
	return nil
}

func timestamp() string {
	return timeNow().Format("20060102-150405")
}

// mergeFieldFiles 把 --field 的值与 --field-file 指向的文件内容合并。
// 文件只用于避免秘密出现在 argv；读取后按普通字段提交。
func mergeFieldFiles(values, files map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range values {
		out[k] = v
	}
	for name, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(os.Stderr, "warning: %s 是 %v，建议 chmod 600\n", path, info.Mode().Perm())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		out[name] = strings.TrimRight(string(data), "\n")
	}
	return out, nil
}

// kvFlag 收集可重复的 name=value 参数。
type kvFlag struct {
	values  map[string]string
	order   []string
	prompts []string
}

func (k *kvFlag) String() string { return fmt.Sprint(k.values) }

func (k *kvFlag) Set(v string) error {
	parts := strings.SplitN(v, "=", 2)
	if parts[0] == "" {
		return fmt.Errorf("expected name=value or name")
	}
	if len(parts) != 2 {
		// 只给字段名时改为隐藏输入或 stdin 读取，避免秘密进入 shell 历史与进程参数。
		if parts[0] == "" {
			return fmt.Errorf("expected name=value or name")
		}
		if k.prompts == nil {
			k.prompts = []string{}
		}
		k.prompts = append(k.prompts, parts[0])
		return nil
	}
	if k.values == nil {
		k.values = map[string]string{}
	}
	if _, ok := k.values[parts[0]]; !ok {
		k.order = append(k.order, parts[0])
	}
	k.values[parts[0]] = parts[1]
	return nil
}

// Resolve 把「只给字段名」的条目从隐藏输入或 stdin 补齐。
// 命令行里显式给值仍然支持，但推荐使用 name 形式或 --field-file。
func (k *kvFlag) Resolve(fromStdin bool) (map[string]string, error) {
	out := map[string]string{}
	for name, value := range k.Map() {
		out[name] = value
	}
	for _, name := range k.prompts {
		value, err := readSecretValue(name, fromStdin)
		if err != nil {
			return nil, err
		}
		out[name] = value
	}
	return out, nil
}

// readSecretValue 读取一个秘密字段值：终端下不回显，管道下按行读取。
func readSecretValue(name string, fromStdin bool) (string, error) {
	if !fromStdin && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "%s: ", name)
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		if len(value) == 0 {
			return "", fmt.Errorf("%s is empty", name)
		}
		return string(value), nil
	}
	var line string
	if _, err := fmt.Fscanln(os.Stdin, &line); err != nil {
		return "", fmt.Errorf("read %s from stdin: %w", name, err)
	}
	if line == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	return line, nil
}

// Map 返回字段映射。
func (k *kvFlag) Map() map[string]string {
	if k.values == nil {
		return map[string]string{}
	}
	return k.values
}
