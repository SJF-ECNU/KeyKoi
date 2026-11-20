package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// maxSignPayloadBytes 是 CLI 允许计算摘要的单个 payload 上限。
// 分块/流式上传不属于任何受支持签名模式（aws-sigv4 / tencent-tc3 / huawei-aksk）。
const maxSignPayloadBytes = 256 << 20

// signUsage 是 `keykoi sign` 的用法说明。
const signUsage = "usage: keykoi sign <aws-sigv4|tencent-tc3|huawei-aksk> --binding ID --method GET --url URL " +
	"[--header k:v ...] [--region R --service S] [--action Name] [--payload-file F] [--out headers.json]"

// headerFlag 收集可重复的 "Name: value" header。
type headerFlag struct {
	values map[string]string
	order  []string
}

func (h *headerFlag) String() string { return fmt.Sprint(len(h.values)) }

func (h *headerFlag) Set(v string) error {
	name, value, ok := strings.Cut(v, ":")
	if !ok {
		return fmt.Errorf("header must be Name: value")
	}
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if name == "" {
		return fmt.Errorf("header name must not be empty")
	}
	if h.values == nil {
		h.values = map[string]string{}
	}
	if _, seen := h.values[name]; !seen {
		h.order = append(h.order, name)
	}
	h.values[name] = value
	return nil
}

func (h *headerFlag) Map() map[string]string {
	if h.values == nil {
		return map[string]string{}
	}
	return h.values
}

// cmdSign 只输出签名头；密钥与会话令牌不写入 stdout/stderr。
func cmdSign(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(signUsage)
	}
	protocol := args[0]
	switch protocol {
	case "aws-sigv4", "tencent-tc3", "huawei-aksk":
	default:
		return fmt.Errorf("%s\n%s", "unsupported protocol "+protocol, signUsage)
	}
	fs := flag.NewFlagSet("sign "+protocol, flag.ContinueOnError)
	binding := fs.String("binding", "", "binding id registered with a "+protocol+" adapter")
	method := fs.String("method", "", "HTTP method (GET, PUT, POST, DELETE, HEAD, PATCH, OPTIONS)")
	rawURL := fs.String("url", "", "absolute request URL on the registered upstream origin")
	region := fs.String("region", "", "region override; must match the registered adapter")
	service := fs.String("service", "", "service override; must match the registered adapter")
	payloadFile := fs.String("payload-file", "", "file whose SHA-256 is the request payload digest (default: empty body)")
	action := fs.String("action", "", "Tencent Cloud API 3.0 action name / X-TC-Action (tencent-tc3 only)")
	outPath := fs.String("out", "", "write the signature headers as JSON to this path (0600)")
	var headers headerFlag
	fs.Var(&headers, "header", "request header to sign, Name: value (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *binding == "" || *method == "" || *rawURL == "" {
		return fmt.Errorf("--binding, --method and --url are required")
	}
	if *action != "" && protocol != "tencent-tc3" {
		return fmt.Errorf("--action is only valid for tencent-tc3")
	}

	payloadHash, err := payloadDigest(*payloadFile)
	if err != nil {
		return err
	}
	sess, err := client().CreateSession("keykoi sign "+protocol, false)
	if err != nil {
		return err
	}
	// 签名结束即撤销本次会话，避免每次签名留下运行时会话。
	defer func() {
		_ = client().Post("/v1/sessions/close", map[string]any{"session_id": sess.ID}, nil)
	}()
	body := map[string]any{
		"token":          sess.Token,
		"binding_id":     *binding,
		"protocol":       protocol,
		"method":         *method,
		"url":            *rawURL,
		"headers":        headers.Map(),
		"payload_sha256": payloadHash,
	}
	if *region != "" {
		body["region"] = *region
	}
	if *service != "" {
		body["service"] = *service
	}
	if *action != "" {
		body["action"] = *action
	}
	var out struct {
		Headers map[string]string `json:"headers"`
	}
	if err := client().Post("/v1/signatures", body, &out); err != nil {
		return err
	}
	if len(out.Headers) == 0 {
		return fmt.Errorf("keykoid returned no signature headers")
	}

	if *outPath != "" {
		data, err := json.MarshalIndent(out.Headers, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if err := os.WriteFile(*outPath, data, 0o600); err != nil {
			return err
		}
		if err := os.Chmod(*outPath, 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "signature headers written to %s\n", *outPath)
		return nil
	}
	if g.json {
		return printJSON(out.Headers)
	}
	for _, name := range orderSignatureHeaders(out.Headers) {
		fmt.Printf("%s: %s\n", name, out.Headers[name])
	}
	return nil
}

func payloadDigest(path string) (string, error) {
	h := sha256.New()
	if path == "" {
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open payload file: %w", err)
	}
	defer f.Close()
	n, err := io.Copy(h, io.LimitReader(f, maxSignPayloadBytes+1))
	if err != nil {
		return "", fmt.Errorf("read payload file: %w", err)
	}
	if n > maxSignPayloadBytes {
		return "", fmt.Errorf("payload file exceeds %d bytes; chunked uploads are not a supported signing mode", maxSignPayloadBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func orderSignatureHeaders(h map[string]string) []string {
	preferred := []string{
		"Authorization",
		"X-Amz-Date", "X-Amz-Content-Sha256", "X-Amz-Security-Token",
		"X-TC-Timestamp", "X-TC-Action", "X-TC-Token",
		"X-Sdk-Date", "X-Security-Token",
	}
	seen := map[string]bool{}
	names := make([]string, 0, len(h))
	for _, name := range preferred {
		if _, ok := h[name]; ok {
			seen[name] = true
			names = append(names, name)
		}
	}
	var rest []string
	for name := range h {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	return append(names, rest...)
}
