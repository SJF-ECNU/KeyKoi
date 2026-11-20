package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"keykoi/internal/helper"
	"keykoi/internal/measure"
)

func timeNow() time.Time { return time.Now() }

func cmdHelper(sub string, args []string) error {
	switch sub {
	case "aws":
		fs := flag.NewFlagSet("helper aws", flag.ContinueOnError)
		binding := fs.String("binding", "", "binding id served to the tool")
		mode := fs.String("mode", "runtime_delivery", "delivery mode (runtime_delivery only)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *binding == "" {
			return fmt.Errorf("--binding is required")
		}
		return helper.RunAWS(context.Background(), helper.AWSOptions{
			Client: client(), BindingID: *binding, Mode: *mode,
		}, os.Stdout)
	case "git-token":
		fs := flag.NewFlagSet("helper git-token", flag.ContinueOnError)
		binding := fs.String("binding", "", "binding id whose proxy grant authorizes the repository")
		ttl := fs.Duration("ttl", time.Hour, "session lifetime")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *binding == "" {
			return fmt.Errorf("--binding is required")
		}
		sess, err := client().CreateSessionTTL("git-credential", false, *ttl)
		if err != nil {
			return err
		}
		// git 只需要把中介令牌当密码发送；真实仓库凭据由网关注入。
		fmt.Printf("username=keykoi\npassword=%s\n", sess.Token)
		return nil
	case "git":
		fs := flag.NewFlagSet("helper git", flag.ContinueOnError)
		binding := fs.String("binding", "", "binding id")
		action := fs.String("action", "", "get|store|erase")
		if err := fs.Parse(args); err != nil {
			return err
		}
		act := *action
		// git 会把动作作为位置参数追加，例如 `helper git --binding X get`。
		if act == "" && fs.NArg() > 0 {
			act = fs.Arg(0)
		}
		if *binding == "" || act == "" {
			return fmt.Errorf("--binding and an action (get|store|erase) are required")
		}
		return helper.RunGit(context.Background(), helper.AWSOptions{Client: client(), BindingID: *binding}, act, os.Stdin, os.Stdout)
	}
	return fmt.Errorf("unknown helper %q", sub)
}

func cmdMeasure(args []string) error {
	fs := flag.NewFlagSet("measure", flag.ContinueOnError)
	gateway := fs.String("gateway", "", "gateway address (default: from daemon status)")
	route := fs.String("route", "", "gateway route name")
	direct := fs.String("direct", "", "direct upstream base URL for comparison")
	path := fs.String("path", "/echo", "request path")
	requests := fs.Int("requests", 10, "number of requests per path")
	stream := fs.Bool("stream", false, "also measure streaming first-chunk timing")
	streamPath := fs.String("stream-path", "/stream?chunks=4&delay=120ms", "streaming endpoint path")
	out := fs.String("out", "", "write measurement JSON to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *route == "" {
		return fmt.Errorf("--route is required")
	}
	c := client()
	if *gateway == "" {
		st, err := c.Status()
		if err != nil {
			return err
		}
		gw, _ := st["gateway"].(string)
		if gw == "" {
			return fmt.Errorf("daemon did not report a gateway address; pass --gateway")
		}
		*gateway = gw
	}
	sess, err := c.CreateSession("measure", false)
	if err != nil {
		return err
	}
	proxyURL := "http://" + *gateway + "/gateway/" + *route + *path
	proxyClient := newMeasureClient()
	headers := map[string]string{"X-KeyKoi-Session": sess.Token}
	result := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"gateway":      *gateway,
		"route":        *route,
		"path":         *path,
	}
	proxyRes := measure.Run(context.Background(), proxyClient, "proxy", proxyURL, headers, *requests)
	result["proxy"] = proxyRes
	if *direct != "" {
		directURL := strings.TrimRight(*direct, "/") + *path
		directClient := newMeasureClient()
		directRes := measure.Run(context.Background(), directClient, "direct", directURL, nil, *requests)
		result["direct"] = directRes
	}
	if *stream {
		streamURL := "http://" + *gateway + "/gateway/" + *route + *streamPath
		sres := measure.RunStreaming(context.Background(), proxyClient, streamURL, headers)
		result["proxy_stream"] = sres
		if *direct != "" {
			dres := measure.RunStreaming(context.Background(), newMeasureClient(),
				strings.TrimRight(*direct, "/")+*streamPath, nil)
			result["direct_stream"] = dres
		}
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, data, 0o600); err != nil {
			return err
		}
	}
	if g.json {
		_, _ = os.Stdout.Write(data)
		fmt.Println()
		return nil
	}
	fmt.Println(proxyRes.Summary())
	if d, ok := result["direct"].(measure.Result); ok {
		fmt.Println(d.Summary())
	}
	if *stream {
		if ps, ok := result["proxy_stream"].(measure.StreamingResult); ok {
			fmt.Printf("proxy stream: first_chunk=%.2fms total=%.2fms chunks=%d\n", ps.FirstChunkMs, ps.TotalMs, len(ps.ChunkTimesMs))
		}
	}
	if *out != "" {
		fmt.Printf("measurement written to %s\n", *out)
	}
	return nil
}

// newMeasureClient 构造诊断测量用的 HTTP 客户端。
//
// 测量请求会带中介会话令牌（X-KeyKoi-Session）。Go 的默认跳转策略只拦
// Authorization/Cookie，自定义的中介请求头会被原样带到跳转目标，因此这里
// 显式限制跳转：目标必须与刚才测量的来源一致，且跳转请求不带中介会话头。
func newMeasureClient() *http.Client {
	return &http.Client{
		Transport:     newMeasureTransport(),
		Timeout:       60 * time.Second,
		CheckRedirect: checkMeasureRedirect,
	}
}

// maxMeasureRedirects 是单次测量允许跟随的同来源跳转次数。
const maxMeasureRedirects = 5

// checkMeasureRedirect 只放行同来源跳转，并在跳转前清除中介会话请求头。
// 跨来源跳转直接返回错误，客户端把响应当作失败样本记录，不再发出第二个请求。
func checkMeasureRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return http.ErrUseLastResponse
	}
	if len(via) >= maxMeasureRedirects {
		return fmt.Errorf("stopped after %d redirects", maxMeasureRedirects)
	}
	origin := via[0].URL
	if !sameOrigin(req.URL, origin) {
		return fmt.Errorf("redirect to %s is outside the measured origin %s and is not followed",
			redactedOrigin(req.URL), redactedOrigin(origin))
	}
	stripIntermediaryHeaders(req.Header)
	return nil
}

// sameOrigin 报告两个 URL 的 scheme 与 host（含默认端口归一）是否一致。
func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(originHost(a), originHost(b))
}

// originHost 返回归一化后的 host:port，省略 http/https 的默认端口。
func originHost(u *url.URL) string {
	host := strings.ToLower(u.Host)
	port := u.Port()
	switch {
	case u.Scheme == "http" && port == "80", u.Scheme == "https" && port == "443":
		return strings.TrimSuffix(host, ":"+port)
	}
	return host
}

// redactedOrigin 只保留 scheme://host:port，供错误信息与日志使用（不含路径与查询）。
func redactedOrigin(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// stripIntermediaryHeaders 清除会泄露中介会话的请求头：Authorization 与所有 X-KeyKoi-*。
func stripIntermediaryHeaders(h http.Header) {
	h.Del("Authorization")
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-keykoi-") {
			h.Del(name)
		}
	}
}

func newMeasureTransport() *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        16,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// readAllLimited 读取受控大小响应，供诊断命令使用。
func readAllLimited(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, n))
}
