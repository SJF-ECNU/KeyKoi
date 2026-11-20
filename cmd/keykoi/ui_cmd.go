package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// cmdUI 在本机浏览器里打开管理看板，把管理令牌经 URL fragment 交给页面。
//
// 令牌只出现在链接的 fragment 里：页面在加载时读取 token=<值>、填进登录框并自动
// 连接，然后立即用 history.replaceState 清除 hash，因此令牌不会留在地址栏、
// 历史记录或服务端请求行里。默认模式不把令牌写到标准输出；令牌只随
// `--no-open` 打印的登录链接出现一次，方便在没有自动打开能力的终端里复制。
func cmdUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	admin := fs.String("admin", "", "管理界面地址，例如 127.0.0.1:8378（默认取后台实际监听地址）")
	noOpen := fs.Bool("no-open", false, "只打印登录链接与说明，不启动浏览器")
	if err := fs.Parse(args); err != nil {
		return err
	}

	addr := strings.TrimSpace(*admin)
	if addr == "" {
		var st map[string]any
		if err := client().Get("/v1/status", &st); err != nil {
			return fmt.Errorf("读取后台管理地址失败（keykoid 是否在运行，或用 --admin ADDR 指定）：%w", err)
		}
		if v, ok := st["admin"].(string); ok {
			addr = strings.TrimSpace(v)
		}
		if addr == "" {
			return errors.New("后台没有启用管理界面；用 --admin ADDR 指定地址")
		}
	}
	base, err := adminBaseURL(addr)
	if err != nil {
		return err
	}
	token, err := adminTokenFromDisk(g.dataDir)
	if err != nil {
		return err
	}

	link := base + "/#token=" + url.QueryEscape(token)
	if *noOpen {
		fmt.Println("登录链接（令牌在 fragment 里，页面读取后立即清除）：")
		fmt.Println(link)
		fmt.Println("在浏览器打开上面的链接会自动填入令牌并连接；令牌不进入请求行、Referer 或服务端日志。")
		return nil
	}
	if err := openBrowser(link); err != nil {
		return err
	}
	fmt.Printf("已在本机浏览器打开 %s/\n", base)
	fmt.Println("令牌经 URL fragment 传递，页面读取后立即清除，不留在地址栏与浏览历史里。")
	return nil
}

// adminBaseURL 把 `host:port` 或带 scheme 的地址规范化成 `scheme://host[:port][/path]`。
func adminBaseURL(addr string) (string, error) {
	raw := addr
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("无法解析管理地址 %q：%w", addr, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("管理地址 %q 只支持 http/https", addr)
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return "", errors.New("管理地址必须为本机回环地址")
	}
	if u.User != nil {
		return "", errors.New("管理地址不能包含用户名或密码")
	}
	return u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/"), nil
}

// adminTokenFromDisk 按与其它子命令相同的数据目录规则读取管理令牌。
func adminTokenFromDisk(dataDir string) (string, error) {
	path := filepath.Join(dataDir, "admin.token")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("读取管理令牌失败（先初始化密钥库或启动 keykoid）：%w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("管理令牌文件为空：%s", path)
	}
	return token, nil
}

// openBrowser 调用系统默认浏览器。子进程输出一律丢弃：链接里含令牌，
// 任何回显都会把令牌写进终端或日志。
func openBrowser(link string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", link)
	case "linux":
		cmd = exec.Command("xdg-open", link)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", link)
	default:
		return errors.New("当前系统不支持自动打开浏览器；用 --no-open 查看登录链接")
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("无法启动浏览器（%v）；用 --no-open 查看登录链接", err)
	}
	return nil
}
