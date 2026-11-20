package central

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// ListenPlan 是中心监听的传输安全决策。
type ListenPlan struct {
	// Addr 是实际监听地址。
	Addr string
	// TLS 为 true 时必须用 CertFile/KeyFile 启动 HTTPS。
	TLS      bool
	CertFile string
	KeyFile  string
}

// ResolveListenPlan 决定监听方式：回环地址允许明文，非回环地址必须显式提供
// 证书与私钥。设备秘密、许可与撤销事件都走这条链路，跨机器部署不允许明文。
func ResolveListenPlan(addr, certFile, keyFile string) (ListenPlan, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ListenPlan{}, fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	loopback := isLoopbackHost(host)
	if !loopback && (certFile == "" || keyFile == "") {
		return ListenPlan{}, fmt.Errorf("listening on non-loopback address %q requires both --tls-cert and --tls-key; device credentials and leases must not cross the network in plaintext", addr)
	}
	if (certFile == "") != (keyFile == "") {
		return ListenPlan{}, fmt.Errorf("--tls-cert and --tls-key must be provided together")
	}
	plan := ListenPlan{Addr: addr, TLS: certFile != "" && keyFile != "", CertFile: certFile, KeyFile: keyFile}
	if plan.TLS {
		for _, path := range []string{certFile, keyFile} {
			info, err := os.Stat(path)
			if err != nil {
				return ListenPlan{}, fmt.Errorf("TLS material %q is not readable: %w", path, err)
			}
			if info.IsDir() {
				return ListenPlan{}, fmt.Errorf("TLS material %q is a directory", path)
			}
		}
	}
	return plan, nil
}

// Describe 返回不含秘密的监听说明，供启动日志使用。
func (p ListenPlan) Describe() string {
	scheme := "http"
	if p.TLS {
		scheme = "https"
	}
	return scheme + "://" + p.Addr
}

// isLoopbackHost 判断监听主机是否只对本机可见。空主机表示全部网卡，不算回环。
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
