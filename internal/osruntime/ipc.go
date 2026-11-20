// Package osruntime 封装平台本地通信与宿主差异。本轮只实现 macOS 与 Linux 的
// Unix socket 对端校验；Windows 命名管道按延期范围保留接口。
package osruntime

import (
	"net"
	"os"
	"path/filepath"
	"time"
)

// sameUserListener 拒绝非当前用户的本地连接。
type sameUserListener struct {
	net.Listener
}

// Accept 校验对端凭据后才返回连接。
func (l *sameUserListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, ok, err := PeerUID(conn)
		if err != nil || !ok || uid != uint32(os.Getuid()) {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

// DialUnix 以短超时连接本地 socket。
func DialUnix(path string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.Dial("unix", path)
}

// DefaultDataDir 返回本机数据目录。
func DefaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Library", "Application Support", "KeyKoi")
}

// SocketPath 返回后台 IPC socket 路径。
func SocketPath(dataDir string) string {
	return filepath.Join(dataDir, "keykoid.sock")
}
