package osruntime

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ResolveDataDir 返回本机数据目录。shim 与主 CLI 必须共用这一个解析，
// 否则安装后直接启动 `gh`、`aliyun` 等入口时会落到旧默认目录，
// 找不到安装目录下的 data/keykoid.sock。
//
// 解析顺序：KEYKOI_DATA_DIR 环境变量 → 可执行文件旁的 data/（存在后台 socket 时）
// → 本机默认数据目录。
func ResolveDataDir() string {
	if v := os.Getenv("KEYKOI_DATA_DIR"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			installed := filepath.Join(filepath.Dir(filepath.Dir(resolved)), "data")
			if info, err := os.Stat(SocketPath(installed)); err == nil && info.Mode()&os.ModeSocket != 0 {
				return installed
			}
		}
	}
	return DefaultDataDir()
}

// ErrSocketLive 表示路径上已有可连接的监听者，调用方不得替换它。
var ErrSocketLive = errors.New("socket is already served by a running process")

// ListenUnix 在 path 上建立只允许当前用户的本地监听。
// 监听目录以 0700 创建，socket 文件以 0600 创建，并在 Accept 时校验对端用户。
//
// 替换路径前先探测：能连上说明另一个实例仍在服务，直接报错而不是把它的 socket
// 删掉；只有连接被拒绝（残留文件）才清理。
func ListenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("prepare socket directory: %w", err)
	}
	if err := clearStaleSocket(path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return &sameUserListener{Listener: ln}, nil
}

// clearStaleSocket 只在确认没有活跃监听者时删除残留 socket 文件。
func clearStaleSocket(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace %s: it exists and is not a socket", path)
	}
	conn, err := net.DialTimeout("unix", path, 300*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("%w: %s", ErrSocketLive, path)
	}
	// 只有「连接被拒绝」或「文件已消失」能证明没有服务在用这个路径。
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return os.Remove(path)
	}
	return fmt.Errorf("cannot verify socket %s is stale: %w", path, err)
}
