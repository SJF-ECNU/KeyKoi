package osruntime

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// shortDir 返回一个短路径目录：Unix socket 路径长度在 macOS 上有限制。
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "kk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// 已有监听者的 socket 不能被替换：那会让原客户端失去连接。
func TestListenUnixRefusesLiveSocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "daemon.sock")
	first, err := ListenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	second, err := ListenUnix(path)
	if err == nil {
		_ = second.Close()
		t.Fatal("a second listener must not replace a live socket")
	}
	if !errors.Is(err, ErrSocketLive) {
		t.Fatalf("expected ErrSocketLive, got %v", err)
	}
	// 原监听者仍然可用。
	ok := make(chan error, 1)
	go func() {
		conn, aerr := first.Accept()
		if aerr != nil {
			ok <- aerr
			return
		}
		_ = conn.Close()
		ok <- nil
	}()
	conn, err := DialUnix(path)
	if err != nil {
		t.Fatalf("the original socket must stay usable: %v", err)
	}
	_ = conn.Close()
	if err := <-ok; err != nil {
		t.Fatalf("accept failed: %v", err)
	}
}

// 残留（无人监听）的 socket 文件可以被清理后重新监听。
func TestListenUnixClearsStaleSocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "stale.sock")
	// 建一个关闭后仍留在磁盘上的 socket 文件，模拟异常退出留下的残留。
	raw, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	raw.SetUnlinkOnClose(false)
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected a leftover socket file: %v", err)
	}
	second, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("a stale socket must be replaceable: %v", err)
	}
	_ = second.Close()
}

// 非 socket 的普通文件不会被当成残留删除。
func TestListenUnixRefusesRegularFile(t *testing.T) {
	path := filepath.Join(shortDir(t), "notasocket")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenUnix(path); err == nil {
		t.Fatal("a regular file must not be replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "data" {
		t.Fatalf("the file must be left untouched: %v %q", err, data)
	}
}

// 数据目录解析：环境变量优先，其次是安装目录旁的 data/。
func TestResolveDataDirPrecedence(t *testing.T) {
	t.Setenv("KEYKOI_DATA_DIR", "/tmp/keykoi-env-dir")
	if got := ResolveDataDir(); got != "/tmp/keykoi-env-dir" {
		t.Fatalf("KEYKOI_DATA_DIR must win, got %q", got)
	}
	t.Setenv("KEYKOI_DATA_DIR", "")
	if got := ResolveDataDir(); got == "" {
		t.Fatal("ResolveDataDir must always return a path")
	}
}
