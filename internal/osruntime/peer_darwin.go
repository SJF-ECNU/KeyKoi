//go:build darwin

package osruntime

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID 返回 Unix socket 对端的有效用户 ID。
// macOS 使用 LOCAL_PEERCRED / xucred，只在内核提供时可信。
func PeerUID(conn net.Conn) (uint32, bool, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false, fmt.Errorf("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false, err
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, false, err
	}
	if credErr != nil {
		return 0, false, credErr
	}
	return cred.Uid, true, nil
}
