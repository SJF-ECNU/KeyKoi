//go:build linux

package osruntime

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID 返回 Unix socket 对端的用户 ID（SO_PEERCRED）。
func PeerUID(conn net.Conn) (uint32, bool, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false, fmt.Errorf("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, false, err
	}
	if credErr != nil {
		return 0, false, credErr
	}
	return cred.Uid, true, nil
}
