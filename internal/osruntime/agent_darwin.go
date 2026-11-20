//go:build darwin && cgo

package osruntime

/*
#include <libproc.h>
*/
import "C"

import (
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ProcessExecutables returns the kernel-reported executable paths from the IPC peer to its ancestors.
func ProcessExecutables(conn net.Conn) []string {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil
	}
	var pid int
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		pid, peerErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil || peerErr != nil {
		return nil
	}

	var paths []string
	for depth := 0; depth < 32 && pid > 1; depth++ {
		proc, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil || int(proc.Proc.P_pid) != pid {
			break
		}
		if path := processPath(pid); path != "" {
			paths = append(paths, path)
		}
		pid = int(proc.Eproc.Ppid)
	}
	return paths
}

func processPath(pid int) string {
	var buf [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	if C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf))) <= 0 {
		return ""
	}
	return C.GoString(&buf[0])
}
