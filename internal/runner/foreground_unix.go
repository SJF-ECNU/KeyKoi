//go:build darwin || linux

package runner

import (
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// applyForeground 在标准输入是终端时把子进程放进前台进程组并接管终端。
//
// 运行器为了能整组转发信号给子进程单开了进程组；如果不同时移交前台，
// 交互式工具（分页器、编辑器、口令提示）读写终端会因 SIGTTIN/SIGTTOU 挂起。
// 返回的函数在子进程结束后把终端前台还给启动器。
func applyForeground(attr *syscall.SysProcAttr, stdin io.Reader) func() {
	f, ok := stdin.(*os.File)
	if !ok || f == nil {
		return func() {}
	}
	fd := int(f.Fd())
	if !term.IsTerminal(fd) {
		return func() {}
	}
	attr.Foreground = true
	attr.Ctty = fd
	return func() {
		// 子进程退出后启动器仍要读终端；先把自己放回前台进程组。
		_ = unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, os.Getpid())
	}
}
