//go:build !darwin && !linux

package runner

import (
	"io"
	"syscall"
)

// applyForeground 在未实现终端移交的平台上保持原有行为。
func applyForeground(_ *syscall.SysProcAttr, _ io.Reader) func() { return func() {} }
