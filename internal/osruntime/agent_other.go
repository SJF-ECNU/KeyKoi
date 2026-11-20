//go:build !darwin || !cgo

package osruntime

import "net"

// ProcessExecutables reports no ancestry where macOS process inspection is unavailable.
func ProcessExecutables(net.Conn) []string { return nil }
