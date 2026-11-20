//go:build !darwin && !linux

package osruntime

import (
	"fmt"
	"net"
)

// PeerUID 在未实现的平台上明确报告不支持，而不是降级为普通端口。
func PeerUID(net.Conn) (uint32, bool, error) {
	return 0, false, fmt.Errorf("peer credential verification is not implemented on this platform")
}
