package osruntime

import (
	"fmt"
	"net"
	"strings"
)

// ListenLoopbackTCP opens a TCP listener and verifies its actual bound address.
func ListenLoopbackTCP(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if !strings.EqualFold(host, "localhost") && !net.ParseIP(host).IsLoopback() {
		return nil, fmt.Errorf("listen address %q must be a loopback address", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if !ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
		_ = ln.Close()
		return nil, fmt.Errorf("listen address %q resolved outside loopback", addr)
	}
	return ln, nil
}
