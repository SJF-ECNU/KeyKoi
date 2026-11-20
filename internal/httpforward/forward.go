// Package httpforward contains shared HTTP relay mechanics for the KeyKoi gateways.
package httpforward

import (
	"errors"
	"io"
	"net/http"
	"strings"
)

var hopHeaders = [...]string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// CopyHeaders appends headers outside the fixed hop-by-hop list, preserving repeated values.
func CopyHeaders(dst, src http.Header) {
	for name, values := range src {
		if isHopHeader(name) {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func isHopHeader(name string) bool {
	for _, header := range hopHeaders {
		if strings.EqualFold(name, header) {
			return true
		}
	}
	return false
}

// StreamBody flushes each written chunk and distinguishes upstream interruption
// from a write failure so callers can retain their audit and abort behavior.
func StreamBody(w http.ResponseWriter, from io.Reader) (readErr, writeErr error) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := from.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return nil, err
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, nil
			}
			return err, nil
		}
	}
}
