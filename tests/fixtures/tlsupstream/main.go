// Command tlsupstream 是 p4 验收用的受控 HTTPS 上游。
//
// 它自己生成测试 CA 与服务器证书（写入 --ca-dir），只回报是否收到预期认证头，
// 不把凭证写盘；/stats 用于验证未登记目标没有到达上游、令牌没有泄露。
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"keykoi/internal/tlsproxy"
)

type stats struct {
	mu            sync.Mutex
	requests      int
	matched       int
	lastPath      string
	lastQuery     string
	authScheme    string
	headerNames   []string
	sessionTokens int
}

func (s *stats) observe(r *http.Request, expect string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	s.lastPath = r.URL.Path
	s.lastQuery = r.URL.RawQuery
	s.authScheme = authScheme(r.Header.Get("Authorization"))
	s.headerNames = s.headerNames[:0]
	for k := range r.Header {
		s.headerNames = append(s.headerNames, k)
	}
	for _, vals := range r.Header {
		for _, v := range vals {
			if strings.Contains(v, "kks_") {
				s.sessionTokens++
			}
		}
	}
	ok := false
	got := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(expect, "Bearer "):
		ok = got == expect
	case strings.HasPrefix(expect, "Basic "):
		ok = got == expect
	case strings.HasPrefix(expect, "raw:"):
		ok = r.Header.Get(strings.TrimPrefix(expect, "raw:")) != ""
	}
	if ok {
		s.matched++
	}
	return ok
}

func authScheme(v string) string {
	if v == "" {
		return "none"
	}
	if i := strings.IndexByte(v, ' '); i > 0 {
		return v[:i]
	}
	return "other"
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	hostname := flag.String("hostname", "api.keykoi.test", "primary certificate name")
	caDir := flag.String("ca-dir", "", "directory for the test CA (created if missing)")
	addrFile := flag.String("addr-file", "", "write the actual listen address to this file")
	expect := flag.String("expect", "", "expected auth header, e.g. Bearer <random>")
	flag.Parse()
	if *caDir == "" {
		log.Fatal("--ca-dir is required")
	}

	ca, err := tlsproxy.LoadOrCreateCA(*caDir, time.Now)
	if err != nil {
		log.Fatalf("prepare test CA: %v", err)
	}
	cert, err := ca.CertificateForHosts(*hostname, "127.0.0.1", "::1")
	if err != nil {
		log.Fatalf("issue test certificate: %v", err)
	}

	st := &stats{}
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		matched := st.observe(r, *expect)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"matched":            matched,
			"path":               r.URL.EscapedPath(),
			"query":              r.URL.RawQuery,
			"auth_scheme":        authScheme(r.Header.Get("Authorization")),
			"x_api_key_present":  r.Header.Get("X-Api-Key") != "",
			"keykoi_header_seen": hasKeyKoiHeader(r),
		})
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		st.observe(r, *expect)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 4; i++ {
			fmt.Fprintf(w, "chunk-%d\n", i)
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(60 * time.Millisecond)
		}
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"requests":          st.requests,
			"matched":           st.matched,
			"session_tokens":    st.sessionTokens,
			"last_path":         st.lastPath,
			"last_query":        st.lastQuery,
			"last_auth_scheme":  st.authScheme,
			"last_header_names": st.headerNames,
		})
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	actual := ln.Addr().String()
	if *addrFile != "" {
		_ = os.WriteFile(*addrFile, []byte(actual), 0o600)
	}
	fmt.Println(actual)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	server := &http.Server{Handler: mux, TLSConfig: tlsConfig, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.Serve(tls.NewListener(ln, tlsConfig)))
}

func hasKeyKoiHeader(r *http.Request) bool {
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-keykoi-") {
			return true
		}
	}
	return false
}
