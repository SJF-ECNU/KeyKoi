// Command githttp 是受控 git smart HTTP 服务：要求 Basic 认证并转给 git http-backend。
// 只用于验收，不记录凭据。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type stats struct {
	mu       sync.Mutex
	requests int
	denied   int
	kksSeen  int
	lastPath string
}

func (s *stats) observe(r *http.Request, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	if !ok {
		s.denied++
	}
	s.lastPath = r.URL.Path
	if strings.Contains(r.Header.Get("Authorization"), "kks_") {
		s.kksSeen++
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	root := flag.String("root", "", "git project root (bare repositories)")
	expect := flag.String("expect-basic", "", "expected Authorization header value")
	addrFile := flag.String("addr-file", "", "write listen address here")
	flag.Parse()
	if *root == "" || *expect == "" {
		log.Fatal("--root and --expect-basic are required")
	}
	st := &stats{}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"requests": st.requests, "denied": st.denied,
			"kks_seen": st.kksSeen, "last_path": st.lastPath,
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ok := r.Header.Get("Authorization") == *expect
		st.observe(r, ok)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := serveCGI(w, r, *root); err != nil {
			http.Error(w, "git backend failed", http.StatusInternalServerError)
		}
	})
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	if *addrFile != "" {
		_ = os.WriteFile(*addrFile, []byte(ln.Addr().String()), 0o600)
	}
	fmt.Println(ln.Addr().String())
	log.Fatal(http.Serve(ln, mux))
}

func serveCGI(w http.ResponseWriter, r *http.Request, root string) error {
	cmd := exec.Command("git", "http-backend")
	cmd.Env = append(os.Environ(),
		"GIT_PROJECT_ROOT="+root,
		"GIT_HTTP_EXPORT_ALL=1",
		"PATH_INFO="+r.URL.Path,
		"QUERY_STRING="+r.URL.RawQuery,
		"REQUEST_METHOD="+r.Method,
		"CONTENT_TYPE="+r.Header.Get("Content-Type"),
		"CONTENT_LENGTH="+strconv.FormatInt(r.ContentLength, 10),
		"REMOTE_USER=fixture",
		"REMOTE_ADDR=127.0.0.1",
		"SERVER_PROTOCOL=HTTP/1.1",
		"GATEWAY_INTERFACE=CGI/1.1",
	)
	var body bytes.Buffer
	if r.Body != nil {
		_, _ = io.Copy(&body, r.Body)
		cmd.Stdin = &body
	}
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	head, rest, ok := bytes.Cut(out, []byte("\r\n\r\n"))
	if !ok {
		head, rest, ok = bytes.Cut(out, []byte("\n\n"))
		if !ok {
			return fmt.Errorf("malformed CGI output")
		}
	}
	status := http.StatusOK
	for _, line := range strings.Split(string(head), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "status:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if code, err := strconv.Atoi(parts[1]); err == nil {
					status = code
				}
			}
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			w.Header().Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	w.WriteHeader(status)
	_, _ = w.Write(rest)
	return nil
}
