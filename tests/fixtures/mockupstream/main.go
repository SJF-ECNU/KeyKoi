// Command mockupstream 是受控上游：它只回报是否收到预期凭证，不把凭证落盘。
// 用于验证网关注入、目标绑定、流式时序与真实 CLI 的认证行为。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type stats struct {
	mu            sync.Mutex
	requests      int
	matched       int
	tokenLeaked   int
	lastPath      string
	lastQuery     string
	authScheme    string
	headerNames   []string
	sessionTokens int
	// Aliyun RPC 观测：只记录是否存在与动作名，不记录秘密值。
	accessKeySeen   bool
	signatureSeen   bool
	securityTokSeen bool
	lastAction      string
	queryMatched    int
	headerMatched   int
}

func (s *stats) observeQuery(q url.Values) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessKeySeen = q.Get("AccessKeyId") != ""
	s.signatureSeen = q.Get("Signature") != ""
	s.securityTokSeen = q.Get("SecurityToken") != ""
	s.lastAction = q.Get("Action")
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
	q := r.URL.Query()
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		for k, vals := range r.PostForm {
			if len(vals) > 0 {
				q.Set(k, vals[0])
			}
		}
	}
	if expectedHeader != "" {
		if name, value, ok := strings.Cut(expectedHeader, "="); ok && r.Header.Get(name) == value {
			s.headerMatched++
		}
	}
	if expectedQuery != "" {
		if k, v, ok := strings.Cut(expectedQuery, "="); ok && q.Get(k) == v {
			s.queryMatched++
		}
	}
	if q.Get("AccessKeyId") != "" {
		s.accessKeySeen = true
	}
	if q.Get("Signature") != "" {
		s.signatureSeen = true
	}
	if q.Get("SecurityToken") != "" {
		s.securityTokSeen = true
	}
	if q.Get("Action") != "" {
		s.lastAction = q.Get("Action")
	}
	got := r.Header.Get("Authorization")
	ok := false
	switch {
	case strings.HasPrefix(expect, "Bearer "):
		ok = got == expect
	case strings.HasPrefix(expect, "Basic "):
		ok = got == expect
	case strings.HasPrefix(expect, "raw:"):
		ok = r.Header.Get(strings.TrimPrefix(expect, "raw:")) != ""
	case strings.HasPrefix(expect, "sigv4:"):
		// AWS CLI 会自行 SigV4 签名；只校验凭证 ID 出现在签名头中。
		ok = strings.Contains(got, strings.TrimPrefix(expect, "sigv4:"))
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
	expect := flag.String("expect", "", "expected auth header (Bearer X / Basic Y / raw:Header:Value / sigv4:ACCESS_KEY_ID)")
	expectQuery := flag.String("expect-query", "", "expected query/form parameter K=V (e.g. AccessKeyId=AKID)")
	expectHeader := flag.String("expect-header", "", "expected header Name=Value (exact match)")
	addrFile := flag.String("addr-file", "", "write actual listen address to this file")
	redirectTo := flag.String("redirect-to", "http://127.0.0.1:9/elsewhere", "cross-origin redirect target")
	tlsCert := flag.String("tls-cert", "", "serve HTTPS with this certificate")
	tlsKey := flag.String("tls-key", "", "serve HTTPS with this key")
	flag.Parse()

	expectedQuery = *expectQuery
	expectedHeader = *expectHeader
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

	// STS GetCallerIdentity：让真实 AWS CLI 走一遍 credential_process。
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		matched := st.observe(r, *expect)
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
		}
		// 阿里云 RPC 风格请求：Action 在 query 或表单里，返回对应 XML。
		action := r.URL.Query().Get("Action")
		if action == "" {
			action = r.PostFormValue("Action")
		}
		if action != "" && action != "GetCallerIdentity" {
			w.Header().Set("Content-Type", "text/xml")
			w.WriteHeader(http.StatusOK)
			if action == "DescribeRegions" {
				fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<DescribeRegionsResponse><RequestId>fixture-request</RequestId><Regions><Region><RegionId>cn-hangzhou</RegionId><LocalName>Hangzhou</LocalName><Status>available</Status></Region></Regions></DescribeRegionsResponse>`)
				return
			}
			fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><%sResponse><RequestId>fixture-request</RequestId></%sResponse>`, action, action)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::000000000000:user/keykoi-fixture</Arn>
    <UserId>KEYKOIFIXTURE</UserId>
    <Account>000000000000</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>fixture-request</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`)
		_ = matched
	})

	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		st.observe(r, *expect)
		chunks := 4
		delay := 120 * time.Millisecond
		if v := r.URL.Query().Get("chunks"); v != "" {
			if n, err := fmt.Sscanf(v, "%d", &chunks); n != 1 || err != nil {
				chunks = 4
			}
		}
		if v := r.URL.Query().Get("delay"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				delay = d
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			fmt.Fprintf(w, "chunk-%d\n", i)
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(delay)
		}
	})

	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		st.observe(r, *expect)
		n := 1 << 20
		if v := r.URL.Query().Get("bytes"); v != "" {
			if parsed, err := parseInt(v); err == nil {
				n = parsed
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		chunk := make([]byte, 32*1024)
		for i := range chunk {
			chunk[i] = 'a'
		}
		for written := 0; written < n; {
			m := len(chunk)
			if n-written < m {
				m = n - written
			}
			if _, err := w.Write(chunk[:m]); err != nil {
				return
			}
			written += m
		}
	})

	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		st.observe(r, *expect)
		http.Redirect(w, r, *redirectTo, http.StatusFound)
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"requests":            st.requests,
			"matched":             st.matched,
			"session_tokens":      st.sessionTokens,
			"last_path":           st.lastPath,
			"last_query":          st.lastQuery,
			"last_auth_scheme":    st.authScheme,
			"last_header_names":   st.headerNames,
			"last_action":         st.lastAction,
			"access_key_seen":     st.accessKeySeen,
			"signature_seen":      st.signatureSeen,
			"security_token_seen": st.securityTokSeen,
			"query_matched":       st.queryMatched,
			"header_matched":      st.headerMatched,
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
	if *tlsCert != "" && *tlsKey != "" {
		log.Fatal(http.ServeTLS(ln, mux, *tlsCert, *tlsKey))
	}
	log.Fatal(http.Serve(ln, mux))
}

func hasKeyKoiHeader(r *http.Request) bool {
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-keykoi-") {
			return true
		}
	}
	return false
}

var expectedQuery string
var expectedHeader string

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}
