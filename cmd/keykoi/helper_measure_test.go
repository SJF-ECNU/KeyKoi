package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"keykoi/internal/measure"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// TestMeasureClientRejectsCrossOriginRedirect 覆盖 34：测量请求带着中介会话令牌，
// 跳转到别的来源必须被拒绝。
func TestMeasureClientRejectsCrossOriginRedirect(t *testing.T) {
	c := newMeasureClient()
	via := []*http.Request{{URL: mustParseURL(t, "http://127.0.0.1:49717/gateway/svc/echo")}}
	req, err := http.NewRequest(http.MethodGet, "http://collector.example/collect", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-KeyKoi-Session", "kks_secret")
	req.Header.Set("Authorization", "Bearer kks_secret")
	if err := c.CheckRedirect(req, via); err == nil {
		t.Fatal("cross-origin redirect was followed")
	}
}

// TestMeasureClientStripsIntermediaryHeaders 覆盖 34：同来源跳转也不携带中介会话头。
func TestMeasureClientStripsIntermediaryHeaders(t *testing.T) {
	c := newMeasureClient()
	via := []*http.Request{{URL: mustParseURL(t, "http://127.0.0.1/gateway/svc/echo")}}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/gateway/svc/moved", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-KeyKoi-Session", "kks_secret")
	req.Header.Set("X-KeyKoi-Caller", "measure")
	req.Header.Set("Authorization", "Bearer kks_secret")
	req.Header.Set("Accept", "application/json")
	if err := c.CheckRedirect(req, via); err != nil {
		t.Fatalf("same-origin redirect rejected: %v", err)
	}
	for _, name := range []string{"X-KeyKoi-Session", "X-KeyKoi-Caller", "Authorization"} {
		if got := req.Header.Get(name); got != "" {
			t.Fatalf("%s was carried to the redirect target: %q", name, got)
		}
	}
	if req.Header.Get("Accept") != "application/json" {
		t.Fatal("unrelated headers must be preserved across same-origin redirects")
	}
}

// TestMeasureRunDoesNotFollowCrossOrigin 覆盖 34 的端到端路径：上游返回跳转时
// 测量客户端不再向跳转目标发出带会话头的请求。
func TestMeasureRunDoesNotFollowCrossOrigin(t *testing.T) {
	var hits int64
	var leaked int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		if r.Header.Get("X-KeyKoi-Session") != "" || r.Header.Get("Authorization") != "" {
			atomic.AddInt64(&leaked, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/collect", http.StatusFound)
	}))
	defer redirector.Close()

	res := measure.Run(context.Background(), newMeasureClient(), "proxy", redirector.URL+"/echo",
		map[string]string{"X-KeyKoi-Session": "kks_secret"}, 1)
	if atomic.LoadInt64(&hits) != 0 {
		t.Fatalf("measurement followed the cross-origin redirect: %d requests reached the target", hits)
	}
	if atomic.LoadInt64(&leaked) != 0 {
		t.Fatal("intermediary session headers reached the redirect target")
	}
	if res.Errors == 0 {
		t.Fatal("refused redirect must be recorded as a failed sample")
	}
}
