package daemon

import (
	"io/fs"
	"net"
	"net/http"
	"strings"

	"keykoi/web"
)

// adminRouter 提供本机管理界面与 JSON API。它只监听回环地址，
// 并校验 Host、Origin 与自定义请求头以防止浏览器跨站请求伪造。
func (d *Daemon) adminRouter() http.Handler {
	api := d.ipcRouter()
	static, err := fs.Sub(web.FS(), ".")
	if err != nil {
		static = web.FS()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host) {
			http.Error(w, `{"error":{"code":"SESSION_INVALID","message":"unexpected host"}}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/api/", http.StripPrefix("/api", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !d.adminRequestAllowed(w, r) {
			return
		}
		// 管理界面 API 一律要求本机管理员凭据；用钥接口在 IPC 上另走会话令牌。
		if tok := r.Header.Get("X-KeyKoi-Admin"); tok == "" || !subtleEqual(tok, d.adminToken) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"SESSION_INVALID","message":"management API requires the local administrator token"}}`))
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		api.ServeHTTP(w, r)
	})))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host) {
			http.Error(w, `{"error":{"code":"SESSION_INVALID","message":"unexpected host"}}`, http.StatusForbidden)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		data, err := fs.ReadFile(static, "index.html")
		if err != nil {
			http.Error(w, "management UI unavailable", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	})
	return mux
}

// adminRequestAllowed 校验 Host、Origin 与 CSRF 头。
func (d *Daemon) adminRequestAllowed(w http.ResponseWriter, r *http.Request) bool {
	if !hostAllowed(r.Host) {
		http.Error(w, `{"error":{"code":"SESSION_INVALID","message":"unexpected host"}}`, http.StatusForbidden)
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if !strings.HasSuffix(origin, "://"+r.Host) {
			http.Error(w, `{"error":{"code":"SESSION_INVALID","message":"cross-origin management request rejected"}}`, http.StatusForbidden)
			return false
		}
	}
	if r.Method != http.MethodGet {
		if r.Header.Get("X-KeyKoi-CSRF") != "1" {
			http.Error(w, `{"error":{"code":"SESSION_INVALID","message":"missing CSRF header"}}`, http.StatusForbidden)
			return false
		}
	}
	return true
}

// hostAllowed 只接受 127.0.0.1 / localhost / [::1] 形式的本机 Host。
func hostAllowed(host string) bool {
	h := host
	if name, _, err := net.SplitHostPort(host); err == nil {
		h = name
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}
