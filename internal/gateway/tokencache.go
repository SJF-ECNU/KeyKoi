package gateway

import (
	"context"
	"fmt"
	"sync"
	"time"

	"keykoi/internal/model"
	"keykoi/internal/secret"
)

// maxCachedTokens 是内存缓存可保留的条目上限；超过后先清理已过期条目。
// token 缓存只驻留内存，不写入磁盘，也不参与任何序列化。
const maxCachedTokens = 256

// tokenCache 是按缓存键保存 access token 的内存缓存，并保证同一个键上的
// 并发请求只触发一次上游换取（single-flight）：
//   - 命中的条目必须是“尚未到期”的；过期条目不返回。
//   - 换取失败的请求不写入缓存，下一次请求会重新尝试上游。
//   - 并发等待者共享同一次换取的结果（成功或失败），不重复请求 token 端点。
type tokenCache struct {
	mu       sync.Mutex
	entries  map[string]cachedToken
	inflight map[string]*tokenFlight
	now      func() time.Time
}

type cachedToken struct {
	value     secret.Value
	expiresAt time.Time
}

// tokenFlight 是一次进行中的换取；done 关闭后字段才可读。
type tokenFlight struct {
	done      chan struct{}
	value     secret.Value
	expiresAt time.Time
	err       error
}

func newTokenCache(now func() time.Time) *tokenCache {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &tokenCache{
		entries:  make(map[string]cachedToken),
		inflight: make(map[string]*tokenFlight),
		now:      now,
	}
}

// get 返回缓存有效期内可用的 token；否则调用 fetch 换取一次。
// fetch 返回零值 expiresAt 表示该 token 不可缓存（上游未给 expires_in）。
func (c *tokenCache) get(ctx context.Context, key string, fetch func(context.Context) (secret.Value, time.Time, error)) (secret.Value, error) {
	for {
		c.mu.Lock()
		if entry, ok := c.entries[key]; ok {
			if c.now().Before(entry.expiresAt) {
				value := entry.value
				c.mu.Unlock()
				return value, nil
			}
			delete(c.entries, key)
		}
		if flight, ok := c.inflight[key]; ok {
			c.mu.Unlock()
			select {
			case <-flight.done:
			case <-ctx.Done():
				return secret.Empty, model.WrapError(model.CodeUpstreamUnavailable, ctx.Err(), "token exchange canceled")
			}
			if flight.err != nil {
				return secret.Empty, flight.err
			}
			return flight.value, nil
		}
		flight := &tokenFlight{done: make(chan struct{})}
		c.inflight[key] = flight
		c.mu.Unlock()

		// 换取过程不持锁，避免阻塞其它键的缓存读取。
		value, expiresAt, err := fetch(ctx)

		c.mu.Lock()
		flight.value, flight.expiresAt, flight.err = value, expiresAt, err
		if err == nil && !expiresAt.IsZero() && c.now().Before(expiresAt) {
			c.entries[key] = cachedToken{value: value, expiresAt: expiresAt}
			c.pruneLocked()
		}
		delete(c.inflight, key)
		close(flight.done)
		c.mu.Unlock()
		return value, err
	}
}

// pruneLocked 在条目过多时清理已过期项，避免长期运行时无界增长。
func (c *tokenCache) pruneLocked() {
	if len(c.entries) <= maxCachedTokens {
		return
	}
	now := c.now()
	for key, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

// tokenCacheKey 组合缓存键：认证方式 + 凭证 ID + 凭证版本 + scope。
// 版本变化必然落到新键，因此轮换后不会复用旧版凭证换来的 token。
func tokenCacheKey(scheme model.AuthScheme, version model.CredentialVersion, scope string) string {
	return fmt.Sprintf("%s|%s|%d|%s", scheme, version.CredentialID, version.Version, scope)
}
