// Package measure 提供可复测的直连与代理测量：时间分位数、冷热连接与流式首块。
package measure

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sort"
	"time"
)

// Sample 是一次请求的观测值。
type Sample struct {
	StatusCode int     `json:"status"`
	TTFBms     float64 `json:"ttfb_ms"`
	TotalMs    float64 `json:"total_ms"`
	Bytes      int64   `json:"bytes"`
	Err        string  `json:"error,omitempty"`
}

// Result 是一组样本的统计。
type Result struct {
	Label       string             `json:"label"`
	URL         string             `json:"url"`
	Requests    int                `json:"requests"`
	Samples     []Sample           `json:"samples"`
	TTFBP       map[string]float64 `json:"ttfb_percentiles_ms"`
	TotalP      map[string]float64 `json:"total_percentiles_ms"`
	Errors      int                `json:"errors"`
	FirstColdMs float64            `json:"first_request_ms"`
}

// Run 顺序执行 n 次请求。第一次是冷连接（新进程新连接池），其余为热连接。
func Run(ctx context.Context, client *http.Client, label, url string, headers map[string]string, n int) Result {
	res := Result{Label: label, URL: url, Requests: n, Samples: make([]Sample, 0, n)}
	for i := 0; i < n; i++ {
		s := one(ctx, client, url, headers)
		if i == 0 {
			res.FirstColdMs = s.TotalMs
		}
		if s.Err != "" {
			res.Errors++
		}
		res.Samples = append(res.Samples, s)
	}
	var ttfb, total []float64
	for _, s := range res.Samples {
		if s.Err != "" {
			continue
		}
		ttfb = append(ttfb, s.TTFBms)
		total = append(total, s.TotalMs)
	}
	res.TTFBP = percentiles(ttfb)
	res.TotalP = percentiles(total)
	return res
}

func one(ctx context.Context, client *http.Client, url string, headers map[string]string) Sample {
	var t0, firstByte time.Time
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, url, nil)
	if err != nil {
		return Sample{Err: err.Error()}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	t0 = time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Sample{Err: err.Error()}
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	end := time.Now()
	if err != nil {
		return Sample{StatusCode: resp.StatusCode, Err: err.Error()}
	}
	if firstByte.IsZero() {
		firstByte = end
	}
	return Sample{
		StatusCode: resp.StatusCode,
		TTFBms:     float64(firstByte.Sub(t0).Microseconds()) / 1000,
		TotalMs:    float64(end.Sub(t0).Microseconds()) / 1000,
		Bytes:      n,
	}
}

// Streaming 记录流式响应首块到达与结束时间。
type StreamingResult struct {
	URL          string    `json:"url"`
	Status       int       `json:"status"`
	FirstChunkMs float64   `json:"first_chunk_ms"`
	TotalMs      float64   `json:"total_ms"`
	ChunkTimesMs []float64 `json:"chunk_times_ms"`
	Bytes        int64     `json:"bytes"`
	Error        string    `json:"error,omitempty"`
}

// RunStreaming 读取块并记录每块到达时间，用于验证首块先于完整响应返回。
func RunStreaming(ctx context.Context, client *http.Client, url string, headers map[string]string) StreamingResult {
	out := StreamingResult{URL: url}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer resp.Body.Close()
	out.Status = resp.StatusCode
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			now := time.Now()
			out.ChunkTimesMs = append(out.ChunkTimesMs, float64(now.Sub(start).Microseconds())/1000)
			if out.FirstChunkMs == 0 {
				out.FirstChunkMs = float64(now.Sub(start).Microseconds()) / 1000
			}
			out.Bytes += int64(n)
		}
		if rerr != nil {
			break
		}
	}
	out.TotalMs = float64(time.Since(start).Microseconds()) / 1000
	return out
}

func percentiles(vals []float64) map[string]float64 {
	if len(vals) == 0 {
		return map[string]float64{"p50": 0, "p95": 0, "p99": 0, "min": 0, "max": 0}
	}
	sorted := append([]float64(nil), vals...)
	sort.Float64s(sorted)
	at := func(p float64) float64 {
		idx := int(float64(len(sorted)-1) * p)
		return sorted[idx]
	}
	return map[string]float64{
		"p50": at(0.50),
		"p95": at(0.95),
		"p99": at(0.99),
		"min": sorted[0],
		"max": sorted[len(sorted)-1],
	}
}

// Summary 返回便于阅读的一行统计。
func (r Result) Summary() string {
	return fmt.Sprintf("%s: n=%d errors=%d ttfb p50=%.2fms p95=%.2fms total p50=%.2fms p95=%.2fms first_cold=%.2fms",
		r.Label, r.Requests, r.Errors, r.TTFBP["p50"], r.TTFBP["p95"], r.TotalP["p50"], r.TotalP["p95"], r.FirstColdMs)
}
