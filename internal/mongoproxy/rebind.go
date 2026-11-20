package mongoproxy

import (
	"errors"
	"log"
	"time"

	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
)

// bindingCheckInterval 是既有连接核对绑定改绑的间隔上限：转发环再忙也最多每秒查一次。
// 它同时是读超时的唤醒间隔，因此空闲连接同样会按这个节奏发现改绑。
const bindingCheckInterval = time.Second

// bindingWatch 在客户端→上游的转发环里按时间戳节流核对绑定。
//
// 它不持有 goroutine，也没有无界后台任务：调用方在转发循环里用 due 判断是否到点，
// 到点后用 changed 做一次有界查询。查询失败只记录，留到下一次检查重试，不断开连接。
type bindingWatch struct {
	getter    Broker
	bindingID string
	// revision / origin 是建立连接时那次授权返回的快照，后续只用于比较。
	revision int64
	origin   string
	interval time.Duration
	last     time.Time
	failures int
	logger   *log.Logger
}

// newBindingWatch 用授权快照构造监视器。interval 已由 Config 归一化为不超过 1 秒。
func (s *Server) newBindingWatch(target UpstreamTarget) *bindingWatch {
	return &bindingWatch{
		getter:    s.broker,
		bindingID: s.cfg.BindingID,
		revision:  target.Revision,
		origin:    target.UpstreamOrigin,
		interval:  s.cfg.RevalidateInterval,
		last:      time.Now(),
		logger:    s.logger,
	}
}

// due 报告现在是否该做下一次核对。
func (w *bindingWatch) due(now time.Time) bool {
	return w.getter != nil && !now.Before(w.last.Add(w.interval))
}

// changed 查询一次绑定详情，返回 true 表示这条连接必须结束：
// revision 变化、状态不再是 active、或授权时的上游 origin 已被改绑。
// 查询失败（daemon 暂时不可达等）不结束连接，由下一次检查重试。
func (w *bindingWatch) changed() bool {
	// 先记时间戳：一次慢查询不应导致紧接着再查一次。
	w.last = time.Now()
	if w.getter == nil {
		return false
	}
	var binding model.Binding
	err := w.getter.Get("/v1/bindings/"+w.bindingID, &binding)
	if err != nil {
		var apiErr *ipcclient.APIError
		if errors.As(err, &apiErr) && model.Code(apiErr.Code) == model.CodeBindingDisabled {
			w.logger.Printf("mongo-proxy binding %s is no longer registered; closing connection", w.bindingID)
			return true
		}
		w.failures++
		if w.failures == 1 || w.failures%30 == 0 {
			w.logger.Printf("mongo-proxy binding revalidation failed (%d consecutive); keeping the connection: %v", w.failures, err)
		}
		return false
	}
	w.failures = 0
	if binding.Status != "" && binding.Status != model.StatusActive {
		w.logger.Printf("mongo-proxy binding %s status changed to %s; closing connection", w.bindingID, binding.Status)
		return true
	}
	if binding.Revision != w.revision {
		w.logger.Printf("mongo-proxy binding %s revision changed from %d to %d; closing connection", w.bindingID, w.revision, binding.Revision)
		return true
	}
	if w.origin != "" && binding.UpstreamOrigin != "" && binding.UpstreamOrigin != w.origin {
		w.logger.Printf("mongo-proxy binding %s upstream origin changed; closing connection", w.bindingID)
		return true
	}
	return false
}
