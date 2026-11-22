// 文件职责：实现 WebUI 3 分钟冷态闲置物理内存自动归还巡检器（IdleScavenger）与请求活跃度原子追踪。
package webui

import (
	"context"
	"net/http"
	"runtime"
	"runtime/debug"
	"time"

	"singctl/internal/daemon"
)

// DefaultIdleScavengeThreshold 默认连续无 HTTP 请求冷态闲置回收阈值（3 分钟）。
const DefaultIdleScavengeThreshold = 3 * time.Minute

// DefaultIdleScavengeCheckInterval 默认冷态闲置后台轻量巡检间隔（30 秒）。
const DefaultIdleScavengeCheckInterval = 30 * time.Second

func (s *Server) now() time.Time {
	if s != nil && s.opts.NowFunc != nil {
		return s.opts.NowFunc()
	}
	return time.Now()
}

func (s *Server) effectiveIdleThreshold() time.Duration {
	if s != nil && s.opts.IdleThreshold > 0 {
		return s.opts.IdleThreshold
	}
	return DefaultIdleScavengeThreshold
}

func (s *Server) effectiveIdleCheckInterval() time.Duration {
	if s != nil && s.opts.IdleCheckInterval > 0 {
		return s.opts.IdleCheckInterval
	}
	return DefaultIdleScavengeCheckInterval
}

func (s *Server) isLowMemoryMode() bool {
	if s != nil && s.opts.LowMemoryMode != nil {
		return *s.opts.LowMemoryMode
	}
	return daemon.IsLowMemoryDevice()
}

func (s *Server) scavengeMemory() {
	if s != nil && s.opts.ScavengeFunc != nil {
		s.opts.ScavengeFunc()
		return
	}
	runtime.GC()
	debug.FreeOSMemory()
}

// LastRequestUnixNano 返回最近一次 HTTP 请求活跃时间戳（UnixNano）。
func (s *Server) LastRequestUnixNano() int64 {
	if s == nil {
		return 0
	}
	return s.lastReqUnixNano.Load()
}

// RecordRequestActivity 以无锁原子方式记录一次 HTTP 请求活跃并推进活跃纪元（使后续闲置可再次触发单次回收）。
func (s *Server) RecordRequestActivity() {
	if s == nil {
		return
	}
	s.lastReqUnixNano.Store(s.now().UnixNano())
	s.activeEpoch.Add(1)
}

// Handler 返回包裹了请求活跃度原子记录与路由分发的顶层 HTTP Handler。
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.RecordRequestActivity()
		s.Mux.ServeHTTP(w, r)
	})
}

// MaybeScavengeIdle 检查当前是否已连续闲置 >= 阈值且本活跃周期尚未回收；满足时执行一次物理内存归还并标记已回收。
func (s *Server) MaybeScavengeIdle() bool {
	if s == nil {
		return false
	}
	epoch := s.activeEpoch.Load()
	if epoch == 0 {
		return false
	}
	prevScav := s.scavengedEpoch.Load()
	if prevScav == epoch {
		return false
	}
	lastNano := s.lastReqUnixNano.Load()
	if lastNano <= 0 {
		return false
	}
	if s.now().Sub(time.Unix(0, lastNano)) < s.effectiveIdleThreshold() {
		return false
	}
	if !s.scavengedEpoch.CompareAndSwap(prevScav, epoch) {
		return false
	}
	if s.activeEpoch.Load() != epoch {
		return false
	}
	s.scavengeMemory()
	return true
}

func (s *Server) runIdleScavengerLoop(ctx context.Context) {
	ticker := time.NewTicker(s.effectiveIdleCheckInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.MaybeScavengeIdle()
			if s.isLowMemoryMode() && WebLogPathOverride == "" {
				_, _ = TrimWebLog(WebLogPath(), MaxLowMemWebLogBytes)
			}
		}
	}
}
