// 文件职责：提供零外部依赖的泛型有界单飞缓存（Single-Flight + Stale-While-Revalidate + 硬超时回退）。
package swrcache

import (
	"cmp"
	"context"
	"errors"
	"os"
	"sync"
	"time"
)

type inflightCall[T any] struct {
	done chan struct{}
	val  T
	err  error
}

// Bounded 为带 TTL 保鲜期、并发单飞请求合并与慢 I/O 有界等待回退的泛型内存缓存。
type Bounded[T any] struct {
	ttl     time.Duration
	maxWait time.Duration
	loader  func(context.Context) (T, error)

	mu        sync.Mutex
	val       T
	hasValue  bool
	fetchedAt time.Time
	inflight  *inflightCall[T]
}

// NewBounded 创建泛型有界单飞缓存实例。
func NewBounded[T any](ttl, maxWait time.Duration, loader func(context.Context) (T, error)) *Bounded[T] {
	if maxWait <= 0 {
		maxWait = 2 * time.Second
	}
	return &Bounded[T]{
		ttl:     ttl,
		maxWait: maxWait,
		loader:  loader,
	}
}

// Get 获取缓存值；若未命中或过期则合并单飞刷新，超时时若有历史快照则回退返回陈旧值。
func (b *Bounded[T]) Get(ctx context.Context) (T, error) {
	var zero T
	return b.GetWithFallback(ctx, b.maxWait, zero)
}

// GetWithFallback 允许按次指定最大等待时长与冷启动无历史值时的兜底值。
func (b *Bounded[T]) GetWithFallback(ctx context.Context, maxWait time.Duration, fallback T) (T, error) {
	if b == nil {
		return fallback, errors.New("nil swrcache.Bounded")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	b.mu.Lock()
	if b.hasValue && b.ttl > 0 && time.Since(b.fetchedAt) < b.ttl {
		v := b.val
		b.mu.Unlock()
		return v, nil
	}
	staleVal, hasStale := b.val, b.hasValue
	if b.loader == nil {
		b.mu.Unlock()
		if hasStale {
			return staleVal, nil
		}
		return fallback, errors.New("swrcache loader not configured")
	}

	call := b.inflight
	if call == nil {
		call = &inflightCall[T]{done: make(chan struct{})}
		b.inflight = call
		loader := b.loader
		go b.runInflight(call, loader)
	}
	b.mu.Unlock()

	wait := cmp.Or(maxWait, b.maxWait)
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-call.done:
		if call.err == nil {
			return call.val, nil
		}
		if hasStale {
			return staleVal, call.err
		}
		return fallback, call.err
	case <-ctx.Done():
		if hasStale {
			return staleVal, ctx.Err()
		}
		return fallback, ctx.Err()
	case <-timer.C:
		if hasStale {
			return staleVal, os.ErrDeadlineExceeded
		}
		return fallback, os.ErrDeadlineExceeded
	}
}

func (b *Bounded[T]) runInflight(call *inflightCall[T], loader func(context.Context) (T, error)) {
	// 后台单飞加载绑定独立有界上下文，避免首个调用方提前取消导致同批其余等待者雪崩失败。
	loadTimeout := max(b.maxWait*4, 5*time.Second)
	loadCtx, cancel := context.WithTimeout(context.Background(), loadTimeout)
	defer cancel()

	v, err := loader(loadCtx)

	b.mu.Lock()
	if err == nil {
		b.val = v
		b.hasValue = true
		b.fetchedAt = time.Now()
	}
	if b.inflight == call {
		b.inflight = nil
	}
	call.val = v
	call.err = err
	close(call.done)
	b.mu.Unlock()
}

// Set 直接写透更新当前缓存快照并重置保鲜时间戳。
func (b *Bounded[T]) Set(val T) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.val = val
	b.hasValue = true
	b.fetchedAt = time.Now()
	b.mu.Unlock()
}

// Invalidate 将当前缓存标记为过期（保留历史值以供慢盘超时期间降级兜底）。
func (b *Bounded[T]) Invalidate() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.fetchedAt = time.Time{}
	b.mu.Unlock()
}
