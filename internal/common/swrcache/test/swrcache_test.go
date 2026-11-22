// 文件职责：验证 swrcache 泛型有界单飞缓存的高并发合并（Single-Flight）、TTL 命中、慢 I/O 超时陈旧值兜底与显式失效。
package swrcache_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/common/swrcache"
)

func TestBounded_SingleFlight_TTL_And_StaleFallback(t *testing.T) {
	var loadCalls atomic.Int32
	gate := make(chan struct{})

	cache := swrcache.NewBounded(200*time.Millisecond, time.Second, func(context.Context) (string, error) {
		n := loadCalls.Add(1)
		<-gate
		return "v" + string(rune('0'+n)), nil
	})

	// 1. 32 concurrent callers on cold cache MUST coalesce into a single loader invocation!
	var wg sync.WaitGroup
	results := make([]string, 32)
	for i := range 32 {
		idx := i
		wg.Go(func() {
			v, err := cache.Get(t.Context())
			if err != nil {
				t.Errorf("Get[%d] err: %v", idx, err)
			}
			results[idx] = v
		})
	}
	time.Sleep(15 * time.Millisecond)
	close(gate)
	wg.Wait()

	if loadCalls.Load() != 1 {
		t.Fatalf("expected exactly 1 single-flight load call, got %d", loadCalls.Load())
	}
	for i, r := range results {
		if r != "v1" {
			t.Fatalf("results[%d] = %q, want v1", i, r)
		}
	}

	// 2. Subsequent Get within TTL returns cached value with 0 extra loader calls
	if v, err := cache.Get(t.Context()); err != nil || v != "v1" || loadCalls.Load() != 1 {
		t.Fatalf("TTL hit failed: v=%q err=%v calls=%d", v, err, loadCalls.Load())
	}

	// 3. Explicit Set & Invalidate
	cache.Set("manual")
	if v, err := cache.Get(t.Context()); err != nil || v != "manual" {
		t.Fatalf("after Set: v=%q err=%v", v, err)
	}
	cache.Invalidate()

	// 4. Slow loader exceeding maxWait returns stale cached value (or fallback) without blocking caller!
	blockCh := make(chan struct{})
	defer close(blockCh)
	slowCache := swrcache.NewBounded(10*time.Millisecond, 30*time.Millisecond, func(context.Context) (int, error) {
		<-blockCh
		return 99, nil
	})
	slowCache.Set(42)
	time.Sleep(20 * time.Millisecond) // expire TTL while keeping stale value 42

	start := time.Now()
	val, err := slowCache.GetWithFallback(t.Context(), 25*time.Millisecond, -1)
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("GetWithFallback blocked past maxWait")
	}
	if val != 42 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected stale value 42 + ErrDeadlineExceeded on slow refresh, got (%d, %v)", val, err)
	}

	// 5. Cold cache timeout with no prior value returns caller-supplied fallback
	coldSlow := swrcache.NewBounded(time.Second, 20*time.Millisecond, func(context.Context) (string, error) {
		<-blockCh
		return "never", nil
	})
	fbVal, fbErr := coldSlow.GetWithFallback(t.Context(), 20*time.Millisecond, "fallback-default")
	if fbVal != "fallback-default" || !errors.Is(fbErr, os.ErrDeadlineExceeded) {
		t.Fatalf("cold timeout = (%q, %v), want (fallback-default, ErrDeadlineExceeded)", fbVal, fbErr)
	}
}
