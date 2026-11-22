// 文件职责：验证确定性三阶段生命周期编排器（lifecycle.Group）的顺序启动、半途异常逆序回滚、有界超时回收与并发幂等性。
package lifecycle_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/lifecycle"
)

func TestStageString(t *testing.T) {
	tests := []struct {
		stage lifecycle.Stage
		want  string
	}{
		{lifecycle.StageInit, "init"},
		{lifecycle.StageStart, "start"},
		{lifecycle.StagePostStart, "post_start"},
		{lifecycle.Stage(99), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.stage.String(); got != tc.want {
			t.Fatalf("Stage(%d).String() = %q, want %q", tc.stage, got, tc.want)
		}
	}
}

func TestGroupForwardStagesAndReverseClose(t *testing.T) {
	var events []string
	var mu sync.Mutex
	record := func(ev string) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	}

	g := lifecycle.NewGroup()
	for _, name := range []string{"storage", "worker", "warmup"} {
		n := name
		g.Add(nil, lifecycle.FuncService{
			ServiceName: n,
			OnInit: func(context.Context) error {
				record("init:" + n)
				return nil
			},
			OnStart: func(context.Context) error {
				record("start:" + n)
				return nil
			},
			OnPostStart: func(context.Context) error {
				record("post_start:" + n)
				return nil
			},
			OnClose: func() error {
				record("close:" + n)
				return nil
			},
		}, nil)
	}

	if err := g.Start(t.Context()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if err := g.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	want := []string{
		"init:storage", "init:worker", "init:warmup",
		"start:storage", "start:worker", "start:warmup",
		"post_start:storage", "post_start:worker", "post_start:warmup",
		"close:warmup", "close:worker", "close:storage",
	}
	if !slices.Equal(events, want) {
		t.Fatalf("events mismatch:\ngot:  %v\nwant: %v", events, want)
	}
}

func TestGroupMidStageFailureRollsBackInReverseOrder(t *testing.T) {
	sentinel := errors.New("boom")

	t.Run("fail_in_stage_init", func(t *testing.T) {
		var closed []string
		g := lifecycle.NewGroup()
		g.Add(
			lifecycle.FuncService{
				ServiceName: "s0",
				OnInit:      func(context.Context) error { return nil },
				OnClose:     func() error { closed = append(closed, "s0"); return nil },
			},
			lifecycle.FuncService{
				ServiceName: "s1",
				OnInit:      func(context.Context) error { return sentinel },
				OnClose:     func() error { closed = append(closed, "s1"); return nil },
			},
			lifecycle.FuncService{
				ServiceName: "s2",
				OnInit:      func(context.Context) error { return nil },
				OnClose:     func() error { closed = append(closed, "s2"); return nil },
			},
		)

		err := g.Start(t.Context())
		if !errors.Is(err, sentinel) {
			t.Fatalf("expected sentinel error, got %v", err)
		}
		if !slices.Equal(closed, []string{"s0"}) {
			t.Fatalf("expected only [s0] closed on StageInit failure at s1, got %v", closed)
		}
	})

	t.Run("fail_in_stage_start_after_all_init", func(t *testing.T) {
		var closed []string
		g := lifecycle.NewGroup()
		g.Add(
			lifecycle.FuncService{
				ServiceName: "s0",
				OnInit:      func(context.Context) error { return nil },
				OnClose:     func() error { closed = append(closed, "s0"); return nil },
			},
			lifecycle.FuncService{
				ServiceName: "s1",
				OnInit:      func(context.Context) error { return nil },
				OnStart:     func(context.Context) error { return sentinel },
				OnClose:     func() error { closed = append(closed, "s1"); return nil },
			},
			lifecycle.FuncService{
				ServiceName: "s2",
				OnInit:      func(context.Context) error { return nil },
				OnClose:     func() error { closed = append(closed, "s2"); return nil },
			},
		)

		err := g.Start(t.Context())
		if !errors.Is(err, sentinel) {
			t.Fatalf("expected sentinel error, got %v", err)
		}
		if !slices.Equal(closed, []string{"s2", "s1", "s0"}) {
			t.Fatalf("expected reverse rollback [s2 s1 s0], got %v", closed)
		}
	})
}

func TestGroupCanceledContextShortCircuit(t *testing.T) {
	t.Run("canceled_before_start", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		called := false
		g := lifecycle.NewGroup()
		g.Add(lifecycle.FuncService{
			ServiceName: "s0",
			OnInit: func(context.Context) error {
				called = true
				return nil
			},
		})

		err := g.Start(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if called {
			t.Fatal("expected service OnInit not to be called when ctx already canceled")
		}
	})

	t.Run("canceled_mid_stage", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		var closed []string
		g := lifecycle.NewGroup()
		g.Add(
			lifecycle.FuncService{
				ServiceName: "s0",
				OnInit: func(context.Context) error {
					cancel()
					return nil
				},
				OnClose: func() error {
					closed = append(closed, "s0")
					return nil
				},
			},
			lifecycle.FuncService{
				ServiceName: "s1",
				OnInit: func(context.Context) error {
					return fmt.Errorf("should not reach s1")
				},
				OnClose: func() error {
					closed = append(closed, "s1")
					return nil
				},
			},
		)

		err := g.Start(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled mid-stage, got %v", err)
		}
		if !slices.Equal(closed, []string{"s0"}) {
			t.Fatalf("expected [s0] closed on mid-stage cancel, got %v", closed)
		}
	})
}

func TestGroupCloseTimeout(t *testing.T) {
	blockCh := make(chan struct{})
	defer close(blockCh)

	var order []string
	var mu sync.Mutex
	record := func(s string) {
		mu.Lock()
		order = append(order, s)
		mu.Unlock()
	}

	g := lifecycle.NewGroup(lifecycle.WithCloseTimeout(40 * time.Millisecond))
	g.Add(
		lifecycle.FuncService{
			ServiceName: "fast-early",
			OnClose: func() error {
				record("fast-early")
				return nil
			},
		},
		lifecycle.FuncService{
			ServiceName: "stuck",
			OnClose: func() error {
				record("stuck-enter")
				<-blockCh
				return nil
			},
		},
	)

	if err := g.Start(t.Context()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	start := time.Now()
	err := g.Close()
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded wrapped error, got %v", err)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("Close took too long: %v", elapsed)
	}

	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(order, []string{"stuck-enter", "fast-early"}) {
		t.Fatalf("expected earlier service still closed in reverse order, got %v", order)
	}
}

func TestGroupConcurrentCloseAndGuards(t *testing.T) {
	var closeCalls atomic.Int32
	g := lifecycle.NewGroup()
	g.Add(lifecycle.FuncService{
		OnClose: func() error {
			closeCalls.Add(1)
			return nil
		},
	})

	if err := g.Start(t.Context()); err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	if err := g.Start(t.Context()); !errors.Is(err, lifecycle.ErrAlreadyStarted) {
		t.Fatalf("second Start expected ErrAlreadyStarted, got %v", err)
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := g.Close(); err != nil {
				t.Errorf("concurrent Close error: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("expected Close callback called once, got %d", got)
	}
	if err := g.Start(t.Context()); !errors.Is(err, lifecycle.ErrGroupClosed) {
		t.Fatalf("Start after Close expected ErrGroupClosed, got %v", err)
	}
}
