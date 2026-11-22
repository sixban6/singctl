// 文件职责：覆盖 Tailscale P2P 防线在缺失 nftables (nft) 固件上的单次报错、30 分钟静默退避、配置重载重置及并发安全测试。
package tailscale_test

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

func TestP2PAssistController_MissingNFTBackoffAndReset(t *testing.T) {
	t.Run("lookpath_missing_nft_errors_once_then_silent_for_30m_and_resets_on_reload", func(t *testing.T) {
		clk := newFakeClock()
		var lookPathCalls atomic.Int32
		var runnerCalls atomic.Int32
		var statusCalls atomic.Int32
		var hasNFT atomic.Bool

		api := &fakeLocalAPI{
			statusFn: func(call int) (*tailscale.StatusSnapshot, error) {
				statusCalls.Add(1)
				return &tailscale.StatusSnapshot{BackendState: "Running"}, nil
			},
		}
		fw4 := &tailscale.FW4Manager{
			BaseDir: t.TempDir(),
			Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
				runnerCalls.Add(1)
				if name == "nft" && len(args) >= 2 && args[0] == "-c" {
					return nil, nil
				}
				if name == "fw4" {
					return nil, nil
				}
				if name == "nft" && len(args) >= 4 && args[0] == "-j" {
					return []byte(`{"nftables":[]}`), nil
				}
				return nil, nil
			},
		}

		ctrl := &tailscale.P2PAssistController{
			LocalAPI: api,
			FW4:      fw4,
			Now:      clk.Now,
			Sleep:    clk.Sleep,
			LookPath: func(file string) (string, error) {
				lookPathCalls.Add(1)
				if !hasNFT.Load() {
					return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
				}
				return "/usr/sbin/nft", nil
			},
		}
		cfg := config.TailscaleP2PAssistConfig{Enabled: true}

		// 1st probe: fails with ErrNFTUnavailable (wrapping exec.ErrNotFound) and sets LastError.
		snap1, err1 := ctrl.Reconcile(t.Context(), cfg)
		if !errors.Is(err1, tailscale.ErrNFTUnavailable) || !errors.Is(err1, exec.ErrNotFound) {
			t.Fatalf("expected ErrNFTUnavailable wrapping exec.ErrNotFound, got err=%v", err1)
		}
		if snap1.LastError == "" || !snap1.Enabled {
			t.Fatalf("expected Enabled=true and non-empty LastError, got %+v", snap1)
		}
		if lookPathCalls.Load() != 1 || runnerCalls.Load() != 0 || statusCalls.Load() != 0 {
			t.Fatalf("expected 1 lookPath, 0 runner, 0 status calls; got lookPath=%d runner=%d status=%d",
				lookPathCalls.Load(), runnerCalls.Load(), statusCalls.Load())
		}

		// Subsequent calls within 30 minutes return nil error (no log spam), preserve LastError, and zero forks.
		for range 8 {
			clk.Advance(3 * time.Second)
			snapN, errN := ctrl.Reconcile(t.Context(), cfg)
			if errN != nil {
				t.Fatalf("expected nil error during 30m silent backoff, got %v", errN)
			}
			if snapN.LastError != snap1.LastError {
				t.Fatalf("expected LastError preserved during backoff: got %q want %q", snapN.LastError, snap1.LastError)
			}
		}
		if lookPathCalls.Load() != 1 || runnerCalls.Load() != 0 {
			t.Fatalf("expected zero re-probes during backoff, got lookPath=%d runner=%d", lookPathCalls.Load(), runnerCalls.Load())
		}

		// Advance past 30m backoff while nft is still absent: re-probes once, stays silent (no repeated spam error).
		clk.Advance(30 * time.Minute)
		snapStillMissing, errStillMissing := ctrl.Reconcile(t.Context(), cfg)
		if errStillMissing != nil {
			t.Fatalf("expected already-reported missing nft re-probe to stay silent, got err=%v", errStillMissing)
		}
		if snapStillMissing.LastError == "" {
			t.Fatalf("expected LastError retained when nft still missing, got %+v", snapStillMissing)
		}
		if lookPathCalls.Load() != 2 {
			t.Fatalf("expected 2nd LookPath probe after 30m expiry, got %d", lookPathCalls.Load())
		}

		// Config reload resets backoff immediately; if nft is now present, normal reconcile succeeds.
		hasNFT.Store(true)
		ctrl.ResetNFTUnavailableBackoff()
		snapOK, errOK := ctrl.Reconcile(t.Context(), cfg)
		if errOK != nil {
			t.Fatalf("expected reconcile to succeed after ResetNFTUnavailableBackoff + nft present, got %v", errOK)
		}
		if snapOK.LastError != "" || snapOK.ApplyMode != tailscale.ApplyModeFW4Reload {
			t.Fatalf("expected clean snapshot after recovery, got %+v", snapOK)
		}
	})

	t.Run("runner_returns_errnotfound_enters_backoff_without_pinhole_forks", func(t *testing.T) {
		clk := newFakeClock()
		var runnerCalls atomic.Int32

		api := &fakeLocalAPI{
			statusFn: func(call int) (*tailscale.StatusSnapshot, error) {
				return &tailscale.StatusSnapshot{BackendState: "Running"}, nil
			},
		}
		fw4 := &tailscale.FW4Manager{
			BaseDir: t.TempDir(),
			Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
				runnerCalls.Add(1)
				return nil, &exec.Error{Name: name, Err: exec.ErrNotFound}
			},
		}

		ctrl := &tailscale.P2PAssistController{
			LocalAPI: api,
			FW4:      fw4,
			Now:      clk.Now,
			Sleep:    clk.Sleep,
		}
		cfg := config.TailscaleP2PAssistConfig{Enabled: true}

		snap1, err1 := ctrl.Reconcile(t.Context(), cfg)
		if !errors.Is(err1, tailscale.ErrNFTUnavailable) || !errors.Is(err1, exec.ErrNotFound) {
			t.Fatalf("expected ErrNFTUnavailable from runner ErrNotFound, got %v", err1)
		}
		if snap1.LastError == "" {
			t.Fatalf("expected LastError populated, got %+v", snap1)
		}
		if got := runnerCalls.Load(); got != 1 {
			t.Fatalf("expected exactly 1 runner call (no CountOpenPinholes fork after nft ErrNotFound), got %d", got)
		}

		// Subsequent ticks stay in silent backoff with zero runner calls.
		for range 5 {
			clk.Advance(3 * time.Second)
			if _, err := ctrl.Reconcile(t.Context(), cfg); err != nil {
				t.Fatalf("expected silent backoff, got %v", err)
			}
		}
		if got := runnerCalls.Load(); got != 1 {
			t.Fatalf("expected runnerCalls to remain 1 during backoff, got %d", got)
		}

		// Disabling P2P clears backoff so re-enabling probes fresh.
		cfg.Enabled = false
		_, _ = ctrl.Reconcile(t.Context(), cfg)
		cfg.Enabled = true
		_, errReenable := ctrl.Reconcile(t.Context(), cfg)
		if !errors.Is(errReenable, tailscale.ErrNFTUnavailable) {
			t.Fatalf("expected fresh ErrNFTUnavailable after disable+reenable, got %v", errReenable)
		}
	})

	t.Run("concurrent_reconcile_and_reset_race_safe", func(t *testing.T) {
		clk := newFakeClock()
		ctrl := &tailscale.P2PAssistController{
			Now: clk.Now,
			LookPath: func(file string) (string, error) {
				return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
			},
		}
		cfg := config.TailscaleP2PAssistConfig{Enabled: true}

		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = ctrl.Reconcile(t.Context(), cfg)
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctrl.ResetNFTUnavailableBackoff()
		}()
		wg.Wait()
	})
}
