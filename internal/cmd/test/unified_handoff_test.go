// 文件职责：验证单进程合体守护进程（dm）在由独立 WebUI 触发时的两阶段礼貌等让交接、超时兜底强停、ctx 取消与前台端口重试逻辑。
package cmd_test

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/cmd"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/daemon"
)

func loadMinimalTestConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, cfgPath
}

func testDaemonPaths(t *testing.T) daemon.Paths {
	t.Helper()
	dir := t.TempDir()
	return daemon.Paths{
		PidFile:         filepath.Join(dir, "dm.pid"),
		StateFile:       filepath.Join(dir, "dm.state"),
		LogFile:         filepath.Join(dir, "dm.log"),
		WebEmbeddedFile: filepath.Join(dir, "web.embedded"),
		WebLogFile:      filepath.Join(dir, "web.log"),
	}
}

func TestBuildUnifiedDaemon_DeferWebHandoff(t *testing.T) {
	lowMemInfo := func() (sysinfo.MemInfo, error) {
		return sysinfo.MemInfo{TotalBytes: 491040 * 1024, AvailableBytes: 210260 * 1024}, nil
	}
	emptyEnv := ""
	deferTrue := true
	deferFalse := false

	t.Run("polite_wait_until_standalone_exits_then_binds_without_killing", func(t *testing.T) {
		cfg, cfgPath := loadMinimalTestConfig(t)
		paths := testDaemonPaths(t)

		// Occupy an ephemeral TCP port to simulate standalone singctl web streaming HTTP NDJSON.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		targetAddr := ln.Addr().String()
		defer func() { _ = ln.Close() }()

		var standaloneRunning atomic.Bool
		standaloneRunning.Store(true)
		var stopCalls atomic.Int32
		readyCh := make(chan string, 1)

		d, unified := cmd.BuildUnifiedDaemon(cfg, cfgPath, "v1.14.163-test", cmd.DaemonStartDeps{
			ReadMemInfo:            lowMemInfo,
			UnifiedEnvValue:        &emptyEnv,
			WebListen:              targetAddr,
			Paths:                  paths,
			SkipSignalSetup:        true,
			DeferWebHandoff:        &deferTrue,
			WebHandoffTimeout:      3 * time.Second,
			WebHandoffPollInterval: 20 * time.Millisecond,
			IsStandaloneWebRunning: func() bool { return standaloneRunning.Load() },
			StopStandaloneWeb: func() (bool, error) {
				stopCalls.Add(1)
				return true, nil
			},
			OnWebReady: func(addr string) {
				readyCh <- addr
			},
		})
		if !unified {
			t.Fatal("expected unified daemon enabled")
		}

		// Lifecycle Start must return immediately (non-blocking ready-pipe) while EmbeddedService waits politely.
		startAt := time.Now()
		lc := d.BuildForegroundLifecycle()
		if err := lc.Start(t.Context()); err != nil {
			t.Fatalf("lc.Start failed: %v", err)
		}
		defer lc.Close()
		if time.Since(startAt) > 500*time.Millisecond {
			t.Fatalf("lc.Start should not block on standalone handoff wait, took %v", time.Since(startAt))
		}

		// Keep standalone alive for 120ms to verify dm does NOT send SIGTERM / call StopStandaloneWeb!
		time.Sleep(120 * time.Millisecond)
		if got := stopCalls.Load(); got != 0 {
			t.Fatalf("expected 0 StopStandaloneWeb calls while standalone is still streaming, got %d", got)
		}

		// Standalone finishes NDJSON push, releases port and exits cleanly.
		_ = ln.Close()
		standaloneRunning.Store(false)

		select {
		case bound := <-readyCh:
			if bound != targetAddr {
				t.Fatalf("expected embedded WebUI bound to %s, got %s", targetAddr, bound)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for embedded WebUI to take over port after standalone exited")
		}

		if got := stopCalls.Load(); got != 0 {
			t.Fatalf("expected 0 StopStandaloneWeb calls after polite handoff, got %d", got)
		}

		resp, err := http.Get("http://" + targetAddr + "/api/auth/check")
		if err != nil {
			t.Fatalf("HTTP GET to embedded WebUI after handoff failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from embedded WebUI, got %d", resp.StatusCode)
		}
	})

	t.Run("timeout_fallback_stops_hung_standalone_and_takes_over", func(t *testing.T) {
		cfg, cfgPath := loadMinimalTestConfig(t)
		paths := testDaemonPaths(t)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		targetAddr := ln.Addr().String()
		defer func() { _ = ln.Close() }()

		var standaloneRunning atomic.Bool
		standaloneRunning.Store(true)
		var stopCalls atomic.Int32
		readyCh := make(chan string, 1)

		d, _ := cmd.BuildUnifiedDaemon(cfg, cfgPath, "v1.14.163-test", cmd.DaemonStartDeps{
			ReadMemInfo:            lowMemInfo,
			UnifiedEnvValue:        &emptyEnv,
			WebListen:              targetAddr,
			Paths:                  paths,
			SkipSignalSetup:        true,
			DeferWebHandoff:        &deferTrue,
			WebHandoffTimeout:      120 * time.Millisecond,
			WebHandoffPollInterval: 20 * time.Millisecond,
			IsStandaloneWebRunning: func() bool { return standaloneRunning.Load() },
			StopStandaloneWeb: func() (bool, error) {
				stopCalls.Add(1)
				_ = ln.Close()
				standaloneRunning.Store(false)
				return true, nil
			},
			OnWebReady: func(addr string) {
				readyCh <- addr
			},
		})

		lc := d.BuildForegroundLifecycle()
		if err := lc.Start(t.Context()); err != nil {
			t.Fatalf("lc.Start failed: %v", err)
		}
		defer lc.Close()

		select {
		case <-readyCh:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for fallback StopStandaloneWeb takeover")
		}
		if got := stopCalls.Load(); got != 1 {
			t.Fatalf("expected fallback StopStandaloneWeb called exactly once on timeout, got %d", got)
		}
	})

	t.Run("ctx_cancel_during_polite_wait_exits_cleanly_without_killing", func(t *testing.T) {
		cfg, cfgPath := loadMinimalTestConfig(t)
		paths := testDaemonPaths(t)

		var stopCalls atomic.Int32
		d, _ := cmd.BuildUnifiedDaemon(cfg, cfgPath, "v1.14.163-test", cmd.DaemonStartDeps{
			ReadMemInfo:            lowMemInfo,
			UnifiedEnvValue:        &emptyEnv,
			WebListen:              "127.0.0.1:0",
			Paths:                  paths,
			SkipSignalSetup:        true,
			DeferWebHandoff:        &deferTrue,
			WebHandoffTimeout:      5 * time.Second,
			WebHandoffPollInterval: 20 * time.Millisecond,
			IsStandaloneWebRunning: func() bool { return true },
			StopStandaloneWeb: func() (bool, error) {
				stopCalls.Add(1)
				return true, nil
			},
		})

		lc := d.BuildForegroundLifecycle()
		if err := lc.Start(t.Context()); err != nil {
			t.Fatalf("lc.Start failed: %v", err)
		}
		time.Sleep(60 * time.Millisecond)

		closeStart := time.Now()
		if err := lc.Close(); err != nil {
			t.Fatalf("lc.Close failed: %v", err)
		}
		if time.Since(closeStart) > 1*time.Second {
			t.Fatalf("expected lc.Close to cancel polite wait quickly, took %v", time.Since(closeStart))
		}
		if got := stopCalls.Load(); got != 0 {
			t.Fatalf("expected 0 StopStandaloneWeb calls on ctx cancel, got %d", got)
		}
	})

	t.Run("non_webui_cli_start_calls_stop_immediately", func(t *testing.T) {
		cfg, cfgPath := loadMinimalTestConfig(t)
		paths := testDaemonPaths(t)

		var stopCalls atomic.Int32
		readyCh := make(chan string, 1)

		d, _ := cmd.BuildUnifiedDaemon(cfg, cfgPath, "v1.14.163-test", cmd.DaemonStartDeps{
			ReadMemInfo:            lowMemInfo,
			UnifiedEnvValue:        &emptyEnv,
			WebListen:              "127.0.0.1:0",
			Paths:                  paths,
			SkipSignalSetup:        true,
			DeferWebHandoff:        &deferFalse,
			IsStandaloneWebRunning: func() bool { return true },
			StopStandaloneWeb: func() (bool, error) {
				stopCalls.Add(1)
				return true, nil
			},
			OnWebReady: func(addr string) {
				readyCh <- addr
			},
		})

		lc := d.BuildForegroundLifecycle()
		if err := lc.Start(t.Context()); err != nil {
			t.Fatalf("lc.Start failed: %v", err)
		}
		defer lc.Close()

		select {
		case <-readyCh:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for immediate takeover")
		}
		if got := stopCalls.Load(); got != 1 {
			t.Fatalf("expected immediate StopStandaloneWeb called once when DeferWebHandoff=false, got %d", got)
		}
	})

	t.Run("foreground_standalone_without_pidfile_retries_addrinuse_until_released", func(t *testing.T) {
		cfg, cfgPath := loadMinimalTestConfig(t)
		paths := testDaemonPaths(t)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		targetAddr := ln.Addr().String()
		defer func() { _ = ln.Close() }()

		var stopCalls atomic.Int32
		readyCh := make(chan string, 1)

		d, _ := cmd.BuildUnifiedDaemon(cfg, cfgPath, "v1.14.163-test", cmd.DaemonStartDeps{
			ReadMemInfo:            lowMemInfo,
			UnifiedEnvValue:        &emptyEnv,
			WebListen:              targetAddr,
			Paths:                  paths,
			SkipSignalSetup:        true,
			DeferWebHandoff:        &deferTrue,
			WebHandoffTimeout:      3 * time.Second,
			WebHandoffPollInterval: 20 * time.Millisecond,
			IsStandaloneWebRunning: func() bool { return false }, // foreground webui has no pidfile
			StopStandaloneWeb: func() (bool, error) {
				stopCalls.Add(1)
				return false, nil
			},
			OnWebReady: func(addr string) {
				readyCh <- addr
			},
		})

		lc := d.BuildForegroundLifecycle()
		if err := lc.Start(t.Context()); err != nil {
			t.Fatalf("lc.Start failed: %v", err)
		}
		defer lc.Close()

		// Release occupied port after 120ms (simulating foreground standalone RequestShutdown).
		time.Sleep(120 * time.Millisecond)
		_ = ln.Close()

		select {
		case bound := <-readyCh:
			if bound != targetAddr {
				t.Fatalf("expected bound addr %s, got %s", targetAddr, bound)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for embedded WebUI bind retry after foreground port release")
		}
		if got := stopCalls.Load(); got != 0 {
			t.Fatalf("expected 0 StopStandaloneWeb calls on clean port release, got %d", got)
		}
	})
}
