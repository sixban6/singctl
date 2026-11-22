// 文件职责：覆盖守护进程单进程合体模式（EmbeddedService 注入、内存阈值判定、内嵌状态落盘/清理与 256KiB 日志截断）的完整边界与并发测试。
package daemon_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/daemon"
)

func TestShouldEnableUnifiedDaemon_TableDriven(t *testing.T) {
	const mib = 1024 * 1024
	tests := []struct {
		name   string
		mi     sysinfo.MemInfo
		envVal string
		want   bool
	}{
		{
			name:   "n60pro_479mib_total_205mib_avail_auto_enabled",
			mi:     sysinfo.MemInfo{TotalBytes: 491040 * 1024, AvailableBytes: 210260 * 1024},
			envVal: "",
			want:   true,
		},
		{
			name:   "openwrt_224mib_total_auto_enabled",
			mi:     sysinfo.MemInfo{TotalBytes: 224 * mib, AvailableBytes: 120 * mib},
			envVal: "",
			want:   true,
		},
		{
			name:   "exact_512mib_boundary_auto_enabled",
			mi:     sysinfo.MemInfo{TotalBytes: 512 * mib, AvailableBytes: 300 * mib},
			envVal: "",
			want:   true,
		},
		{
			name:   "high_total_1gib_but_low_avail_200mib_auto_enabled",
			mi:     sysinfo.MemInfo{TotalBytes: 1024 * mib, AvailableBytes: 200 * mib},
			envVal: "",
			want:   true,
		},
		{
			name:   "exact_256mib_avail_boundary_auto_enabled",
			mi:     sysinfo.MemInfo{TotalBytes: 1024 * mib, AvailableBytes: 256 * mib},
			envVal: "",
			want:   true,
		},
		{
			name:   "above_threshold_1gib_total_600mib_avail_disabled",
			mi:     sysinfo.MemInfo{TotalBytes: 1024 * mib, AvailableBytes: 600 * mib},
			envVal: "",
			want:   false,
		},
		{
			name:   "zero_meminfo_darwin_fallback_disabled",
			mi:     sysinfo.MemInfo{},
			envVal: "",
			want:   false,
		},
		{
			name:   "env_explicit_1_overrides_high_ram",
			mi:     sysinfo.MemInfo{TotalBytes: 16384 * mib, AvailableBytes: 12000 * mib},
			envVal: "1",
			want:   true,
		},
		{
			name:   "env_explicit_true_with_spaces_enabled",
			mi:     sysinfo.MemInfo{},
			envVal: "  true ",
			want:   true,
		},
		{
			name:   "env_explicit_0_disables_even_on_low_ram",
			mi:     sysinfo.MemInfo{TotalBytes: 224 * mib, AvailableBytes: 100 * mib},
			envVal: "0",
			want:   false,
		},
		{
			name:   "env_explicit_false_disables_even_on_n60pro",
			mi:     sysinfo.MemInfo{TotalBytes: 491040 * 1024, AvailableBytes: 210260 * 1024},
			envVal: "FALSE",
			want:   false,
		},
		{
			name:   "malformed_env_falls_back_to_meminfo",
			mi:     sysinfo.MemInfo{TotalBytes: 256 * mib, AvailableBytes: 128 * mib},
			envVal: "invalid-garbage;rm -rf /",
			want:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := daemon.ShouldEnableUnifiedDaemon(tc.mi, tc.envVal)
			if got != tc.want {
				t.Fatalf("ShouldEnableUnifiedDaemon(%+v, %q) = %v, want %v", tc.mi, tc.envVal, got, tc.want)
			}
		})
	}
}

func TestDaemonEmbeddedService_LifecycleStateAndGracefulCancel(t *testing.T) {
	t.Run("normal_embedded_start_dynamic_listen_and_graceful_close", func(t *testing.T) {
		tmpDir := t.TempDir()
		paths := daemon.Paths{
			PidFile:         filepath.Join(tmpDir, "daemon.pid"),
			StateFile:       filepath.Join(tmpDir, "daemon.state"),
			LogFile:         filepath.Join(tmpDir, "daemon.log"),
			WebEmbeddedFile: filepath.Join(tmpDir, "web.embedded"),
		}
		cfgPath := filepath.Join(tmpDir, "singctl.yaml")
		if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 35\n  down: 200\n"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}

		startedCh := make(chan *config.Store, 1)
		stoppedCh := make(chan struct{}, 1)
		var d *daemon.Daemon

		d = daemon.NewDaemonWithOptions(cfg, daemon.DaemonOptions{
			ConfigPath:        cfgPath,
			Version:           "v1.14.161-test",
			Paths:             paths,
			SkipSignalSetup:   true,
			WebEmbeddedListen: ":8090",
			PidWriter:         func() error { return daemon.WritePidFileAt(paths.PidFile) },
			PidRemover:        func() error { return daemon.RemovePidFileAt(paths.PidFile) },
			EmbeddedService: func(ctx context.Context, cfgStore *config.Store) error {
				d.RecordWebEmbeddedListen("127.0.0.1:18090")
				startedCh <- cfgStore
				<-ctx.Done()
				close(stoppedCh)
				return nil
			},
		})

		lc := d.BuildForegroundLifecycle()
		if err := lc.Start(t.Context()); err != nil {
			t.Fatalf("BuildForegroundLifecycle Start failed: %v", err)
		}

		var gotStore *config.Store
		select {
		case gotStore = <-startedCh:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for EmbeddedService to start")
		}
		if gotStore == nil || gotStore != d.ConfigStore() {
			t.Fatalf("expected EmbeddedService to receive Daemon's exact *config.Store (%p != %p)", gotStore, d.ConfigStore())
		}

		// Verify 0600 permissions and content of web.embedded state file
		fi, err := os.Stat(paths.WebEmbeddedFile)
		if err != nil {
			t.Fatalf("expected web.embedded file written: %v", err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 perm on web.embedded, got %o", fi.Mode().Perm())
		}

		embSt, ok := daemon.ReadWebEmbeddedStateAt(paths.WebEmbeddedFile, paths.StateFile, paths.PidFile, func(pid int) bool {
			return pid == os.Getpid()
		})
		if !ok || embSt.Listen != "127.0.0.1:18090" || embSt.Pid != os.Getpid() {
			t.Fatalf("unexpected embedded state: ok=%v st=%+v", ok, embSt)
		}

		// Verify stale PID rejection
		if _, staleOK := daemon.ReadWebEmbeddedStateAt(paths.WebEmbeddedFile, paths.StateFile, paths.PidFile, func(int) bool {
			return false
		}); staleOK {
			t.Fatal("expected dead/mismatched PID to return false for ReadWebEmbeddedStateAt")
		}

		// Verify runtime snapshot records WebEmbedded
		snap := daemon.NewStateStore(paths).Load()
		if !snap.WebEmbedded || snap.WebEmbeddedListen != "127.0.0.1:18090" {
			t.Fatalf("expected runtime snapshot WebEmbedded=true listen=127.0.0.1:18090, got %+v", snap)
		}

		// Concurrent RecordWebEmbeddedListen race check
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.RecordWebEmbeddedListen(":8090")
				_, _ = daemon.ReadWebEmbeddedStateAt(paths.WebEmbeddedFile, paths.StateFile, paths.PidFile, func(int) bool { return true })
			}()
		}
		wg.Wait()

		// Close lifecycle -> EmbeddedService ctx cancelled & web.embedded file removed
		if err := lc.Close(); err != nil {
			t.Fatalf("lifecycle Close failed: %v", err)
		}
		select {
		case <-stoppedCh:
		case <-time.After(2 * time.Second):
			t.Fatal("expected EmbeddedService goroutine to exit cleanly on Close")
		}
		if _, err := os.Stat(paths.WebEmbeddedFile); !os.IsNotExist(err) {
			t.Fatalf("expected web.embedded file removed on Close, stat err=%v", err)
		}
	})

	t.Run("embedded_bind_error_cleans_embedded_state_without_killing_daemon", func(t *testing.T) {
		tmpDir := t.TempDir()
		paths := daemon.Paths{
			PidFile:         filepath.Join(tmpDir, "daemon.pid"),
			StateFile:       filepath.Join(tmpDir, "daemon.state"),
			LogFile:         filepath.Join(tmpDir, "daemon.log"),
			WebEmbeddedFile: filepath.Join(tmpDir, "web.embedded"),
		}
		errDone := make(chan struct{})
		d := daemon.NewDaemonWithOptions(&config.Config{}, daemon.DaemonOptions{
			Paths:             paths,
			SkipSignalSetup:   true,
			WebEmbeddedListen: ":8090",
			PidWriter:         func() error { return daemon.WritePidFileAt(paths.PidFile) },
			PidRemover:        func() error { return daemon.RemovePidFileAt(paths.PidFile) },
			EmbeddedService: func(context.Context, *config.Store) error {
				defer close(errDone)
				return errors.New("address already in use")
			},
		})

		lc := d.BuildForegroundLifecycle()
		if err := lc.Start(t.Context()); err != nil {
			t.Fatalf("daemon watchdog lifecycle must still start even if embedded web fails: %v", err)
		}
		defer lc.Close()

		select {
		case <-errDone:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for failing EmbeddedService")
		}
		// Give cleanup callback a moment to remove web.embedded
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, ok := daemon.ReadWebEmbeddedStateAt(paths.WebEmbeddedFile, paths.StateFile, paths.PidFile, func(int) bool { return true }); !ok {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("expected failed EmbeddedService to clear embedded running state so status does not lie")
	})
}

func TestDaemonLowMemoryLogTruncation_StartupAndPeriodic256KiB(t *testing.T) {
	tmpDir := t.TempDir()
	daemonLog := filepath.Join(tmpDir, "singctl-daemon.log")
	webLog := filepath.Join(tmpDir, "singctl-web.log")

	bigChunk := bytes.Repeat([]byte("2026-11-22 12:00:00 [INFO] [WATCHDOG] low-memory router log line padding\n"), 6000) // ~438 KiB > 256 KiB
	if err := os.WriteFile(daemonLog, bigChunk, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(webLog, bigChunk, 0644); err != nil {
		t.Fatal(err)
	}

	lowMem := true
	var pidCalls atomic.Int32
	d := daemon.NewDaemonWithOptions(&config.Config{}, daemon.DaemonOptions{
		Paths: daemon.Paths{
			LogFile:    daemonLog,
			WebLogFile: webLog,
			StateFile:  filepath.Join(tmpDir, "daemon.state"),
			PidFile:    filepath.Join(tmpDir, "daemon.pid"),
		},
		SkipSignalSetup: true,
		LowMemoryMode:   &lowMem,
		PidWriter: func() error {
			pidCalls.Add(1)
			return nil
		},
		PidRemover: func() error { return nil },
	})

	lc := d.BuildForegroundLifecycle()
	if err := lc.Start(t.Context()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer lc.Close()

	for _, p := range []string{daemonLog, webLog} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if fi.Size() > daemon.MaxLowMemDaemonLogBytes {
			t.Fatalf("startup expected %s <= %d bytes (256 KiB), got %d", filepath.Base(p), daemon.MaxLowMemDaemonLogBytes, fi.Size())
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 on %s, got %o", filepath.Base(p), fi.Mode().Perm())
		}
	}

	// Simulate runtime log growth past 256 KiB and trigger periodic rotation
	f1, err := os.OpenFile(daemonLog, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f1.Write(bigChunk)
	_ = f1.Close()

	f2, err := os.OpenFile(webLog, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f2.Write(bigChunk)
	_, _ = f2.WriteString("LATEST_WEB_TAIL_MARKER\n")
	_ = f2.Close()

	d.RotateLogsNow()

	for _, p := range []string{daemonLog, webLog} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat after rotate %s: %v", p, err)
		}
		if fi.Size() > daemon.MaxLowMemDaemonLogBytes {
			t.Fatalf("periodic rotate expected %s <= %d bytes (256 KiB), got %d", filepath.Base(p), daemon.MaxLowMemDaemonLogBytes, fi.Size())
		}
	}
	webRaw, _ := os.ReadFile(webLog)
	if !strings.Contains(string(webRaw), "LATEST_WEB_TAIL_MARKER") {
		t.Fatal("expected tail marker preserved after 256 KiB truncation")
	}
}
