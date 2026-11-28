// 文件职责：覆盖守护进程派生环境透传（SINGCTL_DEFER_WEB_HANDOFF）与缺失 nft 时 Tailscale-P2P 单次告警及 30 分钟静默退避测试。
package daemon_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/logger"
	"singctl/internal/tailscale"
)

func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

func TestBuildDaemonSpawnEnv_PropagatesDeferWebHandoff(t *testing.T) {
	tests := []struct {
		name      string
		parentEnv []string
		wantDefer string
	}{
		{
			name:      "from_webui_sets_defer_handoff",
			parentEnv: []string{"PATH=/usr/bin", "SINGCTL_FROM_WEBUI=1"},
			wantDefer: "1",
		},
		{
			name:      "existing_defer_handoff_preserved_without_duplicate",
			parentEnv: []string{"PATH=/usr/bin", "SINGCTL_DEFER_WEB_HANDOFF=1", "SINGCTL_DAEMONIZED=0"},
			wantDefer: "1",
		},
		{
			name:      "normal_cli_does_not_set_defer_handoff",
			parentEnv: []string{"PATH=/usr/bin", "SINGCTL_FROM_WEBUI=0"},
			wantDefer: "",
		},
		{
			name:      "empty_parent_env_sets_daemonized_only",
			parentEnv: nil,
			wantDefer: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := daemon.BuildDaemonSpawnEnv(tc.parentEnv)
			gotMap := envSliceToMap(got)
			if gotMap["SINGCTL_DAEMONIZED"] != "1" {
				t.Fatalf("expected SINGCTL_DAEMONIZED=1, got %q (env=%v)", gotMap["SINGCTL_DAEMONIZED"], got)
			}
			if gotMap[daemon.EnvDeferWebHandoff] != tc.wantDefer {
				t.Fatalf("expected %s=%q, got %q (env=%v)", daemon.EnvDeferWebHandoff, tc.wantDefer, gotMap[daemon.EnvDeferWebHandoff], got)
			}
			// Ensure no duplicate keys for SINGCTL_DAEMONIZED or SINGCTL_DEFER_WEB_HANDOFF
			daemonizedCount, deferCount := 0, 0
			for _, kv := range got {
				if strings.HasPrefix(kv, "SINGCTL_DAEMONIZED=") {
					daemonizedCount++
				}
				if strings.HasPrefix(kv, daemon.EnvDeferWebHandoff+"=") {
					deferCount++
				}
			}
	if daemonizedCount != 1 {
				t.Fatalf("expected exactly 1 SINGCTL_DAEMONIZED entry, got %d (%v)", daemonizedCount, got)
			}
			if tc.wantDefer == "1" && deferCount != 1 {
				t.Fatalf("expected exactly 1 %s entry, got %d (%v)", daemon.EnvDeferWebHandoff, deferCount, got)
			}
		})
	}
}

func TestBuildCleanSubprocessEnv_StripsDaemonizedAndAppliesExtras(t *testing.T) {
	tests := []struct {
		name      string
		parentEnv []string
		extra     []string
		wantSet   map[string]string
		wantUnset []string
	}{
		{
			name:      "strips_single_and_duplicate_daemonized_preserves_other",
			parentEnv: []string{"PATH=/usr/bin", "SINGCTL_DAEMONIZED=1", "SINGCTL_DAEMONIZED=true", "HOME=/root"},
			extra:     []string{"LC_ALL=C"},
			wantSet:   map[string]string{"PATH": "/usr/bin", "HOME": "/root", "LC_ALL": "C"},
			wantUnset: []string{daemon.EnvDaemonized},
		},
		{
			name:      "extra_empty_value_explicitly_removes_key",
			parentEnv: []string{"PATH=/usr/bin", "REMOVE_ME=secret", "KEEP=yes"},
			extra:     []string{"REMOVE_ME=", "EXTRA=ok"},
			wantSet:   map[string]string{"PATH": "/usr/bin", "KEEP": "yes", "EXTRA": "ok"},
			wantUnset: []string{daemon.EnvDaemonized, "REMOVE_ME"},
		},
		{
			name:      "empty_slice_parent_env_does_not_leak_daemonized",
			parentEnv: []string{},
			extra:     []string{"LC_ALL=C", "SINGCTL_DAEMONIZED=1"},
			wantSet:   map[string]string{"LC_ALL": "C"},
			wantUnset: []string{daemon.EnvDaemonized},
		},
		{
			name:      "nil_parent_env_reads_os_environ_and_strips_daemonized",
			parentEnv: nil,
			extra:     []string{"LC_ALL=C"},
			wantSet:   map[string]string{"LC_ALL": "C"},
			wantUnset: []string{daemon.EnvDaemonized},
		},
	}

	t.Setenv(daemon.EnvDaemonized, "1")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := daemon.BuildCleanSubprocessEnv(tc.parentEnv, tc.extra...)
			gotMap := envSliceToMap(got)
			for k, wantV := range tc.wantSet {
				if gotMap[k] != wantV {
					t.Fatalf("expected %s=%q, got %q (env=%v)", k, wantV, gotMap[k], got)
				}
			}
			for _, k := range tc.wantUnset {
				if _, exists := gotMap[k]; exists {
					t.Fatalf("expected %s stripped from env, found %q (env=%v)", k, gotMap[k], got)
				}
			}
		})
	}
}

func TestBuildDetachedHandoffCmd_StripsDaemonizedEnv(t *testing.T) {
	tests := []struct {
		name     string
		cfgPath  string
		wantArgs []string
	}{
		{
			name:     "with_config_path",
			cfgPath:  "/etc/singctl/singctl.yaml",
			wantArgs: []string{"/usr/bin/singctl", "--config", "/etc/singctl/singctl.yaml", "dm", "restart"},
		},
		{
			name:     "without_config_path",
			cfgPath:  "  ",
			wantArgs: []string{"/usr/bin/singctl", "dm", "restart"},
		},
	}

	parentEnv := []string{"PATH=/usr/bin", "SINGCTL_DAEMONIZED=1", "CUSTOM_KEEP=1"}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := daemon.BuildDetachedHandoffCmd("/usr/bin/singctl", tc.cfgPath, parentEnv)
			if cmd == nil {
				t.Fatal("expected non-nil *exec.Cmd")
			}
			if len(cmd.Args) != len(tc.wantArgs) {
				t.Fatalf("unexpected cmd.Args %v, want %v", cmd.Args, tc.wantArgs)
			}
			for i := range tc.wantArgs {
				if cmd.Args[i] != tc.wantArgs[i] {
					t.Fatalf("cmd.Args[%d] = %q, want %q", i, cmd.Args[i], tc.wantArgs[i])
				}
			}
			if cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
				t.Fatalf("expected nil stdio streams on detached cmd")
			}
			if cmd.Env == nil {
				t.Fatalf("expected explicit non-nil cmd.Env stripped of %s, got nil", daemon.EnvDaemonized)
			}
			envMap := envSliceToMap(cmd.Env)
			if _, leaked := envMap[daemon.EnvDaemonized]; leaked {
				t.Fatalf("expected %s stripped from cmd.Env, got %v", daemon.EnvDaemonized, cmd.Env)
			}
			if envMap["PATH"] != "/usr/bin" || envMap["CUSTOM_KEEP"] != "1" {
				t.Fatalf("expected parent env preserved, got %v", cmd.Env)
			}
		})
	}
}

func TestDaemonRunForeground_UnsetsDaemonizedEnv(t *testing.T) {
	t.Setenv(daemon.EnvDaemonized, "1")
	tmpDir := t.TempDir()
	sentinel := errors.New("stop foreground start after pid hook")
	var envInside string
	pidCalled := false

	d := daemon.NewDaemonWithOptions(&config.Config{}, daemon.DaemonOptions{
		Version: "v1.0.0-test",
		Paths: daemon.Paths{
			PidFile:   filepath.Join(tmpDir, "daemon.pid"),
			StateFile: filepath.Join(tmpDir, "daemon.state"),
			LogFile:   filepath.Join(tmpDir, "daemon.log"),
		},
		SkipSignalSetup: true,
		PidWriter: func() error {
			pidCalled = true
			envInside = os.Getenv(daemon.EnvDaemonized)
			return sentinel
		},
	})

	err := d.Start()
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error from foreground lifecycle, got %v", err)
	}
	if !pidCalled {
		t.Fatal("expected PidWriter invoked inside runForeground()")
	}
	if envInside != "" {
		t.Fatalf("expected %s unset inside runForeground before lifecycle start, got %q", daemon.EnvDaemonized, envInside)
	}
	if got := os.Getenv(daemon.EnvDaemonized); got != "" {
		t.Fatalf("expected %s cleared in process env, got %q", daemon.EnvDaemonized, got)
	}
}

func TestDaemon_ReconcileTailscaleP2P_MissingNFTLogsOnceAndSilentBackoff(t *testing.T) {
	tmpDir := t.TempDir()
	paths := daemon.Paths{
		PidFile:   filepath.Join(tmpDir, "dm.pid"),
		StateFile: filepath.Join(tmpDir, "dm.state"),
		LogFile:   filepath.Join(tmpDir, "dm.log"),
	}

	var logMu sync.Mutex
	var logBuf bytes.Buffer
	syncWriter := &lockedBufferWriter{mu: &logMu, buf: &logBuf}
	logger.SetOutput(syncWriter)
	logger.SetColor(false)
	defer logger.SetOutput(os.Stdout)

	var clockMu sync.Mutex
	curNow := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return curNow
	}
	advanceClock := func(d time.Duration) {
		clockMu.Lock()
		curNow = curNow.Add(d)
		clockMu.Unlock()
	}

	var lookPathCalls atomic.Int32
	var nftAvailable atomic.Bool

	p2pCtrl := &tailscale.P2PAssistController{
		Now: nowFn,
		LookPath: func(file string) (string, error) {
			if file == "nft" {
				lookPathCalls.Add(1)
			}
			if !nftAvailable.Load() || file != "nft" {
				return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
			}
			return "/usr/sbin/nft", nil
		},
		FW4: &tailscale.FW4Manager{
			BaseDir: tmpDir,
			Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
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
		},
		LocalAPI: &stubDaemonTSLocalAPI{},
	}

	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{
			P2PAssist: config.TailscaleP2PAssistConfig{
				Enabled: true,
			},
		},
	}

	d := daemon.NewDaemonWithOptions(cfg, daemon.DaemonOptions{
		Paths:           paths,
		SkipSignalSetup: true,
		P2PController:   p2pCtrl,
	})

	// Simulate 10 consecutive 3-second watchdog ticks on an iptables-only router without `nft`.
	for i := range 10 {
		d.ReconcileTailscaleP2POnce(t.Context(), i == 0)
		advanceClock(3 * time.Second)
	}

	if got := lookPathCalls.Load(); got != 1 {
		t.Fatalf("expected nft LookPath probed exactly once during 30m backoff, got %d", got)
	}

	logMu.Lock()
	logOut := logBuf.String()
	logMu.Unlock()
	warnCount := strings.Count(logOut, "[Tailscale-P2P]")
	if warnCount != 1 {
		t.Fatalf("expected exactly 1 [Tailscale-P2P] warning log on missing nft, got %d:\n%s", warnCount, logOut)
	}

	snap := daemon.NewStateStore(paths).Load()
	if snap.TailscaleP2P == nil || snap.TailscaleP2P.LastError == "" {
		t.Fatalf("expected DaemonRuntimeSnapshot.TailscaleP2P.LastError recorded, got %+v", snap.TailscaleP2P)
	}

	// Concurrent ticks under -race remain silent and do not trigger extra probes.
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.ReconcileTailscaleP2POnce(t.Context(), false)
		}()
	}
	wg.Wait()
	if got := lookPathCalls.Load(); got != 1 {
		t.Fatalf("expected concurrent ticks within backoff to stay at 1 LookPath call, got %d", got)
	}

	// After 31 minutes, controller re-probes and selects nft backend on apply; error clears.
	nftAvailable.Store(true)
	advanceClock(31 * time.Minute)
	d.ReconcileTailscaleP2POnce(t.Context(), false)
	if got := lookPathCalls.Load(); got < 2 {
		t.Fatalf("expected re-probe after 30m backoff, got %d nft LookPath calls", got)
	}
	snapAfter := daemon.NewStateStore(paths).Load()
	if snapAfter.TailscaleP2P == nil || snapAfter.TailscaleP2P.LastError != "" {
		t.Fatalf("expected LastError cleared after nft becomes available, got %+v", snapAfter.TailscaleP2P)
	}
}

type lockedBufferWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w *lockedBufferWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

type stubDaemonTSLocalAPI struct{}

func (s *stubDaemonTSLocalAPI) Status(context.Context) (*tailscale.StatusSnapshot, error) {
	return &tailscale.StatusSnapshot{BackendState: "Running"}, nil
}

func (s *stubDaemonTSLocalAPI) NetMap(context.Context) (*tailscale.NetMapSnapshot, error) {
	return &tailscale.NetMapSnapshot{PeerEndpoints: map[string][]string{}}, nil
}

func (s *stubDaemonTSLocalAPI) PingDisco(context.Context, string) (*tailscale.PingResult, error) {
	return &tailscale.PingResult{}, nil
}
