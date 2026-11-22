// 文件职责：验证 CLI 层 `singctl dm start` 低内存自动内嵌合体装配与 `singctl web status/start/restart` 合体模式无缝兼容。
package cmd_test

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/cmd"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/logger"
	"singctl/internal/webui"
)

func TestWebCmd_EmbeddedModeStatusStartRestart(t *testing.T) {
	tmpDir := t.TempDir()
	prevState := webui.WebStatePathOverride
	webui.WebStatePathOverride = filepath.Join(tmpDir, "no-standalone.pid")
	defer func() { webui.WebStatePathOverride = prevState }()

	var buf bytes.Buffer
	logger.SetOutput(&buf)
	logger.SetColor(false)
	defer logger.SetOutput(os.Stdout)

	var restartCfg string
	var restartCalled atomic.Int32

	deps := cmd.WebCmdDeps{
		Background: webui.BackgroundDeps{
			EmbeddedStatus: func() (webui.WebState, bool) {
				return webui.WebState{
					Pid:        9527,
					Listen:     "127.0.0.1:8090",
					ConfigPath: "/etc/singctl/singctl.yaml",
					Embedded:   true,
				}, true
			},
			RestartDaemon: func(cfgPath string) error {
				restartCalled.Add(1)
				restartCfg = cfgPath
				return nil
			},
		},
	}

	// 1. `singctl web status` displays exact unified mode message
	statusRoot := cmd.NewWebCmdWithDeps("v1.14.161", deps)
	statusRoot.PersistentFlags().String("config", "/etc/singctl/singctl.yaml", "")
	statusRoot.SetArgs([]string{"status"})
	if err := statusRoot.Execute(); err != nil {
		t.Fatalf("web status failed: %v", err)
	}
	out := buf.String()
	wantStatus := "WebUI 运行中 (内嵌于守护进程 pid=9527, 低内存单进程合体模式)"
	if !strings.Contains(out, wantStatus) {
		t.Fatalf("expected status output containing %q, got:\n%s", wantStatus, out)
	}

	// 2. `singctl web start` returns nil idempotently without spawning a 2nd process
	buf.Reset()
	startRoot := cmd.NewWebCmdWithDeps("v1.14.161", deps)
	startRoot.PersistentFlags().String("config", "/etc/singctl/singctl.yaml", "")
	startRoot.SetArgs([]string{"start"})
	if err := startRoot.Execute(); err != nil {
		t.Fatalf("web start in embedded mode must succeed idempotently: %v", err)
	}

	// 3. `singctl web restart` smoothly delegates to daemon.RestartDaemon
	buf.Reset()
	restartRoot := cmd.NewWebCmdWithDeps("v1.14.161", deps)
	restartRoot.PersistentFlags().String("config", "/tmp/test-singctl.yaml", "")
	restartRoot.SetArgs([]string{"restart"})
	if err := restartRoot.Execute(); err != nil {
		t.Fatalf("web restart in embedded mode failed: %v", err)
	}
	if restartCalled.Load() != 1 || restartCfg != "/tmp/test-singctl.yaml" {
		t.Fatalf("expected RestartDaemon(/tmp/test-singctl.yaml) called once, got calls=%d cfg=%q", restartCalled.Load(), restartCfg)
	}
}

func TestBuildUnifiedDaemon_SharesConfigStoreAndInjectsEmbeddedWebUI(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 88\n  down: 300\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Case 1: Explicit SINGCTL_UNIFIED_DAEMON=0 disables unified mode even on n60pro RAM
	zeroVal := "0"
	_, unifiedOff := cmd.BuildUnifiedDaemon(cfg, cfgPath, "v1.14.161", cmd.DaemonStartDeps{
		ReadMemInfo: func() (sysinfo.MemInfo, error) {
			return sysinfo.MemInfo{TotalBytes: 491040 * 1024, AvailableBytes: 210260 * 1024}, nil
		},
		UnifiedEnvValue: &zeroVal,
		SkipSignalSetup: true,
	})
	if unifiedOff {
		t.Fatal("expected SINGCTL_UNIFIED_DAEMON=0 to disable unified daemon")
	}

	// Case 2: Auto-enabled on n60pro RAM -> starts real embedded WebUI sharing config.Store inside daemon lifecycle!
	readyCh := make(chan string, 1)
	emptyEnv := ""
	paths := daemon.Paths{
		PidFile:         filepath.Join(tmpDir, "dm.pid"),
		StateFile:       filepath.Join(tmpDir, "dm.state"),
		LogFile:         filepath.Join(tmpDir, "dm.log"),
		WebEmbeddedFile: filepath.Join(tmpDir, "web.embedded"),
		WebLogFile:      filepath.Join(tmpDir, "web.log"),
	}
	d, unifiedOn := cmd.BuildUnifiedDaemon(cfg, cfgPath, "v1.14.161", cmd.DaemonStartDeps{
		ReadMemInfo: func() (sysinfo.MemInfo, error) {
			return sysinfo.MemInfo{TotalBytes: 491040 * 1024, AvailableBytes: 210260 * 1024}, nil
		},
		UnifiedEnvValue: &emptyEnv,
		WebListen:       "127.0.0.1:0",
		Paths:           paths,
		SkipSignalSetup: true,
		OnWebReady: func(addr string) {
			readyCh <- addr
		},
	})
	if !unifiedOn {
		t.Fatal("expected unified daemon auto-enabled on n60pro RAM")
	}

	lc := d.BuildForegroundLifecycle()
	if err := lc.Start(t.Context()); err != nil {
		t.Fatalf("unified daemon lifecycle Start failed: %v", err)
	}
	defer lc.Close()

	var actualAddr string
	select {
	case actualAddr = <-readyCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for embedded WebUI inside daemon to bind and signal ready")
	}

	resp, err := http.Get("http://" + actualAddr + "/api/auth/check")
	if err != nil {
		t.Fatalf("HTTP GET to embedded WebUI failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from embedded WebUI, got %d", resp.StatusCode)
	}

	embSt, ok := daemon.ReadWebEmbeddedStateAt(paths.WebEmbeddedFile, paths.StateFile, paths.PidFile, func(int) bool { return true })
	if !ok || embSt.Listen != actualAddr {
		t.Fatalf("expected web.embedded updated with actual bound addr %q, got ok=%v st=%+v", actualAddr, ok, embSt)
	}
}
