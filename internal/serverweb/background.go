package serverweb

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"singctl/internal/config"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/updater"
)

const (
	ServiceName       = "singctl-ui"
	DefaultListenAddr = "127.0.0.1:8092"
	systemdUnitPath   = "/etc/systemd/system/singctl-ui.service"
	legacyUnitPath    = "/etc/systemd/system/singctl-serverweb.service"
	legacyStatePath   = "/tmp/singctl-serverweb.pid"
	legacyLogPath     = "/tmp/singctl-serverweb.log"
)

// InstallService cleans up any legacy background PID/service, installs the singctl-ui
// systemd service, enables and starts it, and waits briefly for port readiness.
func InstallService(cfgPath string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("singctl-ui service installation is only supported on Linux (current: %s)", runtime.GOOS)
	}

	cleanupLegacyProcessAndUnit()

	exePath, err := updater.ResolveExecutablePath()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	if realExe, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = updater.SanitizeExecutablePath(realExe)
	}

	absCfg := cmp.Or(strings.TrimSpace(cfgPath), "/etc/singctl/singctl.yaml")
	if resolved, err := filepath.Abs(absCfg); err == nil {
		absCfg = resolved
	}

	content := fmt.Sprintf(`[Unit]
Description=SingCtl Server Admin UI
After=network.target caddy.service

[Service]
Type=simple
User=root
ExecStart=%s -c %s sr ui
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, exePath, absCfg)

	mgr := servicemgr.NewSystemd(defaultServiceCmdRunner{})
	spec := servicemgr.UnitSpec{
		Name:        ServiceName,
		SystemdPath: systemdUnitPath,
		SystemdBody: content,
	}
	if err := mgr.InstallUnit(context.Background(), spec); err != nil {
		return err
	}

	waitForReady(resolveListenAddr(absCfg), 3*time.Second)
	return nil
}

// StopService stops the singctl-ui systemd service and cleans up any legacy process.
func StopService() error {
	cleanupLegacyProcessAndUnit()
	if _, err := os.Stat(systemdUnitPath); err != nil {
		return nil
	}
	return servicemgr.NewSystemd(defaultServiceCmdRunner{}).Stop(context.Background(), ServiceName)
}

// RestartService restarts the singctl-ui systemd service if installed.
func RestartService() error {
	cleanupLegacyProcessAndUnit()
	if _, err := os.Stat(systemdUnitPath); err != nil {
		return nil
	}
	return servicemgr.NewSystemd(defaultServiceCmdRunner{}).Restart(context.Background(), ServiceName)
}

// UninstallService stops and removes the singctl-ui systemd service.
func UninstallService() error {
	cleanupLegacyProcessAndUnit()
	if runtime.GOOS == "linux" {
		_ = servicemgr.NewSystemd(defaultServiceCmdRunner{}).RemoveUnit(context.Background(), servicemgr.UnitSpec{
			Name:        ServiceName,
			SystemdPath: systemdUnitPath,
		})
	}
	return nil
}

// IsRunning checks whether singctl-ui is active via systemd or listening on its configured address.
func IsRunning(cfgPath ...string) bool {
	if runtime.GOOS == "linux" {
		if servicemgr.NewSystemd(defaultServiceCmdRunner{}).IsActive(context.Background(), ServiceName) {
			return true
		}
	}
	cfg := ""
	if len(cfgPath) > 0 {
		cfg = cfgPath[0]
	}
	conn, err := net.DialTimeout("tcp", resolveListenAddr(cfg), 800*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func resolveListenAddr(cfgPath string) string {
	if cfgPath != "" {
		if cfg, err := config.Load(cfgPath); err == nil && cfg != nil {
			return fmt.Sprintf("127.0.0.1:%d", cfg.Server.GetWebAdminPort())
		}
	}
	return DefaultListenAddr
}

func waitForReady(listenAddr string, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", listenAddr, 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// cleanupLegacyProcessAndUnit stops and removes any legacy /tmp/singctl-serverweb.pid process
// or singctl-serverweb.service unit so port 8092 is cleanly handed over to singctl-ui.service.
func cleanupLegacyProcessAndUnit() {
	if runtime.GOOS == "linux" {
		if _, err := os.Stat(legacyUnitPath); err == nil {
			_ = servicemgr.NewSystemd(defaultServiceCmdRunner{}).RemoveUnit(context.Background(), servicemgr.UnitSpec{
				Name:        "singctl-serverweb.service",
				SystemdPath: legacyUnitPath,
			})
		}
	}

	data, err := os.ReadFile(legacyStatePath)
	if err == nil {
		var st struct {
			Pid int `json:"pid"`
		}
		if json.Unmarshal(data, &st) == nil && st.Pid > 0 {
			if proc, err := os.FindProcess(st.Pid); err == nil {
				_ = proc.Signal(syscall.SIGTERM)
				deadline := time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) {
					if proc.Signal(syscall.Signal(0)) != nil {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				_ = proc.Kill()
			}
		}
		_ = os.Remove(legacyStatePath)
	}
	_ = os.Remove(legacyLogPath)
}
