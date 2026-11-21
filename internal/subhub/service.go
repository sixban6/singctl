package subhub

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"singctl/internal/constant"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/updater"
)

const ServiceName = "singctl-sub"

func subhubUnitSpec(exePath, cfgPath string) servicemgr.UnitSpec {
	unitPath := cmp.Or(constant.SubHubSystemdService, "/etc/systemd/system/singctl-sub.service")
	scriptPath := cmp.Or(constant.SubHubInitdScript, "/etc/init.d/singctl-sub")
	return servicemgr.UnitSpec{
		Name:        ServiceName,
		SystemdPath: unitPath,
		SystemdBody: fmt.Sprintf(`[Unit]
Description=SingCtl Native Subscription Aggregation Engine (SubHub)
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s -c %s sr sub --listen %s
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, exePath, cfgPath, DefaultListenAddr),
		ProcdPath: scriptPath,
		ProcdBody: fmt.Sprintf(`#!/bin/sh /etc/rc.common

START=98
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command %s -c %s sr sub --listen %s
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`, exePath, cfgPath, DefaultListenAddr),
	}
}

// InstallService installs the singctl-sub systemd/OpenWrt service,
// enables and starts it, and waits briefly for HTTP readiness.
func InstallService(cfgPath string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("singctl-sub service installation is only supported on Linux (current: %s)", runtime.GOOS)
	}

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

	if err := os.MkdirAll(constant.SubStoreDir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", constant.SubStoreDir, err)
	}

	st := NewStore(constant.SubStoreDir, constant.SubStoreFile)
	if _, err := st.EnsureKey(); err != nil {
		return fmt.Errorf("ensure subscription key: %w", err)
	}

	mgr := servicemgr.Detect(nil)
	if err := mgr.InstallUnit(context.Background(), subhubUnitSpec(exePath, absCfg)); err != nil {
		return err
	}

	waitForReady(3 * time.Second)
	return nil
}

// StopService stops the singctl-sub service.
func StopService() error {
	return servicemgr.Detect(nil).Stop(context.Background(), ServiceName)
}

// RestartService restarts the singctl-sub service if installed.
func RestartService() error {
	if servicemgr.IsOpenWrt() {
		script := cmp.Or(constant.SubHubInitdScript, "/etc/init.d/singctl-sub")
		if _, err := os.Stat(script); err != nil {
			return nil
		}
		return servicemgr.NewProcd(nil, filepath.Dir(script)).Restart(context.Background(), ServiceName)
	}
	unit := cmp.Or(constant.SubHubSystemdService, "/etc/systemd/system/singctl-sub.service")
	if _, err := os.Stat(unit); err != nil {
		return nil
	}
	return servicemgr.NewSystemd(nil).Restart(context.Background(), ServiceName)
}

// UninstallService stops and removes the singctl-sub service and optionally /etc/sub-store.
func UninstallService(removeData bool) error {
	if runtime.GOOS == "linux" {
		spec := servicemgr.UnitSpec{
			Name:        ServiceName,
			SystemdPath: cmp.Or(constant.SubHubSystemdService, "/etc/systemd/system/singctl-sub.service"),
			ProcdPath:   cmp.Or(constant.SubHubInitdScript, "/etc/init.d/singctl-sub"),
		}
		_ = servicemgr.Detect(nil).RemoveUnit(context.Background(), spec)
	}

	if removeData && constant.SubStoreDir != "" {
		if err := os.RemoveAll(constant.SubStoreDir); err != nil {
			return fmt.Errorf("remove %s: %w", constant.SubStoreDir, err)
		}
	}
	return nil
}

// IsRunning checks whether SubHub is active via systemd or responding on 127.0.0.1:3001/healthz.
func IsRunning() bool {
	if runtime.GOOS == "linux" && !servicemgr.IsOpenWrt() {
		if servicemgr.NewSystemd(nil).IsActive(context.Background(), ServiceName) {
			return true
		}
	}
	client := &http.Client{Timeout: 1200 * time.Millisecond}
	resp, err := client.Get("http://" + DefaultListenAddr + "/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func waitForReady(maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + DefaultListenAddr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
}
