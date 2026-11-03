package subhub

import (
	"cmp"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"singctl/internal/constant"
	"singctl/internal/logger"
)

const ServiceName = "singctl-sub"

// InstallService stops any legacy Docker sub-store container, installs the singctl-sub
// systemd/OpenWrt service, enables and starts it, and waits briefly for HTTP readiness.
func InstallService(cfgPath string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("singctl-sub service installation is only supported on Linux (current: %s)", runtime.GOOS)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	if realExe, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = realExe
	}

	absCfg := cmp.Or(strings.TrimSpace(cfgPath), "/etc/singctl/singctl.yaml")
	if resolved, err := filepath.Abs(absCfg); err == nil {
		absCfg = resolved
	}

	if err := os.MkdirAll(constant.SubStoreDir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", constant.SubStoreDir, err)
	}

	// Migrate key from legacy Docker sub-store container before removing it if /etc/sub-store/key is missing.
	MigrateKeyFromLegacyDocker()
	if CleanupLegacyDockerContainer() {
		logger.Info("Removed legacy Docker sub-store container; port 3001 handed over to native SubHub.")
	}

	st := NewStore(constant.SubStoreDir, constant.SubStoreFile)
	if _, err := st.EnsureKey(); err != nil {
		return fmt.Errorf("ensure subscription key: %w", err)
	}

	if isOpenWrt() {
		if err := installOpenWrtService(exePath, absCfg); err != nil {
			return err
		}
	} else {
		if err := installSystemdService(exePath, absCfg); err != nil {
			return err
		}
	}

	waitForReady(3 * time.Second)
	return nil
}

// MigrateKeyFromLegacyDocker extracts SUB_STORE_FRONTEND_BACKEND_PATH from a legacy
// sub-store Docker container if /etc/sub-store/key does not yet exist.
func MigrateKeyFromLegacyDocker() string {
	keyFile := filepath.Join(constant.SubStoreDir, "key")
	if data, err := os.ReadFile(keyFile); err == nil && strings.TrimSpace(string(data)) != "" {
		return strings.TrimSpace(string(data))
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return ""
	}
	out, err := exec.Command("docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", "sub-store").Output()
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "SUB_STORE_FRONTEND_BACKEND_PATH="); ok {
			key := strings.TrimPrefix(strings.TrimSpace(after), "/")
			if key != "" {
				_ = os.MkdirAll(constant.SubStoreDir, 0755)
				_ = os.WriteFile(keyFile, []byte(key), 0600)
				return key
			}
		}
	}
	return ""
}

// CleanupLegacyDockerContainer stops and removes the legacy Docker "sub-store" container if present.
func CleanupLegacyDockerContainer() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	out, err := exec.Command("docker", "ps", "-a", "-q", "-f", "name=^sub-store$").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return false
	}
	_ = exec.Command("docker", "rm", "-f", "sub-store").Run()
	return true
}

func installSystemdService(exePath, cfgPath string) error {
	unitPath := cmp.Or(constant.SubHubSystemdService, "/etc/systemd/system/singctl-sub.service")
	content := fmt.Sprintf(`[Unit]
Description=SingCtl Native Subscription Aggregation Engine (SubHub)
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s -c %s sr sub serve --listen %s
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, exePath, cfgPath, DefaultListenAddr)

	if err := os.WriteFile(unitPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", unitPath, err)
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("systemctl", "enable", ServiceName).Run()
	if out, err := exec.Command("systemctl", "restart", ServiceName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart %s: %v (%s)", ServiceName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func installOpenWrtService(exePath, cfgPath string) error {
	scriptPath := cmp.Or(constant.SubHubInitdScript, "/etc/init.d/singctl-sub")
	content := fmt.Sprintf(`#!/bin/sh /etc/rc.common

START=98
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command %s -c %s sr sub serve --listen %s
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`, exePath, cfgPath, DefaultListenAddr)

	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		return fmt.Errorf("write %s: %w", scriptPath, err)
	}
	_ = exec.Command(scriptPath, "enable").Run()
	if out, err := exec.Command(scriptPath, "restart").CombinedOutput(); err != nil {
		return fmt.Errorf("restart %s: %v (%s)", scriptPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// StartService starts the singctl-sub service.
func StartService() error {
	if isOpenWrt() {
		return exec.Command(cmp.Or(constant.SubHubInitdScript, "/etc/init.d/singctl-sub"), "start").Run()
	}
	return exec.Command("systemctl", "start", ServiceName).Run()
}

// StopService stops the singctl-sub service.
func StopService() error {
	if isOpenWrt() {
		return exec.Command(cmp.Or(constant.SubHubInitdScript, "/etc/init.d/singctl-sub"), "stop").Run()
	}
	return exec.Command("systemctl", "stop", ServiceName).Run()
}

// RestartService restarts the singctl-sub service if installed.
func RestartService() error {
	if isOpenWrt() {
		script := cmp.Or(constant.SubHubInitdScript, "/etc/init.d/singctl-sub")
		if _, err := os.Stat(script); err != nil {
			return nil
		}
		return exec.Command(script, "restart").Run()
	}
	unit := cmp.Or(constant.SubHubSystemdService, "/etc/systemd/system/singctl-sub.service")
	if _, err := os.Stat(unit); err != nil {
		return nil
	}
	return exec.Command("systemctl", "restart", ServiceName).Run()
}

// UninstallService stops and removes the singctl-sub service, legacy Docker container, and optionally /etc/sub-store.
func UninstallService(removeData bool) error {
	CleanupLegacyDockerContainer()

	if runtime.GOOS == "linux" {
		if isOpenWrt() {
			script := cmp.Or(constant.SubHubInitdScript, "/etc/init.d/singctl-sub")
			_ = exec.Command(script, "stop").Run()
			_ = exec.Command(script, "disable").Run()
			_ = os.Remove(script)
		} else {
			_ = exec.Command("systemctl", "stop", ServiceName).Run()
			_ = exec.Command("systemctl", "disable", ServiceName).Run()
			_ = os.Remove(cmp.Or(constant.SubHubSystemdService, "/etc/systemd/system/singctl-sub.service"))
			_ = exec.Command("systemctl", "daemon-reload").Run()
		}
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
	if runtime.GOOS == "linux" && !isOpenWrt() {
		if exec.Command("systemctl", "is-active", "--quiet", ServiceName).Run() == nil {
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

func isOpenWrt() bool {
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return true
	}
	if _, err := os.Stat("/etc/openwrt_version"); err == nil {
		return true
	}
	return false
}
