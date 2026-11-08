package heal

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/updater"
)

var healRunMu = make(chan struct{}, 1)

// Run performs a full 3-layer security scan and (unless opts.CheckOnly) executes availability-safe self-healing.
func Run(ctx context.Context, opts RunOptions) (RunResult, error) {
	cfgPath := strings.TrimSpace(opts.ConfigPath)
	if cfgPath == "" {
		if _, err := os.Stat("/etc/singctl/singctl.yaml"); err == nil {
			cfgPath = "/etc/singctl/singctl.yaml"
		}
	}

	if opts.CheckOnly {
		report := Scan(ctx, cfgPath, opts.CurrentSingctlVer)
		return RunResult{
			Execution: HealHistoryItem{
				Timestamp:      report.CheckedAt,
				Trigger:        cmp.Or(opts.Trigger, "manual"),
				Success:        true,
				Summary:        report.PostureLabel,
				RebootRequired: report.Kernel.RebootRequired,
			},
			Status: report,
		}, nil
	}

	// Prevent concurrent heal runs on the same machine
	select {
	case healRunMu <- struct{}{}:
		defer func() { <-healRunMu }()
	default:
		return RunResult{}, fmt.Errorf("当前已有安全自愈任务正在运行，请稍候重试")
	}

	start := time.Now()
	trigger := cmp.Or(strings.TrimSpace(opts.Trigger), "manual")

	var cfg *config.Config
	if cfgPath != "" {
		cfg, _ = config.Load(cfgPath)
	}

	initial := Scan(ctx, cfgPath, opts.CurrentSingctlVer)
	var actions []LayerActionDetail
	allOK := true
	updatedCount := 0
	rollbackCount := 0

	// ── Layer 1: Core Binary Canary Upgrade + Live Health Probe + Auto Rollback ──
	effectiveSingctlVer := opts.CurrentSingctlVer
	for _, comp := range initial.Core.Components {
		if !comp.Installed || !comp.HasUpdate {
			continue
		}
		act := healCoreComponent(ctx, cfg, cfgPath, comp, opts.AsyncWebRestart)
		actions = append(actions, act)
		if !act.Success {
			allOK = false
		}
		if act.Updated {
			updatedCount++
			if comp.Name == "singctl" && comp.LatestVersion != "" {
				effectiveSingctlVer = comp.LatestVersion
			}
		}
		if act.RolledBack {
			rollbackCount++
		}
	}

	// Automatically heal Hysteria2 certificate_path / masquerade if Caddy renewed or switched from local CA
	if certHealed, certMsg, certErr := deploy.SyncHysteria2CertIfNeeded(cfg); certErr != nil {
		allOK = false
		actions = append(actions, LayerActionDetail{
			Layer:   "core",
			Target:  "hysteria2-cert",
			Success: false,
			Message: "Hysteria2 证书同步异常: " + certErr.Error(),
		})
	} else if certHealed {
		updatedCount++
		actions = append(actions, LayerActionDetail{
			Layer:   "core",
			Target:  "hysteria2-cert",
			Success: true,
			Updated: true,
			Message: certMsg,
		})
	}

	// Automatically heal WARP (wireproxy) IPv4 resolution strategy & WireGuard tunnel connectivity
	if warpHealed, warpMsg, warpErr := deploy.SyncWarpConfigIfNeeded(); warpErr != nil {
		allOK = false
		actions = append(actions, LayerActionDetail{
			Layer:   "core",
			Target:  "warp-tunnel",
			Success: false,
			Message: "WARP 隧道自愈异常: " + warpErr.Error(),
		})
	} else if warpHealed {
		updatedCount++
		actions = append(actions, LayerActionDetail{
			Layer:   "core",
			Target:  "warp-tunnel",
			Success: true,
			Updated: true,
			Message: warpMsg,
		})
	}

	// ── Layer 2: OS Security Patches (Preserving sshd_config) + Stale .so Reload ──
	if runtime.GOOS == "linux" {
		osActs := healOSLayer(ctx, opts.AsyncWebRestart)
		for _, a := range osActs {
			actions = append(actions, a)
			if !a.Success {
				allOK = false
			}
			if a.Updated {
				updatedCount++
			}
		}
	}

	// ── Post-Heal Verification Scan ──
	finalReport := Scan(ctx, cfgPath, effectiveSingctlVer)
	if opts.AsyncWebRestart && len(finalReport.OS.StaleServices) > 0 {
		// AsyncWebRestart uses `sleep 2 && singctl sr web restart` so HTTP response returns first;
		// remove singctl-web from the immediate post-scan StaleServices so the persisted report reflects the scheduled restart.
		finalReport.OS.StaleServices = slices.DeleteFunc(finalReport.OS.StaleServices, func(s string) bool {
			return s == "singctl-web"
		})
		finalReport.OS.Healthy = finalReport.OS.SecurityCount == 0 && len(finalReport.OS.StaleServices) == 0
		finalReport.Posture, finalReport.PostureLabel = evaluatePosture(finalReport.Core, finalReport.OS, finalReport.Kernel)
	}

	// ── Layer 3: Kernel Reboot Handling ──
	willReboot := false
	if finalReport.Kernel.RebootRequired {
		if opts.AllowReboot && runtime.GOOS == "linux" && !isOpenWrtSystem() {
			willReboot = true
			actions = append(actions, LayerActionDetail{
				Layer:   "kernel",
				Target:  "kernel-reboot",
				Success: true,
				Updated: true,
				Message: "将在 3 秒后平滑重启以加载新安全内核 (" + cmp.Or(finalReport.Kernel.InstalledKernel, "reboot-required") + ")",
			})
			updatedCount++
		} else {
			actions = append(actions, LayerActionDetail{
				Layer:   "kernel",
				Target:  "kernel-pending",
				Success: true,
				Updated: false,
				Message: cmp.Or(finalReport.Kernel.RebootReason, "存在待重启生效的内核补丁（已保留当前会话不断联，可在维护窗口执行滚动重启）"),
			})
		}
	}

	var summary string
	switch {
	case rollbackCount > 0:
		summary = fmt.Sprintf("自愈完成：更新 %d 项，触发 %d 项异常自动回滚保护（服务未中断）", updatedCount, rollbackCount)
	case updatedCount > 0 && !allOK:
		summary = fmt.Sprintf("已修复 %d 项安全更新，但部分组件更新遇到异常，请查看明细", updatedCount)
	case updatedCount > 0 && willReboot:
		summary = fmt.Sprintf("成功修复 %d 项安全更新，节点即将平滑重启加载新内核", updatedCount)
	case updatedCount > 0:
		summary = fmt.Sprintf("成功静默修复 %d 项安全更新，核心代理全程零中断", updatedCount)
	case !allOK:
		summary = "部分安全检查或更新步骤遇到异常，请查看明细"
	default:
		summary = "全栈已是最新安全基线，无需变更"
	}

	hist := HealHistoryItem{
		Timestamp:      time.Now().Format(time.RFC3339),
		Trigger:        trigger,
		Success:        allOK,
		DurationMs:     time.Since(start).Milliseconds(),
		Summary:        summary,
		Actions:        actions,
		RebootRequired: finalReport.Kernel.RebootRequired && !willReboot,
	}

	_ = RecordExecution(cfgPath, hist, &finalReport)
	finalReport.History = append([]HealHistoryItem{hist}, finalReport.History...)
	if len(finalReport.History) > 30 {
		finalReport.History = finalReport.History[:30]
	}

	if willReboot {
		triggerDelayedReboot()
	}

	return RunResult{
		Execution: hist,
		Status:    finalReport,
	}, nil
}

func healCoreComponent(ctx context.Context, cfg *config.Config, cfgPath string, comp ComponentCheck, asyncWebRestart bool) LayerActionDetail {
	switch comp.Name {
	case "singbox":
		binPath := locateBinary([]string{"/usr/local/bin/sing-box", "/usr/bin/sing-box"}, "sing-box")
		bakPath := backupBinary(binPath)
		defer cleanupBackup(bakPath)

		wasActive := isServiceActive("sing-box")
		res, err := deploy.UpgradeSingbox(cfg)
		if err != nil {
			if bakPath != "" {
				_ = restoreBinary(bakPath, binPath)
				if wasActive {
					_ = exec.Command("systemctl", "restart", "sing-box").Run()
				}
				return LayerActionDetail{
					Layer:      "core",
					Target:     "singbox",
					Success:    false,
					RolledBack: true,
					Message:    fmt.Sprintf("sing-box 升级异常，已自动回滚至 v%s: %v", comp.CurrentVersion, err),
				}
			}
			return LayerActionDetail{Layer: "core", Target: "singbox", Success: false, Message: err.Error()}
		}

		// Canary config check + 15s live systemd probe
		if probeErr := verifySingBoxHealth(ctx, binPath, wasActive); probeErr != nil {
			if bakPath != "" {
				_ = restoreBinary(bakPath, binPath)
				if wasActive {
					_ = exec.Command("systemctl", "restart", "sing-box").Run()
				}
			}
			return LayerActionDetail{
				Layer:      "core",
				Target:     "singbox",
				Success:    false,
				RolledBack: true,
				Message:    fmt.Sprintf("sing-box 新版健康自检未通过 (%v)，已秒级回滚至 v%s", probeErr, comp.CurrentVersion),
			}
		}
		return LayerActionDetail{
			Layer:   "core",
			Target:  "singbox",
			Success: true,
			Updated: res != nil && res.Updated,
			Message: fmt.Sprintf("sing-box 核心已安全升级 (v%s → v%s) 并通过健康校验", comp.CurrentVersion, cmp.Or(res.NewVersion, comp.LatestVersion)),
		}

	case "caddy":
		binPath := locateBinary([]string{"/usr/bin/caddy", "/usr/local/bin/caddy"}, "caddy")
		bakPath := backupBinary(binPath)
		defer cleanupBackup(bakPath)

		wasActive := isServiceActive("caddy")
		res, err := deploy.UpgradeCaddy(cfg)
		if err != nil {
			if bakPath != "" {
				_ = restoreBinary(bakPath, binPath)
				if wasActive {
					_ = exec.Command("systemctl", "restart", "caddy").Run()
				}
				return LayerActionDetail{
					Layer:      "core",
					Target:     "caddy",
					Success:    false,
					RolledBack: true,
					Message:    fmt.Sprintf("Caddy 升级异常，已自动回滚至 v%s: %v", comp.CurrentVersion, err),
				}
			}
			return LayerActionDetail{Layer: "core", Target: "caddy", Success: false, Message: err.Error()}
		}

		if probeErr := verifyCaddyHealth(ctx, binPath, wasActive); probeErr != nil {
			if bakPath != "" {
				_ = restoreBinary(bakPath, binPath)
				if wasActive {
					_ = exec.Command("systemctl", "restart", "caddy").Run()
				}
			}
			return LayerActionDetail{
				Layer:      "core",
				Target:     "caddy",
				Success:    false,
				RolledBack: true,
				Message:    fmt.Sprintf("Caddy 新版网关校验未通过 (%v)，已秒级回滚至 v%s", probeErr, comp.CurrentVersion),
			}
		}
		return LayerActionDetail{
			Layer:   "core",
			Target:  "caddy",
			Success: true,
			Updated: res != nil && res.Updated,
			Message: fmt.Sprintf("Caddy 网关已安全升级 (v%s → v%s) 并通过配置与存活验证", comp.CurrentVersion, cmp.Or(res.NewVersion, comp.LatestVersion)),
		}

	case "warp":
		binPath := locateBinary([]string{"/usr/local/bin/wireproxy", "/usr/bin/wireproxy"}, "wireproxy")
		bakPath := backupBinary(binPath)
		defer cleanupBackup(bakPath)

		wasActive := isServiceActive("wireproxy")
		res, err := deploy.UpgradeWarp(cfg)
		if err != nil {
			if bakPath != "" {
				_ = restoreBinary(bakPath, binPath)
				if wasActive {
					_ = exec.Command("systemctl", "restart", "wireproxy").Run()
				}
			}
			return LayerActionDetail{
				Layer:      "core",
				Target:     "warp",
				Success:    false,
				RolledBack: bakPath != "",
				Message:    fmt.Sprintf("WARP 升级失败，已保护性回滚: %v", err),
			}
		}
		if wasActive && !waitServiceActive(ctx, "wireproxy", 12*time.Second) {
			if bakPath != "" {
				_ = restoreBinary(bakPath, binPath)
				_ = exec.Command("systemctl", "restart", "wireproxy").Run()
			}
			return LayerActionDetail{
				Layer:      "core",
				Target:     "warp",
				Success:    false,
				RolledBack: true,
				Message:    "WARP 新版进程未就绪，已自动回滚至稳定版",
			}
		}
		return LayerActionDetail{
			Layer:   "core",
			Target:  "warp",
			Success: true,
			Updated: res != nil && res.Updated,
			Message: fmt.Sprintf("WARP (wireproxy) 已平滑升级至 v%s", cmp.Or(res.NewVersion, comp.LatestVersion)),
		}

	case "singctl":
		mirror := ""
		if cfg != nil {
			mirror = cfg.GitHub.MirrorURL
		}
		exePath, _ := updater.ResolveExecutablePath()
		bakPath := backupBinary(exePath)
		defer cleanupBackup(bakPath)

		up := updater.New(mirror, "")
		if err := up.UpdateSelf(cfgPath, comp.CurrentVersion); err != nil {
			if bakPath != "" {
				_ = restoreBinary(bakPath, exePath)
			}
			return LayerActionDetail{
				Layer:   "core",
				Target:  "singctl",
				Success: false,
				Message: fmt.Sprintf("SingCtl 自升级未完成: %v", err),
			}
		}
		if isServiceActive("singctl-sub") {
			_ = exec.Command("systemctl", "restart", "singctl-sub").Run()
		}
		restartWebDaemonSafely(asyncWebRestart)
		return LayerActionDetail{
			Layer:   "core",
			Target:  "singctl",
			Success: true,
			Updated: true,
			Message: fmt.Sprintf("SingCtl 与 SubHub 已通过 SHA-256 校验并平滑升级 (v%s → v%s)", comp.CurrentVersion, comp.LatestVersion),
		}
	}

	return LayerActionDetail{Layer: "core", Target: comp.Name, Success: true, Message: "无需变更"}
}

func healOSLayer(ctx context.Context, asyncWebRestart bool) []LayerActionDetail {
	var actions []LayerActionDetail

	if isOpenWrtSystem() {
		actions = append(actions, LayerActionDetail{
			Layer:   "os",
			Target:  "openwrt-guard",
			Success: true,
			Updated: false,
			Message: "OpenWrt 闪存防变砖保护生效：跳过全量 opkg upgrade，仅维护核心二进制",
		})
		return actions
	}

	switch {
	case hasBinary("apt-get"):
		uCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		updCmd := exec.CommandContext(uCtx, "apt-get", "update", "-qq")
		updCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		_ = updCmd.Run()
		cancel()

		sCtx, sCancel := context.WithTimeout(ctx, 20*time.Second)
		simCmd := exec.CommandContext(sCtx, "apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade")
		simCmd.Env = append(os.Environ(), "LC_ALL=C")
		simOut, simErr := simCmd.CombinedOutput()
		sCancel()

		if simErr == nil {
			secPkgs := ParseAptSimulateSecurityUpdates(string(simOut))
			if len(secPkgs) > 0 {
				iCtx, iCancel := context.WithTimeout(ctx, 4*time.Minute)
				args := []string{
					"install", "--only-upgrade", "-y",
					"-o", "Dpkg::Options::=--force-confdef",
					"-o", "Dpkg::Options::=--force-confold",
					"--",
				}
				args = append(args, secPkgs...)
				instCmd := exec.CommandContext(iCtx, "apt-get", args...)
				instCmd.Env = append(os.Environ(),
					"DEBIAN_FRONTEND=noninteractive",
					"NEEDRESTART_MODE=l",
					"APT_LISTCHANGES_FRONTEND=none",
				)
				out, iErr := instCmd.CombinedOutput()
				iCancel()

				if iErr != nil {
					actions = append(actions, LayerActionDetail{
						Layer:   "os",
						Target:  "apt-security",
						Success: false,
						Message: fmt.Sprintf("APT 安全补丁安装异常: %v (%s)", iErr, truncateText(string(out), 160)),
					})
				} else {
					verifySSHDConfig()
					preview := strings.Join(secPkgs[:min(5, len(secPkgs))], ", ")
					if len(secPkgs) > 5 {
						preview += fmt.Sprintf(" 等 %d 个包", len(secPkgs))
					}
					actions = append(actions, LayerActionDetail{
						Layer:   "os",
						Target:  "apt-security",
						Success: true,
						Updated: true,
						Message: fmt.Sprintf("已无感安装 %d 个系统安全补丁 (%s)，保留全部自定义配置", len(secPkgs), preview),
					})
				}
			}
		}

	case hasBinary("dnf"):
		cCtx, cCancel := context.WithTimeout(ctx, 20*time.Second)
		chkOut, _ := exec.CommandContext(cCtx, "dnf", "check-update", "--security", "-q").CombinedOutput()
		cCancel()
		secPkgs := ParseDnfSecurityCheckUpdate(string(chkOut))
		if len(secPkgs) > 0 {
			uCtx, uCancel := context.WithTimeout(ctx, 4*time.Minute)
			out, uErr := exec.CommandContext(uCtx, "dnf", "update", "--security", "-y").CombinedOutput()
			uCancel()
			if uErr != nil {
				actions = append(actions, LayerActionDetail{
					Layer:   "os",
					Target:  "dnf-security",
					Success: false,
					Message: fmt.Sprintf("DNF 安全更新异常: %v (%s)", uErr, truncateText(string(out), 160)),
				})
			} else {
				verifySSHDConfig()
				actions = append(actions, LayerActionDetail{
					Layer:   "os",
					Target:  "dnf-security",
					Success: true,
					Updated: true,
					Message: fmt.Sprintf("已安装 %d 个 RHEL/DNF 安全更新", len(secPkgs)),
				})
			}
		}
	}

	// Reload any daemons still holding unlinked/vulnerable shared libraries (.so) in RAM
	stale := ScanStaleSharedLibraryServices()
	if len(stale) > 0 {
		var reloaded []string
		for _, svc := range stale {
			switch svc {
			case "sshd":
				if verifySSHDConfig() {
					if exec.Command("systemctl", "reload", "sshd").Run() != nil {
						_ = exec.Command("systemctl", "reload", "ssh").Run()
					}
					reloaded = append(reloaded, "sshd")
				}
			case "caddy":
				if exec.Command("systemctl", "reload", "caddy").Run() != nil {
					_ = exec.Command("systemctl", "restart", "caddy").Run()
				}
				reloaded = append(reloaded, "caddy")
			case "singctl-web":
				restartWebDaemonSafely(asyncWebRestart)
				reloaded = append(reloaded, "singctl-web")
			default:
				if exec.Command("systemctl", "restart", svc).Run() == nil {
					reloaded = append(reloaded, svc)
				}
			}
		}
		if len(reloaded) > 0 {
			actions = append(actions, LayerActionDetail{
				Layer:   "os",
				Target:  "stale-libs",
				Success: true,
				Updated: true,
				Message: "检测到内存残留旧版动态库 (.so)，已平滑热重载服务: " + strings.Join(reloaded, ", "),
			})
		}
	}

	return actions
}

func verifySingBoxHealth(ctx context.Context, binPath string, expectActive bool) error {
	if binPath != "" {
		if _, err := os.Stat("/etc/sing-box/config.json"); err == nil {
			if out, cErr := exec.Command(binPath, "check", "-c", "/etc/sing-box/config.json").CombinedOutput(); cErr != nil {
				return fmt.Errorf("config check failed: %s", truncateText(string(out), 120))
			}
		}
	}
	if expectActive && !waitServiceActive(ctx, "sing-box", 15*time.Second) {
		return fmt.Errorf("sing-box systemd service failed to reach active state within 15s")
	}
	return nil
}

func verifyCaddyHealth(ctx context.Context, binPath string, expectActive bool) error {
	if binPath != "" {
		if _, err := os.Stat("/etc/caddy/Caddyfile"); err == nil {
			if out, cErr := exec.Command(binPath, "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile").CombinedOutput(); cErr != nil {
				return fmt.Errorf("Caddyfile validate failed: %s", truncateText(string(out), 120))
			}
		}
	}
	if expectActive && !waitServiceActive(ctx, "caddy", 15*time.Second) {
		return fmt.Errorf("caddy systemd service failed to reach active state within 15s")
	}
	return nil
}

func verifySSHDConfig() bool {
	sshdBin := locateBinary([]string{"/usr/sbin/sshd", "/sbin/sshd"}, "sshd")
	if sshdBin == "" {
		return true
	}
	return exec.Command(sshdBin, "-t").Run() == nil
}

func isServiceActive(unit string) bool {
	if !hasBinary("systemctl") {
		return false
	}
	out, err := exec.Command("systemctl", "is-active", unit).Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

func waitServiceActive(ctx context.Context, unit string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if isServiceActive(unit) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(1 * time.Second):
		}
	}
	return isServiceActive(unit)
}

func restartWebDaemonSafely(async bool) {
	hasSystemdUnit := false
	unitName := ""
	if hasBinary("systemctl") {
		for _, candidate := range []string{"singctl-serverweb", "singctl-web"} {
			if out, err := exec.Command("systemctl", "is-active", candidate).Output(); err == nil && strings.TrimSpace(string(out)) == "active" {
				hasSystemdUnit = true
				unitName = candidate
				break
			}
		}
	}

	hasBgPid := false
	if _, err := os.Stat("/tmp/singctl-serverweb.pid"); err == nil {
		hasBgPid = true
	}

	if !hasSystemdUnit && !hasBgPid {
		return
	}

	binPath := locateBinary([]string{"/usr/local/bin/singctl", "/usr/bin/singctl"}, "singctl")
	if async {
		if hasSystemdUnit {
			cmd := exec.Command("sh", "-c", fmt.Sprintf("sleep 2 && systemctl restart %s >/dev/null 2>&1", unitName))
			_ = cmd.Start()
		} else if hasBgPid && binPath != "" {
			cmd := exec.Command("sh", "-c", fmt.Sprintf("sleep 2 && env -u SINGCTL_SERVER_WEB_BACKGROUND %s sr web restart >/dev/null 2>&1", binPath))
			_ = cmd.Start()
		}
		return
	}
	if hasSystemdUnit {
		_ = exec.Command("systemctl", "restart", unitName).Run()
	} else if hasBgPid && binPath != "" {
		cmd := exec.Command("env", "-u", "SINGCTL_SERVER_WEB_BACKGROUND", binPath, "sr", "web", "restart")
		_ = cmd.Run()
	}
}

func triggerDelayedReboot() {
	cmd := exec.Command("sh", "-c", "nohup sh -c 'sleep 3 && (systemctl reboot || reboot)' >/dev/null 2>&1 &")
	_ = cmd.Start()
}

func locateBinary(candidates []string, name string) string {
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func backupBinary(src string) string {
	if strings.TrimSpace(src) == "" {
		return ""
	}
	in, err := os.Open(src)
	if err != nil {
		return ""
	}
	defer in.Close()
	bak := src + ".heal.bak"
	out, err := os.OpenFile(bak, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return ""
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(bak)
		return ""
	}
	_ = out.Close()
	return bak
}

func restoreBinary(bak, dst string) error {
	if bak == "" || dst == "" {
		return fmt.Errorf("empty path")
	}
	tmp := dst + ".heal.restore"
	in, err := os.Open(bak)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	_ = out.Close()
	return os.Rename(tmp, dst)
}

func cleanupBackup(bak string) {
	if bak != "" {
		_ = os.Remove(bak)
	}
}

func truncateText(s string, maxLen int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " | ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
