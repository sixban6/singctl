// 文件职责：定义 sing-box、AdGuard Home、Tailscale 与 SingCtl 四个内置组件自动更新目标及零断网切换/回滚逻辑。
package daemon

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/common/fsx"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/singbox"
	"singctl/internal/tailscale"
	"singctl/internal/updater"
)

// DefaultAutoUpdateTargets 返回按安全顺序排列的 4 个默认组件自动更新目标：
// sing-box → AdGuard Home → Tailscale → SingCtl（本体放最后，防止自身热重启打断其他组件检查）。
func DefaultAutoUpdateTargets(d *Daemon) []AutoUpdateTarget {
	return []AutoUpdateTarget{
		&singboxAutoUpdateTarget{daemon: d},
		&adguardAutoUpdateTarget{daemon: d},
		&tailscaleAutoUpdateTarget{},
		&singctlAutoUpdateTarget{daemon: d},
	}
}

type singboxAutoUpdateTarget struct {
	daemon *Daemon
}

func (t *singboxAutoUpdateTarget) ID() string          { return AutoUpdateComponentSingBox }
func (t *singboxAutoUpdateTarget) DisplayName() string { return "sing-box" }
func (t *singboxAutoUpdateTarget) Enabled(cfg *config.Config) bool {
	return cfg != nil && cfg.Watchdog.AutoUpdate.SingBox
}

func (t *singboxAutoUpdateTarget) Run(_ context.Context, cfg *config.Config) (AutoUpdateCheckResult, error) {
	if !cfg.NeedsSingBox() {
		return AutoUpdateCheckResult{
			Component: AutoUpdateComponentSingBox,
			Skipped:   true,
			Message:   "当前处于托管模式（免运行本机 sing-box），已跳过",
		}, nil
	}
	binPath := constant.SingBoxInstallDir
	if _, err := os.Stat(binPath); err != nil {
		if looked, lErr := exec.LookPath("sing-box"); lErr == nil {
			binPath = looked
		} else {
			return AutoUpdateCheckResult{
				Component: AutoUpdateComponentSingBox,
				Installed: false,
				Skipped:   true,
				Message:   "未安装 sing-box，已跳过",
			}, nil
		}
	}

	sb := singbox.New(cfg)
	curVer, latestVer, upToDate, err := sb.CheckUpdate()
	if err != nil {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentSingBox,
			Installed:      true,
			CurrentVersion: curVer,
		}, err
	}
	if upToDate {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentSingBox,
			Installed:      true,
			Updated:        false,
			CurrentVersion: curVer,
			LatestVersion:  latestVer,
			Message:        fmt.Sprintf("已是最新版本 (%s)", curVer),
		}, nil
	}

	wasRunning := IsSingBoxRunning()
	bakPath := binPath + ".auto-update.bak"
	hasBackup := false
	if raw, rErr := os.ReadFile(binPath); rErr == nil && len(raw) > 0 {
		if wErr := os.WriteFile(bakPath, raw, 0700); wErr == nil {
			hasBackup = true
			defer os.Remove(bakPath)
		}
	}

	if err := sb.Update(); err != nil {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentSingBox,
			Installed:      true,
			CurrentVersion: curVer,
			LatestVersion:  latestVer,
		}, err
	}

	if wasRunning {
		rollback := func(cause error) error {
			if hasBackup {
				if rbErr := fsx.InstallOrReplace(bakPath, binPath); rbErr == nil {
					_ = sb.Start()
				}
			}
			return cause
		}
		if t.daemon != nil {
			t.daemon.lifecycleMu.Lock()
			t.daemon.reloading.Store(true)
			defer func() {
				t.daemon.reloading.Store(false)
				t.daemon.lifecycleMu.Unlock()
			}()
		}
		if vErr := sb.ValidateConfig(); vErr != nil {
			return AutoUpdateCheckResult{
				Component:      AutoUpdateComponentSingBox,
				Installed:      true,
				CurrentVersion: curVer,
				LatestVersion:  latestVer,
			}, rollback(fmt.Errorf("新版配置预检失败并已回滚: %w", vErr))
		}
		_ = sb.Stop()
		if sErr := sb.Start(); sErr != nil {
			return AutoUpdateCheckResult{
				Component:      AutoUpdateComponentSingBox,
				Installed:      true,
				CurrentVersion: curVer,
				LatestVersion:  latestVer,
			}, rollback(fmt.Errorf("新版启动失败并已回滚: %w", sErr))
		}
	}

	return AutoUpdateCheckResult{
		Component:      AutoUpdateComponentSingBox,
		Installed:      true,
		Updated:        true,
		CurrentVersion: latestVer,
		LatestVersion:  latestVer,
		Message:        fmt.Sprintf("已自动更新 %s → %s 并平滑切换", cmp.Or(curVer, "旧版"), latestVer),
	}, nil
}

type adguardAutoUpdateTarget struct {
	daemon *Daemon
}

func (t *adguardAutoUpdateTarget) ID() string          { return AutoUpdateComponentAdGuard }
func (t *adguardAutoUpdateTarget) DisplayName() string { return "AdGuard Home" }
func (t *adguardAutoUpdateTarget) Enabled(cfg *config.Config) bool {
	return cfg != nil && cfg.Watchdog.AutoUpdate.AdGuardHome
}

func (t *adguardAutoUpdateTarget) Run(ctx context.Context, cfg *config.Config) (AutoUpdateCheckResult, error) {
	if !adguard.IsInstalled() {
		return AutoUpdateCheckResult{
			Component: AutoUpdateComponentAdGuard,
			Installed: false,
			Skipped:   true,
			Message:   "未安装 AdGuard Home，已跳过",
		}, nil
	}
	cfgPath := ""
	if t.daemon != nil {
		cfgPath = t.daemon.configPath
	}
	mgr := adguard.NewManager(cfg, cfgPath)
	curVer, latestVer, upToDate, err := mgr.CheckLatestVersion(ctx)
	if err != nil {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentAdGuard,
			Installed:      true,
			CurrentVersion: curVer,
		}, err
	}
	if upToDate {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentAdGuard,
			Installed:      true,
			Updated:        false,
			CurrentVersion: curVer,
			LatestVersion:  latestVer,
			Message:        fmt.Sprintf("已是最新版本 (%s)", curVer),
		}, nil
	}

	if _, err := mgr.Install(adguard.InstallOptions{
		ConfigPath:     cfgPath,
		NonInteractive: true,
		ForceDownload:  true,
	}); err != nil {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentAdGuard,
			Installed:      true,
			CurrentVersion: curVer,
			LatestVersion:  latestVer,
		}, err
	}

	return AutoUpdateCheckResult{
		Component:      AutoUpdateComponentAdGuard,
		Installed:      true,
		Updated:        true,
		CurrentVersion: latestVer,
		LatestVersion:  latestVer,
		Message:        fmt.Sprintf("已自动更新 %s → %s 并平滑重启", cmp.Or(curVer, "旧版"), latestVer),
	}, nil
}

type tailscaleAutoUpdateTarget struct{}

func (t *tailscaleAutoUpdateTarget) ID() string          { return AutoUpdateComponentTailscale }
func (t *tailscaleAutoUpdateTarget) DisplayName() string { return "Tailscale" }
func (t *tailscaleAutoUpdateTarget) Enabled(cfg *config.Config) bool {
	return cfg != nil && cfg.Watchdog.AutoUpdate.Tailscale
}

func (t *tailscaleAutoUpdateTarget) Run(ctx context.Context, cfg *config.Config) (AutoUpdateCheckResult, error) {
	if _, err := exec.LookPath("tailscale"); err != nil {
		return AutoUpdateCheckResult{
			Component: AutoUpdateComponentTailscale,
			Installed: false,
			Skipped:   true,
			Message:   "未安装 Tailscale，已跳过",
		}, nil
	}
	ts := tailscale.New(cfg.GitHub.MirrorURL, &cfg.Tailscale)
	pre, err := ts.PreflightUpgrade(ctx, tailscale.UpgradeOptions{})
	if err != nil {
		return AutoUpdateCheckResult{
			Component: AutoUpdateComponentTailscale,
			Installed: true,
		}, err
	}
	if !pre.Supported {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentTailscale,
			Installed:      true,
			Skipped:        true,
			CurrentVersion: pre.CurrentVersion,
			Message:        cmp.Or(pre.UnsupportedReason, "当前平台不支持 Tailscale 自动升级"),
		}, nil
	}
	if len(pre.BlockedReasons) > 0 {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentTailscale,
			Installed:      true,
			Skipped:        true,
			CurrentVersion: pre.CurrentVersion,
			LatestVersion:  pre.LatestVersion,
			Message:        "安全预检拦截: " + strings.Join(pre.BlockedReasons, "；"),
		}, nil
	}
	if pre.UpToDate {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentTailscale,
			Installed:      true,
			Updated:        false,
			CurrentVersion: pre.CurrentVersion,
			LatestVersion:  pre.LatestVersion,
			Message:        fmt.Sprintf("已是最新版本 (%s)", pre.CurrentVersion),
		}, nil
	}

	if err := ts.SafeUpdate(ctx, tailscale.UpgradeOptions{Wait: true}); err != nil {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentTailscale,
			Installed:      true,
			CurrentVersion: pre.CurrentVersion,
			LatestVersion:  pre.LatestVersion,
		}, err
	}

	return AutoUpdateCheckResult{
		Component:      AutoUpdateComponentTailscale,
		Installed:      true,
		Updated:        true,
		CurrentVersion: pre.LatestVersion,
		LatestVersion:  pre.LatestVersion,
		Message:        fmt.Sprintf("已自动更新 %s → %s 并切换生效", cmp.Or(pre.CurrentVersion, "旧版"), pre.LatestVersion),
	}, nil
}

type singctlAutoUpdateTarget struct {
	daemon *Daemon
}

func (t *singctlAutoUpdateTarget) ID() string          { return AutoUpdateComponentSingCtl }
func (t *singctlAutoUpdateTarget) DisplayName() string { return "SingCtl" }
func (t *singctlAutoUpdateTarget) Enabled(cfg *config.Config) bool {
	return cfg != nil && cfg.Watchdog.AutoUpdate.SingCtl
}

func (t *singctlAutoUpdateTarget) Run(ctx context.Context, cfg *config.Config) (AutoUpdateCheckResult, error) {
	curVer := ""
	cfgPath := ""
	if t.daemon != nil {
		curVer = strings.TrimSpace(t.daemon.version)
		cfgPath = t.daemon.configPath
	}
	normCur := strings.TrimPrefix(curVer, "v")
	if normCur == "" || normCur == "dev" {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentSingCtl,
			Installed:      true,
			Skipped:        true,
			CurrentVersion: curVer,
			Message:        "开发版跳过自动更新",
		}, nil
	}

	up := updater.New(cfg.GitHub.MirrorURL, constant.GitHubRepoURL)
	latestVer, upToDate, err := up.CheckLatest(ctx, curVer)
	if err != nil {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentSingCtl,
			Installed:      true,
			CurrentVersion: curVer,
		}, err
	}
	if upToDate {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentSingCtl,
			Installed:      true,
			Updated:        false,
			CurrentVersion: curVer,
			LatestVersion:  "v" + latestVer,
			Message:        fmt.Sprintf("已是最新版本 (v%s)", normCur),
		}, nil
	}

	if err := up.UpdateSelf(cfgPath, curVer); err != nil {
		return AutoUpdateCheckResult{
			Component:      AutoUpdateComponentSingCtl,
			Installed:      true,
			CurrentVersion: curVer,
			LatestVersion:  "v" + latestVer,
		}, err
	}

	// 延迟 2 秒触发脱离式自重启，确保本轮运行态快照与事件先原子落盘再移交新版二进制。
	scheduleDetachedSingCtlHandoff(cfgPath)

	return AutoUpdateCheckResult{
		Component:      AutoUpdateComponentSingCtl,
		Installed:      true,
		Updated:        true,
		CurrentVersion: "v" + latestVer,
		LatestVersion:  "v" + latestVer,
		Message:        fmt.Sprintf("已自动更新 v%s → v%s，正在平滑切换重启", normCur, latestVer),
	}, nil
}

func scheduleDetachedSingCtlHandoff(cfgPath string) {
	exePath, err := updater.ResolveExecutablePath()
	if err != nil || strings.TrimSpace(exePath) == "" {
		return
	}
	go func() {
		time.Sleep(2 * time.Second)
		// 若存在独立的系统托管 singctl-web 服务，经 platform/servicemgr 平滑重启（不中断 sing-box）。
		if mgr := servicemgr.Detect(nil); mgr != nil {
			rCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			if mgr.IsActive(rCtx, "singctl-web") {
				_ = mgr.Restart(rCtx, "singctl-web")
			}
			cancel()
		}
		args := []string{"dm", "restart"}
		if strings.TrimSpace(cfgPath) != "" {
			args = []string{"--config", cfgPath, "dm", "restart"}
		}
		cmd := exec.Command(exePath, args...)
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		detachExecCmd(cmd)
		if startErr := cmd.Start(); startErr != nil {
			logger.Warn("[AutoUpdate] 脱离重启 singctl dm 失败: %v", startErr)
		}
	}()
}
