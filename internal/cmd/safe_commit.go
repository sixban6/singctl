// 文件职责：提供 `singctl safe-commit` 远端安全回滚保险丝子命令族（arm/confirm/rollback/status/_watch）与真实服务回滚回调装配。
package cmd

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/firewall"
	"singctl/internal/localdns"
	"singctl/internal/logger"
	"singctl/internal/notify"
	"singctl/internal/safecommit"
	"singctl/internal/singbox"

	"github.com/spf13/cobra"
)

// SafeCommitCmdDeps 封装 CLI 安全回滚子命令的可注入依赖（零值自动回退生产默认实现）。
type SafeCommitCmdDeps struct {
	StateDir           string
	ProcRoot           string
	SingBoxConfigPath  string
	SmartDNSConfigPath string
	AdGuardConfigPath  string
	NowFunc            func() time.Time
	WatchInterval      time.Duration
	SpawnWatcher       func(token string) (int, error)
	KillWatcher        func(pid int) error
	BaselineProbe      func() (sbRunning bool, fwActive bool)
	RollbackOps        *safecommit.RollbackOps
	NotifyHTTPClient   *http.Client
}

// NewSafeCommitCmd 创建 `singctl safe-commit` 远端安全回滚保险丝命令。
func NewSafeCommitCmd(configPath string) *cobra.Command {
	return NewSafeCommitCmdWithDeps(configPath, SafeCommitCmdDeps{})
}

// NewSafeCommitCmdWithDeps 创建带显式依赖注入的 `singctl safe-commit` 命令（供离线单元测试使用）。
func NewSafeCommitCmdWithDeps(configPath string, deps SafeCommitCmdDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "safe-commit",
		Aliases: []string{"sc"},
		Short:   "保险丝: 远端安全回滚保险丝与 OOM 免疫保护 / Safe commit rollback fuse",
		Long:    "在执行高危路由/防火墙/DNS/sing-box 变更前启动倒计时回滚保险丝；若未在超时前确认，将自动还原快照并恢复网络连通。",
	}

	cmd.AddCommand(
		newSafeCommitArmCmd(configPath, deps),
		newSafeCommitConfirmCmd(configPath, deps),
		newSafeCommitRollbackCmd(configPath, deps),
		newSafeCommitStatusCmd(configPath, deps),
		newSafeCommitWatchCmd(configPath, deps),
	)
	return cmd
}

func resolveSafeCommitPaths(deps SafeCommitCmdDeps) (sbPath, sdPath, aghPath string) {
	sbPath = cmp.Or(strings.TrimSpace(deps.SingBoxConfigPath), constant.SingBoxConfigFile)
	sdPath = cmp.Or(strings.TrimSpace(deps.SmartDNSConfigPath), constant.SmartDNSConfigFile)
	aghPath = cmp.Or(strings.TrimSpace(deps.AdGuardConfigPath), constant.AdGuardConfigFile)
	return sbPath, sdPath, aghPath
}

func buildCLISafeCommitManager(cfgPath string, deps SafeCommitCmdDeps) *safecommit.Manager {
	sbPath, _, _ := resolveSafeCommitPaths(deps)
	workPath := ""
	if sbPath == constant.SingBoxConfigFile {
		workPath = constant.SingBoxWorkConfigFile
	}

	loadCfg := func() *config.Config {
		if strings.TrimSpace(cfgPath) != "" {
			if cfg, err := config.Load(cfgPath); err == nil && cfg != nil {
				return cfg
			}
		}
		return &config.Config{}
	}

	var ops safecommit.RollbackOps
	if deps.RollbackOps != nil {
		ops = *deps.RollbackOps
	} else {
		ops = safecommit.RollbackOps{
			StopSingBox: func(context.Context) error {
				return singbox.New(loadCfg()).Stop()
			},
			StartOrReloadSingBox: func(ctx context.Context) error {
				cfg := loadCfg()
				if raw, err := os.ReadFile(sbPath); err == nil && len(raw) > 0 && workPath != "" {
					_ = singbox.SyncSandboxWorkConfig(ctx, sbPath, workPath, string(raw), ".rollback.tmp")
				}
				sb := singbox.New(cfg)
				if daemon.IsSingBoxRunning() {
					_ = sb.Stop()
				}
				return sb.Start()
			},
			DisableFirewall: func(context.Context) error {
				return firewall.Disable()
			},
			ReloadFirewall: func(context.Context) error {
				cfg := loadCfg()
				return firewall.EnableWithOptions(firewall.OptionsFromConfig(cfg, ""), true)
			},
			ReloadDNS: func(ctx context.Context, engine string) error {
				cfg := loadCfg()
				reg := localdns.NewRegistry(cfg, localdns.EngineDeps{ConfigPath: cfgPath})
				eng, ok := reg.Get(engine)
				if !ok || eng == nil {
					eng = reg.ActiveEngine()
				}
				if eng == nil || !eng.IsInstalled() {
					return nil
				}
				if err := eng.SyncCommonConfig(ctx); err != nil {
					return err
				}
				return eng.Restart(ctx)
			},
			OnRolledBack: func(rec safecommit.RollbackRecord) {
				_ = daemon.NotifyReload()
				dispatchCLIRollbackNotify(loadCfg(), rec, deps.NotifyHTTPClient)
			},
		}
	}

	return safecommit.NewManager(safecommit.ManagerOptions{
		StateDir:      strings.TrimSpace(deps.StateDir),
		ProcRoot:      strings.TrimSpace(deps.ProcRoot),
		NowFunc:       deps.NowFunc,
		WatchInterval: deps.WatchInterval,
		SpawnWatcher:  deps.SpawnWatcher,
		KillWatcher:   deps.KillWatcher,
		RollbackOps:   ops,
	})
}

func dispatchCLIRollbackNotify(cfg *config.Config, rec safecommit.RollbackRecord, httpClient *http.Client) {
	if cfg == nil || !cfg.Notify.Enabled {
		return
	}
	opts := notify.OptionsFromConfig(cfg.Notify)
	d := notify.NewDispatcher(opts, notify.DispatcherDeps{HTTPClient: httpClient})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	d.Start(ctx)
	defer d.Close()

	body := fmt.Sprintf("触发方式: %s | 原因: %s | 执行动作: %d 项",
		cmp.Or(rec.Trigger, "timeout"),
		cmp.Or(rec.Reason, "未说明"),
		len(rec.Actions))
	if rec.Error != "" {
		body += " | 部分错误: " + rec.Error
	}
	queued, _ := d.Emit(notify.Event{
		Type:     notify.EventSafeCommitRollback,
		Severity: notify.SeverityCritical,
		DedupKey: cmp.Or(rec.Token, "safecommit"),
		Title:    "Safe Commit 安全回滚已执行",
		Body:     body,
	})
	if !queued {
		return
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if len(d.RecentHistory()) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func absPathClean(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" {
		return ""
	}
	if filepath.IsAbs(trimmed) {
		return filepath.Clean(trimmed)
	}
	if abs, err := filepath.Abs(trimmed); err == nil {
		return abs
	}
	return ""
}

func armSafeCommitCLI(ctx context.Context, cfgPath string, ttlSec int, reason string, deps SafeCommitCmdDeps) (*safecommit.State, error) {
	var cfg *config.Config
	if strings.TrimSpace(cfgPath) != "" {
		cfg, _ = config.Load(cfgPath)
	}
	if cfg == nil {
		cfg = &config.Config{}
	}

	effectiveTTL := ttlSec
	if effectiveTTL == 0 {
		effectiveTTL = cfg.SafeCommit.EffectiveTTLSec()
	}
	if effectiveTTL < constant.SafeCommitMinTTLSec || effectiveTTL > constant.SafeCommitMaxTTLSec {
		return nil, fmt.Errorf("%w: got %d", safecommit.ErrInvalidTTL, ttlSec)
	}

	sbPath, sdPath, aghPath := resolveSafeCommitPaths(deps)
	snapshots := make(map[string]string, 4)
	addSnap := func(name, p string) {
		if abs := absPathClean(p); abs != "" {
			snapshots[name] = abs
		}
	}
	addSnap("singctl.yaml", cfgPath)
	addSnap("sing-box.json", sbPath)
	addSnap("smartdns.conf", sdPath)
	addSnap("adguard.yaml", aghPath)

	sbRunning, fwActive := false, false
	if deps.BaselineProbe != nil {
		sbRunning, fwActive = deps.BaselineProbe()
	} else {
		sbRunning = daemon.IsSingBoxRunning()
		qs := firewall.InspectQuickStatus()
		fwActive = qs.KernelActive || qs.Enabled
	}

	dnsEngine := ""
	if active := localdns.NewRegistry(cfg, localdns.EngineDeps{ConfigPath: cfgPath}).ActiveEngine(); active != nil {
		dnsEngine = active.ID()
	}

	mgr := buildCLISafeCommitManager(cfgPath, deps)
	return mgr.Arm(ctx, safecommit.ArmRequest{
		TTLSec:            effectiveTTL,
		Reason:            strings.TrimSpace(reason),
		SingBoxWasRunning: sbRunning,
		FirewallWasActive: fwActive,
		DNSEngine:         dnsEngine,
		SnapshotFiles:     snapshots,
	})
}

func newSafeCommitArmCmd(defaultConfigPath string, deps SafeCommitCmdDeps) *cobra.Command {
	var ttlSec int
	var reason string
	cmd := &cobra.Command{
		Use:   "arm",
		Short: "启动安全回滚倒计时保险丝 / Arm safe-commit rollback fuse",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			st, err := armSafeCommitCLI(cmd.Context(), resolvedPath, ttlSec, reason, deps)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"🛡️ Safe Commit 保险丝已激活 (TTL=%ds, Token=%s)\n请在 %d 秒内确认变更，否则自动回滚：\n  singctl safe-commit confirm --token %s\n",
				st.TTLSec, st.Token, st.TTLSec, st.Token)
			return nil
		},
	}
	cmd.Flags().IntVar(&ttlSec, "ttl", 0, "自动回滚倒计时秒数（0=使用配置默认值，范围 60..600）")
	cmd.Flags().StringVar(&reason, "reason", "", "本次变更原因说明")
	return cmd
}

func newSafeCommitConfirmCmd(defaultConfigPath string, deps SafeCommitCmdDeps) *cobra.Command {
	var token string
	cmd := &cobra.Command{
		Use:   "confirm",
		Short: "确认变更有效并解除保险丝 / Confirm changes and disarm fuse",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			mgr := buildCLISafeCommitManager(resolvedPath, deps)
			confirmed, err := mgr.Confirm(token)
			if err != nil {
				return err
			}
			if confirmed {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "✅ 已确认变更，Safe Commit 安全回滚保险丝已解除")
			} else {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "当前无激活的安全回滚保险丝")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "保险丝确认令牌（留空则直接解除当前激活保险丝）")
	return cmd
}

func newSafeCommitRollbackCmd(defaultConfigPath string, deps SafeCommitCmdDeps) *cobra.Command {
	var trigger string
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "立即执行安全回滚恢复快照 / Rollback to snapshot immediately",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			mgr := buildCLISafeCommitManager(resolvedPath, deps)
			rec, err := mgr.Rollback(cmd.Context(), cmp.Or(strings.TrimSpace(trigger), "manual"))
			if rec == nil && err == nil {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "当前无激活的安全回滚保险丝")
				return nil
			}
			if rec != nil {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "⏪ 已执行安全回滚 (trigger=%s, success=%v, actions=%d)\n",
					rec.Trigger, rec.Success, len(rec.Actions))
			}
			return err
		},
	}
	cmd.Flags().StringVar(&trigger, "trigger", "manual", "回滚触发原因标签")
	return cmd
}

func newSafeCommitStatusCmd(defaultConfigPath string, deps SafeCommitCmdDeps) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "查看保险丝状态与 Tailscale OOM 免疫状态 / Show safe-commit & OOM shield status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			mgr := buildCLISafeCommitManager(resolvedPath, deps)
			st := mgr.Status()
			if asJSON {
				raw, err := json.MarshalIndent(st, "", "  ")
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(raw))
				return nil
			}
			if st.Active && st.State != nil {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "状态: 激活中 (剩余 %ds, Token=%s, 原因=%s)\n",
					st.RemainingSec, st.State.Token, cmp.Or(st.State.Reason, "-"))
			} else {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "状态: 未激活")
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Tailscale OOM 免疫: %s\n", cmp.Or(st.TailscaleOOM.Message, "-"))
			if st.LastRollback != nil {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "最近回滚: trigger=%s success=%v at=%s\n",
					st.LastRollback.Trigger, st.LastRollback.Success, time.Unix(st.LastRollback.RolledBackAt, 0).Format(time.DateTime))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "以 JSON 格式输出状态")
	return cmd
}

func newSafeCommitWatchCmd(defaultConfigPath string, deps SafeCommitCmdDeps) *cobra.Command {
	var token string
	cmd := &cobra.Command{
		Use:    "_watch",
		Short:  "内部脱离进程组看门狗守护 / Internal detached rollback watcher",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(token) == "" {
				return errors.New("--token is required")
			}
			resolvedPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			mgr := buildCLISafeCommitManager(resolvedPath, deps)
			if err := mgr.Watch(cmd.Context(), token); err != nil {
				logger.Warn("[SafeCommit] watcher exited with error: %v", err)
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "safe-commit watch token")
	return cmd
}
