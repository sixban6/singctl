package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/logger"
	"singctl/internal/singbox"
	ruleset_snapshot "singctl/internal/singbox/ruleset_snapshot"
	"time"

	"github.com/spf13/cobra"
)

var (
	commandRunner = exec.Command
	runtimeGOOS   = runtime.GOOS
	// defaultSingBoxConfigPath 默认 sing-box 配置路径，测试可注入。
	defaultSingBoxConfigPath = constant.SingBoxConfigFile
)

func copyGeneratedConfigToClipboard(targetPath string) (bool, error) {
	if runtimeGOOS != "darwin" || targetPath != defaultSingBoxConfigPath {
		return false, nil
	}

	configFile, err := os.Open(targetPath)
	if err != nil {
		return false, fmt.Errorf("open generated config failed: %w", err)
	}
	defer configFile.Close()

	cmd := commandRunner("pbcopy")
	cmd.Stdin = configFile
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("run pbcopy failed: %w", err)
	}

	return true, nil
}

func runStartSingbox(cfg *config.Config) error {
	sb := singbox.New(cfg)
	if err := sb.ValidateConfig(); err != nil {
		// 现有配置无效或不存在，需要重新生成 → 此时才校验 subs
		logger.Info("Current config is invalid or missing, generating new config...")
		if err := cfg.ValidateSubs(); err != nil {
			return fmt.Errorf("subscription config invalid: %w", err)
		}
		if err := sb.GenerateConfig(); err != nil {
			return err
		}
	} else {
		logger.Info("Using existing valid config")
		// 存量配置迁移：将 remote 规则集本地化，避免 sing-box 启动依赖 GitHub
		migrateRuleSetCache(cfg)
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return sb.StartGUI()
	}
	return sb.Start()
}

// migrateRuleSetCache 将现有配置中的 remote 规则集迁移为本地缓存引用。
// 仅在迁移成功时改写配置文件；失败不影响启动流程。
func migrateRuleSetCache(cfg *config.Config) {
	opts := singbox.LocalizeOptions{MirrorURL: cfg.GitHub.MirrorURL}
	changed, stats, err := singbox.LocalizeConfigFile(constant.SingBoxConfigFile, opts)
	if err != nil {
		logger.Warn("⚠️ 规则集缓存迁移失败(继续使用现有配置): %v", err)
		return
	}
	if changed {
		logger.Success("已将 %d 个规则集切换为本地缓存（回退旧缓存 %d 个），sing-box 启动不再依赖 GitHub",
			stats.Localized, stats.Fallback)
	} else if stats.Remote > 0 {
		logger.Info("规则集缓存: %d 个远程条目保留原样（下载失败且无缓存）", stats.Kept)
	}
}

func runStopSingbox(cfg *config.Config) error {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		logger.Warn("Stop command is not supported/needed for GUI clients on this platform.")
		return nil
	}
	if daemon.IsDaemonRunning() {
		logger.Info("Stopping daemon...")
		if err := daemon.StopDaemon(); err != nil {
			logger.Warn("Failed to stop daemon: %v", err)
		} else {
			logger.Success("Daemon stopped")
		}
	}
	sb := singbox.New(cfg)
	return sb.Stop()
}

func newStartCmd(cfg *config.Config) *cobra.Command {
	// 1. sb start
	cmd := &cobra.Command{
		Use:   "start",
		Short: "生成配置并启动 sing-box / Generate config and start sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStartSingbox(cfg)
		},
	}
	return cmd
}

func newStopCmd(cfg *config.Config) *cobra.Command {
	// 2. sb stop
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "停止 sing-box 和守护进程 / Stop sing-box and daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStopSingbox(cfg)
		},
	}
	return cmd
}

func newRestartCmd(cfg *config.Config) *cobra.Command {
	// 3. sb restart
	cmd := &cobra.Command{
		Use:   "restart",
		Short: "重启 sing-box / Restart sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Restarting sing-box...")
			if err := runStopSingbox(cfg); err != nil {
				return err
			}
			return runStartSingbox(cfg)
		},
		Aliases: []string{"r"},
	}
	return cmd
}

func newGenCmd(cfg *config.Config) *cobra.Command {
	// 4. sb gen (将原 genCmd 逻辑移入，注意保留 Flag 处理)
	var outputPath string
	var stdout bool
	var noLocalize bool
	var platform string
	genCmd := &cobra.Command{
		Use:     "gen",
		Short:   "生成 sing-box 配置文件(可指定目标平台) / Generate sing-box configuration",
		Aliases: []string{"g"},
		RunE: func(cmd *cobra.Command, args []string) error {

			// gen 命令必须依赖 subs，提前校验防止 index-out-of-range panic
			if err := cfg.ValidateSubs(); err != nil {
				return fmt.Errorf("subscription config invalid: %w", err)
			}

			target, err := singbox.ResolvePlatform(platform)
			if err != nil {
				return err
			}
			isIOS := target == singbox.PlatformIOS

			generator := singbox.NewConfigGenerator(cfg)
			configJSON, err := generator.GenerateForPlatform(target)
			if err != nil {
				return err
			}

			// iOS 兼容性检查(含 --stdout 路径): 本地路径规则集在 iPhone 沙盒不可读
			if isIOS {
				if err := singbox.CheckIOSCompatibility(configJSON); err != nil {
					return err
				}
			}

			// 如果指定了--stdout，输出到标准输出
			if stdout {
				fmt.Print(configJSON)
				return nil
			}

			// iOS 配置不写入本机 sing-box 配置路径(看门狗会把 iPhone 配置跑在本机上), 且必须保留远程规则集
			if isIOS {
				if err := guardIOSOutputPath(outputPath); err != nil {
					return err
				}
				if err := guardIOSOutputPath(outputPath); err != nil {
					return err
				}
				if outputPath == "" {
					outputPath = defaultIOSOutputPath()
				}
			} else if !noLocalize {
				// 规则集本地化(可用 --no-localize 关闭，例如需要生成可迁移到其它机器的配置);
				// iOS 分支不做本地化 —— iPhone 沙盒读不到本地路径, 必须保留远程引用
				if localized, stats, err := singbox.LocalizeRuleSets(configJSON, singbox.LocalizeOptions{
					MirrorURL: cfg.GitHub.MirrorURL,
				}); err != nil {
					logger.Warn("⚠️ 规则集本地化已跳过: %v", err)
				} else {
					configJSON = localized
					if stats.Remote > 0 {
						logger.Info("规则集缓存: 远程 %d → 已本地化 %d, 回退旧缓存 %d, 内置快照兑底 %d, 保留远程 %d",
							stats.Remote, stats.Localized, stats.Fallback, stats.Snapshot, stats.Kept)
					}
				}
			}

			// 确定输出路径
			targetPath := constant.SingBoxConfigFile
			if outputPath != "" {
				targetPath = outputPath
			}

			// 创建目录
			dir := filepath.Dir(targetPath)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("创建目录失败: %w", err)
			}

			// 备份现有配置
			if _, err := os.Stat(targetPath); err == nil {
				backupPath := fmt.Sprintf("%s.backup.%d", targetPath, time.Now().Unix())
				if err := os.Rename(targetPath, backupPath); err != nil {
					return fmt.Errorf("备份现有配置失败: %w", err)
				}
				logger.Info("已备份现有配置到: %s", backupPath)
			}

			// 写入新配置(iOS 配置含节点凭据且放在 Downloads 等公共目录, 收紧为 0600)
			perm := os.FileMode(0644)
			if isIOS {
				perm = 0600
			}
			if err := os.WriteFile(targetPath, []byte(configJSON), perm); err != nil {
				return fmt.Errorf("写入配置文件失败: %w", err)
			}
			if perm == 0600 {
				_ = os.Chmod(targetPath, perm) // 防止已存在文件保留了旧权限
			}

			logger.Success("配置已生成: %s", targetPath)
			if isIOS {
				logger.Info("导入 iPhone: AirDrop/隔空投送该文件 → 文件 App → 分享给 sing-box App; 或在 sing-box App 中新建配置时选择该文件")
				return nil
			}
			if copied, err := copyGeneratedConfigToClipboard(targetPath); err != nil {
				logger.Warn("配置已生成，但复制到粘贴板失败: %v", err)
			} else if copied {
				logger.Success("配置文件已经复制到粘贴板，可以直接粘贴")
			}
			return nil
		},
	}
	genCmd.Flags().StringVarP(&outputPath, "output", "o", "", "指定输出文件路径")
	genCmd.Flags().BoolVar(&stdout, "stdout", false, "输出到标准输出而不是文件")
	genCmd.Flags().BoolVar(&noLocalize, "no-localize", false, "不将远程规则集缓存到本地")
	genCmd.Flags().StringVar(&platform, "platform", "auto", "目标平台: auto/darwin/windows/linux/ios (ios=导出给 iPhone sing-box App)")
	return genCmd
}

// defaultIOSOutputPath 返回 iOS 配置的默认导出路径(用户下载/导出目录)
func defaultIOSOutputPath() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "Downloads", "singctl-ios.json")
	}
	return "singctl-ios.json"
}

// guardIOSOutputPath 阻止 iOS 配置覆盖本机 sing-box 配置文件:
// 本机 sing-box/看门狗加载的是桌面端配置, 一旦被 iPhone 配置覆盖会直接改变本机代理行为。
// 保护范围取跨平台并集: 各 OS 的 constant.SingBoxConfigFile + Linux 官方路径 ——
// 后者在 macOS/Windows 上也可能因手工部署而真实存在(已实际发生过覆盖事故)
func guardIOSOutputPath(outputPath string) error {
	if outputPath == "" {
		return nil // 未指定时走默认导出路径, 不会撞上本机配置
	}
	clean := func(p string) string {
		abs, err := filepath.Abs(p)
		if err != nil {
			return filepath.Clean(p)
		}
		return abs
	}
	protected := []string{
		constant.SingBoxConfigFile,
		"/etc/sing-box/config.json", // Linux/OpenWrt 官方路径(跨平台并集)
	}
	target := clean(outputPath)
	for _, p := range protected {
		if p != "" && target == clean(p) {
			return fmt.Errorf("拒绝写入: %q 是本机 sing-box 配置文件, iOS 配置不能覆盖它(可用 -o 指定其它路径, 省略 -o 则导出到 ~/Downloads/singctl-ios.json)", outputPath)
		}
	}
	return nil
}

func newInstallCmd(cfg *config.Config) *cobra.Command {
	// 5. sb install
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "安装 sing-box / Install sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			sb := singbox.New(cfg)
			return sb.Install()
		},
	}
	return installCmd
}

func newUpdateCmd(cfg *config.Config) *cobra.Command {
	// 6. sb update
	updateCmd := &cobra.Command{
		Use:     "update",
		Aliases: []string{"u"},
		Short:   "更新 sing-box / Update sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			sb := singbox.New(cfg)
			return sb.Update()
		},
	}
	return updateCmd
}

// ───────────────────────── sb cache ─────────────────────────

func newCacheCmd(cfg *config.Config) *cobra.Command {
	cacheCmd := &cobra.Command{
		Use:   "cache",
		Short: "管理规则集本地缓存 / Manage rule-set local cache",
		Long: `管理规则集本地缓存。

singctl 会将配置中的远程规则集(rule_set)预下载到本地并改写为本地引用，
使 sing-box 启动不依赖 GitHub。此命令组用于刷新、查看和清理这些缓存。`,
	}
	cacheCmd.AddCommand(
		newCacheUpdateCmd(cfg),
		newCacheStatusCmd(cfg),
		newCacheClearCmd(cfg),
	)
	return cacheCmd
}

func newCacheUpdateCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:     "update",
		Aliases: []string{"u"},
		Short:   "刷新规则集缓存 / Refresh rule-set cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := singbox.LocalizeOptions{MirrorURL: cfg.GitHub.MirrorURL}
			changed, stats, err := singbox.RefreshConfigCache(constant.SingBoxConfigFile, opts)
			if err != nil {
				return fmt.Errorf("刷新规则集缓存失败: %w", err)
			}
			logger.Info("规则集缓存刷新完成: 新本地化 %d, 回退旧缓存 %d, 内置快照兑底 %d, 刷新已有 %d, 保留远程 %d",
				stats.Localized, stats.Fallback, stats.Snapshot, stats.Refreshed, stats.Kept)
			if changed {
				logger.Success("配置文件已更新为本地规则集引用")
			}
			return nil
		},
	}
}

func newCacheStatusCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查看规则集缓存状态 / Show rule-set cache status",
		RunE: func(cmd *cobra.Command, args []string) error {
			entries := singbox.CacheStatus(singbox.LocalizeOptions{
				MirrorURL: cfg.GitHub.MirrorURL,
			})
			if len(entries) == 0 {
				logger.Info("暂无规则集缓存（配置生成或 sb start 时会自动建立）")
				return nil
			}
			snap := ruleset_snapshot.Load()
			logger.Info("规则集缓存目录: %s | 内置快照: %d 个（生成于 %s）",
				singbox.RuleSetCacheDir(), snap.Count(), snap.GeneratedAt())
			for _, e := range entries {
				state := "✅"
				if !e.FileOK {
					if e.InSnapshot {
						state = "📦 仅内置快照"
					} else {
						state = "❌ 缺失"
					}
				}
				updatedAt := e.UpdatedAt
				if updatedAt == "" {
					updatedAt = "-"
				}
				snapMark := ""
				if e.InSnapshot && e.FileOK {
					snapMark = " +📦"
				}
				logger.Info("%s %-28s format=%-6s updated=%s%s", state, e.Tag, e.Format, updatedAt, snapMark)
			}
			return nil
		},
	}
}

func newCacheClearCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "clear",
		Short: "还原配置并清空规则集缓存 / Revert config and clear rule-set cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := singbox.LocalizeOptions{MirrorURL: cfg.GitHub.MirrorURL}
			reverted, err := singbox.RevertAndClearCache(constant.SingBoxConfigFile, opts)
			if err != nil {
				return fmt.Errorf("清理规则集缓存失败: %w", err)
			}
			if reverted > 0 {
				logger.Success("已将 %d 个规则集还原为远程引用，缓存已清空", reverted)
			} else {
				logger.Success("缓存已清空（配置中无可还原的本地规则集）")
			}
			return nil
		},
	}
}

func NewSingboxCommand(configPath string) *cobra.Command {

	cmd := &cobra.Command{
		Use:     "singbox",
		Aliases: []string{"sb"}, // 添加快捷命令 singctl sb
		Short:   "客户端: singbox客户端的启动和配置(简写singctl sb)",
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("配置文件加载失败")
	}

	cmd.AddCommand(
		newStartCmd(cfg),
		newStopCmd(cfg),
		newRestartCmd(cfg),
		newGenCmd(cfg),
		newInstallCmd(cfg),
		newUpdateCmd(cfg),
		newCacheCmd(cfg),
	)
	return cmd
}
