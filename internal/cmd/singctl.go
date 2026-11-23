package cmd

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"singctl/internal/common/redact"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/doctor"
	"singctl/internal/localdns"
	"singctl/internal/logger"
	"singctl/internal/safecommit"
	"singctl/internal/singbox"
	"singctl/internal/updater"
	"singctl/internal/webui"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// NewInfoCommand creates the info command
func NewInfoCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "配置  : 查看配置信息",
		Long:  "显示 sing-box 安装路径、配置文件路径、singctl 版本及订阅信息 / Display sing-box installation path, configuration file path, singctl version and subscription information",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := cmd.Flag("config").Value.String()
			return showSystemInfo(configPath, version)
		},
	}
}

// DoctorCmdDeps 封装 `singctl doctor` 命令的可注入依赖（零值回退生产默认实现）。
type DoctorCmdDeps struct {
	ProcRoot          string
	SingBoxConfigPath string
	SmartDNSConfPath  string
	AdGuardConfPath   string
	Runner            *doctor.Runner
	BuildEnv          func(cfg *config.Config, resolvedPath string) *doctor.Env
	RunServerDoctor   func(cfg *config.Config) *doctor.DoctorReport
	IsServerEnv       func(cfg *config.Config) bool
}

var allowedCLIDoctorFixes = map[string]bool{
	"protect-tailscale-oom": true,
	"sync-dns-local":        true,
	"sync-smartdns-ipv6":    true,
}

func buildCLIDoctorEnv(cfg *config.Config, resolvedPath string, deps DoctorCmdDeps) *doctor.Env {
	var env *doctor.Env
	if deps.BuildEnv != nil {
		env = deps.BuildEnv(cfg, resolvedPath)
	}
	if env == nil {
		env = &doctor.Env{
			Config:            cfg,
			ConfigPath:        resolvedPath,
			SingBoxConfigPath: cmp.Or(strings.TrimSpace(deps.SingBoxConfigPath), constant.SingBoxConfigFile),
			SmartDNSConfPath:  cmp.Or(strings.TrimSpace(deps.SmartDNSConfPath), constant.SmartDNSConfigFile),
			AdGuardConfPath:   cmp.Or(strings.TrimSpace(deps.AdGuardConfPath), constant.AdGuardConfigFile),
			ProcRoot:          strings.TrimSpace(deps.ProcRoot),
		}
	}
	if env.Config == nil {
		env.Config = cfg
	}
	procRoot := cmp.Or(strings.TrimSpace(env.ProcRoot), strings.TrimSpace(deps.ProcRoot))
	sbPath := cmp.Or(strings.TrimSpace(env.SingBoxConfigPath), strings.TrimSpace(deps.SingBoxConfigPath), constant.SingBoxConfigFile)
	workPath := ""
	if sbPath == constant.SingBoxConfigFile {
		workPath = constant.SingBoxWorkConfigFile
	}

	defaults := map[string]func(ctx context.Context) (string, error){
		"protect-tailscale-oom": func(context.Context) (string, error) {
			st, err := safecommit.ProtectTailscaledOOM(procRoot)
			if err != nil {
				return "", err
			}
			return cmp.Or(st.Message, fmt.Sprintf("已为 tailscaled (PID %d) 开启 OOM 免疫保护 (oom_score_adj=%d)", st.PID, st.ScoreAdj)), nil
		},
		"sync-dns-local": func(ctx context.Context) (string, error) {
			dnsPort := 5353
			dnsEnabled := true
			if cfg != nil {
				dnsPort = cfg.DNS.GetDNSPort()
				dnsEnabled = cfg.DNS.IsEnabled()
			}
			useExternal := false
			if dnsEnabled {
				addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort))
				useExternal = doctor.ProbeLocalDNS(ctx, addr) == nil
			}
			changed, err := singbox.SyncLiveSingBoxDNSLocal(ctx, sbPath, workPath, useExternal, dnsPort)
			if err != nil {
				return "", err
			}
			if useExternal {
				return fmt.Sprintf("已同步 sing-box dns_local 至本地防劫持 DNS 127.0.0.1:%d (changed=%v)", dnsPort, changed), nil
			}
			return fmt.Sprintf("已同步 sing-box dns_local 至加密 DoH 兜底 (changed=%v)", changed), nil
		},
		"sync-smartdns-ipv6": func(ctx context.Context) (string, error) {
			reg := localdns.NewRegistry(cfg, localdns.EngineDeps{ConfigPath: resolvedPath})
			sdEng, ok := reg.Get(constant.DNSEngineSmartDNS)
			if !ok || sdEng == nil || !sdEng.IsInstalled() {
				return "", errors.New("未检测到已安装的 SmartDNS 引擎")
			}
			if err := sdEng.SyncCommonConfig(ctx); err != nil {
				return "", err
			}
			return "已按 gateway.ipv6_mode 同步 SmartDNS force-AAAA-SOA 策略", nil
		},
	}
	if env.QuickFixHandlers == nil {
		env.QuickFixHandlers = defaults
	} else {
		for k, fn := range defaults {
			if _, exists := env.QuickFixHandlers[k]; !exists {
				env.QuickFixHandlers[k] = fn
			}
		}
	}
	return env
}

// NewDoctorCmd creates the doctor command
func NewDoctorCmd(configPath string) *cobra.Command {
	return NewDoctorCmdWithDeps(configPath, DoctorCmdDeps{})
}

// NewDoctorCmdWithDeps 创建带显式依赖注入的 `singctl doctor` 命令。
func NewDoctorCmdWithDeps(configPath string, deps DoctorCmdDeps) *cobra.Command {
	var asJSON bool
	var mode string
	var fixAction string

	cmd := &cobra.Command{
		Use:     "doctor",
		Aliases: []string{"doc", "check"},
		Short:   "体检  : 全链路健康体检与故障自检",
		Long:    "客户端网关运行 8 项全链路深度体检与一键修复；服务端 VPS 兼容原有四核/TLS/Reality 体检报告。",
		RunE: func(cmd *cobra.Command, _ []string) error {
			normMode := strings.ToLower(strings.TrimSpace(cmp.Or(mode, "auto")))
			if normMode != "auto" && normMode != "client" && normMode != "server" {
				return fmt.Errorf("invalid --mode %q (expected auto|client|server)", mode)
			}

			cfg, resolvedPath, _ := loadCmdConfig(cmd, configPath)
			runner := deps.Runner
			if runner == nil {
				runner = doctor.NewDefaultRunner()
			}
			env := buildCLIDoctorEnv(cfg, resolvedPath, deps)

			if act := strings.TrimSpace(fixAction); act != "" {
				if !allowedCLIDoctorFixes[act] {
					return fmt.Errorf("unsupported --fix action %q (allowed: protect-tailscale-oom, sync-dns-local, sync-smartdns-ipv6)", act)
				}
				msg, err := runner.Fix(cmd.Context(), env, act)
				if err != nil {
					return err
				}
				if asJSON {
					raw, err := json.MarshalIndent(map[string]any{
						"ok":      true,
						"action":  act,
						"message": msg,
					}, "", "  ")
					if err != nil {
						return err
					}
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(raw))
					return nil
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "✅ 快捷修复成功 [%s]: %s\n", act, msg)
				return nil
			}

			isServer := false
			switch normMode {
			case "server":
				isServer = true
			case "client":
				isServer = false
			default:
				if deps.IsServerEnv != nil {
					isServer = deps.IsServerEnv(cfg)
				} else if !isLiteEdition() {
					isServer = doctor.IsServerEnvironment(cfg)
				}
			}

			if isServer {
				runSrv := deps.RunServerDoctor
				if runSrv == nil {
					runSrv = doctor.RunServerDoctor
				}
				report := runSrv(cfg)
				if asJSON {
					raw, err := json.MarshalIndent(report, "", "  ")
					if err != nil {
						return err
					}
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(raw))
					return nil
				}
				doctor.PrintDoctorReport(report)
				return nil
			}

			report := runner.Run(cmd.Context(), env)
			if asJSON {
				raw, err := json.MarshalIndent(report, "", "  ")
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(raw))
				return nil
			}
			_, _ = fmt.Fprint(cmd.OutOrStdout(), doctor.FormatText(report))
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "以 JSON 格式输出体检报告")
	cmd.Flags().StringVar(&mode, "mode", "auto", "体检模式: auto | client | server")
	cmd.Flags().StringVar(&fixAction, "fix", "", "执行深度体检安全快捷修复动作 (protect-tailscale-oom | sync-dns-local | sync-smartdns-ipv6)")
	return cmd
}

func NewUpdateCmd(configPath string, version string) *cobra.Command {
	return &cobra.Command{
		Use:     "update <target> or u <target>",
		Short:   "更新  : 更新singctl到最新版",
		Aliases: []string{"u"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, configPath)
			if err != nil {
				return err
			}

			switch args[0] {
			case "s", "self":
				up := updater.New(cfg.GitHub.MirrorURL, constant.GitHubRepoURL)
				if err := up.UpdateSelf(resolvedPath, version); err != nil {
					return err
				}
				restartServerServicesAfterSelfUpdate(resolvedPath)
				if daemon.IsDaemonRunning() {
					logger.Info("Restarting watchdog daemon to apply new version...")
					if rErr := daemon.RestartDaemon(resolvedPath); rErr != nil {
						logger.Warn("Failed to restart watchdog daemon: %v", rErr)
					}
				}
				if os.Getenv("SINGCTL_FROM_WEBUI") != "1" {
					if webui.IsWebRunningOrManaged() {
						logger.Info("Restarting client WebUI daemon to apply new version...")
						if rErr := webui.RestartWeb(resolvedPath); rErr != nil {
							logger.Warn("Failed to restart client WebUI daemon: %v", rErr)
						}
					}
				}
				return nil
			default:
				return fmt.Errorf("unknown target: %s", args[0])
			}
		},
	}
}

func NewInternalMigrateCmd() *cobra.Command {
	var configPath string
	var templatePath string

	cmd := &cobra.Command{
		Use:    "internal-migrate",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" || templatePath == "" {
				return fmt.Errorf("both --config and --template are required")
			}
			tplData, err := os.ReadFile(templatePath)
			if err != nil {
				return fmt.Errorf("failed to read template file %s: %w", templatePath, err)
			}
			if err := config.MigrateConfig(configPath, tplData); err != nil {
				return fmt.Errorf("migration failed: %w", err)
			}
			logger.Success("Config migration completed successfully.")
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to user config file")
	cmd.Flags().StringVar(&templatePath, "template", "", "Path to template file")
	return cmd
}

func NewVersionCmd(Version string, BuildTime string, GitCommit string) *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Aliases: []string{"-v"},
		Short:   "查询  : 查询singctl版本",
		Run: func(cmd *cobra.Command, args []string) {
			logger.Info("SingCtl %s", Version)
			logger.Info("Build Time: %s", BuildTime)
			logger.Info("Git Commit: %s", GitCommit)
		},
	}
}

func showSystemInfo(configPath, version string) error {
	// Header
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Success("           🎉 SINGCTL 系统信息 🎉")
	logger.Info("═══════════════════════════════════════════════════════════")

	// 1. Sing-box 信息
	logger.Info("")
	logger.Success("🎯 Sing-Box Information")
	logger.Info("───────────────────────────────────────────────────────────")

	// Sing-box 安装路径
	singboxPath := constant.SingBoxInstallDir
	if _, err := os.Stat(singboxPath); err == nil {
		logger.Success("安装路径        : %s ✓", singboxPath)
	} else {
		logger.Warn("安装路径        : %s (不存在) ✗", singboxPath)
	}

	// Sing-box 配置文件路径
	singboxConfigPath := constant.SingBoxConfigFile
	if _, err := os.Stat(singboxConfigPath); err == nil {
		logger.Success("配置文件路径    : %s ✓", singboxConfigPath)
	} else {
		logger.Warn("配置文件路径    : %s (不存在) ✗", singboxConfigPath)
	}

	// 2. SingCtl 信息
	logger.Info("")
	logger.Success("🚀 SingCtl Information")
	logger.Info("───────────────────────────────────────────────────────────")

	logger.Success("版本            : %s ✓", version)

	// SingCtl 安装路径
	exePath, err := os.Executable()
	if err != nil {
		logger.Warn("安装路径        : 未知 ✗")
	} else {
		logger.Success("安装路径        : %s ✓", exePath)
	}

	// SingCtl 配置文件路径
	if _, err := os.Stat(configPath); err == nil {
		logger.Success("配置文件路径    : %s ✓", configPath)
	} else {
		logger.Warn("配置文件路径    : %s (不存在) ✗", configPath)
	}

	// 3. 守护进程信息
	logger.Info("")
	logger.Success("🤖 守护进程信息")
	logger.Info("───────────────────────────────────────────────────────────")

	cfg, cfgErr := config.Load(configPath)

	if daemon.IsDaemonRunning() {
		logger.Success("守护进程状态    : 运行中 ✓")

		// 显示重启统计（从持久化状态恢复真实计数）
		maxRestarts := 3
		if cfg != nil && cfg.Watchdog.MaxRestarts > 0 {
			maxRestarts = cfg.Watchdog.MaxRestarts
		}
		limiter := daemon.NewRestartLimiterFromState(maxRestarts)
		logger.Info("重启统计        : %d/%d (最近1小时)",
			limiter.GetRestartCount(), limiter.GetMaxRestarts())
	} else {
		logger.Warn("守护进程状态    : 未运行 ✗")
	}

	// 日志文件路径
	logPath := daemon.GetDaemonLogPath()
	if _, err := os.Stat(logPath); err == nil {
		logger.Success("日志文件路径    : %s ✓", logPath)
	} else {
		logger.Info("日志文件路径    : %s (未生成)", logPath)
	}

	// 3.5 客户端本地防劫持 DNS 双引擎信息
	if runtime.GOOS == "linux" && cfg != nil {
		reg := localdns.NewRegistry(cfg, localdns.EngineDeps{ConfigPath: configPath})
		active := reg.ActiveEngine()
		if active != nil {
			st := active.Status(context.Background())
			logger.Info("")
			logger.Success("🛡️  %s (本地防劫持 DNS)", active.Meta().Name)
			logger.Info("───────────────────────────────────────────────────────────")
			logger.Info("引擎策略        : configured=%s / active=%s", cfg.DNS.GetEngine(), active.ID())
			if st.DNSHealthy {
				logger.Success("运行状态        : 运行中 (%s) ✓", st.DNSAddr)
			} else if st.Installed {
				logger.Warn("运行状态        : 未运行 (%s) ✗", st.DNSAddr)
			} else {
				logger.Warn("运行状态        : 未安装 ✗ (sing-box 纯 IP 加密 DoH 兜底防劫持中)")
			}
			if active.ID() == constant.DNSEngineAdGuard {
				logger.Info("Web 管理面板    : %s", st.WebURL)
				logger.Info("管理员账号      : %s", cfg.DNS.GetUsername())
				if cfg.DNS.GetPassword() != "" {
					logger.Info("管理员密码      : %s", cfg.DNS.GetPassword())
				}
			}
		}
	}

	// 4. 订阅连接信息
	logger.Info("")
	logger.Success("📡 订阅连接信息")
	logger.Info("───────────────────────────────────────────────────────────")

	if cfgErr != nil {
		logger.Warn("订阅数量        : 无法读取配置文件 ✗")
		logger.Error("配置文件错误: %v", cfgErr)
	} else {
		if len(cfg.Subs) == 0 {
			logger.Warn("订阅数量        : 0 (未配置订阅) ✗")
		} else {
			logger.Success("订阅数量        : %d ✓", len(cfg.Subs))

			for i, sub := range cfg.Subs {
				name := sub.Name
				if name == "" {
					name = fmt.Sprintf("订阅 %d", i+1)
				}

				// 脱敏处理URL
				maskedURL := redact.MaskURL(sub.URL)
				logger.Info("  └─ %-12s: %s", name, maskedURL)

				if sub.SkipTlsVerify {
					logger.Info("      └─ 跳过TLS验证: 是")
				}
				if sub.RemoveEmoji {
					logger.Info("      └─ 移除Emoji  : 是")
				}
				if sub.Include != "" {
					logger.Info("      └─ 保留规则   : %s", sub.Include)
				}
				if sub.Exclude != "" {
					logger.Info("      └─ 剔除规则   : %s", sub.Exclude)
				}
				if len(sub.Rename) > 0 {
					logger.Info("      └─ 重命名规则 : %d 条", len(sub.Rename))
				}
			}
		}
	}

	// Footer
	logger.Info("")
	logger.Info("═══════════════════════════════════════════════════════════")

	return nil
}
