package cmd

import (
	"cmp"
	"encoding/json"
	"fmt"
	"strings"

	"singctl/internal/heal"
	"singctl/internal/logger"

	"github.com/spf13/cobra"
)

func newServerHealCmd(configPath string, version string) *cobra.Command {
	var (
		checkOnly      bool
		enableTimer    bool
		disableTimer   bool
		schedule       string
		rebootIfNeeded bool
		outputJSON     bool
		triggerSource  string
	)

	cmd := &cobra.Command{
		Use:     "heal",
		Aliases: []string{"auto-heal", "patch", "sec-heal"},
		Short:   "自愈  : 三层自动化安全漏洞检测与无感热修复 (核心组件 + 系统安全补丁 + 内核状态)",
		Long: `三层自动化安全自愈引擎（零常驻内存，原生适配 systemd timer 凌晨窗口）：
  1) 核心服务层 : 自动检测并金丝雀校验升级 SingCtl / sing-box / Caddy / WARP，失败秒级回滚
  2) 系统应用层 : 自动安装 Debian/Ubuntu/RHEL 安全仓库补丁(保护 2222 端口配置)，并平滑重载残留旧版 .so 动态库的进程
  3) 系统内核层 : 识别待重启生效的新内核补丁，支持按维护策略平滑重启

常用命令:
  singctl sr heal --check              # 只读扫描三层安全态势
  singctl sr heal                      # 立即执行无感热修复（默认不主动重启机器）
  singctl sr heal --enable-timer       # 开启每日凌晨 04:00 自动安全巡检与无感自愈`,
		RunE: func(c *cobra.Command, args []string) error {
			resolvedCfg := resolveConfigPath(c, configPath)

			// 1. Handle systemd timer policy toggle if requested
			if enableTimer || disableTimer || c.Flags().Changed("schedule") {
				cur := heal.Scan(c.Context(), resolvedCfg, version).Policy
				if enableTimer {
					cur.AutoHealEnabled = true
				}
				if disableTimer {
					cur.AutoHealEnabled = false
				}
				if strings.TrimSpace(schedule) != "" {
					cur.Schedule = strings.TrimSpace(schedule)
				}
				if c.Flags().Changed("reboot-if-needed") {
					cur.AutoReboot = rebootIfNeeded
				}
				ts, err := heal.ApplyPolicy(resolvedCfg, cur)
				if err != nil {
					return err
				}
				if !outputJSON {
					if cur.AutoHealEnabled {
						logger.Success("已开启每日自动安全自愈定时守护 (调度周期: %s, systemd active=%v)", ts.Schedule, ts.Active)
					} else {
						logger.Info("已关闭自动安全自愈定时任务。")
					}
				}
				// If user ONLY toggled timer (`--disable-timer`), return cleanly unless also running heal
				if disableTimer && !checkOnly {
					if outputJSON {
						rep := heal.Scan(c.Context(), resolvedCfg, version)
						b, _ := json.Marshal(heal.RunResult{Status: rep})
						fmt.Println(string(b))
					}
					return nil
				}
			}

			if !outputJSON {
				if checkOnly {
					logger.Info("正在扫描三层安全态势（核心服务 / 系统安全补丁 / 内核热状态）...")
				} else {
					logger.Info("正在执行三层自动化安全检测与无感自愈（升级前自动备份校验，异常秒级回滚）...")
				}
			}

			res, err := heal.Run(c.Context(), heal.RunOptions{
				ConfigPath:        resolvedCfg,
				CurrentSingctlVer: version,
				CheckOnly:         checkOnly,
				AllowReboot:       rebootIfNeeded,
				Trigger:           cmp.Or(triggerSource, "manual"),
			})
			if err != nil {
				return err
			}

			if outputJSON {
				b, jErr := json.Marshal(res)
				if jErr != nil {
					return jErr
				}
				fmt.Println(string(b))
				return nil
			}

			printHealReport(res, checkOnly)
			return nil
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "仅扫描三层安全态势，不执行任何写入或升级")
	cmd.Flags().BoolVar(&enableTimer, "enable-timer", false, "安装并启用 systemd 每日凌晨自动安全自愈定时器 (零常驻内存)")
	cmd.Flags().BoolVar(&disableTimer, "disable-timer", false, "停用并移除自动安全自愈定时器")
	cmd.Flags().StringVar(&schedule, "schedule", "", "自定义 systemd OnCalendar 调度时间 (默认 '*-*-* 04:00:00')")
	cmd.Flags().BoolVar(&rebootIfNeeded, "reboot-if-needed", false, "若检测到新内核安全补丁待生效，在修复完成后平滑重启")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "以结构化 JSON 输出报告 (供舰队主控或脚本调用)")
	cmd.Flags().StringVar(&triggerSource, "trigger", "manual", "触发来源标识 (manual|timer|fleet)")
	_ = cmd.Flags().MarkHidden("trigger")

	return cmd
}

func printHealReport(res heal.RunResult, checkOnly bool) {
	st := res.Status
	fmt.Println("\n══════════════════════════════════════════════════════════════════════════════")
	fmt.Printf(" 🛡️  SingCtl 三层安全自愈中心  |  当前态势: %s\n", st.PostureLabel)
	fmt.Println("──────────────────────────────────────────────────────────────────────────────")

	// Layer 1
	fmt.Println(" [第一层 · 核心代理栈]")
	for _, c := range st.Core.Components {
		if !c.Installed {
			continue
		}
		mark := "✓ 最新"
		if c.HasUpdate {
			mark = "↑ 待更新 -> v" + c.LatestVersion
		}
		fmt.Printf("   • %-22s : v%-12s (%s)\n", c.DisplayName, c.CurrentVersion, mark)
	}

	// Layer 2
	fmt.Println("\n [第二层 · 系统安全补丁与内存动态库]")
	if st.OS.OpenWrtProtected {
		fmt.Printf("   • 发行版环境             : %s (OpenWrt 闪存保护生效)\n", st.OS.Distro)
	} else {
		secDesc := "0 个待装安全补丁 ✓"
		if st.OS.SecurityCount > 0 {
			secDesc = fmt.Sprintf("%d 个待装安全更新 (%s)", st.OS.SecurityCount, strings.Join(st.OS.SecurityUpdates[:min(5, len(st.OS.SecurityUpdates))], ", "))
		}
		staleDesc := "无残留旧版 .so ✓"
		if len(st.OS.StaleServices) > 0 {
			staleDesc = "需热重载: " + strings.Join(st.OS.StaleServices, ", ")
		}
		fmt.Printf("   • 系统安全源 (%-4s)      : %s\n", cmp.Or(st.OS.PackageManager, "os"), secDesc)
		fmt.Printf("   • 内存动态库 (.so)       : %s\n", staleDesc)
	}

	// Layer 3
	fmt.Println("\n [第三层 · 系统内核安全状态]")
	kernDesc := fmt.Sprintf("运行内核 %s (无需重启 ✓)", cmp.Or(st.Kernel.RunningKernel, "unknown"))
	if st.Kernel.RebootRequired {
		kernDesc = cmp.Or(st.Kernel.RebootReason, "存在待重启生效的内核更新")
	}
	fmt.Printf("   • 内核热状态             : %s\n", kernDesc)

	// Timer
	if st.Timer.Supported {
		tState := "未开启 (可执行 'singctl sr heal --enable-timer' 开启凌晨自动巡检)"
		if st.Timer.Enabled {
			tState = fmt.Sprintf("已开启 ✓ (周期: %s | 下次运行: %s)", st.Timer.Schedule, cmp.Or(st.Timer.NextRun, "待调度"))
		}
		fmt.Printf("   • 自动定时守护           : %s\n", tState)
	}

	if !checkOnly && len(res.Execution.Actions) > 0 {
		fmt.Println("──────────────────────────────────────────────────────────────────────────────")
		fmt.Println(" [本次自愈执行记录]")
		for _, a := range res.Execution.Actions {
			icon := "✓"
			if !a.Success {
				icon = "✗"
			}
			fmt.Printf("   %s [%s/%s] %s\n", icon, a.Layer, a.Target, a.Message)
		}
	}
	fmt.Println("══════════════════════════════════════════════════════════════════════════════")
	if !checkOnly {
		if res.Execution.Success {
			logger.Success("总结: %s", res.Execution.Summary)
		} else {
			logger.Warn("总结: %s", res.Execution.Summary)
		}
	}
}
