//go:build !lite

// 文件职责：提供舰队并发批量指令 (`sync` / `probe` / `doctor` / `reset` / `update`) 与全舰队安全自愈 (`heal`) 子命令。
package cmd

import (
	"fmt"
	"strings"

	"singctl/internal/fleet"
	"singctl/internal/heal"
	"singctl/internal/logger"

	"github.com/spf13/cobra"
)

func newFleetBatchCmd(fc *fleetCmdContext, use string, aliases []string, short string, action string, showDetail bool) *cobra.Command {
	return &cobra.Command{
		Use:     use + " [id...]",
		Aliases: aliases,
		Short:   short,
		RunE: func(c *cobra.Command, args []string) error {
			return runFleetBatchAction(c, fc, action, args, showDetail)
		},
	}
}

func runFleetBatchAction(c *cobra.Command, fc *fleetCmdContext, action string, args []string, showDetail bool) error {
	mgr := fc.buildManager(c)
	logger.Info("正在并发执行舰队指令 [%s] ...", action)
	results, err := mgr.RunAcross(c.Context(), action, args)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		logger.Warn("未匹配到任何已纳管的子节点。")
		return nil
	}
	for _, r := range results {
		if r.Success {
			logger.Success("✓ [%s (%s)] %s", r.Name, r.ID, r.Message)
		} else {
			logger.Error("✗ [%s (%s)] %s", r.Name, r.ID, r.Message)
		}
		if showDetail && strings.TrimSpace(r.Output) != "" {
			fmt.Println(r.Output)
			fmt.Println()
		}
	}
	return nil
}

func newFleetDoctorCmd(fc *fleetCmdContext) *cobra.Command {
	var verboseDoctor bool
	doctorCmd := newFleetBatchCmd(fc, "doctor", []string{"doc", "check"}, "并发对所有子节点执行全链路健康体检与流媒体解锁对比", "doctor", false)
	doctorCmd.Flags().BoolVarP(&verboseDoctor, "verbose", "v", false, "输出每台子节点的完整体检报告明细")
	origDocRunE := doctorCmd.RunE
	doctorCmd.RunE = func(c *cobra.Command, args []string) error {
		if !verboseDoctor {
			return origDocRunE(c, args)
		}
		mgr := fc.buildManager(c)
		results, err := mgr.RunAcross(c.Context(), "doctor", args)
		if err != nil {
			return err
		}
		for _, r := range results {
			if r.Success {
				logger.Success("✓ [%s (%s)] %s", r.Name, r.ID, r.Message)
			} else {
				logger.Error("✗ [%s (%s)] %s", r.Name, r.ID, r.Message)
			}
			if r.Output != "" {
				fmt.Println(r.Output)
			}
		}
		return nil
	}
	return doctorCmd
}

func newFleetHealCmd(fc *fleetCmdContext) *cobra.Command {
	var (
		checkOnly    bool
		noReboot     bool
		enableTimers bool
		schedule     string
		includeLocal bool
	)
	healCmd := &cobra.Command{
		Use:     "heal [id...]",
		Aliases: []string{"auto-heal", "patch", "sec-heal"},
		Short:   "全舰队三层安全自愈：并发热修复组件/系统漏洞 + 单台串行滚动重启 + 异常熔断保护",
		Long: `协调全舰队节点执行高可用安全自愈：
  1) 并发修复所有子节点与主控的核心组件更新、系统安全补丁与残留 .so 动态库（零断流）
  2) 对需重启生效新内核的子节点，严格执行【单台串行滚动重启】——确认前一台恢复满分健康后才重启下一台
  3) 内置【故障熔断】：任一子节点重启后超时未恢复健康，立即中止剩余节点重启，确保全网永不集体失联`,
		RunE: func(c *cobra.Command, args []string) error {
			mgr := fc.buildManager(c)
			resolvedCfg := resolveConfigPath(c, fc.defaultConfigPath)

			if checkOnly {
				logger.Info("正在并发扫描全舰队节点的三层安全态势...")
			} else {
				logger.Info("正在对全舰队执行三层无感安全自愈（内核更新采用单台串行滚动重启 + 故障熔断）...")
			}

			rep, err := mgr.HealFleet(c.Context(), fleet.FleetHealOptions{
				CheckOnly:    checkOnly,
				AllowReboot:  !noReboot,
				EnableTimers: enableTimers,
				Schedule:     schedule,
				TargetIDs:    args,
			})
			if err != nil {
				return err
			}
			printFleetHealReport(rep)

			if len(args) == 0 && includeLocal {
				healLocalMaster(c, resolvedCfg, checkOnly, enableTimers, schedule)
			}
			return nil
		},
	}
	healCmd.Flags().BoolVar(&checkOnly, "check", false, "仅扫描全舰队安全态势，不执行变更或重启")
	healCmd.Flags().BoolVar(&noReboot, "no-reboot", false, "仅热修复组件与动态库，跳过子节点的串行滚动重启")
	healCmd.Flags().BoolVar(&enableTimers, "enable-timer", false, "为所有子节点及主控统一开启每日凌晨 04:00 自动安全自愈定时器")
	healCmd.Flags().StringVar(&schedule, "schedule", "", "自定义自动巡检时间 (默认 '*-*-* 04:00:00')")
	healCmd.Flags().BoolVar(&includeLocal, "include-master", true, "全量执行时同步自愈主控本机 (主控不自动重启)")
	return healCmd
}

func printFleetHealReport(rep fleet.FleetHealReport) {
	for _, r := range rep.Results {
		if r.Success {
			extra := ""
			if r.Rebooted {
				extra = fmt.Sprintf(" [已平滑滚动重启 · 健康分 %d/100]", r.DoctorScoreAfterReboot)
			} else if r.RebootRequired {
				extra = " [待维护窗口重启生效内核]"
			}
			logger.Success("✓ 子节点 [%s (%s)] %s%s", r.Name, r.ID, r.Summary, extra)
		} else {
			logger.Error("✗ 子节点 [%s (%s)] %s", r.Name, r.ID, r.Summary)
		}
	}
	if rep.CircuitBreakerHit {
		logger.Error("🚨 熔断告警: %s", rep.CircuitBreakerNote)
	}
}

func healLocalMaster(c *cobra.Command, resolvedCfg string, checkOnly, enableTimers bool, schedule string) {
	if enableTimers {
		p := heal.Scan(c.Context(), resolvedCfg, "").Policy
		p.AutoHealEnabled = true
		if strings.TrimSpace(schedule) != "" {
			p.Schedule = strings.TrimSpace(schedule)
		}
		_, _ = heal.ApplyPolicy(resolvedCfg, p)
	}
	localRes, lErr := heal.Run(c.Context(), heal.RunOptions{
		ConfigPath:  resolvedCfg,
		CheckOnly:   checkOnly,
		AllowReboot: false,
		Trigger:     "fleet",
	})
	if lErr != nil {
		return
	}
	if checkOnly {
		logger.Info("✓ 主控本机态势: %s (待修复组件=%d, 系统补丁=%d, 需重启=%v)",
			localRes.Status.PostureLabel,
			localRes.Status.Core.PendingCount,
			localRes.Status.OS.SecurityCount,
			localRes.Status.Kernel.RebootRequired,
		)
		return
	}
	logger.Success("✓ 主控本机: %s", localRes.Execution.Summary)
}
