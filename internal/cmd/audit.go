package cmd

import (
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/telemetry"

	"github.com/spf13/cobra"
)

func newAuditCmd(defaultConfigPath string) *cobra.Command {
	var deviceFilter string
	var onlySuspect bool
	var enableAI bool
	var limit int
	var jsonOut bool
	var csvOut bool

	cmd := &cobra.Command{
		Use:     "audit",
		Aliases: []string{"ad"},
		Short:   "审计局域网设备网络行为与可疑上传 / Audit LAN device behaviors & suspicious uploads",
		Long: `基于多维非线性风险引擎（上下行对数不对称度、建连时间变异系数 CV、域名香农信息熵、多维交叉放大与白名单阻尼）
实时审计局域网各设备的上传行为，并支持 --ai 调用 L2 智能顾问评估拉黑影响。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			audit.WarmupAppIndex("")
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)
			collector := audit.NewCollector(cfg)
			effLimit := limit
			if (jsonOut || csvOut) && !cmd.Flags().Changed("limit") {
				effLimit = 0
			}
			rep := collector.Collect(cmd.Context(), audit.CollectOptions{
				DeviceFilter: deviceFilter,
				OnlySuspect:  onlySuspect,
				EnableAI:     enableAI,
				Limit:        effLimit,
			})

			if csvOut {
				return rep.WriteCSV(os.Stdout)
			}
			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}

			renderAuditReport(rep, enableAI)
			return nil
		},
	}

	cmd.Flags().StringVarP(&deviceFilter, "device", "d", "", "按内网设备 IP 或主机名过滤 (例如 192.168.1.55 或 TV)")
	cmd.Flags().BoolVarP(&onlySuspect, "suspicious", "s", false, "仅显示关注/可疑/高危上传记录")
	cmd.Flags().BoolVar(&enableAI, "ai", false, "启用 L2 AI/专家顾问研判每个可疑目标的用途与拉黑影响")
	cmd.Flags().IntVarP(&limit, "limit", "n", 30, "最多显示的流量记录条数")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "以纯 UTF-8 (无 BOM) JSON 格式输出完整审计报告")
	cmd.Flags().BoolVar(&csvOut, "csv", false, "以纯 UTF-8 (无 BOM) CSV 格式输出完整审计明细")
	return cmd
}

func newBlockCmd(defaultConfigPath string) *cobra.Command {
	var sourceIP string
	var reason string

	cmd := &cobra.Command{
		Use:   "block <target-domain-or-ip | list>",
		Short: "一键将可疑域名或IP拉黑至 sing-box 与自建 AdGuard DNS 黑名单 / One-click dual-layer block",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := strings.TrimSpace(args[0])
			resolvedPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)

			if strings.EqualFold(target, "list") || strings.EqualFold(target, "ls") {
				renderBlockList(cfg.CustomRules.Block)
				return nil
			}

			enforcer := audit.NewEnforcer(cfg, resolvedPath)
			res, err := enforcer.Block(cmd.Context(), target, sourceIP, reason)
			if err != nil {
				return err
			}

			logger.Success("🛡️  %s", res.Message)
			if res.SourceIP != "" {
				logger.Info("   • 生效范围 : 仅限局域网设备 %s", res.SourceIP)
			} else {
				logger.Info("   • 生效范围 : 全局所有局域网设备")
			}
			logger.Info("   • 路由阻断 : sing-box route/dns reject 已同步 (%v)", res.SingBoxSynced)
			logger.Info("   • DNS 拦截 : AdGuard Home user_rules 已同步 (%v, 模式: %s)", res.DNSBlocked, cmp.Or(res.DNSMode, "none"))
			logger.Info("   • 实时断流 : 已斩断 %d 条存量活跃连接", res.KilledConnections)
			return nil
		},
	}

	cmd.Flags().StringVarP(&sourceIP, "device", "d", "", "可选：仅针对指定内网设备 IP 拉黑 (例如 192.168.1.55)")
	cmd.Flags().StringVarP(&reason, "reason", "r", "", "拉黑原因备注")
	return cmd
}

func newUnblockCmd(defaultConfigPath string) *cobra.Command {
	var sourceIP string

	cmd := &cobra.Command{
		Use:     "unblock <target-domain-or-ip>",
		Aliases: []string{"unban"},
		Short:   "从 sing-box 与自建 AdGuard DNS 黑名单中一键解封 / Unblock target from Sing-Box and DNS",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := strings.TrimSpace(args[0])
			resolvedPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)

			enforcer := audit.NewEnforcer(cfg, resolvedPath)
			res, err := enforcer.Unblock(cmd.Context(), target, sourceIP)
			if err != nil {
				return err
			}
			logger.Success("✅ %s", res.Message)
			return nil
		},
	}

	cmd.Flags().StringVarP(&sourceIP, "device", "d", "", "可选：仅解封特定内网设备 IP 的规则")
	return cmd
}

func newWhitelistCmd(defaultConfigPath string) *cobra.Command {
	var removeFlag bool

	cmd := &cobra.Command{
		Use:     "whitelist <target-domain-or-ip | list>",
		Aliases: []string{"wl"},
		Short:   "管理设备流量审计信任白名单 (一键放行误报域名或 IP) / Manage audit trust whitelist",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := strings.TrimSpace(args[0])
			resolvedPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)

			if strings.EqualFold(target, "list") || strings.EqualFold(target, "ls") {
				if len(cfg.Audit.Whitelist) == 0 {
					logger.Info("当前自定义审计白名单为空（可通过 'singctl sb whitelist <域名或IP>' 添加）")
					return nil
				}
				fmt.Printf(" ✅ 当前自定义审计信任白名单 (%d 条):\n", len(cfg.Audit.Whitelist))
				for _, w := range cfg.Audit.Whitelist {
					fmt.Printf("   • %s\n", w)
				}
				return nil
			}

			enforcer := audit.NewEnforcer(cfg, resolvedPath)
			if removeFlag {
				removed, err := enforcer.WhitelistRemove(target)
				if err != nil {
					return err
				}
				logger.Success("✅ 已将 %s 移出审计信任白名单", removed)
				return nil
			}
			added, err := enforcer.WhitelistAdd(target)
			if err != nil {
				return err
			}
			logger.Success("✅ 已将 %s 加入审计信任白名单 (后续流量自动降权豁免)", added)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&removeFlag, "remove", "r", false, "从信任白名单中移除该目标")
	return cmd
}

func renderAuditReport(rep *audit.Report, showAI bool) {
	fmt.Println("══════════════════════════════════════════════════════════════════════════════════════════════")
	fmt.Printf(" 🛡️  SINGCTL 局域网设备行为审计报告 (多维非线性风险引擎)   [%s]\n", rep.GeneratedAt)
	fmt.Println("══════════════════════════════════════════════════════════════════════════════════════════════")

	if rep.Message != "" {
		fmt.Printf(" [!] %s\n", rep.Message)
	}
	fmt.Printf(" 采样总流数: %d 条  |  可疑/高危流: %d 条 (高危 %d)  |  生效黑名单: %d 条\n",
		rep.TotalFlows, rep.SuspiciousFlows, rep.HighRiskFlows, rep.BlockedCount)

	if len(rep.Devices) > 0 {
		fmt.Println("──────────────────────────────────────────────────────────────────────────────────────────────")
		fmt.Println(" 📊 局域网设备上传排行 (双轴正交评分: 🛡️安全 × 👁️隐私):")
		fmt.Printf("   %-24s %-8s %10s %10s %7s %6s %15s\n",
			"DEVICE (NAME / IP)", "ROLE", "UPLOAD ↑", "DOWNLOAD ↓", "U/D比", "可疑数", "总分(🛡️安/👁️隐)")
		for i, d := range rep.Devices {
			if i >= 10 {
				break
			}
			devLabel := d.DeviceIP
			if d.DeviceName != "" && d.DeviceName != d.DeviceIP {
				devLabel = fmt.Sprintf("%s (%s)", truncateText(d.DeviceName, 10), d.DeviceIP)
			}
			scoreCol := fmt.Sprintf("%2d分(%2d/%2d)", d.MaxRiskScore, d.MaxSecurityScore, d.MaxPrivacyScore)
			fmt.Printf("   %-24s %-8s %10s %10s %6.1fx %6d %15s\n",
				truncateText(devLabel, 24),
				cmp.Or(d.DeviceRole, "unknown"),
				telemetry.FormatBytes(d.UploadBytes),
				telemetry.FormatBytes(d.DownloadBytes),
				d.UploadRatio,
				d.SuspiciousCount+d.HighRiskCount,
				scoreCol,
			)
		}
	}

	fmt.Println("──────────────────────────────────────────────────────────────────────────────────────────────")
	fmt.Println(" 🔍 连接行为与可疑上传明细:")
	if len(rep.Flows) == 0 {
		fmt.Println("   (暂无匹配条件的连接流量记录)")
	} else {
		fmt.Printf("   %-6s %-11s %-15s %-26s %-4s %9s %9s %6s  %s\n",
			"等级", "总(安/隐)", "源设备IP", "目标地址 (HOST/IP)", "协议", "上传 ↑", "下载 ↓", "比值", "双轴非线性诊断原因")
		for _, f := range rep.Flows {
			badge := "[" + f.ThreatLabel + "]"
			switch f.State {
			case audit.EnforcementBlocked:
				badge = "[已封]"
			case audit.EnforcementWhitelisted:
				badge = "[放行]"
			}
			target := f.Target
			if f.DestPort > 0 && f.IsDirectIP {
				target = fmt.Sprintf("%s:%d", f.Target, f.DestPort)
			}
			if f.AppName != "" {
				target = fmt.Sprintf("[%s] %s", f.AppName, target)
			}
			scoreStr := fmt.Sprintf("%2d(%2d/%2d)", f.RiskScore, f.SecurityScore, f.PrivacyScore)
			reasonStr := strings.Join(f.Reasons, "; ")
			fmt.Printf("   %-6s %-11s %-15s %-26s %-4s %9s %9s %5.1fx  %s\n",
				badge,
				scoreStr,
				truncateText(f.DeviceIP, 15),
				truncateText(target, 26),
				strings.ToUpper(f.Network),
				telemetry.FormatBytes(f.UploadBytes),
				telemetry.FormatBytes(f.DownloadBytes),
				f.UploadRatio,
				truncateText(reasonStr, 42),
			)
			if showAI && f.AIReview != nil {
				src := cmp.Or(f.AIReview.Source, "expert")
				fmt.Printf("          └─ 🤖 AI研判 [%s · %s]: %s | 影响: %s\n",
					src, f.AIReview.VerdictText, f.AIReview.Category, f.AIReview.Impact)
			}
		}
	}

	fmt.Println("══════════════════════════════════════════════════════════════════════════════════════════════")
	fmt.Println(" 💡 一键双层拉黑: singctl sb block <目标域名或IP> [--device <内网设备IP>]")
	fmt.Println(" 💡 深度AI研判  : singctl sb audit --suspicious --ai")
}

func renderBlockList(blocks []config.BlockRule) {
	if len(blocks) == 0 {
		logger.Info("当前双层黑名单为空（可通过 'singctl sb block <域名或IP>' 添加）")
		return
	}
	fmt.Println("══════════════════════════════════════════════════════════════════════════════")
	fmt.Printf(" 🛡️  当前生效的双层黑名单 (Sing-Box + AdGuard DNS) 共 %d 条:\n", len(blocks))
	fmt.Println("──────────────────────────────────────────────────────────────────────────────")
	fmt.Printf(" %-30s %-18s %-20s\n", "TARGET (域名/IP)", "DEVICE (限定设备)", "REASON (原因)")
	for _, b := range blocks {
		dev := cmp.Or(b.SourceIP, "全局 (All)")
		fmt.Printf(" %-30s %-18s %s\n", b.Target, dev, b.Reason)
	}
	fmt.Println("══════════════════════════════════════════════════════════════════════════════")
}

func truncateText(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}
