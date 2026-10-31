package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/netdiag"

	"github.com/spf13/cobra"
)

// NewNetCmd 创建网络诊断与选型综合命令集
func NewNetCmd(configPath string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "net",
		Aliases: []string{"n"},
		Short:   "网络  : 网络线路画像、丢包抖动诊断与选型建议(简写:singctl n)",
		Long: `综合网络诊断与骨干线路识别工具集。
支持 TCP/ICMP 丢包与抖动分析、三网骨干线路特征识别（CN2 GIA/163/9929/4837/CMIN2/CMI）、
VPS 回程测试以及根据本地运营商给出选型与协议优化建议。`,
	}

	cmd.AddCommand(newNetDiagCmd(configPath))
	cmd.AddCommand(newNetPingCmd())
	cmd.AddCommand(newNetTraceCmd())
	cmd.AddCommand(newNetReturnCmd())
	cmd.AddCommand(newNetAdviceCmd())

	return cmd
}

func newNetDiagCmd(configPath string) *cobra.Command {
	var (
		port       int
		count      int
		apply      bool
		verbose    bool
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:     "diag [ip/domain]",
		Aliases: []string{"test", "check"},
		Short:   "一键综合体检: 延迟、丢包、骨干线路识别与选型优化建议",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			target := ""
			if len(args) > 0 {
				target = args[0]
			} else {
				// 尝试从配置文件中读取 server.server_ip 或 server.node_domain
				cfg, err := config.Load(configPath)
				if err == nil && cfg != nil {
					if cfg.Server.ServerIP != "" {
						target = cfg.Server.ServerIP
					} else if cfg.Server.NodeDomain != "" {
						target = cfg.Server.NodeDomain
					}
				}
			}

			if target == "" {
				return fmt.Errorf("未指定探测目标，请传入 IP/域名或在 singctl.yaml 中配置 server_ip: singctl net diag <ip/domain>")
			}

			if !jsonOutput {
				logger.Info("正在启动综合网络链路体检: %s (端口: %d)...", target, port)
			}

			// 1. 本地网络运营商画像
			localISP, _ := netdiag.GetPublicISP(ctx)

			// 2. 目标 IP 解析
			targetIP := target
			if parsed := net.ParseIP(target); parsed == nil {
				if ips, err := net.LookupIP(target); err == nil && len(ips) > 0 {
					targetIP = ips[0].String()
				}
			}

			// 3. 多轮 TCP Ping 测丢包与抖动
			pingRes, err := netdiag.RunPing(ctx, netdiag.PingOptions{
				Host:  targetIP,
				Port:  port,
				Count: count,
			})
			if err != nil {
				return fmt.Errorf("ping test failed: %w", err)
			}

			// 4. 路由追踪与骨干网跳点识别
			traceRes, _ := netdiag.RunTrace(ctx, netdiag.TraceOptions{
				Target:  targetIP,
				MaxHops: 25,
			})

			// 5. 判断是否处于晚高峰 (20:00 - 24:00)
			nowHour := time.Now().Hour()
			isPeak := nowHour >= 20 && nowHour <= 23

			// 6. 建议引擎决策
			adv := netdiag.GenerateAdvice(localISP, pingRes, traceRes, isPeak)

			report := &netdiag.DiagReport{
				Target:     target,
				TargetIP:   targetIP,
				TargetPort: port,
				ScanTime:   time.Now(),
				IsPeakHour: isPeak,
				LocalISP:   localISP,
				Ping:       pingRes,
				Trace:      traceRes,
				Advice:     adv,
			}

			if jsonOutput {
				return netdiag.PrintJSON(os.Stdout, report)
			}

			if err := netdiag.PrintDiagReport(os.Stdout, report, verbose); err != nil {
				return err
			}

			// Phase 3: 自动应用配置回写
			if apply {
				logger.Info("正在将建议参数应用至 %s (hy2.up=%d, hy2.down=%d)...", configPath, adv.SuggestedHy2Up, adv.SuggestedHy2Down)
				if err := netdiag.ApplyHy2Config(configPath, adv.SuggestedHy2Up, adv.SuggestedHy2Down); err != nil {
					logger.Error("更新配置失败: %v", err)
					return err
				}
				logger.Info("✅ 配置已成功更新！您可以使用 'singctl sb gen' 重新生成客户端配置生效。")
			} else {
				fmt.Printf("💡 提示: 您可以添加 --apply 参数自动将建议的上下行带宽写入 singctl.yaml:\n   singctl net diag %s --apply\n\n", target)
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 443, "测试目标端口 (默认 443)")
	cmd.Flags().IntVarP(&count, "count", "n", 10, "测试发包轮数 (默认 10)")
	cmd.Flags().BoolVar(&apply, "apply", false, "自动将建议的 hy2 带宽参数回写至 singctl.yaml")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "显示详细跳点与 RTT 分布明细")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "以 JSON 格式输出结果")

	return cmd
}

func newNetPingCmd() *cobra.Command {
	var (
		port       int
		count      int
		timeoutMs  int
		useICMP    bool
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "ping <ip/domain>",
		Short: "高精度丢包率与网络抖动测试 (支持 TCP Ping 与 ICMP Ping)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			res, err := netdiag.RunPing(ctx, netdiag.PingOptions{
				Host:      args[0],
				Port:      port,
				Count:     count,
				Timeout:   time.Duration(timeoutMs) * time.Millisecond,
				ForceICMP: useICMP,
			})
			if err != nil {
				return err
			}

			if jsonOutput {
				return netdiag.PrintJSON(os.Stdout, res)
			}

			netdiag.PrintPingResult(os.Stdout, res)
			return nil
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 443, "测试端口 (TCP Ping 时使用)")
	cmd.Flags().IntVarP(&count, "count", "n", 10, "发包次数")
	cmd.Flags().IntVarP(&timeoutMs, "timeout", "t", 1500, "单次超时时间 (毫秒)")
	cmd.Flags().BoolVar(&useICMP, "icmp", false, "强制使用系统 ICMP Ping (默认使用更贴合代理端口的 TCP Ping)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "以 JSON 格式输出结果")

	return cmd
}

func newNetTraceCmd() *cobra.Command {
	var (
		maxHops    int
		timeoutSec int
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "trace <ip/domain>",
		Short: "路由追踪并分析沿途骨干网特征 (CN2/163/4837/9929/CMI 等)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			res, err := netdiag.RunTrace(ctx, netdiag.TraceOptions{
				Target:  args[0],
				MaxHops: maxHops,
				Timeout: time.Duration(timeoutSec) * time.Second,
			})
			if err != nil {
				return err
			}

			if jsonOutput {
				return netdiag.PrintJSON(os.Stdout, res)
			}

			netdiag.PrintTraceResult(os.Stdout, res)
			return nil
		},
	}

	cmd.Flags().IntVarP(&maxHops, "max-hops", "m", 25, "最大跳数")
	cmd.Flags().IntVarP(&timeoutSec, "timeout", "t", 1, "单跳超时时间 (秒)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "以 JSON 格式输出结果")

	return cmd
}

func newNetReturnCmd() *cobra.Command {
	var (
		count      int
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "return",
		Short: "VPS 服务端三网回程测试 (探测回程到国内电信/联通/移动的真实线路与丢包)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			logger.Info("正在执行 VPS 服务端回程三网探测 (国内电信/联通/移动骨干节点)...")
			summary, err := netdiag.RunReturnRoute(ctx, count)
			if err != nil {
				return err
			}

			if jsonOutput {
				return netdiag.PrintJSON(os.Stdout, summary)
			}

			netdiag.PrintReturnSummary(os.Stdout, summary)
			return nil
		},
	}

	cmd.Flags().IntVarP(&count, "count", "n", 5, "回程节点 Ping 探测轮数")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "以 JSON 格式输出结果")

	return cmd
}

func newNetAdviceCmd() *cobra.Command {
	var (
		showAll bool
		carrier string
	)

	cmd := &cobra.Command{
		Use:   "advice",
		Short: "自动检测本地宽带并输出专属适配的 VPS 选型与配置指南",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showAll {
				fmt.Fprint(cmd.OutOrStdout(), netdiag.GetCarrierBuyingGuide())
				return nil
			}

			// 如果用户显式指定了运营商
			if carrier != "" {
				c := strings.ToLower(carrier)
				targetType := netdiag.ISPTelecom
				switch {
				case strings.Contains(c, "cu") || strings.Contains(c, "unicom") || strings.Contains(c, "联通"):
					targetType = netdiag.ISPUnicom
				case strings.Contains(c, "cm") || strings.Contains(c, "mobile") || strings.Contains(c, "移动"):
					targetType = netdiag.ISPMobile
				default:
					targetType = netdiag.ISPTelecom
				}

				mockISP := &netdiag.ISPInfo{
					IP:      "手动指定",
					Country: "中国",
					Region:  "-",
					City:    "-",
					Type:    targetType,
				}
				fmt.Fprint(cmd.OutOrStdout(), netdiag.GetTailoredCarrierAdvice(mockISP))
				return nil
			}

			// 默认：自动探测当前网络环境的物理宽带
			logger.Info("正在自动探测本地物理宽带网络环境...")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			isp, err := netdiag.GetPublicISP(ctx)
			if err != nil {
				logger.Warn("未能自动探测到本地宽带信息 (%v)，将展示三网全量选型指南", err)
				fmt.Fprint(cmd.OutOrStdout(), netdiag.GetCarrierBuyingGuide())
				return nil
			}

			fmt.Fprint(cmd.OutOrStdout(), netdiag.GetTailoredCarrierAdvice(isp))
			return nil
		},
	}

	cmd.Flags().BoolVarP(&showAll, "all", "a", false, "查看三大运营商全量选型对比百科")
	cmd.Flags().StringVarP(&carrier, "carrier", "o", "", "手动指定运营商类型 (ct: 电信, cu: 联通, cm: 移动)")

	return cmd
}
