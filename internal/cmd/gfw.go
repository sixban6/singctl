package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"singctl/internal/gfw"
	"singctl/internal/logger"

	"github.com/spf13/cobra"
)

// NewGFWCmd 创建 GFW 模拟主动探测与打分命令
func NewGFWCmd() *cobra.Command {
	var (
		ports      []int
		sni        string
		domain     string
		timeoutSec int
		verbose    bool
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:     "gfw <ip>",
		Aliases: []string{"probe", "detect"},
		Short:   "探测  : 模拟 GFW 主动探测并对节点是否为代理进行打分 (0-100分)",
		Long: `模拟防火墙 (GFW) 经典主动探测 (Active Probing) 手段，对指定 IP 进行多维度探测与特征画像分析。
评估该 IP 是否暴露代理特征并给出 0~100 分风险评分（分值越高越确认为代理）。`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetIP := args[0]
			// 校验 IP 格式
			if parsedIP := net.ParseIP(targetIP); parsedIP == nil {
				// 如果传入的是域名，尝试解析为 IP
				ips, err := net.LookupIP(targetIP)
				if err != nil || len(ips) == 0 {
					return fmt.Errorf("invalid IP address or domain: %s", targetIP)
				}
				logger.Info("域名 %s 已解析至 IP: %s", targetIP, ips[0].String())
				if domain == "" {
					domain = targetIP
				}
				targetIP = ips[0].String()
			}

			opts := gfw.ProbeOptions{
				IP:         targetIP,
				Ports:      ports,
				SNI:        sni,
				Domain:     domain,
				Timeout:    time.Duration(timeoutSec) * time.Second,
				Verbose:    verbose,
				JSONOutput: jsonOutput,
			}

			if !jsonOutput {
				logger.Info("正在启动 GFW 主动探测模拟器...")
				logger.Info("目标 IP: %s | 超时: %ds | 详细模式: %v", targetIP, timeoutSec, verbose)
				if len(ports) > 0 {
					logger.Info("指定端口: %v", ports)
				}
				if sni != "" {
					logger.Info("伪装 SNI: %s", sni)
				}
				if domain != "" {
					logger.Info("节点域名: %s", domain)
				}
			}

			detector := gfw.NewDetector(opts)
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec*5)*time.Second)
			defer cancel()

			report, err := detector.Run(ctx)
			if err != nil {
				return fmt.Errorf("probe failed: %w", err)
			}

			if jsonOutput {
				return gfw.PrintJSONReport(os.Stdout, report)
			}

			return gfw.PrintReport(os.Stdout, report, verbose)
		},
	}

	cmd.Flags().IntSliceVarP(&ports, "ports", "p", nil, "自定义探测端口列表 (默认: 80,443，例如: -p 80,443 或 -p 8443)")
	cmd.Flags().StringVar(&sni, "sni", "", "Reality / 伪装 SNI 域名 (例如 swdist.apple.com)")
	cmd.Flags().StringVar(&domain, "domain", "", "节点所属域名 (例如 cdn.l1.example.com)")
	cmd.Flags().IntVarP(&timeoutSec, "timeout", "t", 4, "单项探测超时时间 (秒)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "显示详细的探测过程与调试信息")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "以 JSON 格式输出检测报告")

	return cmd
}
