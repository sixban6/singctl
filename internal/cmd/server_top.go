package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/telemetry"

	"github.com/spf13/cobra"
)

func newServerTopCmd() *cobra.Command {
	var once bool
	var enable bool
	var interval time.Duration
	var sbConfigPath string

	cmd := &cobra.Command{
		Use:     "top",
		Aliases: []string{"radar", "stats"},
		Short:   "实时监控服务端吞吐速率、协议负载与分流去向 / Live server traffic & routing radar",
		RunE: func(cmd *cobra.Command, args []string) error {
			if sbConfigPath == "" {
				sbConfigPath = constant.SingBoxConfigFile
			}

			if enable {
				changed, addr, _, err := telemetry.EnsureConfigTelemetry(sbConfigPath)
				if err != nil {
					return err
				}
				if changed {
					logger.Info("已写入本地流量遥测配置 (%s)，正在重启 sing-box 生效...", addr)
					if err := exec.Command("systemctl", "restart", "sing-box").Run(); err != nil {
						return fmt.Errorf("重启 sing-box 失败: %w", err)
					}
					time.Sleep(500 * time.Millisecond)
				}
			}

			if !isStdoutTTY() {
				once = true
			}
			if interval < 500*time.Millisecond {
				interval = 500 * time.Millisecond
			}

			collector := telemetry.NewCollector(sbConfigPath)

			if once {
				// Take two quick samples 350ms apart so instantaneous throughput is meaningful even in --once mode
				first := collector.Collect(cmd.Context())
				if !first.Enabled || !first.Reachable {
					renderTopSnapshot(first, true)
					return nil
				}
				time.Sleep(350 * time.Millisecond)
				second := collector.Collect(cmd.Context())
				renderTopSnapshot(second, true)
				return nil
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				snap := collector.Collect(ctx)
				fmt.Print("\033[H\033[2J")
				renderTopSnapshot(snap, false)
				if !snap.Enabled {
					return nil
				}
				select {
				case <-ctx.Done():
					fmt.Println("\n已退出实时流量雷达。")
					return nil
				case <-ticker.C:
				}
			}
		},
	}

	cmd.Flags().BoolVarP(&once, "once", "1", false, "输出单帧快照后立即退出 (非交互终端默认开启)")
	cmd.Flags().BoolVar(&enable, "enable", false, "若尚未开启本地遥测则自动无损写入 sing-box 配置并重启生效")
	cmd.Flags().DurationVarP(&interval, "interval", "i", 1500*time.Millisecond, "刷新周期 (例如 1s, 1500ms)")
	cmd.Flags().StringVar(&sbConfigPath, "singbox-config", "", "指定 sing-box 配置文件路径")
	return cmd
}

func isStdoutTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func renderTopSnapshot(snap telemetry.Snapshot, once bool) {
	fmt.Println("══════════════════════════════════════════════════════════════════════════")
	fmt.Printf(" 🚀 SINGCTL 实时流量与分流雷达   [%s]\n", time.Now().Format("15:04:05"))
	fmt.Println("══════════════════════════════════════════════════════════════════════════")

	if !snap.Enabled {
		fmt.Printf(" [!] %s\n", snap.Message)
		fmt.Println(" 💡 运行 'singctl sr top --enable' 或在 Web 面板一键无损开启（不会重置任何节点密码）。")
		fmt.Println("══════════════════════════════════════════════════════════════════════════")
		return
	}
	if !snap.Reachable {
		fmt.Printf(" [!] %s\n", snap.Message)
		fmt.Println("══════════════════════════════════════════════════════════════════════════")
		return
	}

	fmt.Printf(" 实时吞吐 : ↑ %-14s   ↓ %-14s   活跃连接: %d 个\n",
		telemetry.FormatRate(snap.UpBps),
		telemetry.FormatRate(snap.DownBps),
		snap.ActiveConnections,
	)
	fmt.Printf(" 累计流量 : ↑ %-14s   ↓ %-14s   核心内存: %s\n",
		telemetry.FormatBytes(snap.UploadTotal),
		telemetry.FormatBytes(snap.DownloadTotal),
		telemetry.FormatBytes(snap.MemoryBytes),
	)
	fmt.Println("──────────────────────────────────────────────────────────────────────────")

	hy2Pct, realPct := calcShare(snap.Protocols.Hy2Connections, snap.Protocols.RealityConnections)
	fmt.Printf(" 协议分布 : Hysteria2 [%s %3d%%] (%d)  |  Reality [%s %3d%%] (%d)\n",
		asciiBar(hy2Pct, 10), hy2Pct, snap.Protocols.Hy2Connections,
		asciiBar(realPct, 10), realPct, snap.Protocols.RealityConnections,
	)

	dcPct, warpPct := calcShare(snap.Outbounds.DirectConnections, snap.Outbounds.WarpConnections)
	fmt.Printf(" 出口分流 : 原生直出  [%s %3d%%] (%d)  |  WARP    [%s %3d%%] (%d)\n",
		asciiBar(dcPct, 10), dcPct, snap.Outbounds.DirectConnections,
		asciiBar(warpPct, 10), warpPct, snap.Outbounds.WarpConnections,
	)
	fmt.Println("──────────────────────────────────────────────────────────────────────────")
	fmt.Println(" 活跃目标域名 Top 8:")
	if len(snap.TopDomains) == 0 {
		fmt.Println("   (当前暂无活跃代理连接)")
	} else {
		fmt.Printf("   %-32s %-11s %-8s %5s %10s\n", "TARGET HOST", "PROTOCOL", "OUTBOUND", "CONNS", "TRAFFIC")
		for _, d := range snap.TopDomains {
			host := d.Domain
			if len(host) > 30 {
				host = host[:27] + "..."
			}
			fmt.Printf("   %-32s %-11s %-8s %5d %10s\n",
				host, d.Protocol, d.Outbound, d.Connections, telemetry.FormatBytes(d.Bytes))
		}
	}
	fmt.Println("══════════════════════════════════════════════════════════════════════════")
	if !once {
		fmt.Println(" 按 Ctrl+C 退出实时监控")
	}
	_ = context.Background
}

func calcShare(a, b int) (int, int) {
	total := a + b
	if total <= 0 {
		return 0, 0
	}
	pa := (a * 100) / total
	return pa, 100 - pa
}

func asciiBar(pct, width int) string {
	filled := (pct * width) / 100
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}
