package ssh

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"os"

	"singctl/internal/logger"
)

// PrintExecutionReport prints a structured summary table for singctl ssh init / harden results.
func PrintExecutionReport(results []*HostResult) {
	fmt.Println()
	logger.Info("════════════════════════════════════════════════════════════════════════════════════")
	logger.Success("                          🎉 SSH 执行结果汇总报告 🎉")
	logger.Info("════════════════════════════════════════════════════════════════════════════════════")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "主机别名\t目标地址\t初始端口\t最终端口\t公钥注入\t免密验证\t密码禁用\t状态\t耗时")
	_, _ = fmt.Fprintln(w, "────────\t────────\t────────\t────────\t────────\t────────\t────────\t────\t────")

	successCount := 0
	warningCount := 0
	failedCount := 0

	for _, r := range results {
		keyPushed := "—"
		if r.KeyPushed {
			keyPushed = "✅ 成功"
		}

		keyVerified := "❌ 失败"
		if r.KeyVerified {
			keyVerified = "✅ 已通过"
		}

		passDisabled := "—"
		if r.Host.DisablePasswordAuth {
			if r.PasswordDisabled {
				passDisabled = "🔒 已禁用"
			} else {
				passDisabled = "⚠️ 仍开启"
			}
		}

		statusStr := ""
		switch r.Status {
		case StatusSuccess:
			statusStr = "✅ 成功"
			successCount++
		case StatusWarning:
			statusStr = "⚠️ 警告"
			warningCount++
		case StatusFailed:
			statusStr = "❌ 失败"
			failedCount++
		case StatusSkipped:
			statusStr = "⏭️ 跳过"
		}

		addrStr := r.Host.Host
		if r.Host.IsAliasMode {
			addrStr = fmt.Sprintf("alias(%s)", r.Host.Alias)
		} else if addrStr == "" {
			addrStr = r.Host.IP
		}

		durationStr := fmt.Sprintf("%.1fs", r.Duration.Seconds())
		_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n",
			r.Host.Name,
			addrStr,
			r.InitialPort,
			r.FinalPort,
			keyPushed,
			keyVerified,
			passDisabled,
			statusStr,
			durationStr,
		)
	}

	_ = w.Flush()
	logger.Info("────────────────────────────────────────────────────────────────────────────────────")
	fmt.Printf("📊 总计: %d 台 | 成功: %d | 警告: %d | 失败: %d\n\n", len(results), successCount, warningCount, failedCount)

	// If there are errors or warnings, print details
	hasIssues := false
	for _, r := range results {
		if r.Error != nil {
			if !hasIssues {
				logger.Warn("⚠️ 失败详情与排错建议:")
				hasIssues = true
			}
			fmt.Printf("  • [%s] (%s): %v\n", r.Host.Name, r.Host.IP, r.Error)
		}
		if r.WarningMsg != "" {
			if !hasIssues {
				logger.Warn("⚠️ 告警详情:")
				hasIssues = true
			}
			fmt.Printf("  • [%s] (%s): %s\n", r.Host.Name, r.Host.IP, r.WarningMsg)
		}
	}

	if successCount > 0 {
		logger.Success("💡 提示: 已更新本地 ~/.ssh/config，你可以直接使用别名快速登录:")
		for _, r := range results {
			if r.Status == StatusSuccess {
				fmt.Printf("   ssh %s\n", r.Host.Name)
			}
		}
		fmt.Println()
	}
}

// PrintTestReport prints the diagnostic matrix from singctl ssh test.
func PrintTestReport(results []*TestResult) {
	fmt.Println()
	logger.Info("════════════════════════════════════════════════════════════════════════════════════")
	logger.Success("                          🩺 SSH 主机连通性与合规诊断 🩺")
	logger.Info("════════════════════════════════════════════════════════════════════════════════════")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "主机别名\t目标地址\t当前端口\t目标端口\t免密认证\t密码认证\t安全评级\t耗时")
	_, _ = fmt.Fprintln(w, "────────\t────────\t────────\t────────\t────────\t────────\t────────\t────")

	for _, r := range results {
		addrStr := r.Host.Host
		if r.Host.IsAliasMode {
			addrStr = fmt.Sprintf("alias(%s)", r.Host.Alias)
		} else if addrStr == "" {
			addrStr = r.Host.IP
		}

		curPortStr := fmt.Sprintf("%d ❌", r.Host.CurrentPort)
		if r.Port22Open {
			curPortStr = fmt.Sprintf("%d 🟢", r.Host.CurrentPort)
		}

		targetPortStr := fmt.Sprintf("%d ❌", r.Host.TargetPort)
		if r.TargetPortOpen {
			targetPortStr = fmt.Sprintf("%d 🟢", r.Host.TargetPort)
		}

		keyAuthStr := "❌ 失败"
		if r.KeyAuthWork {
			keyAuthStr = "🟢 正常"
		}

		passAuthStr := "🟢 已禁用"
		if r.PasswordAuthWork {
			passAuthStr = "⚠️ 仍允许"
		}

		compliance := "✅ 达标"
		if !r.KeyAuthWork || r.PasswordAuthWork || (!r.TargetPortOpen && r.Port22Open) {
			if !r.KeyAuthWork {
				compliance = "❌ 未免密"
			} else {
				compliance = "⚠️ 待加固"
			}
		}

		durationStr := fmt.Sprintf("%.1fs", r.Duration.Seconds())
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Host.Name,
			addrStr,
			curPortStr,
			targetPortStr,
			keyAuthStr,
			passAuthStr,
			compliance,
			durationStr,
		)
	}

	_ = w.Flush()
	logger.Info("────────────────────────────────────────────────────────────────────────────────────")
	fmt.Println()
}

// PrintManagedHosts prints the list of managed hosts from ~/.ssh/config.
func PrintManagedHosts(hosts []ManagedHost, configPath string) {
	fmt.Println()
	logger.Info("════════════════════════════════════════════════════════════════════════════════════")
	logger.Success("                   📋 由 singctl 托管的 ~/.ssh/config 节点列表 📋")
	logger.Info("════════════════════════════════════════════════════════════════════════════════════")
	fmt.Printf("配置文件路径: %s\n\n", configPath)

	if len(hosts) == 0 {
		logger.Warn("未发现任何由 singctl 托管的节点标记块。")
		fmt.Println()
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	_, _ = fmt.Fprintln(w, "Host 别名\tHostName (IP)\t端口\t用户\tIdentityFile (私钥)")
	_, _ = fmt.Fprintln(w, "─────────\t─────────────\t────\t────\t───────────────────")

	for _, h := range hosts {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n",
			h.Name,
			h.HostName,
			h.Port,
			h.User,
			strings.ReplaceAll(h.IdentityFile, os.Getenv("HOME"), "~"),
		)
	}

	_ = w.Flush()
	logger.Info("────────────────────────────────────────────────────────────────────────────────────")
	fmt.Printf("总计: %d 个托管节点\n\n", len(hosts))
}
