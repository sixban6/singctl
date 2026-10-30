package ssh

import (
	"fmt"
	"os"
	"text/tabwriter"

	"singctl/internal/logger"
)

// PrintExecutionReport prints a summary table of the execution results across hosts.
func PrintExecutionReport(results []*HostResult) {
	fmt.Println()
	logger.Info("════════════════════════════════════════════════════════════════════════════════════")
	logger.Success("                         📊 SSH 批量操作与加固执行报告 📊")
	logger.Info("════════════════════════════════════════════════════════════════════════════════════")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "主机别名\t目标地址\t端口变更\t公钥分发\t免密拨测\t密码认证\t配置托管\t状态\t耗时")
	_, _ = fmt.Fprintln(w, "────────\t────────\t────────\t────────\t────────\t────────\t────────\t────\t────")

	for _, r := range results {
		addrStr := r.Host.Host
		if r.Host.IsAliasMode {
			addrStr = fmt.Sprintf("alias(%s)", r.Host.Alias)
		} else if addrStr == "" {
			addrStr = r.Host.IP
		}

		portStr := fmt.Sprintf("%d", r.FinalPort)
		if r.InitialPort != r.FinalPort {
			portStr = fmt.Sprintf("%d ➔ %d", r.InitialPort, r.FinalPort)
		}

		keyPushedStr := "➖"
		if r.KeyPushed {
			keyPushedStr = "✅ 已写入"
		}

		keyVerifiedStr := "❌ 失败"
		if r.KeyVerified {
			keyVerifiedStr = "🟢 成功"
		}

		passStr := "保持原样"
		if r.PasswordDisabled {
			passStr = "🔒 已禁用"
		}

		cfgStr := "➖"
		if r.Host.IsAliasMode {
			cfgStr = "已存在"
		} else if r.ConfigUpdated {
			cfgStr = "✅ 已写入"
		}

		statusStr := string(r.Status)
		switch r.Status {
		case StatusSuccess:
			statusStr = "🟢 成功"
		case StatusWarning:
			statusStr = "⚠️ 警告"
		case StatusFailed:
			statusStr = "❌ 失败"
		}

		durationStr := fmt.Sprintf("%.1fs", r.Duration.Seconds())
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Host.Name,
			addrStr,
			portStr,
			keyPushedStr,
			keyVerifiedStr,
			passStr,
			cfgStr,
			statusStr,
			durationStr,
		)
	}

	_ = w.Flush()
	logger.Info("────────────────────────────────────────────────────────────────────────────────────")

	hasErrors := false
	for _, r := range results {
		if r.Error != nil {
			hasErrors = true
			logger.Error("[%s] 异常信息: %v", r.Host.Name, r.Error)
		}
		if r.WarningMsg != "" {
			logger.Warn("[%s] 提示: %s", r.Host.Name, r.WarningMsg)
		}
	}

	if !hasErrors {
		fmt.Println()
		logger.Success("🎉 所有目标主机均已完成验证！您可直接使用标准别名秒级连接：")
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
	_, _ = fmt.Fprintln(w, "主机别名\t目标地址\t当前端口\t目标端口\t密钥免密\t密码登录\t安全评级\t耗时")
	_, _ = fmt.Fprintln(w, "────────\t────────\t────────\t────────\t────────\t────────\t────────\t────")

	for _, r := range results {
		addrStr := r.Host.Host
		if r.Host.IsAliasMode {
			addrStr = fmt.Sprintf("alias(%s)", r.Host.Alias)
		} else if addrStr == "" {
			addrStr = r.Host.IP
		}

		curPortStr := fmt.Sprintf("%d ❌", r.Host.CurrentPort)
		if r.CurrentPortOpen {
			curPortStr = fmt.Sprintf("%d 🟢", r.Host.CurrentPort)
		} else if r.Host.CurrentPort == 22 && r.Host.TargetPort != 22 && r.TargetPortOpen {
			curPortStr = fmt.Sprintf("%d 🔒 已收敛", r.Host.CurrentPort)
		}

		targetPortStr := fmt.Sprintf("%d ❌", r.Host.TargetPort)
		if r.TargetPortOpen {
			targetPortStr = fmt.Sprintf("%d 🟢", r.Host.TargetPort)
		}

		keyAuthStr := "❌ 失败"
		if r.KeyAuthWork {
			keyAuthStr = "🟢 畅通"
		}

		passAuthStr := "🔒 已关闭"
		if r.PasswordAuthWork {
			passAuthStr = "⚠️ 仍开启"
		}

		compliance := "✅ 达标"
		if !r.KeyAuthWork || r.PasswordAuthWork || (r.Port22Open && r.Host.TargetPort != 22) {
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

// PrintManagedHosts displays hosts parsed from ~/.ssh/config.
func PrintManagedHosts(hosts []ManagedHost, configPath string) {
	fmt.Println()
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Info("📋 ~/.ssh/config 中由 singctl 托管的主机清单")
	logger.Info("📍 配置文件路径: %s", configPath)
	logger.Info("═══════════════════════════════════════════════════════════")

	if len(hosts) == 0 {
		logger.Warn("当前 ~/.ssh/config 中没有任何由 singctl 托管的主机。")
		fmt.Println()
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "Host 别名\tHostName\tUser\tPort\tIdentityFile")
	_, _ = fmt.Fprintln(w, "─────────\t────────\t────\t────\t────────────")

	for _, h := range hosts {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
			h.Name,
			h.HostName,
			h.User,
			h.Port,
			h.IdentityFile,
		)
	}

	_ = w.Flush()
	logger.Info("───────────────────────────────────────────────────────────")
	fmt.Printf("总计: %d 台主机\n\n", len(hosts))
}
