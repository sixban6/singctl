package gfw

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// PrintReport 格式化打印探测结果报告
func PrintReport(w io.Writer, report *Report, verbose bool) error {
	divider := strings.Repeat("=", 64)
	subDivider := strings.Repeat("-", 64)

	fmt.Fprintln(w, "\n"+divider)
	fmt.Fprintf(w, "🛡️  GFW 主动探测模拟与风险评估报告\n")
	fmt.Fprintf(w, "🎯 目标 IP: %s", report.TargetIP)
	if report.TargetSNI != "" {
		fmt.Fprintf(w, " | 伪装 SNI: %s", report.TargetSNI)
	}
	if report.TargetDomain != "" {
		fmt.Fprintf(w, " | 节点域名: %s", report.TargetDomain)
	}
	fmt.Fprintf(w, "\n⏱️  检测时间: %s\n", report.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w, divider)

	// 打印各大分类探测详情
	for i, cat := range report.Categories {
		fmt.Fprintf(w, "\n[%d/5] %s (得分贡献: %d/%d 分)\n", i+1, cat.Name, cat.Score, cat.MaxScore)
		for _, item := range cat.Items {
			statusMark := "✅"
			scoreInfo := ""
			if !item.Passed && item.Score > 0 {
				statusMark = "❌"
				scoreInfo = fmt.Sprintf(" (+%d分)", item.Score)
			} else if !item.Passed {
				statusMark = "⚠️"
			}

			fmt.Fprintf(w, "      ├─ %-32s: %s%s\n", item.Name, statusMark, scoreInfo)
			if verbose || !item.Passed {
				fmt.Fprintf(w, "      │  └─ 详情: %s\n", item.Details)
			}
		}
	}

	// 打印风险综合评分仪表盘
	fmt.Fprintln(w, "\n"+divider)
	fmt.Fprintf(w, "📊 GFW 判定风险总评分: %d / 100 分\n", report.TotalScore)
	fmt.Fprintf(w, "🚨 风险等级: %s\n", report.RiskLevel)
	fmt.Fprintln(w, divider)

	// 核心风险特征发现
	if len(report.Findings) > 0 {
		fmt.Fprintln(w, "\n⚠️  识别到的核心翻墙/代理特征 (扣分明细):")
		for _, f := range report.Findings {
			fmt.Fprintf(w, "  • %s\n", f)
		}
	} else {
		fmt.Fprintln(w, "\n✨ 未发现明显的翻墙特征，行为与标准公网 Web 服务器高度一致！")
	}

	// 修复与加固建议
	if len(report.Recommendations) > 0 {
		fmt.Fprintln(w, "\n"+subDivider)
		fmt.Fprintln(w, "💡 singctl 节点伪装与安全加固建议:")
		for _, r := range report.Recommendations {
			fmt.Fprintf(w, "  %s\n", r)
		}
		fmt.Fprintln(w, subDivider)
	}

	fmt.Fprintln(w)
	return nil
}

// PrintJSONReport 输出 JSON 格式
func PrintJSONReport(w io.Writer, report *Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
