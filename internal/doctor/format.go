// 文件职责：提供终端对齐美化输出的深度体检报告格式化器 FormatText。
package doctor

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/mattn/go-runewidth"
)

// FormatText 将深度体检 Report 渲染为终端对齐可读文本。
func FormatText(r Report) string {
	var b strings.Builder
	const bar = "════════════════════════════════════════════════════════════════════"
	const sep = "────────────────────────────────────────────────────────────────────"

	b.WriteString(bar + "\n")
	b.WriteString("                   SingCtl 全链路深度体检报告\n")
	b.WriteString(bar + "\n")
	fmt.Fprintf(&b, "  综合评分: %d / 100  |  状态: %s  |  耗时: %dms\n",
		r.Score, statusBadge(r.Overall), r.DurationMs)
	fmt.Fprintf(&b, "  体检时间: %s  |  通过 %d · 警告 %d · 失败 %d · 跳过 %d\n",
		cmp.Or(r.CheckedAt, "-"), r.Passed, r.Warnings, r.Failed, r.Skipped)
	b.WriteString(sep + "\n")

	titleColWidth := 24
	for _, c := range r.Checks {
		if w := runewidth.StringWidth(cmp.Or(c.Title, c.ID)); w > titleColWidth {
			titleColWidth = min(w, 34)
		}
	}

	for _, c := range r.Checks {
		icon := statusIcon(c.Status)
		title := padRightWidth(cmp.Or(c.Title, c.ID), titleColWidth)
		fmt.Fprintf(&b, "  %s %s  %s (%dms)\n", icon, title, c.Summary, c.DurationMs)
		if c.Detail != "" {
			fmt.Fprintf(&b, "      ├─ 详情: %s\n", c.Detail)
		}
		if c.Advice != "" {
			fmt.Fprintf(&b, "      ├─ 建议: %s\n", c.Advice)
		}
		if c.FixAction != "" {
			label := cmp.Or(c.FixLabel, "一键修复")
			fmt.Fprintf(&b, "      └─ 快捷修复: %s [--fix %s]\n", label, c.FixAction)
		}
	}

	b.WriteString(bar + "\n")
	return b.String()
}

func statusIcon(s Status) string {
	switch s {
	case StatusPass:
		return "[✓]"
	case StatusWarn:
		return "[!]"
	case StatusFail:
		return "[✗]"
	default:
		return "[-]"
	}
}

func statusBadge(s Status) string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusWarn:
		return "WARN"
	case StatusFail:
		return "FAIL"
	default:
		return "SKIP"
	}
}

func padRightWidth(s string, width int) string {
	w := runewidth.StringWidth(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}
