// 文件职责：提供终端对齐美化输出的深度体检报告格式化器 FormatText（零外部宽度表依赖）。
package doctor

import (
	"cmp"
	"fmt"
	"strings"
	"unicode"
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
		if w := displayWidth(cmp.Or(c.Title, c.ID)); w > titleColWidth {
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
	w := displayWidth(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

// displayWidth 按等宽终端习惯估算 Unicode 字符显示列宽（零外部宽度查找表，避免引入大体积 BSS LUT）。
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case r < 0x20 || (r >= 0x7f && r < 0xa0):
			continue
		case unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r):
			continue
		case isWideRune(r):
			w += 2
		default:
			w++
		}
	}
	return w
}

func isWideRune(r rune) bool {
	return (r >= 0x1100 && r <= 0x115F) ||
		r == 0x2329 || r == 0x232A ||
		(r >= 0x2E80 && r <= 0xA4CF && r != 0x303F) ||
		(r >= 0xAC00 && r <= 0xD7A3) ||
		(r >= 0xF900 && r <= 0xFAFF) ||
		(r >= 0xFE10 && r <= 0xFE19) ||
		(r >= 0xFE30 && r <= 0xFE6F) ||
		(r >= 0xFF00 && r <= 0xFF60) ||
		(r >= 0xFFE0 && r <= 0xFFE6) ||
		(r >= 0x1F300 && r <= 0x1FAFF) ||
		(r >= 0x20000 && r <= 0x3FFFD)
}
