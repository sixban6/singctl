// 文件职责：提供终端 ANSI 色彩安全剥离宽度计算、东亚宽字符对齐表格渲染与宽字符安全截断工具。
package table

import (
	"regexp"
	"strings"

	"github.com/mattn/go-runewidth"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

type Alignment int

const (
	AlignLeft Alignment = iota
	AlignCenter
	AlignRight
)

// StringDisplayWidth 剥离 ANSI 控制序列后按东亚字符宽度标准计算终端显示列宽。
func StringDisplayWidth(s string) int {
	clean := ansiRegex.ReplaceAllString(s, "")
	return runewidth.StringWidth(clean)
}

// TruncateWidth 按显示列宽安全截断字符串并附加 "..."（不截断半个 UTF-8 或双宽汉字）。
func TruncateWidth(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	clean := ansiRegex.ReplaceAllString(s, "")
	if runewidth.StringWidth(clean) <= maxWidth {
		return s
	}
	if maxWidth <= 3 {
		return runewidth.Truncate(clean, maxWidth, "")
	}
	return runewidth.Truncate(clean, maxWidth, "...")
}

// PadString 按指定对齐方式补齐空格以达到目标显示列宽。
func PadString(s string, targetWidth int, align Alignment) string {
	w := StringDisplayWidth(s)
	if w >= targetWidth {
		return s
	}
	pad := targetWidth - w
	switch align {
	case AlignRight:
		return strings.Repeat(" ", pad) + s
	case AlignCenter:
		left := pad / 2
		right := pad - left
		return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
	default:
		return s + strings.Repeat(" ", pad)
	}
}

type Table struct {
	Headers []string
	Rows    [][]string
	Aligns  []Alignment
}

func New(headers ...string) *Table {
	return &Table{
		Headers: headers,
		Rows:    make([][]string, 0),
		Aligns:  make([]Alignment, len(headers)),
	}
}

func (t *Table) AddRow(cells ...string) {
	row := make([]string, len(t.Headers))
	for i := range len(t.Headers) {
		if i < len(cells) {
			row[i] = cells[i]
		}
	}
	t.Rows = append(t.Rows, row)
}

func (t *Table) SetAlign(colIdx int, align Alignment) {
	if colIdx >= 0 && colIdx < len(t.Aligns) {
		t.Aligns[colIdx] = align
	}
}

func (t *Table) Render() string {
	colCount := len(t.Headers)
	if colCount == 0 {
		return ""
	}

	colWidths := make([]int, colCount)
	for i, h := range t.Headers {
		colWidths[i] = max(colWidths[i], StringDisplayWidth(h))
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < colCount {
				colWidths[i] = max(colWidths[i], StringDisplayWidth(cell))
			}
		}
	}
	for i := range colWidths {
		colWidths[i] += 2
	}

	var sb strings.Builder
	sb.WriteString("┌")
	for i, w := range colWidths {
		sb.WriteString(strings.Repeat("─", w))
		if i < colCount-1 {
			sb.WriteString("┬")
		}
	}
	sb.WriteString("┐\n│")
	for i, h := range t.Headers {
		sb.WriteString(" " + PadString(h, colWidths[i]-2, AlignCenter) + " │")
	}
	sb.WriteString("\n├")
	for i, w := range colWidths {
		sb.WriteString(strings.Repeat("─", w))
		if i < colCount-1 {
			sb.WriteString("┼")
		}
	}
	sb.WriteString("┤\n")

	for _, row := range t.Rows {
		sb.WriteString("│")
		for i := range colCount {
			val := ""
			if i < len(row) {
				val = row[i]
			}
			align := AlignLeft
			if i < len(t.Aligns) {
				align = t.Aligns[i]
			}
			sb.WriteString(" " + PadString(val, colWidths[i]-2, align) + " │")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("└")
	for i, w := range colWidths {
		sb.WriteString(strings.Repeat("─", w))
		if i < colCount-1 {
			sb.WriteString("┴")
		}
	}
	sb.WriteString("┘\n")
	return sb.String()
}
