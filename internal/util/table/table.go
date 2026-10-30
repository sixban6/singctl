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

// StringDisplayWidth calculates visual column width of a string in terminal.
// It strips ANSI color codes and calculates width using Unicode East Asian Width standard.
func StringDisplayWidth(s string) int {
	clean := ansiRegex.ReplaceAllString(s, "")
	return runewidth.StringWidth(clean)
}

// PadString pads a string to target width according to alignment.
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
	default: // AlignLeft
		return s + strings.Repeat(" ", pad)
	}
}

type Table struct {
	Headers []string
	Rows    [][]string
	Aligns  []Alignment
}

func New(headers ...string) *Table {
	aligns := make([]Alignment, len(headers))
	return &Table{
		Headers: headers,
		Rows:    make([][]string, 0),
		Aligns:  aligns,
	}
}

func (t *Table) AddRow(cells ...string) {
	row := make([]string, len(t.Headers))
	for i := 0; i < len(t.Headers); i++ {
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
		w := StringDisplayWidth(h)
		if w > colWidths[i] {
			colWidths[i] = w
		}
	}

	for _, row := range t.Rows {
		for i, cell := range row {
			if i < colCount {
				w := StringDisplayWidth(cell)
				if w > colWidths[i] {
					colWidths[i] = w
				}
			}
		}
	}

	// Add 2 padding spaces (1 left, 1 right)
	for i := range colWidths {
		colWidths[i] += 2
	}

	var sb strings.Builder

	// Top border: ┌──────┬──────┐
	sb.WriteString("┌")
	for i, w := range colWidths {
		sb.WriteString(strings.Repeat("─", w))
		if i < colCount-1 {
			sb.WriteString("┬")
		}
	}
	sb.WriteString("┐\n")

	// Header row: │  H1  │  H2  │
	sb.WriteString("│")
	for i, h := range t.Headers {
		cellContent := PadString(h, colWidths[i]-2, AlignCenter)
		sb.WriteString(" " + cellContent + " │")
	}
	sb.WriteString("\n")

	// Separator: ├──────┼──────┤
	sb.WriteString("├")
	for i, w := range colWidths {
		sb.WriteString(strings.Repeat("─", w))
		if i < colCount-1 {
			sb.WriteString("┼")
		}
	}
	sb.WriteString("┤\n")

	// Data rows: │  D1  │  D2  │
	for _, row := range t.Rows {
		sb.WriteString("│")
		for i := 0; i < colCount; i++ {
			val := ""
			if i < len(row) {
				val = row[i]
			}
			align := AlignLeft
			if i < len(t.Aligns) {
				align = t.Aligns[i]
			}
			cellContent := PadString(val, colWidths[i]-2, align)
			sb.WriteString(" " + cellContent + " │")
		}
		sb.WriteString("\n")
	}

	// Bottom border: └──────┴──────┘
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
