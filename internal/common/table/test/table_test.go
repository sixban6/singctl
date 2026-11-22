// 文件职责：验证 table 终端表格的 ANSI 色彩剥离宽度计算、东亚宽字符对齐与宽字符安全截断。
package table_test

import (
	"strings"
	"testing"

	"singctl/internal/common/table"
)

func TestTableRender_AnsiWidth_And_TruncateWidth(t *testing.T) {
	tbl := table.New("节点", "状态", "延迟")
	tbl.SetAlign(0, table.AlignLeft)
	tbl.SetAlign(1, table.AlignCenter)
	tbl.SetAlign(2, table.AlignRight)
	tbl.AddRow("node-alpha", "\x1b[32m🟢 正常\x1b[0m", "12ms")
	tbl.AddRow("node-beta", "🟡 待检", "128ms")

	out := tbl.Render()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 6 table lines, got %d", len(lines))
	}
	w0 := table.StringDisplayWidth(lines[0])
	for i, l := range lines {
		if got := table.StringDisplayWidth(l); got != w0 {
			t.Fatalf("line %d width %d != %d: %s", i, got, w0, l)
		}
	}

	if got := table.TruncateWidth("这是一个很长的中文节点名称测试", 10); table.StringDisplayWidth(got) > 10 || !strings.HasSuffix(got, "...") {
		t.Fatalf("TruncateWidth unexpected: %q (width=%d)", got, table.StringDisplayWidth(got))
	}
	if got := table.TruncateWidth("short", 10); got != "short" {
		t.Fatalf("TruncateWidth modified short string: %q", got)
	}
}
