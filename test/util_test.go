package test

import (
	"singctl/internal/util/table"
	"singctl/internal/util/terminalqr"
	"strings"
	"testing"
)

func TestTableRender(t *testing.T) {
	tbl := table.New("主机别名", "目标地址", "当前端口", "目标端口", "密钥登录", "密码登录", "安全评级", "耗时")
	tbl.SetAlign(0, table.AlignLeft)
	tbl.SetAlign(1, table.AlignLeft)
	tbl.SetAlign(2, table.AlignCenter)
	tbl.SetAlign(3, table.AlignCenter)
	tbl.SetAlign(4, table.AlignCenter)
	tbl.SetAlign(5, table.AlignCenter)
	tbl.SetAlign(6, table.AlignCenter)
	tbl.SetAlign(7, table.AlignRight)

	tbl.AddRow("node-alpha", "alias(node-alpha)", "2222 🟢", "2222 🟢", "🟢 畅通", "🔒 已关闭", "✅ 达标", "0.4s")
	tbl.AddRow("node-beta", "alias(node-beta)", "2222 🟢", "2222 🟢", "🟢 畅通", "🔒 已关闭", "✅ 达标", "0.3s")
	tbl.AddRow("node-gamma", "alias(node-gamma)", "2222 🟢", "2222 🟢", "🟢 畅通", "🔓 仍开启", "🟡 待加固", "0.3s")

	output := tbl.Render()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) != 7 {
		t.Fatalf("expected 7 lines (top, header, sep, 3 rows, bottom), got %d", len(lines))
	}

	expectedWidth := table.StringDisplayWidth(lines[0])
	for i, l := range lines {
		w := table.StringDisplayWidth(l)
		if w != expectedWidth {
			t.Errorf("line %d width mismatch: expected %d, got %d: %s", i, expectedWidth, w, l)
		}
	}
}

func TestAnsiStrip(t *testing.T) {
	colored := "\x1b[32mhello\x1b[0m"
	if table.StringDisplayWidth(colored) != 5 {
		t.Errorf("expected width 5 for colored hello, got %d", table.StringDisplayWidth(colored))
	}
}

func TestRenderString(t *testing.T) {
	out, err := terminalqr.RenderString("vless://test-sample-link")
	if err != nil {
		t.Fatalf("RenderString failed: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("expected non-empty output")
	}
	if !strings.Contains(out, " ") && !strings.Contains(out, "▀") {
		t.Fatalf("output does not appear to contain QR block characters: %q", out)
	}
}
