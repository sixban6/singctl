package table

import (
	"strings"
	"testing"
)

func TestTableRender(t *testing.T) {
	tbl := New("主机别名", "目标地址", "当前端口", "目标端口", "密钥登录", "密码登录", "安全评级", "耗时")
	tbl.SetAlign(0, AlignLeft)
	tbl.SetAlign(1, AlignLeft)
	tbl.SetAlign(2, AlignCenter)
	tbl.SetAlign(3, AlignCenter)
	tbl.SetAlign(4, AlignCenter)
	tbl.SetAlign(5, AlignCenter)
	tbl.SetAlign(6, AlignCenter)
	tbl.SetAlign(7, AlignRight)

	tbl.AddRow("vps_sg", "alias(vps_sg)", "2222 🟢", "2222 🟢", "🟢 畅通", "🔒 已关闭", "✅ 达标", "0.4s")
	tbl.AddRow("vps_rn", "alias(vps_rn)", "2222 🟢", "2222 🟢", "🟢 畅通", "🔒 已关闭", "✅ 达标", "0.3s")
	tbl.AddRow("vps_rn2", "alias(vps_rn2)", "2222 🟢", "2222 🟢", "🟢 畅通", "🔓 仍开启", "🟡 待加固", "0.3s")

	output := tbl.Render()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) != 7 {
		t.Fatalf("expected 7 lines (top, header, sep, 3 rows, bottom), got %d", len(lines))
	}

	expectedWidth := StringDisplayWidth(lines[0])
	for i, l := range lines {
		w := StringDisplayWidth(l)
		if w != expectedWidth {
			t.Errorf("line %d width mismatch: expected %d, got %d: %s", i, expectedWidth, w, l)
		}
	}
}

func TestAnsiStrip(t *testing.T) {
	colored := "\x1b[32mhello\x1b[0m"
	if StringDisplayWidth(colored) != 5 {
		t.Errorf("expected width 5 for colored hello, got %d", StringDisplayWidth(colored))
	}
}
