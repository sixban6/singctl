package webui

import (
	"bufio"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTsStartArgs(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
		want   []string
	}{
		{
			name:   "router mode",
			params: map[string]any{"mode": "router"},
			want:   []string{"ts", "start", "--mode", "router"},
		},
		{
			name:   "gateway with accept routes",
			params: map[string]any{"mode": "Gateway", "acceptRoutes": true},
			want:   []string{"ts", "start", "--mode", "gateway", "--accept-routes"},
		},
		{
			name:   "explicit flags",
			params: map[string]any{"exitNode": true, "router": true},
			want:   []string{"ts", "start", "--exit-node", "--router"},
		},
		{
			name:   "client mode only",
			params: map[string]any{"mode": "client"},
			want:   []string{"ts", "start", "--mode", "client"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tsStartArgs(tc.params)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("tsStartArgs(%v) = %v, want %v", tc.params, got, tc.want)
			}
		})
	}
}

func TestActionWhitelist(t *testing.T) {
	for name, def := range actions {
		if def.title == "" {
			t.Errorf("action %q missing title", name)
		}
		args := def.build(nil)
		if len(args) == 0 {
			t.Errorf("action %q produced no args", name)
		}
	}
	if _, ok := actions["sb-start"]; !ok {
		t.Error("sb-start action missing")
	}
}

func TestNDJSONWriterStripsANSI(t *testing.T) {
	rec := httptest.NewRecorder()
	w := newNDJSONWriter(rec)
	// 模拟一行带颜色转义的输出
	_, _ = w.Write([]byte("\x1b[0;32m[SUCCESS] done\x1b[0m\n\x1b[0;31m[ERROR] bad\x1b[0m\n"))

	scanner := bufio.NewScanner(strings.NewReader(rec.Body.String()))
	var lines []string
	for scanner.Scan() {
		if scanner.Text() != "" {
			lines = append(lines, scanner.Text())
		}
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 ndjson lines, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "[SUCCESS] done") || strings.Contains(lines[0], "\x1b") {
		t.Errorf("ANSI not stripped or content wrong: %q", lines[0])
	}
	if !strings.Contains(lines[1], "[ERROR] bad") {
		t.Errorf("second line wrong: %q", lines[1])
	}
}
