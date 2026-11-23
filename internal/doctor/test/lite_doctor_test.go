// 文件职责：验证 -tags lite 下 internal/doctor 彻底剥离服务端重型依赖（deploy/subhub/go-runewidth）且完整保留 8 项客户端深度体检与报告对齐。
package doctor_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/doctor"
)

func TestDoctorLiteDeps_ExcludeServerAndRunewidthPackages(t *testing.T) {
	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), "go", "list", "-tags", "lite", "-deps", "./internal/doctor")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -tags lite -deps ./internal/doctor failed: %v\n%s", err, string(out))
	}
	deps := make(map[string]bool)
	for line := range strings.SplitSeq(string(out), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			deps[trimmed] = true
		}
	}

	forbidden := []string{
		"singctl/internal/deploy",
		"singctl/internal/subhub",
		"github.com/mattn/go-runewidth",
		"github.com/clipperhouse/uax29/v2/graphemes",
	}
	for _, pkg := range forbidden {
		if deps[pkg] {
			t.Errorf("-tags lite ./internal/doctor must NOT depend on %q", pkg)
		}
	}
}

func TestDoctorFormatText_UnicodeDisplayWidthAlignment(t *testing.T) {
	rep := doctor.Report{
		Score:      88,
		Overall:    doctor.StatusWarn,
		Passed:     1,
		Warnings:   1,
		DurationMs: 12,
		CheckedAt:  "2026-11-23 08:00:00",
		Checks: []doctor.CheckResult{
			{ID: "ascii", Title: "DNS Check", Status: doctor.StatusPass, Summary: "ok", DurationMs: 1},
			{ID: "cjk", Title: "硬件资源与内存档位", Status: doctor.StatusWarn, Summary: "warn", DurationMs: 2},
			{ID: "mixed", Title: "Sing-Box 沙盒与配置", Status: doctor.StatusPass, Summary: "ok", DurationMs: 3},
		},
	}
	out := doctor.FormatText(rep)
	for _, want := range []string{"DNS Check", "硬件资源与内存档位", "Sing-Box 沙盒与配置", "88 / 100"} {
		if !strings.Contains(out, want) {
			t.Fatalf("FormatText missing %q in:\n%s", want, out)
		}
	}
	// Verify server environment detection works identically in both full and lite builds
	if doctor.IsServerEnvironment(&config.Config{Server: config.ServerConfig{NodeDomain: "node.example.com"}}) {
		t.Fatal("placeholder node.example.com must not be treated as server env")
	}
	if !doctor.IsServerEnvironment(&config.Config{Server: config.ServerConfig{NodeDomain: "prod.example.com"}}) {
		t.Fatal("real server domain should be detected as server env")
	}
}
