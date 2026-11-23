// 文件职责：验证 -tags lite 编译裁剪红线（剔除服务端/机群/SSH/测速等重型依赖）并确保全套客户端网关命令完整可用。
package cmd_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/cmd"
)

func TestLiteBuild_DepsExcludeHeavyServerPackages(t *testing.T) {
	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	c := exec.CommandContext(t.Context(), "go", "list", "-tags", "lite", "-deps", "./cmd/singctl")
	c.Dir = repoRoot
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -tags lite -deps ./cmd/singctl failed: %v\n%s", err, string(out))
	}
	deps := make(map[string]bool)
	for line := range strings.SplitSeq(string(out), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			deps[trimmed] = true
		}
	}

	forbidden := []string{
		"singctl/internal/serverweb",
		"singctl/internal/deploy",
		"singctl/internal/deploy/masksite",
		"singctl/internal/fleet",
		"singctl/internal/subhub",
		"singctl/internal/sniff",
		"singctl/internal/heal",
		"singctl/internal/ssh",
		"singctl/internal/terminal",
		"singctl/internal/telemetry",
		"singctl/internal/component",
		"golang.org/x/crypto/ssh",
		"github.com/mattn/go-runewidth",
		"github.com/showwin/speedtest-go/speedtest",
	}
	for _, pkg := range forbidden {
		if deps[pkg] {
			t.Errorf("-tags lite ./cmd/singctl must NOT import heavy package %q", pkg)
		}
	}
}

func TestRootCmd_RetainsAllClientGatewayCommands(t *testing.T) {
	root := cmd.NewRootCmd("/tmp/test-singctl.yaml", "/tmp/test-singctl.yaml", cmd.BuildInfo{
		Version:   "v1.14.999-test",
		BuildTime: "2026-11-23",
		GitCommit: "abcdef0",
	})

	requiredClientPaths := [][]string{
		{"singbox"},
		{"sb"},
		{"sb", "start"},
		{"sb", "stop"},
		{"sb", "gen"},
		{"sb", "groups"},
		{"sb", "audit"},
		{"sb", "block"},
		{"sb", "cache", "status"},
		{"dns"},
		{"dns", "switch"},
		{"gfw"},
		{"net"},
		{"web"},
		{"tailscale"},
		{"ts"},
		{"doctor"},
		{"safe-commit"},
		{"info"},
		{"update"},
		{"version"},
		{"daemon"},
		{"dm"},
		{"firewall"},
		{"fw"},
		{"internal-migrate"},
	}

	for _, args := range requiredClientPaths {
		found, _, err := root.Find(args)
		if err != nil || found == nil || found == root {
			t.Fatalf("expected client command %v to be registered, got found=%v err=%v", args, found, err)
		}
	}
}
