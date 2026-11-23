// 文件职责：验证 -tags lite 下 internal/common/netx 彻底剥离 github.com/showwin/speedtest-go 依赖。
package netx_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetxLiteDeps_ExcludeSpeedtest(t *testing.T) {
	repoRoot, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	c := exec.CommandContext(t.Context(), "go", "list", "-tags", "lite", "-deps", "./internal/common/netx")
	c.Dir = repoRoot
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -tags lite -deps ./internal/common/netx failed: %v\n%s", err, string(out))
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		pkg := strings.TrimSpace(line)
		if strings.HasPrefix(pkg, "github.com/showwin/speedtest-go") {
			t.Errorf("-tags lite ./internal/common/netx must NOT import %q", pkg)
		}
	}
}
