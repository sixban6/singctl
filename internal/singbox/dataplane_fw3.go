// 文件职责：生成并同步 OpenWrt 21 (fw3 / iptables) sing-box TProxy mangle 规则持久化脚本与 UCI firewall include，防止 fw3 restart 清空规则。
package singbox

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"singctl/internal/common/fsx"
	"singctl/internal/platform/fwtx"
)

// DefaultSingBoxFW3Script 为 OpenWrt 21 fw3 sing-box 透明代理规则持久化脚本默认路径。
const (
	DefaultSingBoxFW3Script = "/etc/sing-box/singbox.fw3.sh"
	fw3SingBoxUCISec        = "singctl_singbox"
)

// SyncSingBoxFW3Include 在 OpenWrt 21 (fw3) 宿主机写入 0600 持久化脚本并注册 firewall.singctl_singbox=include；清空时幂等删除。
func SyncSingBoxFW3Include(ctx context.Context, scriptPath, v4Batch, v6Batch string, runner fwtx.Runner) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if runner == nil {
		runner = fwtx.ExecRunner{}
	}
	target := cmp.Or(strings.TrimSpace(scriptPath), DefaultSingBoxFW3Script)
	uciSec := "firewall." + fw3SingBoxUCISec

	if strings.TrimSpace(v4Batch) == "" {
		_ = os.Remove(target)
		if _, err := runner.RunStdin(ctx, "", "uci", "-q", "get", uciSec); err == nil {
			_, _ = runner.RunStdin(ctx, "", "uci", "delete", uciSec)
			_, _ = runner.RunStdin(ctx, "", "uci", "commit", "firewall")
		}
		return nil
	}

	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, 0700)

	if err := fsx.WriteAtomic0600(target, []byte(buildSingBoxFW3Script(v4Batch, v6Batch))); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}

	_, _ = runner.RunStdin(ctx, "", "uci", "set", uciSec+"=include")
	_, _ = runner.RunStdin(ctx, "", "uci", "set", uciSec+".type=script")
	_, _ = runner.RunStdin(ctx, "", "uci", "set", uciSec+".path="+target)
	_, _ = runner.RunStdin(ctx, "", "uci", "set", uciSec+".reload=1")
	_, _ = runner.RunStdin(ctx, "", "uci", "commit", "firewall")
	return nil
}

func buildSingBoxFW3Script(v4Batch, v6Batch string) string {
	var b strings.Builder
	b.WriteString("# Managed by singctl sing-box dataplane (OpenWrt fw3 include)\n")
	b.WriteString("cat <<'SINGCTL_EOF' | { iptables-restore --noflush -w 2 2>/dev/null || iptables-restore --noflush; }\n")
	b.WriteString(strings.TrimRight(v4Batch, "\n"))
	b.WriteString("\nSINGCTL_EOF\n")
	b.WriteString("iptables -w 2 -t mangle -C PREROUTING -j SING_BOX 2>/dev/null || iptables -w 2 -t mangle -A PREROUTING -j SING_BOX\n")
	b.WriteString("iptables -w 2 -t mangle -C OUTPUT -j SING_BOX_OUTPUT 2>/dev/null || iptables -w 2 -t mangle -A OUTPUT -j SING_BOX_OUTPUT\n")

	if trimmedV6 := strings.TrimSpace(v6Batch); trimmedV6 != "" {
		b.WriteString("\nif command -v ip6tables-restore >/dev/null 2>&1; then\n")
		b.WriteString("  cat <<'SINGCTL_V6_EOF' | { ip6tables-restore --noflush -w 2 2>/dev/null || ip6tables-restore --noflush; }\n")
		b.WriteString(strings.TrimRight(v6Batch, "\n"))
		b.WriteString("\nSINGCTL_V6_EOF\n")
		b.WriteString("  ip6tables -w 2 -t mangle -C PREROUTING -j SING_BOX 2>/dev/null || ip6tables -w 2 -t mangle -A PREROUTING -j SING_BOX\n")
		b.WriteString("  ip6tables -w 2 -t mangle -C OUTPUT -j SING_BOX_OUTPUT 2>/dev/null || ip6tables -w 2 -t mangle -A OUTPUT -j SING_BOX_OUTPUT\n")
		b.WriteString("fi\n")
	}
	return b.String()
}

func isOpenWrtHost() bool {
	for _, p := range []string{"/etc/openwrt_release", "/etc/openwrt_version"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
