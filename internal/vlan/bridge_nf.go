// 文件职责：在启用 DSA bridge vlan_filtering 时维护同 VLAN 二层 br-lan->br-lan 防火墙直通及 fw4/fw3 重启持久化，避免 kmod-br-netfilter 误杀局域网同段二层互通。
package vlan

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"singctl/internal/common/fsx"
)

const (
	// DefaultFW3BridgeL2Script 为 OpenWrt 21 fw3 同 VLAN br-lan 二层放行持久化脚本默认路径。
	DefaultFW3BridgeL2Script = "/etc/singctl/vlan-br-l2.fw3.sh"
	fw4BridgeL2RelPath       = "chain-pre/forward/singctl-vlan-br-l2.nft"
	fw3BridgeL2UCISec        = "singctl_vlan_br_l2"
	bridgeL2Comment          = "singctl-vlan-br-l2"
)

var bridgeL2Mu sync.Mutex

// SyncBridgeVLANL2Forward 在 DSA bridge vlan_filtering 激活时放行同桥二层转发（br-lan -> br-lan）并持久化 fw4/fw3 include；关闭时幂等清理。
func SyncBridgeVLANL2Forward(ctx context.Context, enabled bool, fw4Root, fw3ScriptPath string, run CommandRunner) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if run == nil {
		if runtime.GOOS != "linux" {
			return nil
		}
		run = defaultSideRouteRunner
	}

	root := cmp.Or(strings.TrimSpace(fw4Root), DefaultFW4NftablesDir)
	nftFile := filepath.Join(root, fw4BridgeL2RelPath)
	scriptPath := cmp.Or(strings.TrimSpace(fw3ScriptPath), DefaultFW3BridgeL2Script)

	bridgeL2Mu.Lock()
	defer bridgeL2Mu.Unlock()

	_, nftErr := run(ctx, "nft", "--version")
	hasNFT := nftErr == nil

	if !enabled {
		_ = os.Remove(nftFile)
		if hasNFT {
			if out, err := run(ctx, "nft", "-a", "list", "chain", "inet", "fw4", "forward"); err == nil {
				deleteManagedNFTRulesByComment(ctx, "forward", string(out), bridgeL2Comment, run)
			}
		}
		deleteBridgeL2IPTables(ctx, "iptables", run)
		deleteBridgeL2IPTables(ctx, "ip6tables", run)
		_ = os.Remove(scriptPath)
		uciSec := "firewall." + fw3BridgeL2UCISec
		if _, gErr := run(ctx, "uci", "-q", "get", uciSec); gErr == nil {
			_, _ = run(ctx, "uci", "delete", uciSec)
			_, _ = run(ctx, "uci", "commit", "firewall")
		}
		return nil
	}

	if hasNFT {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			nftDir := filepath.Dir(nftFile)
			if mkErr := os.MkdirAll(nftDir, 0700); mkErr != nil {
				return fmt.Errorf("mkdir %s: %w", nftDir, mkErr)
			}
			_ = os.Chmod(nftDir, 0700)
			body := "# Managed by singctl DSA bridge vlan_filtering intra-VLAN L2 passthrough\n" +
				`iifname "br-lan" oifname "br-lan" accept comment "` + bridgeL2Comment + `"` + "\n"
			if wErr := fsx.WriteAtomic0600(nftFile, []byte(body)); wErr != nil {
				return fmt.Errorf("write %s: %w", nftFile, wErr)
			}
		}
		if out, err := run(ctx, "nft", "-a", "list", "chain", "inet", "fw4", "forward"); err == nil && strings.Contains(string(out), "chain forward") {
			deleteManagedNFTRulesByComment(ctx, "forward", string(out), bridgeL2Comment, run)
			_, _ = run(ctx, "nft", "insert", "rule", "inet", "fw4", "forward",
				"iifname", "br-lan", "oifname", "br-lan", "accept", "comment", bridgeL2Comment)
		}
		return nil
	}

	// OpenWrt 21 fw3 / iptables 路径
	for _, ipt := range []string{"iptables", "ip6tables"} {
		deleteBridgeL2IPTables(ctx, ipt, run)
		if _, err := run(ctx, ipt, "-w", "2", "-S", "FORWARD"); err == nil {
			_, _ = run(ctx, ipt, "-w", "2", "-I", "FORWARD", "1",
				"-i", "br-lan", "-o", "br-lan", "-m", "comment", "--comment", bridgeL2Comment, "-j", "ACCEPT")
		}
	}

	scriptDir := filepath.Dir(scriptPath)
	if err := os.MkdirAll(scriptDir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", scriptDir, err)
	}
	_ = os.Chmod(scriptDir, 0700)
	if err := fsx.WriteAtomic0600(scriptPath, []byte(buildBridgeL2FW3Script())); err != nil {
		return fmt.Errorf("write %s: %w", scriptPath, err)
	}
	uciSec := "firewall." + fw3BridgeL2UCISec
	_, _ = run(ctx, "uci", "set", uciSec+"=include")
	_, _ = run(ctx, "uci", "set", uciSec+".type=script")
	_, _ = run(ctx, "uci", "set", uciSec+".path="+scriptPath)
	_, _ = run(ctx, "uci", "set", uciSec+".reload=1")
	_, _ = run(ctx, "uci", "commit", "firewall")
	return nil
}

func deleteBridgeL2IPTables(ctx context.Context, ipt string, run CommandRunner) {
	out, err := run(ctx, ipt, "-w", "2", "-S", "FORWARD")
	if err != nil {
		return
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "-A FORWARD ") || !strings.Contains(trimmed, bridgeL2Comment) {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(trimmed, "-A FORWARD "))
		if len(fields) == 0 {
			continue
		}
		args := append([]string{"-w", "2", "-D", "FORWARD"}, fields...)
		_, _ = run(ctx, ipt, args...)
	}
}

func buildBridgeL2FW3Script() string {
	var b strings.Builder
	b.WriteString("# Managed by singctl DSA bridge vlan_filtering intra-VLAN L2 passthrough (OpenWrt fw3 include)\n")
	b.WriteString("for ipt in iptables ip6tables; do\n")
	b.WriteString("  command -v \"$ipt\" >/dev/null 2>&1 || continue\n")
	b.WriteString("  \"$ipt\" -w 2 -S FORWARD 2>/dev/null | while IFS= read -r line; do\n")
	b.WriteString("    case \"$line\" in\n")
	b.WriteString("      \"-A FORWARD \"*" + bridgeL2Comment + "*)\n")
	b.WriteString("        spec=\"${line#-A FORWARD }\"\n")
	b.WriteString("        eval \"set -- $spec\"\n")
	b.WriteString("        \"$ipt\" -w 2 -D FORWARD \"$@\" 2>/dev/null || true\n")
	b.WriteString("        ;;\n")
	b.WriteString("    esac\n")
	b.WriteString("  done\n")
	b.WriteString("  \"$ipt\" -w 2 -I FORWARD 1 -i br-lan -o br-lan -m comment --comment " + bridgeL2Comment + " -j ACCEPT 2>/dev/null || true\n")
	b.WriteString("done\n")
	return b.String()
}
