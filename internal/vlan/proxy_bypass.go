// 文件职责：负责 VLAN 透明代理纯直连绕行 CIDR 清单的 0600 原子持久化与 nftables/iptables 运行时动态同步。
package vlan

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"singctl/internal/common/fsx"
)

const vlanBypassComment = "singctl-vlan-bypass"

// NormalizeBypassCIDRs 严格校验、归一化并去重排序待绕过透明代理的私网 IPv4 CIDR 列表。
func NormalizeBypassCIDRs(raw []string) ([]string, error) {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s := strings.TrimSpace(item)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		pfx, err := netip.ParsePrefix(s)
		if err != nil || !pfx.Addr().Is4() || pfx.Bits() < 8 || pfx.Bits() > 32 {
			return nil, fmt.Errorf("无效的 IPv4 CIDR 绕行网段: %q", s)
		}
		if pfx.Addr().IsLoopback() || pfx.Addr().IsUnspecified() || pfx.Addr().IsMulticast() {
			return nil, fmt.Errorf("不允许将回环或保留网段 (%s) 加入代理绕行列表", pfx.Masked().String())
		}
		norm := pfx.Masked().String()
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	slices.Sort(out)
	return out, nil
}

// WriteProxyBypassList 将需绕过透明代理的 VLAN IPv4 CIDR 清单以 0600 权限原子落盘。
func WriteProxyBypassList(path string, cidrs []string) error {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return fmt.Errorf("proxy bypass file path must not be empty")
	}
	norm, err := NormalizeBypassCIDRs(cidrs)
	if err != nil {
		return err
	}
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, 0700)

	var b strings.Builder
	b.WriteString("# Managed by singctl VLAN manager: IPv4 CIDRs bypassing sing-box TProxy\n")
	for _, c := range norm {
		b.WriteString(c)
		b.WriteByte('\n')
	}
	return fsx.WriteAtomic0600(cleanPath, []byte(b.String()))
}

// ReadProxyBypassList 读取已持久化的 VLAN 透明代理绕行 CIDR 清单（缺失时返回空切片）。
func ReadProxyBypassList(path string) []string {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil
	}
	var lines []string
	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	norm, err := NormalizeBypassCIDRs(lines)
	if err != nil {
		return nil
	}
	return norm
}

// SyncRuntimeProxyBypass 持久化绕行清单，并在 Linux 透明代理运行中实时同步 nftables/iptables 源子网放行规则。
func SyncRuntimeProxyBypass(ctx context.Context, bypassFile string, cidrs []string) error {
	norm, err := NormalizeBypassCIDRs(cidrs)
	if err != nil {
		return err
	}
	if err := WriteProxyBypassList(bypassFile, norm); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if nftPath, err := exec.LookPath("nft"); err == nil {
		if out, listErr := exec.CommandContext(cctx, nftPath, "-a", "list", "chain", "inet", "sing-box", "prerouting").Output(); listErr == nil {
			syncNFTVlanBypass(cctx, nftPath, string(out), norm)
			return nil
		}
	}
	if iptPath, err := exec.LookPath("iptables"); err == nil {
		if exec.CommandContext(cctx, iptPath, "-t", "mangle", "-L", "SING_BOX", "-n").Run() == nil {
			syncIPTablesVlanBypass(cctx, iptPath, norm)
		}
	}
	return nil
}

func syncNFTVlanBypass(ctx context.Context, nftPath, chainDump string, cidrs []string) {
	// 1. Delete stale singctl-vlan-bypass rules by handle.
	for line := range strings.SplitSeq(chainDump, "\n") {
		if !strings.Contains(line, vlanBypassComment) {
			continue
		}
		_, after, ok := strings.Cut(line, "# handle ")
		if !ok {
			continue
		}
		handle := strings.Fields(after)
		if len(handle) > 0 {
			_ = exec.CommandContext(ctx, nftPath, "delete", "rule", "inet", "sing-box", "prerouting", "handle", handle[0]).Run()
		}
	}
	// 2. Insert fresh source-CIDR bypass rules right after fib daddr local / DNS rules or at top (non-local destination only).
	for _, cidr := range cidrs {
		_ = exec.CommandContext(ctx, nftPath, "insert", "rule", "inet", "sing-box", "prerouting",
			"ip", "saddr", cidr, "fib", "daddr", "type", "!=", "local", "accept", "comment", vlanBypassComment).Run()
	}
}

func syncIPTablesVlanBypass(ctx context.Context, iptPath string, cidrs []string) {
	out, err := exec.CommandContext(ctx, iptPath, "-t", "mangle", "-S", "SING_BOX").Output()
	if err == nil {
		for line := range strings.SplitSeq(string(out), "\n") {
			if !strings.Contains(line, vlanBypassComment) || !strings.HasPrefix(line, "-A SING_BOX ") {
				continue
			}
			delArgs := append([]string{"-t", "mangle", "-D", "SING_BOX"}, strings.Fields(strings.TrimPrefix(line, "-A SING_BOX "))...)
			_ = exec.CommandContext(ctx, iptPath, delArgs...).Run()
		}
	}
	for _, cidr := range cidrs {
		_ = exec.CommandContext(ctx, iptPath, "-t", "mangle", "-I", "SING_BOX", "1",
			"-s", cidr, "-m", "addrtype", "!", "--dst-type", "LOCAL",
			"-m", "comment", "--comment", vlanBypassComment, "-j", "RETURN").Run()
	}
}
