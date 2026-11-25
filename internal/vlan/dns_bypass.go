// 文件职责：负责 VLAN 自定义 DNS 与旁路由托管场景下的 OpenWrt fw3/fw4 53 端口免劫持持久化规则生成及运行时防 dns_redirect 同步。
package vlan

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"singctl/internal/common/fsx"
)

const (
	// DefaultFW3DNSBypassScript 为 OpenWrt 21 firewall3 (iptables) 子网自定义 DNS 免劫持持久化 include 脚本路径。
	DefaultFW3DNSBypassScript = "/etc/singctl/vlan-dns-bypass.fw3.sh"
	// DefaultFW3SideDNSBypassScript 为 OpenWrt 21 firewall3 (iptables) 旁路由托管 53 端口免劫持持久化 include 脚本路径。
	DefaultFW3SideDNSBypassScript = "/etc/singctl/vlan-side-dns.fw3.sh"

	fw3DNSBypassUCISec      = "singctl_vlan_dns"
	fw3SideDNSBypassUCISec  = "singctl_vlan_side_dns"
	fw4DNSBypassRelPath     = "chain-pre/dstnat/singctl-vlan-dns.nft"
	fw4SideDNSBypassRelPath = "chain-pre/dstnat/singctl-side-dns.nft"
	sideRouteDNSComment     = "singctl-side-dns"
)

// SyncFW4DNSBypassInclude 持久化 OpenWrt 24 firewall4 (dstnat chain-pre) 子网自定义 DNS 免劫持规则。
func SyncFW4DNSBypassInclude(fw4Root string, rules []VLANDNSBypassRule) error {
	norm, err := NormalizeDNSBypassRules(rules)
	if err != nil {
		return err
	}
	var body string
	if len(norm) > 0 {
		var b strings.Builder
		b.WriteString("# Managed by singctl VLAN custom DNS hijack bypass\n")
		for _, r := range norm {
			for _, dnsIP := range r.DNSIPs {
				b.WriteString(fmt.Sprintf("ip saddr %s ip daddr %s meta l4proto { tcp, udp } th dport 53 accept comment %q\n", r.CIDR, dnsIP, vlanDNSComment))
			}
		}
		body = b.String()
	}
	return syncFW4DstnatInclude(fw4Root, fw4DNSBypassRelPath, body)
}

// SyncFW3DNSBypassInclude 持久化 OpenWrt 21 firewall3 子网自定义 DNS 免劫持脚本并绑定 firewall include。
func SyncFW3DNSBypassInclude(scriptPath string, rules []VLANDNSBypassRule, run CommandRunner) error {
	norm, err := NormalizeDNSBypassRules(rules)
	if err != nil {
		return err
	}
	natSpecs, mangleSpecs := buildCustomDNSIPTablesSpecs(norm)
	path := cmp.Or(strings.TrimSpace(scriptPath), DefaultFW3DNSBypassScript)
	return syncFW3PREROUTINGInclude(path, fw3DNSBypassUCISec, "# Managed by singctl VLAN custom DNS hijack bypass (OpenWrt fw3 include)", vlanDNSComment, natSpecs, mangleSpecs, run)
}

// ApplyRuntimeDNSBypass 在 Linux 运行时同步 nftables/iptables 子网自定义 DNS PREROUTING/mangle 53 端口免劫持规则。
func ApplyRuntimeDNSBypass(ctx context.Context, rules []VLANDNSBypassRule, run CommandRunner) error {
	norm, err := NormalizeDNSBypassRules(rules)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if run == nil {
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			return nil
		}
		run = defaultSideRouteRunner
	}

	sideRouteRuntimeMu.Lock()
	defer sideRouteRuntimeMu.Unlock()

	applyRuntimeCustomDNSBypassLocked(ctx, norm, run)
	return nil
}

// SyncFW4SideDNSBypassInclude 持久化 OpenWrt 24 firewall4 (dstnat chain-pre) 旁路由宿主与托管子网 53 端口免劫持规则。
func SyncFW4SideDNSBypassInclude(fw4Root, sideRouterIP string, cidrs []string) error {
	sideIP, normCIDRs, err := normalizeSideDNSInputs(sideRouterIP, cidrs)
	if err != nil {
		return err
	}
	var body string
	if sideIP != "" {
		var b strings.Builder
		b.WriteString("# Managed by singctl side-router & delegated VLAN DNS hijack bypass\n")
		b.WriteString(fmt.Sprintf("ip saddr %s meta l4proto { tcp, udp } th dport 53 accept comment %q\n", sideIP, sideRouteDNSComment))
		b.WriteString(fmt.Sprintf("ip daddr %s meta l4proto { tcp, udp } th dport 53 accept comment %q\n", sideIP, sideRouteDNSComment))
		if len(normCIDRs) > 0 {
			b.WriteString(fmt.Sprintf("ip saddr { %s } meta l4proto { tcp, udp } th dport 53 accept comment %q\n", strings.Join(normCIDRs, ", "), sideRouteDNSComment))
		}
		body = b.String()
	}
	return syncFW4DstnatInclude(fw4Root, fw4SideDNSBypassRelPath, body)
}

// SyncFW3SideDNSBypassInclude 持久化 OpenWrt 21 firewall3 旁路由宿主与托管子网 53 端口免劫持脚本并绑定 firewall include。
func SyncFW3SideDNSBypassInclude(scriptPath, sideRouterIP string, cidrs []string, run CommandRunner) error {
	sideIP, normCIDRs, err := normalizeSideDNSInputs(sideRouterIP, cidrs)
	if err != nil {
		return err
	}
	natSpecs, mangleSpecs := buildSideDNSIPTablesSpecs(sideIP, normCIDRs)
	path := cmp.Or(strings.TrimSpace(scriptPath), DefaultFW3SideDNSBypassScript)
	return syncFW3PREROUTINGInclude(path, fw3SideDNSBypassUCISec, "# Managed by singctl side-router & delegated VLAN DNS hijack bypass (OpenWrt fw3 include)", sideRouteDNSComment, natSpecs, mangleSpecs, run)
}

// ApplyRuntimeSideDNSBypass 在 Linux 运行时同步旁路由自身及托管子网 53 端口免劫持规则，防止主路由 DNSMASQ 重定向污染 DNS。
func ApplyRuntimeSideDNSBypass(ctx context.Context, sideRouterIP string, cidrs []string, run CommandRunner) error {
	sideIP, normCIDRs, err := normalizeSideDNSInputs(sideRouterIP, cidrs)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if run == nil {
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			return nil
		}
		run = defaultSideRouteRunner
	}

	sideRouteRuntimeMu.Lock()
	defer sideRouteRuntimeMu.Unlock()

	applyRuntimeSideDNSBypassLocked(ctx, sideIP, normCIDRs, run)
	return nil
}

func normalizeSideDNSInputs(rawSideIP string, rawCIDRs []string) (string, []string, error) {
	sideIP, err := validateSideRouterNextHopIP(rawSideIP)
	if err != nil {
		return "", nil, err
	}
	normCIDRs, err := NormalizeBypassCIDRs(rawCIDRs)
	if err != nil {
		return "", nil, err
	}
	return sideIP, normCIDRs, nil
}

func syncDefaultDNSBypassIncludes(rules []VLANDNSBypassRule, run CommandRunner) {
	_ = SyncFW4DNSBypassInclude(DefaultFW4NftablesDir, rules)
	if st, err := os.Stat(DefaultFW4NftablesDir); err == nil && st.IsDir() {
		return
	}
	if _, fw3Err := os.Stat("/sbin/fw3"); fw3Err == nil {
		_ = SyncFW3DNSBypassInclude(DefaultFW3DNSBypassScript, rules, run)
	}
}

func syncDefaultSideDNSIncludes(sideRouterIP string, cidrs []string, run CommandRunner) {
	_ = SyncFW4SideDNSBypassInclude(DefaultFW4NftablesDir, sideRouterIP, cidrs)
	if st, err := os.Stat(DefaultFW4NftablesDir); err == nil && st.IsDir() {
		return
	}
	if _, fw3Err := os.Stat("/sbin/fw3"); fw3Err == nil {
		_ = SyncFW3SideDNSBypassInclude(DefaultFW3SideDNSBypassScript, sideRouterIP, cidrs, run)
	}
}

func syncFW4DstnatInclude(fw4Root, relPath, body string) error {
	root := cmp.Or(strings.TrimSpace(fw4Root), DefaultFW4NftablesDir)
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return nil
	}
	target := filepath.Join(root, relPath)
	if body == "" {
		_ = os.Remove(target)
		return nil
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, 0700)
	return fsx.WriteAtomic0600(target, []byte(body))
}

func syncFW3PREROUTINGInclude(scriptPath, uciSecName, header, comment string, natSpecs, mangleSpecs [][]string, run CommandRunner) error {
	if run == nil {
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			return nil
		}
		run = defaultSideRouteRunner
	}
	uciSec := "firewall." + uciSecName
	if len(natSpecs) == 0 {
		_ = os.Remove(scriptPath)
		if _, gErr := run(context.Background(), "uci", "-q", "get", uciSec); gErr == nil {
			_, _ = run(context.Background(), "uci", "delete", uciSec)
			_, _ = run(context.Background(), "uci", "commit", "firewall")
		}
		return nil
	}

	dir := filepath.Dir(scriptPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, 0700)

	var b strings.Builder
	b.WriteString(header)
	b.WriteByte('\n')
	writeFW3ChainCleanup(&b, "nat", "PREROUTING", comment)
	for _, spec := range natSpecs {
		b.WriteString("iptables -w 2 -t nat -I PREROUTING 1 ")
		b.WriteString(strings.Join(spec, " "))
		b.WriteByte('\n')
	}
	if len(mangleSpecs) > 0 {
		b.WriteString("if iptables -w 2 -t mangle -L SING_BOX -n >/dev/null 2>&1; then\n")
		writeFW3ChainCleanup(&b, "mangle", "SING_BOX", comment)
		for _, spec := range mangleSpecs {
			b.WriteString("  iptables -w 2 -t mangle -I SING_BOX 1 ")
			b.WriteString(strings.Join(spec, " "))
			b.WriteByte('\n')
		}
		b.WriteString("fi\n")
	}

	if err := fsx.WriteAtomic0600(scriptPath, []byte(b.String())); err != nil {
		return err
	}
	_, _ = run(context.Background(), "uci", "set", uciSec+"=include")
	_, _ = run(context.Background(), "uci", "set", uciSec+".type=script")
	_, _ = run(context.Background(), "uci", "set", uciSec+".path="+scriptPath)
	_, _ = run(context.Background(), "uci", "set", uciSec+".reload=1")
	_, _ = run(context.Background(), "uci", "commit", "firewall")
	return nil
}

func writeFW3ChainCleanup(b *strings.Builder, table, chain, comment string) {
	b.WriteString(fmt.Sprintf("iptables -w 2 -t %s -S %s 2>/dev/null | while IFS= read -r line; do\n", table, chain))
	b.WriteString("  case \"$line\" in\n")
	b.WriteString(fmt.Sprintf("    \"-A %s \"*%s*)\n", chain, comment))
	b.WriteString(fmt.Sprintf("      spec=\"${line#-A %s }\"\n", chain))
	b.WriteString("      eval \"set -- $spec\"\n")
	b.WriteString(fmt.Sprintf("      iptables -w 2 -t %s -D %s \"$@\" 2>/dev/null || true\n", table, chain))
	b.WriteString("      ;;\n")
	b.WriteString("  esac\n")
	b.WriteString("done\n")
}

func buildCustomDNSIPTablesSpecs(rules []VLANDNSBypassRule) (natSpecs, mangleSpecs [][]string) {
	for _, r := range rules {
		for _, dnsIP := range r.DNSIPs {
			for _, proto := range []string{"tcp", "udp"} {
				natSpecs = append(natSpecs, []string{"-s", r.CIDR, "-d", dnsIP, "-p", proto, "--dport", "53", "-m", "comment", "--comment", vlanDNSComment, "-j", "ACCEPT"})
				mangleSpecs = append(mangleSpecs, []string{"-s", r.CIDR, "-d", dnsIP, "-p", proto, "--dport", "53", "-m", "comment", "--comment", vlanDNSComment, "-j", "RETURN"})
			}
		}
	}
	return natSpecs, mangleSpecs
}

func buildSideDNSIPTablesSpecs(sideIP string, cidrs []string) (natSpecs, mangleSpecs [][]string) {
	if sideIP == "" {
		return nil, nil
	}
	appendMatch := func(flag, addr string) {
		for _, proto := range []string{"tcp", "udp"} {
			natSpecs = append(natSpecs, []string{flag, addr, "-p", proto, "--dport", "53", "-m", "comment", "--comment", sideRouteDNSComment, "-j", "ACCEPT"})
			mangleSpecs = append(mangleSpecs, []string{flag, addr, "-p", proto, "--dport", "53", "-m", "comment", "--comment", sideRouteDNSComment, "-j", "RETURN"})
		}
	}
	appendMatch("-s", sideIP+"/32")
	appendMatch("-d", sideIP+"/32")
	for _, cidr := range cidrs {
		appendMatch("-s", cidr)
	}
	return natSpecs, mangleSpecs
}

func applyRuntimeCustomDNSBypassLocked(ctx context.Context, rules []VLANDNSBypassRule, run CommandRunner) {
	var nftMatches [][]string
	for _, r := range rules {
		for _, dnsIP := range r.DNSIPs {
			nftMatches = append(nftMatches, []string{"ip", "saddr", r.CIDR, "ip", "daddr", dnsIP})
		}
	}
	natSpecs, mangleSpecs := buildCustomDNSIPTablesSpecs(rules)
	applyRuntimeDNSChainRules(ctx, vlanDNSComment, nftMatches, natSpecs, mangleSpecs, run)
}

func applyRuntimeSideDNSBypassLocked(ctx context.Context, sideIP string, cidrs []string, run CommandRunner) {
	var nftMatches [][]string
	if sideIP != "" {
		nftMatches = append(nftMatches,
			[]string{"ip", "saddr", sideIP},
			[]string{"ip", "daddr", sideIP},
		)
		for _, cidr := range cidrs {
			nftMatches = append(nftMatches, []string{"ip", "saddr", cidr})
		}
	}
	natSpecs, mangleSpecs := buildSideDNSIPTablesSpecs(sideIP, cidrs)
	applyRuntimeDNSChainRules(ctx, sideRouteDNSComment, nftMatches, natSpecs, mangleSpecs, run)
}

func applyRuntimeDNSChainRules(ctx context.Context, comment string, nftMatches, iptNatSpecs, iptMangleSpecs [][]string, run CommandRunner) {
	nftTargets := [][3]string{
		{"inet", "dnsmasq", "prerouting"},
		{"inet", "fw4", "dstnat"},
		{"inet", "sing-box", "prerouting"},
	}
	for _, target := range nftTargets {
		out, err := run(ctx, "nft", "-a", "list", "chain", target[0], target[1], target[2])
		if err != nil || !strings.Contains(string(out), "chain "+target[2]) {
			continue
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			if !strings.Contains(line, comment) {
				continue
			}
			_, after, ok := strings.Cut(line, "# handle ")
			if !ok {
				continue
			}
			if h := strings.Fields(after); len(h) > 0 {
				_, _ = run(ctx, "nft", "delete", "rule", target[0], target[1], target[2], "handle", h[0])
			}
		}
		for _, match := range nftMatches {
			args := append([]string{"insert", "rule", target[0], target[1], target[2]}, match...)
			args = append(args, "meta", "l4proto", "{", "tcp,", "udp", "}", "th", "dport", "53", "accept", "comment", comment)
			_, _ = run(ctx, "nft", args...)
		}
	}

	if out, err := run(ctx, "iptables", "-t", "nat", "-S", "PREROUTING"); err == nil && strings.Contains(string(out), "PREROUTING") {
		deleteCommentedIPTablesRules(ctx, "nat", "PREROUTING", comment, string(out), run)
		for _, spec := range iptNatSpecs {
			args := append([]string{"-t", "nat", "-I", "PREROUTING", "1"}, spec...)
			_, _ = run(ctx, "iptables", args...)
		}
	}

	if out, err := run(ctx, "iptables", "-t", "mangle", "-S", "SING_BOX"); err == nil && strings.Contains(string(out), "SING_BOX") {
		deleteCommentedIPTablesRules(ctx, "mangle", "SING_BOX", comment, string(out), run)
		for _, spec := range iptMangleSpecs {
			args := append([]string{"-t", "mangle", "-I", "SING_BOX", "1"}, spec...)
			_, _ = run(ctx, "iptables", args...)
		}
	}
}

func deleteCommentedIPTablesRules(ctx context.Context, table, chain, comment, dump string, run CommandRunner) {
	prefix := "-A " + chain + " "
	for line := range strings.SplitSeq(dump, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, prefix) || !strings.Contains(trimmed, comment) {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(trimmed, prefix))
		for i := range fields {
			fields[i] = strings.Trim(fields[i], `"`)
		}
		delArgs := append([]string{"-t", table, "-D", chain}, fields...)
		_, _ = run(ctx, "iptables", delArgs...)
	}
}
