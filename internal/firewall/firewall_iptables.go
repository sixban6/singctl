// 文件职责：实现主机安全防火墙加固的 iptables + ip6tables + ipset 后端探测、规则脚本渲染、启停与 OpenWrt fw3/systemd 持久化。
package firewall

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"singctl/internal/common/execx"
	"singctl/internal/common/fsx"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
)

const (
	// BackendNFTables 表示使用 Linux nftables 后端。
	BackendNFTables = "nftables"
	// BackendIPTables 表示使用 Linux iptables + ip6tables + ipset 后端。
	BackendIPTables = "iptables"
	// BackendNone 表示当前宿主机无可用内核防火墙后端。
	BackendNone = "none"

	// IPTablesSecurityChain 是主机安全防火墙加固专用的独立隔离链名（挂载于 INPUT 顶部）。
	IPTablesSecurityChain = "SINGCTL_SECURITY"

	// DefaultIPTablesScriptPath 是 iptables+ipset 后端持久化自启脚本的默认路径（0700）。
	DefaultIPTablesScriptPath = "/etc/sing-box/security-iptables.sh"
	// DefaultFirewallUserPath 是 OpenWrt fw3 自定义恢复脚本挂载文件。
	DefaultFirewallUserPath = "/etc/firewall.user"

	// SecurityFirewallUserBegin 与 SecurityFirewallUserEnd 界定 `/etc/firewall.user` 中受 SingCtl 托管的持久化块。
	SecurityFirewallUserBegin = "# BEGIN SINGCTL_SECURITY_FW"
	SecurityFirewallUserEnd   = "# END SINGCTL_SECURITY_FW"

	iptablesMaxMultiportEntries = 15
	iptablesCmdTimeout          = 5 * time.Second

	// Linux xt_LOG --log-prefix 硬上限为 29 字节，下列前缀严格控制在 24~29 字节且与 ParseNFTLogLines 100% 兼容。
	logPrefixForeverV4     = "[NFT] Ban Forever IPv4: "
	logPrefixBlockedV4List = "[NFT] Blocked IPv4 (listed): "
	logPrefixBlockedV6List = "[NFT] Blocked IPv6 (listed): "
	logPrefixHoneypotTCPV4 = "[NFT] Blocked IPv4 TCP: "
	logPrefixHoneypotUDPv4 = "[NFT] Blocked IPv4 UDP: "
	logPrefixHoneypotTCPV6 = "[NFT] Blocked IPv6 TCP: "
	logPrefixHoneypotUDPv6 = "[NFT] Blocked IPv6 UDP: "

	commentForeverV4     = "singctl-fw:forever_v4"
	commentDynamicV4     = "singctl-fw:dynamic_v4"
	commentDynamicV6     = "singctl-fw:dynamic_v6"
	commentHoneypotTCPV4 = "singctl-fw:honeypot_tcp_v4"
	commentHoneypotUDPv4 = "singctl-fw:honeypot_udp_v4"
	commentHoneypotTCPV6 = "singctl-fw:honeypot_tcp_v6"
	commentHoneypotUDPv6 = "singctl-fw:honeypot_udp_v6"
)

// CmdRunner 允许为防火墙后端注入可控的外部命令执行器，确保单元测试零宿主机污染。
type CmdRunner func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error)

func defaultFirewallCmdRunner(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, execx.WithXtablesWait(name, args)...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// DetectBackend 探测当前宿主机可用的内核防火墙后端：优先 nftables，缺失 nft 且存在 iptables+ipset 时返回 iptables。
func DetectBackend() string {
	return DetectBackendWith(runtime.GOOS, exec.LookPath)
}

// DetectBackendWith 使用可注入的操作系统与 LookPath 探测器判断防火墙后端类型。
func DetectBackendWith(goos string, lookPath func(string) (string, error)) string {
	if goos != "linux" {
		return BackendNone
	}
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	if _, err := lookPath("nft"); err == nil {
		return BackendNFTables
	}
	if _, err := lookPath("iptables"); err == nil {
		if _, setErr := lookPath("ipset"); setErr == nil {
			return BackendIPTables
		}
	}
	return BackendNone
}

// IPTablesBackend 封装主机安全防火墙加固的 iptables + ip6tables + ipset 完整实现。
type IPTablesBackend struct {
	Runner           CmdRunner
	LookPath         func(file string) (string, error)
	ScriptPath       string
	FirewallUserPath string
	IsOpenWrt        func() bool
	SetupSystemd     func(ctx context.Context, scriptPath string) error
	TeardownSystemd  func(ctx context.Context) error
}

func defaultIPTablesBackend() *IPTablesBackend {
	return &IPTablesBackend{}
}

func (b *IPTablesBackend) run(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	if b != nil && b.Runner != nil {
		return b.Runner(ctx, stdin, name, args...)
	}
	return defaultFirewallCmdRunner(ctx, stdin, name, args...)
}

func (b *IPTablesBackend) hasBinary(name string) bool {
	if b != nil && b.LookPath != nil {
		_, err := b.LookPath(name)
		return err == nil
	}
	_, err := exec.LookPath(name)
	return err == nil
}

func (b *IPTablesBackend) scriptPath() string {
	if b != nil && strings.TrimSpace(b.ScriptPath) != "" {
		return strings.TrimSpace(b.ScriptPath)
	}
	return DefaultIPTablesScriptPath
}

func (b *IPTablesBackend) firewallUserPath() string {
	if b != nil && strings.TrimSpace(b.FirewallUserPath) != "" {
		return strings.TrimSpace(b.FirewallUserPath)
	}
	return DefaultFirewallUserPath
}

func (b *IPTablesBackend) isOpenWrt() bool {
	if b != nil && b.IsOpenWrt != nil {
		return b.IsOpenWrt()
	}
	return servicemgr.IsOpenWrt()
}

func prepareSecurityTemplateData(opts BuildOptions) nftSecurityTemplateData {
	isMinimal := strings.EqualFold(strings.TrimSpace(opts.Mode), "minimal")
	timeoutDays := clampDefaultInt(opts.BanTimeoutDays, 7, 1, 30)
	pingLimit := clampDefaultInt(opts.PingLimitPerSec, 10, 1, 100)

	whitelistV4, whitelistV6 := collectNormalizedWhitelists(opts)
	foreverV4 := collectForeverBlocklistV4(opts.ExtraForeverBan)
	protectedPorts := collectProtectedPorts(opts)

	return nftSecurityTemplateData{
		ForeverV4:       foreverV4,
		BanTimeoutDays:  timeoutDays,
		WhitelistV4:     whitelistV4,
		WhitelistV6:     whitelistV6,
		ProtectedPorts:  protectedPorts,
		PingLimitPerSec: pingLimit,
		EnableHoneypot:  !isMinimal && len(protectedPorts) > 0,
	}
}

func chunkProtectedPorts(ports []int, chunkSize int) []string {
	if chunkSize <= 0 {
		chunkSize = iptablesMaxMultiportEntries
	}
	var out []string
	for i := 0; i < len(ports); i += chunkSize {
		end := min(len(ports), i+chunkSize)
		parts := make([]string, 0, end-i)
		for _, p := range ports[i:end] {
			parts = append(parts, strconv.Itoa(p))
		}
		out = append(out, strings.Join(parts, ","))
	}
	return out
}

// RenderScript 生成 POSIX 兼容、可在 OpenWrt fw3 / systemd 重启后完整恢复 5 大 ipset 与 SINGCTL_SECURITY 链的 shell 脚本。
func (b *IPTablesBackend) RenderScript(opts BuildOptions) string {
	data := prepareSecurityTemplateData(opts)
	timeoutSec := data.BanTimeoutDays * 86400
	pingBurst := min(200, max(5, data.PingLimitPerSec*2))
	portChunks := chunkProtectedPorts(data.ProtectedPorts, iptablesMaxMultiportEntries)

	var sb strings.Builder
	sb.WriteString("#!/bin/sh\n")
	sb.WriteString("# Managed by SingCtl Host Security Firewall (iptables+ipset) — DO NOT EDIT MANUALLY\n")
	sb.WriteString("set -e\n\n")
	sb.WriteString("command -v ipset >/dev/null 2>&1 || exit 0\n")
	sb.WriteString("command -v iptables >/dev/null 2>&1 || exit 0\n\n")

	// 5 大 ipset 集合（与 nftables 集合严格同名）
	sb.WriteString("ipset create blocklist_ip4_forever hash:net family inet maxelem 65535 -exist\n")
	fmt.Fprintf(&sb, "ipset create blocklist_ip4 hash:ip family inet timeout %d -exist\n", timeoutSec)
	fmt.Fprintf(&sb, "ipset create blocklist_ip6 hash:ip family inet6 timeout %d -exist 2>/dev/null || true\n", timeoutSec)
	sb.WriteString("ipset create whitelist_ip hash:net family inet -exist\n")
	sb.WriteString("ipset create whitelist_ip6 hash:net family inet6 -exist 2>/dev/null || true\n\n")

	sb.WriteString("ipset flush blocklist_ip4_forever\n")
	for _, entry := range data.ForeverV4 {
		fmt.Fprintf(&sb, "ipset add blocklist_ip4_forever %s -exist\n", entry)
	}
	sb.WriteString("ipset flush whitelist_ip\n")
	for _, entry := range data.WhitelistV4 {
		fmt.Fprintf(&sb, "ipset add whitelist_ip %s -exist\n", entry)
	}
	sb.WriteString("ipset flush whitelist_ip6 2>/dev/null || true\n")
	for _, entry := range data.WhitelistV6 {
		fmt.Fprintf(&sb, "ipset add whitelist_ip6 %s -exist 2>/dev/null || true\n", entry)
	}
	sb.WriteByte('\n')

	writeSecurityChainScript(&sb, "iptables -w 5", false, data, pingBurst, portChunks)
	sb.WriteString("\nif command -v ip6tables >/dev/null 2>&1; then\n")
	writeSecurityChainScript(&sb, "ip6tables -w 5", true, data, pingBurst, portChunks)
	sb.WriteString("fi\n")
	return sb.String()
}

func writeSecurityChainScript(sb *strings.Builder, bin string, isV6 bool, data nftSecurityTemplateData, pingBurst int, portChunks []string) {
	indent := ""
	if isV6 {
		indent = "    "
	}
	fmt.Fprintf(sb, "%s%s -N %s 2>/dev/null || true\n", indent, bin, IPTablesSecurityChain)
	fmt.Fprintf(sb, "%s%s -F %s\n", indent, bin, IPTablesSecurityChain)
	fmt.Fprintf(sb, "%s%s -A %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", indent, bin, IPTablesSecurityChain)
	for _, iface := range []string{"lo", "tailscale0", "wg+", "tun+", "docker0"} {
		fmt.Fprintf(sb, "%s%s -A %s -i %s -j ACCEPT\n", indent, bin, IPTablesSecurityChain, iface)
	}
	if isV6 {
		fmt.Fprintf(sb, "%s%s -A %s -p ipv6-icmp --icmpv6-type echo-request -m limit --limit %d/sec --limit-burst %d -j ACCEPT\n",
			indent, bin, IPTablesSecurityChain, data.PingLimitPerSec, pingBurst)
		fmt.Fprintf(sb, "%s%s -A %s -m set --match-set whitelist_ip6 src -j ACCEPT\n", indent, bin, IPTablesSecurityChain)
		fmt.Fprintf(sb, "%s%s -A %s -m set --match-set blocklist_ip6 src -m limit --limit 10/min -j LOG --log-prefix %q\n",
			indent, bin, IPTablesSecurityChain, logPrefixBlockedV6List)
		fmt.Fprintf(sb, "%s%s -A %s -m set --match-set blocklist_ip6 src -m comment --comment %q -j DROP\n",
			indent, bin, IPTablesSecurityChain, commentDynamicV6)
	} else {
		fmt.Fprintf(sb, "%s%s -A %s -p icmp --icmp-type echo-request -m limit --limit %d/sec --limit-burst %d -j ACCEPT\n",
			indent, bin, IPTablesSecurityChain, data.PingLimitPerSec, pingBurst)
		fmt.Fprintf(sb, "%s%s -A %s -m set --match-set whitelist_ip src -j ACCEPT\n", indent, bin, IPTablesSecurityChain)
		fmt.Fprintf(sb, "%s%s -A %s -m set --match-set blocklist_ip4_forever src -m limit --limit 10/min -j LOG --log-prefix %q\n",
			indent, bin, IPTablesSecurityChain, logPrefixForeverV4)
		fmt.Fprintf(sb, "%s%s -A %s -m set --match-set blocklist_ip4_forever src -m comment --comment %q -j DROP\n",
			indent, bin, IPTablesSecurityChain, commentForeverV4)
		fmt.Fprintf(sb, "%s%s -A %s -m set --match-set blocklist_ip4 src -m limit --limit 10/min -j LOG --log-prefix %q\n",
			indent, bin, IPTablesSecurityChain, logPrefixBlockedV4List)
		fmt.Fprintf(sb, "%s%s -A %s -m set --match-set blocklist_ip4 src -m comment --comment %q -j DROP\n",
			indent, bin, IPTablesSecurityChain, commentDynamicV4)
	}

	if data.EnableHoneypot {
		setName := "blocklist_ip4"
		tcpPrefix, udpPrefix := logPrefixHoneypotTCPV4, logPrefixHoneypotUDPv4
		tcpComment, udpComment := commentHoneypotTCPV4, commentHoneypotUDPv4
		if isV6 {
			setName = "blocklist_ip6"
			tcpPrefix, udpPrefix = logPrefixHoneypotTCPV6, logPrefixHoneypotUDPv6
			tcpComment, udpComment = commentHoneypotTCPV6, commentHoneypotUDPv6
		}
		for _, chunk := range portChunks {
			for _, spec := range []struct {
				proto, prefix, comment string
			}{
				{"tcp", tcpPrefix, tcpComment},
				{"udp", udpPrefix, udpComment},
			} {
				fmt.Fprintf(sb, "%s%s -A %s -p %s -m multiport --dports %s -m limit --limit 5/min -j LOG --log-prefix %q\n",
					indent, bin, IPTablesSecurityChain, spec.proto, chunk, spec.prefix)
				fmt.Fprintf(sb, "%s%s -A %s -p %s -m multiport --dports %s -m limit --limit 5/min -j SET --add-set %s src --exist 2>/dev/null || true\n",
					indent, bin, IPTablesSecurityChain, spec.proto, chunk, setName)
				fmt.Fprintf(sb, "%s%s -A %s -p %s -m multiport --dports %s -m comment --comment %q -j DROP\n",
					indent, bin, IPTablesSecurityChain, spec.proto, chunk, spec.comment)
			}
		}
	}

	fmt.Fprintf(sb, "%s%s -C INPUT -j %s 2>/dev/null || %s -I INPUT 1 -j %s\n",
		indent, bin, IPTablesSecurityChain, bin, IPTablesSecurityChain)
}

// EnableWithOptions 使用 iptables + ip6tables + ipset 下发主机安全加固规则并持久化。
func (b *IPTablesBackend) EnableWithOptions(opts BuildOptions, preserveDynamic bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if len(opts.ActiveSSHPorts) == 0 {
		opts.ActiveSSHPorts = DetectSSHPorts()
	}
	if opts.SSHConnection == "" {
		opts.SSHConnection = os.Getenv("SSH_CONNECTION")
	}

	var dynamicV4, dynamicV6 []BanItem
	if preserveDynamic {
		if snap, err := b.InspectSnapshot(); err == nil && snap != nil && snap.Active {
			dynamicV4 = slices.Clone(snap.DynamicV4)
			dynamicV6 = slices.Clone(snap.DynamicV6)
		}
	}

	script := b.RenderScript(opts)
	scriptPath := b.scriptPath()
	if err := fsx.WriteAtomic(scriptPath, []byte(script), 0700); err != nil {
		return fmt.Errorf("failed to write %s: %w", scriptPath, err)
	}

	data := prepareSecurityTemplateData(opts)
	timeoutStr := strconv.Itoa(data.BanTimeoutDays * 86400)
	if out, err := b.run(ctx, "", "ipset", "create", "blocklist_ip4_forever", "hash:net", "family", "inet", "maxelem", "65535", "-exist"); err != nil {
		return fmt.Errorf("ipset create blocklist_ip4_forever failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := b.run(ctx, "", "ipset", "create", "blocklist_ip4", "hash:ip", "family", "inet", "timeout", timeoutStr, "-exist"); err != nil {
		return fmt.Errorf("ipset create blocklist_ip4 failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	_, _ = b.run(ctx, "", "ipset", "create", "blocklist_ip6", "hash:ip", "family", "inet6", "timeout", timeoutStr, "-exist")
	if out, err := b.run(ctx, "", "ipset", "create", "whitelist_ip", "hash:net", "family", "inet", "-exist"); err != nil {
		return fmt.Errorf("ipset create whitelist_ip failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	_, _ = b.run(ctx, "", "ipset", "create", "whitelist_ip6", "hash:net", "family", "inet6", "-exist")

	if err := b.repopulateStaticSet(ctx, "blocklist_ip4_forever", data.ForeverV4); err != nil {
		return err
	}
	if err := b.repopulateStaticSet(ctx, "whitelist_ip", data.WhitelistV4); err != nil {
		return err
	}
	_ = b.repopulateStaticSet(ctx, "whitelist_ip6", data.WhitelistV6)

	if err := b.applyChainLive(ctx, "iptables", false, data); err != nil {
		return err
	}
	if b.hasBinary("ip6tables") {
		_ = b.applyChainLive(ctx, "ip6tables", true, data)
	}

	if preserveDynamic {
		for _, it := range dynamicV4 {
			if net.ParseIP(it.Target) == nil {
				continue
			}
			_, _ = b.run(ctx, "", "ipset", "add", "blocklist_ip4", it.Target, "timeout", strconv.FormatInt(max(int64(60), it.ExpiresSec), 10), "-exist")
		}
		for _, it := range dynamicV6 {
			if net.ParseIP(it.Target) == nil {
				continue
			}
			_, _ = b.run(ctx, "", "ipset", "add", "blocklist_ip6", it.Target, "timeout", strconv.FormatInt(max(int64(60), it.ExpiresSec), 10), "-exist")
		}
	}

	b.persistAutostart(ctx, scriptPath)
	return nil
}

func (b *IPTablesBackend) repopulateStaticSet(ctx context.Context, setName string, entries []string) error {
	if out, err := b.run(ctx, "", "ipset", "flush", setName); err != nil {
		return fmt.Errorf("ipset flush %s failed: %w (%s)", setName, err, strings.TrimSpace(string(out)))
	}
	for _, entry := range entries {
		if out, err := b.run(ctx, "", "ipset", "add", setName, entry, "-exist"); err != nil {
			return fmt.Errorf("ipset add %s %s failed: %w (%s)", setName, entry, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (b *IPTablesBackend) applyChainLive(ctx context.Context, bin string, isV6 bool, data nftSecurityTemplateData) error {
	if out, err := b.run(ctx, "", bin, "-N", IPTablesSecurityChain); err != nil {
		if !strings.Contains(strings.ToLower(string(out)), "already exists") {
			if _, fErr := b.run(ctx, "", bin, "-F", IPTablesSecurityChain); fErr != nil {
				return fmt.Errorf("%s -N %s failed: %w (%s)", bin, IPTablesSecurityChain, err, strings.TrimSpace(string(out)))
			}
		}
	}
	if out, err := b.run(ctx, "", bin, "-F", IPTablesSecurityChain); err != nil {
		return fmt.Errorf("%s -F %s failed: %w (%s)", bin, IPTablesSecurityChain, err, strings.TrimSpace(string(out)))
	}

	mustAdd := func(args ...string) error {
		full := append([]string{"-A", IPTablesSecurityChain}, args...)
		if out, err := b.run(ctx, "", bin, full...); err != nil {
			return fmt.Errorf("%s %s failed: %w (%s)", bin, strings.Join(full, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	if err := mustAdd("-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	for _, iface := range []string{"lo", "tailscale0", "wg+", "tun+", "docker0"} {
		if err := mustAdd("-i", iface, "-j", "ACCEPT"); err != nil {
			return err
		}
	}

	pingLimitExpr := fmt.Sprintf("%d/sec", data.PingLimitPerSec)
	pingBurstExpr := strconv.Itoa(min(200, max(5, data.PingLimitPerSec*2)))
	if isV6 {
		if err := mustAdd("-p", "ipv6-icmp", "--icmpv6-type", "echo-request", "-m", "limit", "--limit", pingLimitExpr, "--limit-burst", pingBurstExpr, "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := mustAdd("-m", "set", "--match-set", "whitelist_ip6", "src", "-j", "ACCEPT"); err != nil {
			return err
		}
		_, _ = b.run(ctx, "", bin, "-A", IPTablesSecurityChain, "-m", "set", "--match-set", "blocklist_ip6", "src", "-m", "limit", "--limit", "10/min", "-j", "LOG", "--log-prefix", logPrefixBlockedV6List)
		if err := mustAdd("-m", "set", "--match-set", "blocklist_ip6", "src", "-m", "comment", "--comment", commentDynamicV6, "-j", "DROP"); err != nil {
			return err
		}
	} else {
		if err := mustAdd("-p", "icmp", "--icmp-type", "echo-request", "-m", "limit", "--limit", pingLimitExpr, "--limit-burst", pingBurstExpr, "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := mustAdd("-m", "set", "--match-set", "whitelist_ip", "src", "-j", "ACCEPT"); err != nil {
			return err
		}
		_, _ = b.run(ctx, "", bin, "-A", IPTablesSecurityChain, "-m", "set", "--match-set", "blocklist_ip4_forever", "src", "-m", "limit", "--limit", "10/min", "-j", "LOG", "--log-prefix", logPrefixForeverV4)
		if err := mustAdd("-m", "set", "--match-set", "blocklist_ip4_forever", "src", "-m", "comment", "--comment", commentForeverV4, "-j", "DROP"); err != nil {
			return err
		}
		_, _ = b.run(ctx, "", bin, "-A", IPTablesSecurityChain, "-m", "set", "--match-set", "blocklist_ip4", "src", "-m", "limit", "--limit", "10/min", "-j", "LOG", "--log-prefix", logPrefixBlockedV4List)
		if err := mustAdd("-m", "set", "--match-set", "blocklist_ip4", "src", "-m", "comment", "--comment", commentDynamicV4, "-j", "DROP"); err != nil {
			return err
		}
	}

	if data.EnableHoneypot {
		setName := "blocklist_ip4"
		tcpPrefix, udpPrefix := logPrefixHoneypotTCPV4, logPrefixHoneypotUDPv4
		tcpComment, udpComment := commentHoneypotTCPV4, commentHoneypotUDPv4
		if isV6 {
			setName = "blocklist_ip6"
			tcpPrefix, udpPrefix = logPrefixHoneypotTCPV6, logPrefixHoneypotUDPv6
			tcpComment, udpComment = commentHoneypotTCPV6, commentHoneypotUDPv6
		}
		for _, chunk := range chunkProtectedPorts(data.ProtectedPorts, iptablesMaxMultiportEntries) {
			for _, spec := range []struct {
				proto, prefix, comment string
			}{
				{"tcp", tcpPrefix, tcpComment},
				{"udp", udpPrefix, udpComment},
			} {
				_, _ = b.run(ctx, "", bin, "-A", IPTablesSecurityChain, "-p", spec.proto, "-m", "multiport", "--dports", chunk, "-m", "limit", "--limit", "5/min", "-j", "LOG", "--log-prefix", spec.prefix)
				// 若内核未编译 xt_SET 目标，则静默降级为仅记录日志 + DROP，不阻断整体规则下发。
				_, _ = b.run(ctx, "", bin, "-A", IPTablesSecurityChain, "-p", spec.proto, "-m", "multiport", "--dports", chunk, "-m", "limit", "--limit", "5/min", "-j", "SET", "--add-set", setName, "src", "--exist")
				if err := mustAdd("-p", spec.proto, "-m", "multiport", "--dports", chunk, "-m", "comment", "--comment", spec.comment, "-j", "DROP"); err != nil {
					return err
				}
			}
		}
	}

	if _, err := b.run(ctx, "", bin, "-C", "INPUT", "-j", IPTablesSecurityChain); err != nil {
		if out, iErr := b.run(ctx, "", bin, "-I", "INPUT", "1", "-j", IPTablesSecurityChain); iErr != nil {
			return fmt.Errorf("%s -I INPUT 1 -j %s failed: %w (%s)", bin, IPTablesSecurityChain, iErr, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (b *IPTablesBackend) persistAutostart(ctx context.Context, scriptPath string) {
	if b.isOpenWrt() {
		block := strings.Join([]string{
			SecurityFirewallUserBegin,
			"# Managed by SingCtl Host Security Firewall — DO NOT EDIT MANUALLY",
			fmt.Sprintf("[ -x %q ] && %q", scriptPath, scriptPath),
			SecurityFirewallUserEnd,
		}, "\n") + "\n"
		if err := syncManagedFirewallUserFile(b.firewallUserPath(), SecurityFirewallUserBegin, SecurityFirewallUserEnd, block); err != nil {
			logger.Warn("Rules applied, but failed to persist %s: %v", b.firewallUserPath(), err)
		}
		return
	}
	if b.SetupSystemd != nil {
		if err := b.SetupSystemd(ctx, scriptPath); err != nil {
			logger.Warn("Rules applied, but failed to setup systemd persistence: %v", err)
		}
		return
	}
	if err := setupIPTablesSystemdService(ctx, scriptPath); err != nil {
		logger.Warn("Rules applied, but failed to setup systemd persistence: %v", err)
	}
}

func setupIPTablesSystemdService(ctx context.Context, scriptPath string) error {
	content := BuildIPTablesFirewallSystemdUnit(scriptPath)
	if err := os.WriteFile(constant.FirewallSystemdService, []byte(content), 0644); err != nil {
		return err
	}
	mgr := servicemgr.NewSystemd(nil)
	_ = mgr.DaemonReload(ctx)
	if err := mgr.Enable(ctx, "singctl-firewall.service"); err != nil {
		return err
	}
	return mgr.Start(ctx, "singctl-firewall.service")
}

// Disable 卸载 SINGCTL_SECURITY 隔离链、销毁 5 大 ipset 集合并清理持久化脚本与 `/etc/firewall.user` 受管块。
func (b *IPTablesBackend) Disable() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if b.isOpenWrt() {
		_ = syncManagedFirewallUserFile(b.firewallUserPath(), SecurityFirewallUserBegin, SecurityFirewallUserEnd, "")
	} else if b.TeardownSystemd != nil {
		_ = b.TeardownSystemd(ctx)
	} else {
		teardownSystemdService()
	}

	for _, bin := range []string{"iptables", "ip6tables"} {
		if !b.hasBinary(bin) {
			continue
		}
		for range 8 {
			if _, err := b.run(ctx, "", bin, "-C", "INPUT", "-j", IPTablesSecurityChain); err != nil {
				break
			}
			_, _ = b.run(ctx, "", bin, "-D", "INPUT", "-j", IPTablesSecurityChain)
		}
		_, _ = b.run(ctx, "", bin, "-F", IPTablesSecurityChain)
		_, _ = b.run(ctx, "", bin, "-X", IPTablesSecurityChain)
	}

	for _, setName := range []string{"blocklist_ip4_forever", "blocklist_ip4", "blocklist_ip6", "whitelist_ip", "whitelist_ip6"} {
		_, _ = b.run(ctx, "", "ipset", "flush", setName)
		_, _ = b.run(ctx, "", "ipset", "destroy", setName)
	}

	_ = os.Remove(b.scriptPath())
	return nil
}

func syncManagedFirewallUserFile(targetPath, beginMarker, endMarker, newBlock string) error {
	cleanPath := strings.TrimSpace(targetPath)
	if cleanPath == "" {
		return nil
	}
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			if newBlock == "" {
				return nil
			}
			if mkErr := os.MkdirAll(filepath.Dir(cleanPath), 0755); mkErr != nil {
				return mkErr
			}
			return fsx.WriteAtomic0600(cleanPath, []byte(newBlock))
		}
		return err
	}

	var kept []string
	skipping := false
	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == beginMarker {
			skipping = true
			continue
		}
		if skipping {
			if trimmed == endMarker {
				skipping = false
			}
			continue
		}
		kept = append(kept, line)
	}

	base := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	var updated string
	if newBlock == "" {
		if base != "" {
			updated = base + "\n"
		}
	} else {
		cleanBlock := strings.TrimRight(newBlock, "\n") + "\n"
		if base == "" {
			updated = cleanBlock
		} else {
			updated = base + "\n\n" + cleanBlock
		}
	}
	if updated == string(raw) {
		return nil
	}
	return fsx.WriteAtomic0600(cleanPath, []byte(updated))
}
