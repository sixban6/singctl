// 文件职责：提供纯 Go sing-box 透明代理数据面编译器（策略路由表规格、单事务 nftables 规则批、iptables-restore --noflush 规则批）与失败自动回滚编排器。
package singbox

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"singctl/internal/common/fsx"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/platform/fwtx"
	"singctl/internal/platform/rtnl"
	"singctl/internal/singbox/scripts"
)

// DataplaneInput 描述纯内存透明代理数据面编译所需全部拓扑与白名单参数。
type DataplaneInput struct {
	TProxyPort      int
	ForwardFwMark   uint32
	ForwardTable    int
	LocalFwMark     uint32
	LocalTable      int
	EnableIPv6      bool
	LocalIPv4s      []netip.Addr
	LANIPv6Prefixes []netip.Prefix
	BypassDNSV4     []netip.Addr
	BypassDNSV6     []netip.Addr
	BypassVLANCIDRs []netip.Prefix
}

// IPTablesCaps 声明当前宿主 ip(6)tables-restore 内核与用户态模块能力，用于无缝降级兼容老旧固件。
type IPTablesCaps struct {
	HasAddrType     bool
	HasMangleReject bool
	HasIPv6TProxy   bool
}

var (
	defaultBypassDNSV4 = []netip.Addr{
		netip.MustParseAddr("223.5.5.5"),
		netip.MustParseAddr("223.6.6.6"),
		netip.MustParseAddr("1.12.12.12"),
		netip.MustParseAddr("120.53.53.53"),
	}
	defaultBypassDNSV6 = []netip.Addr{
		netip.MustParseAddr("2400:3200::1"),
		netip.MustParseAddr("2400:3200:baba::1"),
	}
	upstreamV4Re = regexp.MustCompile(`(?:https|tls|quic|h3)://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
	upstreamV6Re = regexp.MustCompile(`(?:https|tls|quic|h3)://\[([0-9a-fA-F:]+)\]`)
	smartTLSV4Re = regexp.MustCompile(`^server-(?:tls|https|quic|h3)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
	smartTLSV6Re = regexp.MustCompile(`^server-(?:tls|https|quic|h3)\s+\[([0-9a-fA-F:]+)\]`)
)

func normalizeInput(in DataplaneInput) (DataplaneInput, error) {
	if in.TProxyPort <= 0 || in.TProxyPort > 65535 {
		return DataplaneInput{}, fmt.Errorf("dataplane: invalid TProxy port %d", in.TProxyPort)
	}
	in.ForwardFwMark = cmp.Or(in.ForwardFwMark, uint32(0x1))
	in.ForwardTable = cmp.Or(in.ForwardTable, 100)
	in.LocalFwMark = cmp.Or(in.LocalFwMark, uint32(0x2))
	in.LocalTable = cmp.Or(in.LocalTable, 101)
	return in, nil
}

// BuildTProxyRouteSpec 根据输入参数构建表 100/101 透明代理策略路由与 src_valid_mark=1 防护逃生前缀规格。
func BuildTProxyRouteSpec(in DataplaneInput) rtnl.TProxyRouteSpec {
	v4Throws := rtnl.DefaultThrowV4Prefixes()
	v6Throws := rtnl.DefaultThrowV6Prefixes()
	for _, pfx := range in.LANIPv6Prefixes {
		if !pfx.IsValid() {
			continue
		}
		norm := netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()).Masked()
		if norm.Addr().Is6() && !slices.Contains(v6Throws, norm) {
			v6Throws = append(v6Throws, norm)
		}
	}
	return rtnl.TProxyRouteSpec{
		ForwardFwMark:   cmp.Or(in.ForwardFwMark, uint32(0x1)),
		ForwardTable:    cmp.Or(in.ForwardTable, 100),
		LocalFwMark:     cmp.Or(in.LocalFwMark, uint32(0x2)),
		LocalTable:      cmp.Or(in.LocalTable, 101),
		EnableIPv6:      in.EnableIPv6,
		ThrowV4Prefixes: v4Throws,
		ThrowV6Prefixes: v6Throws,
	}
}

// CollectDataplaneInput 从本机 AF_NETLINK 接口地址及配置文件采集纯净透明代理输入参数。
func CollectDataplaneInput(cfg *config.Config, nlClient rtnl.Client, adguardPath, smartdnsPath, vlanBypassPath string) DataplaneInput {
	in := DataplaneInput{
		TProxyPort:    7895,
		ForwardFwMark: 0x1,
		ForwardTable:  100,
		LocalFwMark:   0x2,
		LocalTable:    101,
		BypassDNSV4:   slices.Clone(defaultBypassDNSV4),
		BypassDNSV6:   slices.Clone(defaultBypassDNSV6),
	}
	if cfg != nil && cfg.Gateway.EffectiveIPv6Mode() != config.GatewayIPv6Off {
		in.EnableIPv6 = true
	}

	if nlClient == nil {
		nlClient = rtnl.Default()
	}
	if addrs, err := nlClient.ListAddresses(); err == nil {
		for _, a := range addrs {
			addr := a.Prefix.Addr().Unmap()
			if addr.Is4() && !slices.Contains(in.LocalIPv4s, addr) {
				in.LocalIPv4s = append(in.LocalIPv4s, addr)
			}
		}
		in.LANIPv6Prefixes = rtnl.ExtractLANIPv6Prefixes(addrs, "")
	}

	collectEncryptedDNSBypassFromFile(cmp.Or(adguardPath, "/etc/AdGuardHome/AdGuardHome.yaml"), &in)
	collectEncryptedDNSBypassFromFile(cmp.Or(smartdnsPath, "/etc/singctl/smartdns.conf"), &in)
	collectVLANBypassFromFile(cmp.Or(vlanBypassPath, "/etc/singctl/vlan-proxy-bypass.list"), &in)
	return in
}

func appendUniqueAddr(dst *[]netip.Addr, raw string, wantV4 bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() || addr.Is4() != wantV4 {
		return
	}
	if !slices.Contains(*dst, addr) {
		*dst = append(*dst, addr)
	}
}

func collectEncryptedDNSBypassFromFile(path string, in *DataplaneInput) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		for _, re := range []*regexp.Regexp{upstreamV4Re, smartTLSV4Re} {
			for _, m := range re.FindAllStringSubmatch(trim, -1) {
				if len(m) >= 2 {
					appendUniqueAddr(&in.BypassDNSV4, m[1], true)
				}
			}
		}
		for _, re := range []*regexp.Regexp{upstreamV6Re, smartTLSV6Re} {
			for _, m := range re.FindAllStringSubmatch(trim, -1) {
				if len(m) >= 2 {
					appendUniqueAddr(&in.BypassDNSV6, m[1], false)
				}
			}
		}
	}
}

func collectVLANBypassFromFile(path string, in *DataplaneInput) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		pfx, err := netip.ParsePrefix(trim)
		if err != nil {
			continue
		}
		addr := pfx.Addr().Unmap()
		if !addr.Is4() || addr.IsLoopback() || pfx.Bits() < 8 || pfx.Bits() > 32 {
			continue
		}
		norm := netip.PrefixFrom(addr, pfx.Bits()).Masked()
		if !slices.Contains(in.BypassVLANCIDRs, norm) {
			in.BypassVLANCIDRs = append(in.BypassVLANCIDRs, norm)
		}
	}
}

// RenderSingBoxNFTBatch 编译单事务无空窗 nftables 规则脚本文本（add table + flush table + table inet sing-box）。
func RenderSingBoxNFTBatch(in DataplaneInput) (string, error) {
	norm, err := normalizeInput(in)
	if err != nil {
		return "", err
	}
	fwdMark := fmt.Sprintf("0x%x", norm.ForwardFwMark)
	locMark := fmt.Sprintf("0x%x", norm.LocalFwMark)

	v6Elems := []string{"::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}
	for _, p := range norm.LANIPv6Prefixes {
		if p.IsValid() && p.Addr().Is6() {
			s := netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked().String()
			if !slices.Contains(v6Elems, s) {
				v6Elems = append(v6Elems, s)
			}
		}
	}

	var vlanLine string
	if len(norm.BypassVLANCIDRs) > 0 {
		strs := make([]string, 0, len(norm.BypassVLANCIDRs))
		for _, p := range norm.BypassVLANCIDRs {
			strs = append(strs, p.Masked().String())
		}
		vlanLine = fmt.Sprintf("        ip saddr { %s } fib daddr type != local accept comment \"singctl-vlan-bypass\"\n", strings.Join(strs, ", "))
	}

	var bypassDNSLines strings.Builder
	if len(norm.BypassDNSV4) > 0 {
		strs := make([]string, 0, len(norm.BypassDNSV4))
		for _, a := range norm.BypassDNSV4 {
			strs = append(strs, a.Unmap().String())
		}
		fmt.Fprintf(&bypassDNSLines, "        ip daddr { %s } meta l4proto { tcp, udp } th dport { 443, 853 } accept comment \"Bypass local encrypted DNS upstreams\"\n", strings.Join(strs, ", "))
	}
	if len(norm.BypassDNSV6) > 0 {
		strs := make([]string, 0, len(norm.BypassDNSV6))
		for _, a := range norm.BypassDNSV6 {
			strs = append(strs, a.Unmap().String())
		}
		fmt.Fprintf(&bypassDNSLines, "        ip6 daddr { %s } meta l4proto { tcp, udp } th dport { 443, 853 } accept comment \"Bypass local IPv6 encrypted DNS upstreams\"\n", strings.Join(strs, ", "))
	}

	body := fmt.Sprintf(`#!/usr/sbin/nft -f
table inet sing-box {

    set LOCAL_IPV4_SET {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255/32, 100.64.0.0/10 }
    }

    set LOCAL_IPV6_SET {
        type ipv6_addr
        flags interval
        auto-merge
        elements = { %s }
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;

        fib daddr type local meta l4proto { tcp, udp } th dport %d reject with icmpx type host-unreachable
        fib daddr type local accept

        iifname "lo" meta mark %s meta l4proto { tcp, udp } tproxy to :%d meta mark set %s accept

%s        ip daddr { 127.0.0.0/8, 100.64.0.0/10 } accept
        ip6 daddr { ::1, fd7a:115c:a1e0::/48 } accept

        ct status dnat accept comment "Allow forwarded traffic"

        meta l4proto { tcp, udp } th dport 53 tproxy to :%d meta mark set %s accept comment "DNS透明代理"

        ip daddr @LOCAL_IPV4_SET accept
        ip6 daddr @LOCAL_IPV6_SET accept

        meta l4proto { tcp, udp } tproxy to :%d meta mark set %s accept
    }

    chain output {
        type route hook output priority mangle; policy accept;

        meta mark %s accept
        meta mark %s accept

        meta mark 0x80000 accept comment "Bypass Tailscale fwmark"
        udp sport 41641 accept comment "Bypass Tailscale UDP port"
        oifname "tailscale*" accept comment "Bypass outbound traffic to tailscale interface"

%s        meta l4proto ipv6-icmp accept comment "Allow ICMPv6 traffic"

        ip daddr { 127.0.0.0/8, 100.64.0.0/10 } accept
        ip6 daddr { ::1, fd7a:115c:a1e0::/48 } accept
        meta l4proto { tcp, udp } th dport 53 meta mark set %s accept

        ip daddr @LOCAL_IPV4_SET accept
        ip6 daddr @LOCAL_IPV6_SET accept

        meta l4proto { tcp, udp } meta mark set %s accept
    }
}
`,
		strings.Join(v6Elems, ", "),
		norm.TProxyPort,
		locMark, norm.TProxyPort, locMark,
		vlanLine,
		norm.TProxyPort, fwdMark,
		norm.TProxyPort, fwdMark,
		fwdMark, locMark,
		bypassDNSLines.String(),
		locMark, locMark,
	)

	return fwtx.WrapAtomicNFTTable("inet", "sing-box", body)
}

// RenderSingBoxIPTablesRestore 生成适配 iptables-restore --noflush / ip6tables-restore --noflush 的隔离链批处理规则。
func RenderSingBoxIPTablesRestore(in DataplaneInput, caps IPTablesCaps) (v4Batch, v6Batch string, err error) {
	norm, err := normalizeInput(in)
	if err != nil {
		return "", "", err
	}

	rejectTarget := "DROP"
	if caps.HasMangleReject {
		rejectTarget = "REJECT"
	}
	portStr := strconv.Itoa(norm.TProxyPort)
	fwdMarkStr := strconv.FormatUint(uint64(norm.ForwardFwMark), 10)
	locMarkStr := strconv.FormatUint(uint64(norm.LocalFwMark), 10)

	var v4 strings.Builder
	v4.WriteString("*mangle\n:SING_BOX - [0:0]\n:SING_BOX_OUTPUT - [0:0]\n-F SING_BOX\n-F SING_BOX_OUTPUT\n")
	if caps.HasAddrType {
		fmt.Fprintf(&v4, "-A SING_BOX -m addrtype --dst-type LOCAL -p tcp --dport %s -j %s\n", portStr, rejectTarget)
		fmt.Fprintf(&v4, "-A SING_BOX -m addrtype --dst-type LOCAL -p udp --dport %s -j %s\n", portStr, rejectTarget)
		v4.WriteString("-A SING_BOX -m addrtype --dst-type LOCAL -j RETURN\n")
	} else {
		for _, ip := range norm.LocalIPv4s {
			ip = ip.Unmap()
			if !ip.Is4() {
				continue
			}
			s := ip.String()
			fmt.Fprintf(&v4, "-A SING_BOX -d %s -p tcp --dport %s -j %s\n", s, portStr, rejectTarget)
			fmt.Fprintf(&v4, "-A SING_BOX -d %s -p udp --dport %s -j %s\n", s, portStr, rejectTarget)
			fmt.Fprintf(&v4, "-A SING_BOX -d %s -j RETURN\n", s)
		}
	}
	fmt.Fprintf(&v4, "-A SING_BOX -i lo -m mark --mark %s -p tcp -j TPROXY --on-port %s --tproxy-mark %s\n", locMarkStr, portStr, locMarkStr)
	fmt.Fprintf(&v4, "-A SING_BOX -i lo -m mark --mark %s -p udp -j TPROXY --on-port %s --tproxy-mark %s\n", locMarkStr, portStr, locMarkStr)
	for _, cidr := range norm.BypassVLANCIDRs {
		fmt.Fprintf(&v4, "-A SING_BOX -s %s -m comment --comment singctl-vlan-bypass -j RETURN\n", cidr.Masked().String())
	}
	v4.WriteString("-A SING_BOX -d 127.0.0.0/8 -j RETURN\n")
	v4.WriteString("-A SING_BOX -d 100.64.0.0/10 -j RETURN\n")
	v4.WriteString("-A SING_BOX -m conntrack --ctstate DNAT -j RETURN\n")
	v4.WriteString("-A SING_BOX -p udp --dport 67:68 -j RETURN\n")
	fmt.Fprintf(&v4, "-A SING_BOX -p udp --dport 53 -j TPROXY --on-port %s --tproxy-mark %s\n", portStr, fwdMarkStr)
	fmt.Fprintf(&v4, "-A SING_BOX -p tcp --dport 53 -j TPROXY --on-port %s --tproxy-mark %s\n", portStr, fwdMarkStr)
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"} {
		fmt.Fprintf(&v4, "-A SING_BOX -d %s -j RETURN\n", cidr)
	}
	fmt.Fprintf(&v4, "-A SING_BOX -p tcp -j TPROXY --on-port %s --tproxy-mark %s\n", portStr, fwdMarkStr)
	fmt.Fprintf(&v4, "-A SING_BOX -p udp -j TPROXY --on-port %s --tproxy-mark %s\n", portStr, fwdMarkStr)

	fmt.Fprintf(&v4, "-A SING_BOX_OUTPUT -m mark --mark %s -j RETURN\n", fwdMarkStr)
	fmt.Fprintf(&v4, "-A SING_BOX_OUTPUT -m mark --mark %s -j RETURN\n", locMarkStr)
	v4.WriteString("-A SING_BOX_OUTPUT -m mark --mark 0x80000 -j RETURN\n")
	v4.WriteString("-A SING_BOX_OUTPUT -p udp --sport 41641 -j RETURN\n")
	v4.WriteString("-A SING_BOX_OUTPUT -o tailscale+ -j RETURN\n")
	for _, dnsIP := range norm.BypassDNSV4 {
		s := dnsIP.Unmap().String()
		for _, proto := range []string{"tcp", "udp"} {
			fmt.Fprintf(&v4, "-A SING_BOX_OUTPUT -d %s -p %s --dport 443 -j RETURN\n", s, proto)
			fmt.Fprintf(&v4, "-A SING_BOX_OUTPUT -d %s -p %s --dport 853 -j RETURN\n", s, proto)
		}
	}
	v4.WriteString("-A SING_BOX_OUTPUT -d 127.0.0.0/8 -j RETURN\n")
	v4.WriteString("-A SING_BOX_OUTPUT -d 100.64.0.0/10 -j RETURN\n")
	fmt.Fprintf(&v4, "-A SING_BOX_OUTPUT -p udp --dport 53 -j MARK --set-mark %s\n", locMarkStr)
	fmt.Fprintf(&v4, "-A SING_BOX_OUTPUT -p tcp --dport 53 -j MARK --set-mark %s\n", locMarkStr)
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"} {
		fmt.Fprintf(&v4, "-A SING_BOX_OUTPUT -d %s -j RETURN\n", cidr)
	}
	fmt.Fprintf(&v4, "-A SING_BOX_OUTPUT -p tcp -j MARK --set-mark %s\n", locMarkStr)
	fmt.Fprintf(&v4, "-A SING_BOX_OUTPUT -p udp -j MARK --set-mark %s\n", locMarkStr)
	v4.WriteString("COMMIT\n")

	if !norm.EnableIPv6 || !caps.HasIPv6TProxy {
		return v4.String(), "", nil
	}

	var v6 strings.Builder
	v6.WriteString("*mangle\n:SING_BOX - [0:0]\n:SING_BOX_OUTPUT - [0:0]\n-F SING_BOX\n-F SING_BOX_OUTPUT\n")
	if caps.HasAddrType {
		fmt.Fprintf(&v6, "-A SING_BOX -m addrtype --dst-type LOCAL -p tcp --dport %s -j %s\n", portStr, rejectTarget)
		fmt.Fprintf(&v6, "-A SING_BOX -m addrtype --dst-type LOCAL -p udp --dport %s -j %s\n", portStr, rejectTarget)
		v6.WriteString("-A SING_BOX -m addrtype --dst-type LOCAL -j RETURN\n")
	}
	fmt.Fprintf(&v6, "-A SING_BOX -i lo -m mark --mark %s -p tcp -j TPROXY --on-port %s --tproxy-mark %s\n", locMarkStr, portStr, locMarkStr)
	fmt.Fprintf(&v6, "-A SING_BOX -i lo -m mark --mark %s -p udp -j TPROXY --on-port %s --tproxy-mark %s\n", locMarkStr, portStr, locMarkStr)
	v6.WriteString("-A SING_BOX -d ::1/128 -j RETURN\n")
	v6.WriteString("-A SING_BOX -d fd7a:115c:a1e0::/48 -j RETURN\n")
	v6.WriteString("-A SING_BOX -m conntrack --ctstate DNAT -j RETURN\n")
	fmt.Fprintf(&v6, "-A SING_BOX -p udp --dport 53 -j TPROXY --on-port %s --tproxy-mark %s\n", portStr, fwdMarkStr)
	fmt.Fprintf(&v6, "-A SING_BOX -p tcp --dport 53 -j TPROXY --on-port %s --tproxy-mark %s\n", portStr, fwdMarkStr)
	for _, fixed := range []string{"fc00::/7", "fe80::/10", "ff00::/8"} {
		fmt.Fprintf(&v6, "-A SING_BOX -d %s -j RETURN\n", fixed)
	}
	for _, pfx := range norm.LANIPv6Prefixes {
		fmt.Fprintf(&v6, "-A SING_BOX -d %s -j RETURN\n", pfx.Masked().String())
	}
	fmt.Fprintf(&v6, "-A SING_BOX -p tcp -j TPROXY --on-port %s --tproxy-mark %s\n", portStr, fwdMarkStr)
	fmt.Fprintf(&v6, "-A SING_BOX -p udp -j TPROXY --on-port %s --tproxy-mark %s\n", portStr, fwdMarkStr)

	fmt.Fprintf(&v6, "-A SING_BOX_OUTPUT -m mark --mark %s -j RETURN\n", fwdMarkStr)
	fmt.Fprintf(&v6, "-A SING_BOX_OUTPUT -m mark --mark %s -j RETURN\n", locMarkStr)
	v6.WriteString("-A SING_BOX_OUTPUT -m mark --mark 0x80000 -j RETURN\n")
	v6.WriteString("-A SING_BOX_OUTPUT -p udp --sport 41641 -j RETURN\n")
	v6.WriteString("-A SING_BOX_OUTPUT -o tailscale+ -j RETURN\n")
	v6.WriteString("-A SING_BOX_OUTPUT -p icmpv6 -j RETURN\n")
	for _, dnsV6 := range norm.BypassDNSV6 {
		s := dnsV6.Unmap().String()
		for _, proto := range []string{"tcp", "udp"} {
			fmt.Fprintf(&v6, "-A SING_BOX_OUTPUT -d %s -p %s --dport 443 -j RETURN\n", s, proto)
			fmt.Fprintf(&v6, "-A SING_BOX_OUTPUT -d %s -p %s --dport 853 -j RETURN\n", s, proto)
		}
	}
	v6.WriteString("-A SING_BOX_OUTPUT -d ::1/128 -j RETURN\n")
	v6.WriteString("-A SING_BOX_OUTPUT -d fd7a:115c:a1e0::/48 -j RETURN\n")
	fmt.Fprintf(&v6, "-A SING_BOX_OUTPUT -p udp --dport 53 -j MARK --set-mark %s\n", locMarkStr)
	fmt.Fprintf(&v6, "-A SING_BOX_OUTPUT -p tcp --dport 53 -j MARK --set-mark %s\n", locMarkStr)
	for _, fixed := range []string{"fc00::/7", "fe80::/10", "ff00::/8"} {
		fmt.Fprintf(&v6, "-A SING_BOX_OUTPUT -d %s -j RETURN\n", fixed)
	}
	for _, pfx := range norm.LANIPv6Prefixes {
		fmt.Fprintf(&v6, "-A SING_BOX_OUTPUT -d %s -j RETURN\n", pfx.Masked().String())
	}
	fmt.Fprintf(&v6, "-A SING_BOX_OUTPUT -p tcp -j MARK --set-mark %s\n", locMarkStr)
	fmt.Fprintf(&v6, "-A SING_BOX_OUTPUT -p udp -j MARK --set-mark %s\n", locMarkStr)
	v6.WriteString("COMMIT\n")

	return v4.String(), v6.String(), nil
}

// ApplyDataplane 编排纯 Go RTNL 策略路由与单事务防火墙挂载，防火墙失败时自动回滚表 100/101 路由。
func ApplyDataplane(
	ctx context.Context,
	in DataplaneInput,
	caps IPTablesCaps,
	useNFT bool,
	nlClient rtnl.Client,
	fwRunner fwtx.Runner,
) (retErr error) {
	if nlClient == nil {
		nlClient = rtnl.Default()
	}
	spec := BuildTProxyRouteSpec(in)
	if err := nlClient.ReconcileTProxyRoutes(spec); err != nil {
		return fmt.Errorf("dataplane reconcile routes failed: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = nlClient.CleanupTProxyRoutes(spec.ForwardTable, spec.LocalTable)
		}
	}()

	if useNFT {
		script, err := RenderSingBoxNFTBatch(in)
		if err != nil {
			return err
		}
		if err := fwtx.ApplyAtomicNFT(ctx, fwRunner, script, true); err != nil {
			return err
		}
		if os.Geteuid() == 0 {
			if st, sErr := os.Stat(constant.SingBoxConfigDir); sErr == nil && st.IsDir() {
				_ = fsx.WriteAtomic0600(constant.SingBoxConfigDir+"/singbox.nft", []byte(script))
			}
		}
		return nil
	}

	v4Batch, v6Batch, err := RenderSingBoxIPTablesRestore(in, caps)
	if err != nil {
		return err
	}
	if err := fwtx.ApplyIPTablesRestoreNoFlush(ctx, fwRunner, false, v4Batch, false); err != nil {
		return err
	}
	ensureIPTablesJump(ctx, fwRunner, "iptables", "PREROUTING", "SING_BOX")
	ensureIPTablesJump(ctx, fwRunner, "iptables", "OUTPUT", "SING_BOX_OUTPUT")

	if v6Batch != "" {
		if err := fwtx.ApplyIPTablesRestoreNoFlush(ctx, fwRunner, true, v6Batch, false); err != nil {
			return err
		}
		ensureIPTablesJump(ctx, fwRunner, "ip6tables", "PREROUTING", "SING_BOX")
		ensureIPTablesJump(ctx, fwRunner, "ip6tables", "OUTPUT", "SING_BOX_OUTPUT")
	}
	return nil
}

// CleanupDataplane 幂等拆除透明代理防火墙规则与策略路由表 100/101。
func CleanupDataplane(ctx context.Context, useNFT bool, nlClient rtnl.Client, fwRunner fwtx.Runner) error {
	if nlClient == nil {
		nlClient = rtnl.Default()
	}
	if useNFT {
		if err := fwtx.DeleteNFTTableIdempotent(ctx, fwRunner, "inet", "sing-box"); err != nil {
			return err
		}
		if os.Geteuid() == 0 {
			_ = os.Remove(constant.SingBoxConfigDir + "/singbox.nft")
		}
	} else {
		cleanupIPTablesChains(ctx, fwRunner, "iptables")
		cleanupIPTablesChains(ctx, fwRunner, "ip6tables")
	}
	return nlClient.CleanupTProxyRoutes(100, 101)
}

func ensureIPTablesJump(ctx context.Context, runner fwtx.Runner, ipt, parent, chain string) {
	if runner == nil {
		runner = fwtx.ExecRunner{}
	}
	if _, err := runner.RunStdin(ctx, "", ipt, "-t", "mangle", "-C", parent, "-j", chain); err != nil {
		_, _ = runner.RunStdin(ctx, "", ipt, "-t", "mangle", "-A", parent, "-j", chain)
	}
}

func cleanupIPTablesChains(ctx context.Context, runner fwtx.Runner, ipt string) {
	if runner == nil {
		runner = fwtx.ExecRunner{}
	}
	for _, pair := range [][2]string{
		{"PREROUTING", "SING_BOX"},
		{"OUTPUT", "SING_BOX_OUTPUT"},
		{"PREROUTING", "SINGBOX"},
		{"OUTPUT", "SINGBOX_OUTPUT"},
	} {
		for range 8 {
			if _, err := runner.RunStdin(ctx, "", ipt, "-t", "mangle", "-D", pair[0], "-j", pair[1]); err != nil {
				break
			}
		}
	}
	for _, ch := range []string{"SING_BOX", "SING_BOX_OUTPUT", "SINGBOX", "SINGBOX_OUTPUT"} {
		_, _ = runner.RunStdin(ctx, "", ipt, "-t", "mangle", "-F", ch)
		_, _ = runner.RunStdin(ctx, "", ipt, "-t", "mangle", "-X", ch)
	}
}

// DetectIPTablesCaps 一次性探测宿主 iptables/ip6tables 模块能力。
func DetectIPTablesCaps(ctx context.Context) IPTablesCaps {
	var caps IPTablesCaps
	_, hasAddr := exec.CommandContext(ctx, "iptables", "-t", "mangle", "-m", "addrtype", "--help").CombinedOutput()
	caps.HasAddrType = hasAddr == nil

	// 探测 mangle 表是否支持 -j REJECT（部分精简内核仅支持 DROP）
	_ = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-F", "SING_BOX_PROBE").Run()
	_ = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-X", "SING_BOX_PROBE").Run()
	if exec.CommandContext(ctx, "iptables", "-t", "mangle", "-N", "SING_BOX_PROBE").Run() == nil {
		caps.HasMangleReject = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-A", "SING_BOX_PROBE", "-p", "tcp", "-j", "REJECT").Run() == nil
		_ = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-F", "SING_BOX_PROBE").Run()
		_ = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-X", "SING_BOX_PROBE").Run()
	}

	if _, lpErr := exec.LookPath("ip6tables-restore"); lpErr == nil {
		_ = exec.CommandContext(ctx, "ip6tables", "-t", "mangle", "-F", "SING_BOX_PROBE").Run()
		_ = exec.CommandContext(ctx, "ip6tables", "-t", "mangle", "-X", "SING_BOX_PROBE").Run()
		if exec.CommandContext(ctx, "ip6tables", "-t", "mangle", "-N", "SING_BOX_PROBE").Run() == nil {
			caps.HasIPv6TProxy = exec.CommandContext(ctx, "ip6tables", "-t", "mangle", "-A", "SING_BOX_PROBE", "-p", "tcp", "-j", "TPROXY", "--on-port", "7895", "--tproxy-mark", "1").Run() == nil
			_ = exec.CommandContext(ctx, "ip6tables", "-t", "mangle", "-F", "SING_BOX_PROBE").Run()
			_ = exec.CommandContext(ctx, "ip6tables", "-t", "mangle", "-X", "SING_BOX_PROBE").Run()
		}
	}
	return caps
}

func useNativeNFTBackend() bool {
	if scripts.DetectOpenWrtFirewallBackend() == scripts.BackendNFTables {
		return true
	}
	if _, err := exec.LookPath("nft"); err == nil && os.Geteuid() == 0 {
		// DetectOpenWrtFirewallBackend already accounts for OpenWrt <= 22; on non-OpenWrt Linux with nft, prefer nft.
		if _, relErr := os.Stat("/etc/openwrt_release"); os.IsNotExist(relErr) {
			return true
		}
	}
	return false
}

func (sb *SingBox) applyNativeDataplane(ctx context.Context) error {
	useNFT := useNativeNFTBackend()
	in := CollectDataplaneInput(sb.config, rtnl.Default(), "", "", "")
	var caps IPTablesCaps
	if !useNFT {
		caps = DetectIPTablesCaps(ctx)
	}
	return ApplyDataplane(ctx, in, caps, useNFT, rtnl.Default(), fwtx.ExecRunner{})
}

func (sb *SingBox) cleanupNativeDataplane(ctx context.Context) error {
	useNFT := useNativeNFTBackend()
	_ = constant.SingBoxConfigDir
	return CleanupDataplane(ctx, useNFT, rtnl.Default(), fwtx.ExecRunner{})
}
