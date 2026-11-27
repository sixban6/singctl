// 文件职责：负责宿主 IPv6 就绪状态探测（ProbeIPv6Status）及 OpenWrt LAN RA/DHCPv6/dnsmasq 与防火墙豁免的幂等同步与还原。
package gateway

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/platform/rtnl"
)

const (
	defaultIPv6BackupPath = "/etc/singctl/ipv6-uci-backup.json"
	lanIPv6NFTComment     = "singctl-lan-v6"
	proxyTableIPv6Throw   = "fd7a:115c:a1e0::/48"
)

var defaultThrowIPv6CIDRs = []string{
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	proxyTableIPv6Throw,
}

// IPv6StatusInfo 描述当前宿主的 IPv6 内核、WAN 前缀下发与 OpenWrt LAN 分发就绪状态。
type IPv6StatusInfo struct {
	Supported         bool     `json:"supported"`
	IsOpenWrt         bool     `json:"isOpenWrt"`
	KernelEnabled     bool     `json:"kernelEnabled"`
	ForwardingEnabled bool     `json:"forwardingEnabled"`
	WANHasGUA         bool     `json:"wanHasGua"`
	HasPublicIPv6     bool     `json:"hasPublicIpv6"`
	WANHasDefaultV6   bool     `json:"wanHasDefaultV6"`
	PDPrefix          string   `json:"pdPrefix,omitempty"`
	LANGUA            string   `json:"lanGua,omitempty"`
	LANPrefixes       []string `json:"lanPrefixes,omitempty"`
	LANRAMode         string   `json:"lanRaMode,omitempty"`
	LANDHCPv6Mode     string   `json:"lanDhcpv6Mode,omitempty"`
	DnsmasqFilterAAAA string   `json:"dnsmasqFilterAaaa,omitempty"`
	DnsmasqForwardMax string   `json:"dnsmasqForwardMax,omitempty"`
	RADNSAnnounce     bool     `json:"raDnsAnnounce"`
	AutoConfigurable  bool     `json:"autoConfigurable"`
	Warnings          []string `json:"warnings,omitempty"`
}

// IPv6ApplyResult 记录切换并同步宿主 IPv6 自动配置后的结果与实时状态。
type IPv6ApplyResult struct {
	Mode               string         `json:"mode"`
	OpenWrtAutoApplied bool           `json:"openwrtAutoApplied"`
	RestoredFromBackup bool           `json:"restoredFromBackup"`
	Actions            []string       `json:"actions,omitempty"`
	Status             IPv6StatusInfo `json:"status"`
}

type uciBackupValue struct {
	Set   bool   `json:"set"`
	Value string `json:"value,omitempty"`
}

type ipv6UCIBackup struct {
	Keys map[string]uciBackupValue `json:"keys"`
}

var managedOpenWrtIPv6UCIKeys = []string{
	"network.lan.delegate",
	"network.lan.ip6assign",
	"dhcp.lan.ra",
	"dhcp.lan.dhcpv6",
	"dhcp.lan.ra_slaac",
	"dhcp.lan.ra_flags",
	"dhcp.lan.ra_dns",
	"dhcp.lan.dns_service",
	"dhcp.@dnsmasq[0].dnsforwardmax",
}

func (c *Controller) ipv6BackupPath() string {
	return cmp.Or(strings.TrimSpace(c.IPv6BackupPath), defaultIPv6BackupPath)
}

func (c *Controller) isOpenWrt() bool {
	if c.IsOpenWrt != nil {
		return c.IsOpenWrt()
	}
	return isOpenWrtSystem()
}

func (c *Controller) hasProprietaryMTKWifi() bool {
	if c.HasProprietaryMTKWifi != nil {
		return c.HasProprietaryMTKWifi()
	}
	st, err := os.Stat("/etc/wireless/mediatek")
	return err == nil && st.IsDir()
}

func (c *Controller) reloadOpenWrtLANNetworkSafe(ctx context.Context, isRestoreOff bool) bool {
	if c.hasProprietaryMTKWifi() {
		if !isRestoreOff {
			_, _ = c.runCmd(ctx, "ubus", "call", "network.interface.lan", "renew")
		}
		return true
	}
	_, _ = c.runCmd(ctx, "ubus", "call", "network", "reload")
	return false
}

// ParseOpenWrtIfstatusPDPrefix 从 OpenWrt `ifstatus wan_6` / `ifstatus wan6` JSON 输出中提取运营商下发的公网 IPv6-PD 前缀。
func ParseOpenWrtIfstatusPDPrefix(raw []byte) (string, int, bool) {
	var parsed struct {
		Up         bool `json:"up"`
		IPv6Prefix []struct {
			Address string `json:"address"`
			Mask    int    `json:"mask"`
		} `json:"ipv6-prefix"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", 0, false
	}
	for _, p := range parsed.IPv6Prefix {
		addr, err := netip.ParseAddr(strings.TrimSpace(p.Address))
		if err != nil || p.Mask <= 0 || p.Mask > 128 {
			continue
		}
		pfx := netip.PrefixFrom(addr.Unmap(), p.Mask).Masked()
		return pfx.String(), p.Mask, true
	}
	return "", 0, false
}

func isPublicGlobalIPv6(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.Is6() || !addr.IsGlobalUnicast() {
		return false
	}
	// 排除 RFC 4193 ULA (fc00::/7)、链路本地及 Tailscale 组网地址
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return false
	}
	return true
}

// probeInterfaceIPv6Summary 探测本机所有接口上的公网 IPv6 GUA 与 LAN 口 /64 前缀。
func probeInterfaceIPv6Summary(lanIface string) (wanHasGUA bool, lanGUA string, lanPrefixes []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, "", nil
	}
	if lanIface == "" {
		lanIface = "br-lan"
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(ifc.Name)
		if strings.HasPrefix(name, "tailscale") || strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "tun") {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		isLAN := strings.EqualFold(ifc.Name, lanIface)
		for _, rawAddr := range addrs {
			ipNet, ok := rawAddr.(*net.IPNet)
			if !ok || ipNet == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !isPublicGlobalIPv6(addr) {
				continue
			}
			if isLAN {
				if lanGUA == "" {
					lanGUA = addr.String()
				}
				ones, bits := ipNet.Mask.Size()
				if bits != 128 || ones <= 0 || ones > 64 {
					ones = 64
				}
				pfx := netip.PrefixFrom(addr, ones).Masked().String()
				if !slices.Contains(lanPrefixes, pfx) {
					lanPrefixes = append(lanPrefixes, pfx)
				}
			} else {
				wanHasGUA = true
			}
		}
	}
	return wanHasGUA, lanGUA, lanPrefixes
}

// ProbeIPv6Status 只读探测当前系统内核 IPv6、WAN PD 前缀、LAN 分配与 OpenWrt RA/DHCPv6/dnsmasq 状态。
func ProbeIPv6Status(ctx context.Context, gwCfg config.GatewayConfig, topo TopologyInfo) IPv6StatusInfo {
	c := NewController()
	return c.ProbeIPv6Status(ctx, gwCfg, topo)
}

// ProbeIPv6Status 使用 Controller 上显式注入的 Exec/IsOpenWrt 依赖探测 IPv6 就绪状态。
func (c *Controller) ProbeIPv6Status(ctx context.Context, gwCfg config.GatewayConfig, topo TopologyInfo) IPv6StatusInfo {
	info := IPv6StatusInfo{
		Supported: runtime.GOOS == "linux",
		IsOpenWrt: c.isOpenWrt(),
	}
	if runtime.GOOS != "linux" && c.Exec == nil {
		info.Warnings = append(info.Warnings, "当前非 Linux/OpenWrt 系统，仅配置路由级 IPv6 分流规则")
		return info
	}

	if c.IPv6KernelProbe != nil {
		info.KernelEnabled, info.ForwardingEnabled = c.IPv6KernelProbe()
	} else if c.Exec == nil {
		if raw, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err == nil {
			info.KernelEnabled = strings.TrimSpace(string(raw)) == "0"
		}
		if raw, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding"); err == nil {
			info.ForwardingEnabled = strings.TrimSpace(string(raw)) == "1"
		}
	} else {
		info.KernelEnabled = true
	}

	// 旁路由只有单臂 LAN 口，公网 IPv6 由上级主路由经 RA/DHCPv6 下发到该口；
	// 因此不能只把非 LAN 网卡上的 GUA 当作可用 IPv6，否则单臂旁路由会被误判为“无 IPv6”。
	if c.IPv6IfaceProbe != nil {
		wanGUA, lanGUA, lanPfxs := c.IPv6IfaceProbe(topo.LANIface)
		info.WANHasGUA = wanGUA
		info.LANGUA = lanGUA
		info.LANPrefixes = lanPfxs
	} else if rc := c.rtnlClient(); rc != nil {
		if addrs, err := rc.ListAddresses(); err == nil && len(addrs) > 0 {
			wanGUA, lanGUA, lanPfxs := summarizeIPv6FromRTNL(addrs, topo.LANIface)
			info.WANHasGUA = wanGUA
			info.LANGUA = lanGUA
			info.LANPrefixes = lanPfxs
		} else if c.Exec == nil {
			wanGUA, lanGUA, lanPfxs := probeInterfaceIPv6Summary(topo.LANIface)
			info.WANHasGUA = wanGUA
			info.LANGUA = lanGUA
			info.LANPrefixes = lanPfxs
		}
	} else if c.Exec == nil {
		wanGUA, lanGUA, lanPfxs := probeInterfaceIPv6Summary(topo.LANIface)
		info.WANHasGUA = wanGUA
		info.LANGUA = lanGUA
		info.LANPrefixes = lanPfxs
	}

	if rc := c.rtnlClient(); rc != nil {
		if _, ok, err := rc.GetDefaultRoute(6); err == nil {
			info.WANHasDefaultV6 = ok
		}
	} else if c.Exec != nil || func() bool { _, err := exec.LookPath("ip"); return err == nil }() {
		if out, err := c.runCmd(ctx, "ip", "-6", "route", "show", "default"); err == nil && strings.TrimSpace(string(out)) != "" {
			info.WANHasDefaultV6 = true
		}
	}

	if info.IsOpenWrt && (c.Exec != nil || func() bool { _, err := exec.LookPath("uci"); return err == nil }()) {
		info.AutoConfigurable = true
		for _, iface := range []string{"wan_6", "wan6"} {
			if out, err := c.runCmd(ctx, "ifstatus", iface); err == nil {
				if pfx, _, ok := ParseOpenWrtIfstatusPDPrefix(out); ok {
					info.PDPrefix = pfx
					info.WANHasGUA = true
					break
				}
			}
		}
		info.LANRAMode = c.readUCIKey(ctx, "dhcp.lan.ra")
		info.LANDHCPv6Mode = c.readUCIKey(ctx, "dhcp.lan.dhcpv6")
		info.DnsmasqFilterAAAA = c.readUCIKey(ctx, "dhcp.@dnsmasq[0].filter_aaaa")
		info.DnsmasqForwardMax = c.readUCIKey(ctx, "dhcp.@dnsmasq[0].dnsforwardmax")
		raDNS := c.readUCIKey(ctx, "dhcp.lan.ra_dns")
		dnsSvc := c.readUCIKey(ctx, "dhcp.lan.dns_service")
		info.RADNSAnnounce = (raDNS != "0" || dnsSvc != "0") && (info.LANRAMode == "server" || info.LANDHCPv6Mode == "server")
	}

	info.HasPublicIPv6 = info.WANHasGUA || info.PDPrefix != ""
	if gwCfg.IsSideRouter() && !info.HasPublicIPv6 {
		info.HasPublicIPv6 = info.LANGUA != "" || len(info.LANPrefixes) > 0
	}

	mode := gwCfg.EffectiveIPv6Mode()
	switch {
	case !info.KernelEnabled:
		info.Warnings = append(info.Warnings, "系统内核已禁用 IPv6 (net.ipv6.conf.all.disable_ipv6=1)")
	case gwCfg.IsSideRouter():
		if info.HasPublicIPv6 {
			info.Warnings = append(info.Warnings, "旁路由已通过 LAN 口从上级路由获取公网 IPv6；主路由若继续广播 IPv6 RA 可能绕过旁路由，因此 IPv6 透明代理保持关闭")
		} else {
			info.Warnings = append(info.Warnings, "旁路由 LAN 口未检测到公网 IPv6 地址或前缀；请确认上级主路由已开启 IPv6 并向旁路由下发 RA/DHCPv6")
		}
	case !info.HasPublicIPv6:
		info.Warnings = append(info.Warnings, "WAN 口暂未检测到公网 IPv6 地址或 PD 前缀，请检查光猫拨号/ISP IPv6 下发")
	case mode != config.GatewayIPv6Off && len(info.LANPrefixes) == 0 && info.AutoConfigurable:
		info.Warnings = append(info.Warnings, "WAN 已获取 IPv6，但 LAN 口尚无公网 IPv6 前缀（保存后将自动配置 OpenWrt RA/DHCPv6 下发）")
	}

	return info
}

func (c *Controller) readUCIKey(ctx context.Context, key string) string {
	out, err := c.runCmd(ctx, "uci", "-q", "get", key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (c *Controller) saveOpenWrtIPv6Backup(ctx context.Context) error {
	path := c.ipv6BackupPath()
	var snap ipv6UCIBackup
	fileExists := false
	if raw, err := os.ReadFile(path); err == nil {
		fileExists = true
		_ = json.Unmarshal(raw, &snap)
	}
	if snap.Keys == nil {
		snap.Keys = make(map[string]uciBackupValue, len(managedOpenWrtIPv6UCIKeys))
	}

	dirty := !fileExists
	for _, key := range managedOpenWrtIPv6UCIKeys {
		if _, exists := snap.Keys[key]; exists {
			continue
		}
		dirty = true
		out, err := c.runCmd(ctx, "uci", "-q", "get", key)
		if err != nil {
			snap.Keys[key] = uciBackupValue{Set: false}
			continue
		}
		snap.Keys[key] = uciBackupValue{
			Set:   true,
			Value: strings.TrimSpace(string(out)),
		}
	}
	if !dirty {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (c *Controller) restoreOpenWrtIPv6Backup(ctx context.Context) (bool, bool) {
	path := c.ipv6BackupPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	var snap ipv6UCIBackup
	if err := json.Unmarshal(raw, &snap); err != nil || len(snap.Keys) == 0 {
		return false, false
	}

	networkDirty := false
	dhcpDirty := false
	for _, key := range managedOpenWrtIPv6UCIKeys {
		orig, ok := snap.Keys[key]
		if !ok {
			continue
		}
		targetVal := strings.TrimSpace(orig.Value)
		if strings.HasPrefix(key, "network.") {
			curVal := c.readUCIKey(ctx, key)
			if (!orig.Set || targetVal == "") && curVal == "" {
				continue
			}
			if orig.Set && targetVal != "" && curVal == targetVal {
				continue
			}
			networkDirty = true
		} else if strings.HasPrefix(key, "dhcp.") {
			dhcpDirty = true
		}
		if !orig.Set || targetVal == "" {
			_, _ = c.runCmd(ctx, "uci", "-q", "delete", key)
			continue
		}
		if key == "dhcp.lan.ra_flags" {
			_, _ = c.runCmd(ctx, "uci", "-q", "delete", key)
			for flag := range strings.FieldsSeq(orig.Value) {
				_, _ = c.runCmd(ctx, "uci", "add_list", key+"="+flag)
			}
			continue
		}
		_, _ = c.runCmd(ctx, "uci", "set", key+"="+orig.Value)
	}
	skippedGlobalReload := false
	if networkDirty {
		_, _ = c.runCmd(ctx, "uci", "commit", "network")
		skippedGlobalReload = c.reloadOpenWrtLANNetworkSafe(ctx, true)
	}
	if dhcpDirty {
		_, _ = c.runCmd(ctx, "uci", "commit", "dhcp")
		_, _ = c.runCmd(ctx, "/etc/init.d/odhcpd", "reload")
		_, _ = c.runCmd(ctx, "/etc/init.d/dnsmasq", "reload")
		_, _ = c.runCmd(ctx, "killall", "-HUP", "dnsmasq")
	}
	_ = os.Remove(path)
	return true, skippedGlobalReload
}

// SyncIPv6Host 根据 gateway.ipv6_mode 自动探测并幂等配置/还原宿主 IPv6 转发、OpenWrt RA/DHCPv6、dnsmasq filter_aaaa 与表 100/nftables 豁免。
func (c *Controller) SyncIPv6Host(ctx context.Context, gwCfg config.GatewayConfig) (*IPv6ApplyResult, error) {
	mode := gwCfg.EffectiveIPv6Mode()
	if gwCfg.IsSideRouter() && mode != config.GatewayIPv6Off {
		return nil, fmt.Errorf("旁路由模式不支持自动配置与开启 IPv6 透明代理（主路由会广播 IPv6 网关导致流量绕过）")
	}

	topo := c.probe()
	res := &IPv6ApplyResult{Mode: mode}

	if runtime.GOOS != "linux" && c.Exec == nil {
		res.Status = c.ProbeIPv6Status(ctx, gwCfg, topo)
		return res, nil
	}

	isOpenWrtHost := c.isOpenWrt()

	if mode == config.GatewayIPv6Off {
		if isOpenWrtHost {
			_, _ = c.runCmd(ctx, "uci", "set", "dhcp.@dnsmasq[0].filter_aaaa=1")
			_, _ = c.runCmd(ctx, "uci", "commit", "dhcp")
			_, _ = c.runCmd(ctx, "/etc/init.d/dnsmasq", "reload")
			_, _ = c.runCmd(ctx, "killall", "-HUP", "dnsmasq")
			res.Actions = append(res.Actions, "已恢复 dnsmasq filter_aaaa=1")

			if restored, skippedGlobal := c.restoreOpenWrtIPv6Backup(ctx); restored {
				res.RestoredFromBackup = true
				res.Actions = append(res.Actions, "已按安全备份还原 OpenWrt LAN IPv6 配置")
				if skippedGlobal {
					res.Actions = append(res.Actions, "检测到 MediaTek 闭源无线驱动，已跳过全局 network reload 以防无线与网桥断流")
				}
			}
		}
		res.Status = c.ProbeIPv6Status(ctx, gwCfg, topo)
		return res, nil
	}

	// 开启 cn_only / full: 确保 IPv6 转发已开启
	if _, err := c.runCmd(ctx, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"); err == nil {
		res.Actions = append(res.Actions, "已确认开启内核 net.ipv6.conf.all.forwarding=1")
	}

	// OpenWrt 主路由自动配置 LAN PD 委派 + RA/DHCPv6 服务 + dnsmasq 放行 AAAA（仅重载网络/odhcpd/dnsmasq，绝不中断 PPPoE WAN）
	if isOpenWrtHost {
		if err := c.saveOpenWrtIPv6Backup(ctx); err != nil {
			logger.Warn("备份 OpenWrt 原有 IPv6 UCI 配置失败: %v", err)
		}

		curDelegate := c.readUCIKey(ctx, "network.lan.delegate")
		curIP6Assign := c.readUCIKey(ctx, "network.lan.ip6assign")
		networkDirty := false
		if curDelegate != "1" {
			_, _ = c.runCmd(ctx, "uci", "set", "network.lan.delegate=1")
			networkDirty = true
		}
		if curIP6Assign == "" || curIP6Assign == "0" {
			_, _ = c.runCmd(ctx, "uci", "set", "network.lan.ip6assign=64")
			networkDirty = true
		}
		_, _ = c.runCmd(ctx, "uci", "set", "dhcp.lan.ra=server")
		_, _ = c.runCmd(ctx, "uci", "set", "dhcp.lan.dhcpv6=server")
		_, _ = c.runCmd(ctx, "uci", "set", "dhcp.lan.ra_slaac=1")
		_, _ = c.runCmd(ctx, "uci", "-q", "delete", "dhcp.lan.ra_flags")
		_, _ = c.runCmd(ctx, "uci", "add_list", "dhcp.lan.ra_flags=managed-config")
		_, _ = c.runCmd(ctx, "uci", "add_list", "dhcp.lan.ra_flags=other-config")
		_, _ = c.runCmd(ctx, "uci", "set", "dhcp.lan.ra_dns=0")
		_, _ = c.runCmd(ctx, "uci", "set", "dhcp.lan.dns_service=0")
		_, _ = c.runCmd(ctx, "uci", "set", "dhcp.@dnsmasq[0].filter_aaaa=0")
		_, _ = c.runCmd(ctx, "uci", "set", "dhcp.@dnsmasq[0].dnsforwardmax=1024")
		_, _ = c.runCmd(ctx, "uci", "commit", "dhcp")
		if networkDirty {
			_, _ = c.runCmd(ctx, "uci", "commit", "network")
			if c.reloadOpenWrtLANNetworkSafe(ctx, false) {
				res.Actions = append(res.Actions, "检测到 MediaTek 闭源无线驱动，已使用轻量 lan renew 替代全局 network reload 以防无线断流")
			}
		}

		// 短轮询等待 netifd 将 PD 前缀分发到 br-lan（仅真实宿主机），随后再重载 odhcpd/dnsmasq 以确保绑定新 LAN GUA 并立即广播 RA
		if c.Exec == nil {
		waitPrefix:
			for range 6 {
				_, _, pfxs := probeInterfaceIPv6Summary(topo.LANIface)
				if len(pfxs) > 0 {
					break
				}
				select {
				case <-ctx.Done():
					break waitPrefix
				case <-time.After(400 * time.Millisecond):
				}
			}
		}

		_, _ = c.runCmd(ctx, "/etc/init.d/odhcpd", "enable")
		if _, rErr := c.runCmd(ctx, "/etc/init.d/odhcpd", "reload"); rErr != nil {
			_, _ = c.runCmd(ctx, "/etc/init.d/odhcpd", "restart")
		}
		_, _ = c.runCmd(ctx, "/etc/init.d/dnsmasq", "reload")
		_, _ = c.runCmd(ctx, "killall", "-HUP", "dnsmasq")
		res.OpenWrtAutoApplied = true
		res.Actions = append(res.Actions, "已自动配置 OpenWrt LAN IPv6 前缀分配 (关闭 IPv6 RDNSS 仅经 IPv4 DNS 防泄漏)、放行 dnsmasq AAAA 并提升并发上限至 1024")
	}

	// 热刷新 IPv6 策略路由表 100 throw 逃生路由与 nftables LOCAL_IPV6_SET 豁免（不重启 sing-box）
	status := c.ProbeIPv6Status(ctx, gwCfg, topo)
	c.ensureIPv6ProxyTableThrowRoutes(ctx, status.LANPrefixes)
	c.syncNFTLocalIPv6Exemptions(ctx, status.LANPrefixes)
	if len(status.LANPrefixes) > 0 {
		res.Actions = append(res.Actions, fmt.Sprintf("已热同步 LAN IPv6 前缀 (%s) 至透明代理内网豁免与路由逃生表", strings.Join(status.LANPrefixes, ", ")))
	}

	res.Status = status
	return res, nil
}

func summarizeIPv6FromRTNL(addrs []rtnl.InterfaceAddr, lanIface string) (wanHasGUA bool, lanGUA string, lanPrefixes []string) {
	if lanIface == "" {
		lanIface = "br-lan"
	}
	for _, p := range rtnl.ExtractLANIPv6Prefixes(addrs, lanIface) {
		lanPrefixes = append(lanPrefixes, p.String())
	}
	for _, a := range addrs {
		if !a.IsUp || a.IsLoop {
			continue
		}
		name := strings.ToLower(a.IfName)
		if strings.HasPrefix(name, "tailscale") || strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "tun") {
			continue
		}
		addr := a.Prefix.Addr().Unmap()
		if !isPublicGlobalIPv6(addr) {
			continue
		}
		if strings.EqualFold(a.IfName, lanIface) {
			if lanGUA == "" {
				lanGUA = addr.String()
			}
		} else {
			wanHasGUA = true
		}
	}
	return wanHasGUA, lanGUA, lanPrefixes
}

func (c *Controller) ensureIPv6ProxyTableThrowRoutes(ctx context.Context, lanPrefixes []string) {
	if rc := c.rtnlClient(); rc != nil {
		has100, err := rc.HasRouteTableLocal(6, 100)
		if err == nil {
			if !has100 {
				return
			}
			v6Prefixes := rtnl.DefaultThrowV6Prefixes()
			for _, raw := range lanPrefixes {
				if pfx, pErr := netip.ParsePrefix(strings.TrimSpace(raw)); pErr == nil {
					v6Prefixes = append(v6Prefixes, pfx.Masked())
				}
			}
			_ = rc.EnsureThrowRoutes(6, 100, v6Prefixes)
			return
		}
	}
	if !c.hasCommand("ip") {
		return
	}
	out, err := c.runCmd(ctx, "ip", "-6", "route", "show", "table", proxyRouteTable)
	if err != nil || !strings.Contains(string(out), "local ") {
		return
	}
	cidrs := append(slices.Clone(defaultThrowIPv6CIDRs), lanPrefixes...)
	for _, cidr := range cidrs {
		if strings.TrimSpace(cidr) != "" {
			_, _ = c.runCmd(ctx, "ip", "-6", "route", "replace", "throw", cidr, "table", proxyRouteTable)
		}
	}
}

func (c *Controller) syncNFTLocalIPv6Exemptions(ctx context.Context, lanPrefixes []string) {
	if !c.hasCommand("nft") {
		return
	}
	if _, err := c.runCmd(ctx, "nft", "list", "table", "inet", "sing-box"); err != nil {
		return
	}

	elems := append([]string{"::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}, lanPrefixes...)
	if _, err := c.runCmd(ctx, "nft", "list", "set", "inet", "sing-box", "LOCAL_IPV6_SET"); err == nil {
		_, _ = c.runCmd(ctx, "nft", "flush", "set", "inet", "sing-box", "LOCAL_IPV6_SET")
		_, _ = c.runCmd(ctx, "nft", "add", "element", "inet", "sing-box", "LOCAL_IPV6_SET", "{ "+strings.Join(elems, ", ")+" }")
		return
	}

	// 兼容热运行中的旧版 singbox.nft（尚未重建 LOCAL_IPV6_SET）：安全按注释清理旧规则并在末尾 TProxy 规则前精准插入 LAN GUA 放行
	for _, chain := range []string{"prerouting", "output"} {
		out, err := c.runCmd(ctx, "nft", "-a", "list", "chain", "inet", "sing-box", chain)
		if err != nil {
			continue
		}
		var catchAllHandle string
		for line := range strings.SplitSeq(string(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, lanIPv6NFTComment) {
				if _, after, ok := strings.Cut(trimmed, "# handle "); ok {
					fields := strings.Fields(after)
					if len(fields) > 0 {
						_, _ = c.runCmd(ctx, "nft", "delete", "rule", "inet", "sing-box", chain, "handle", fields[0])
					}
				}
				continue
			}
			isFinalTProxy := chain == "prerouting" &&
				strings.Contains(trimmed, "meta l4proto { tcp, udp } tproxy to") &&
				!strings.Contains(trimmed, "th dport") &&
				!strings.Contains(trimmed, "iifname \"lo\"")
			isFinalOutput := chain == "output" &&
				strings.Contains(trimmed, "meta l4proto { tcp, udp } meta mark set") &&
				!strings.Contains(trimmed, "th dport")
			if isFinalTProxy || isFinalOutput {
				if _, after, ok := strings.Cut(trimmed, "# handle "); ok {
					fields := strings.Fields(after)
					if len(fields) > 0 {
						catchAllHandle = fields[0]
					}
				}
			}
		}
		if catchAllHandle == "" || len(lanPrefixes) == 0 {
			continue
		}
		for _, pfx := range lanPrefixes {
			_, _ = c.runCmd(ctx, "nft", "insert", "rule", "inet", "sing-box", chain, "position", catchAllHandle, "ip6", "daddr", pfx, "accept", "comment", "\""+lanIPv6NFTComment+"\"")
		}
	}
}
