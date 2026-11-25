// 文件职责：实现三源设备自动发现（本机路由 + 局域网 DHCP/ARP + Tailscale 节点）、外网可达性评估与 MAC 自动跟随 DHCP IP 更新。
package homedomain

import (
	"cmp"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"singctl/internal/common/netx"
	"singctl/internal/config"
	"singctl/internal/tailscale"
)

// SelfRouterInfo 描述当前路由器的本机网络标识与 Tailscale 广播子网信息。
type SelfRouterInfo struct {
	Hostname          string   `json:"hostname"`
	SuggestedAlias    string   `json:"suggestedAlias"`
	LANIP             string   `json:"lanIp,omitempty"`
	TailscaleIP       string   `json:"tailscaleIp,omitempty"`
	TailscaleOnline   bool     `json:"tailscaleOnline"`
	AdvertisedSubnets []string `json:"advertisedSubnets,omitempty"`
}

// DiscoveredLANDevice 描述从本机 DHCP 租约或 ARP 表发现的一台局域网终端。
type DiscoveredLANDevice struct {
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	SuggestedAlias string `json:"suggestedAlias,omitempty"`
	Online         bool   `json:"online"`
	Interface      string `json:"interface,omitempty"`
}

// DiscoveredTailscalePeer 描述同 Tailnet 下的对端设备（便于跨子网/下级路由一键命名导入）。
type DiscoveredTailscalePeer struct {
	Hostname       string   `json:"hostname"`
	DNSName        string   `json:"dnsName,omitempty"`
	SuggestedAlias string   `json:"suggestedAlias,omitempty"`
	TailscaleIP    string   `json:"tailscaleIp"`
	Online         bool     `json:"online"`
	OS             string   `json:"os,omitempty"`
	Subnets        []string `json:"subnets,omitempty"`
}

// DiscoverySnapshot 汇总三源设备发现快照。
type DiscoverySnapshot struct {
	Self           SelfRouterInfo            `json:"self"`
	LANDevices     []DiscoveredLANDevice     `json:"lanDevices"`
	TailscalePeers []DiscoveredTailscalePeer `json:"tailscalePeers"`
}

// ReachabilityInfo 描述单台命名设备在外出（咖啡馆/5G 经 Tailscale）场景下的可达性评估结论。
type ReachabilityInfo struct {
	Status               string `json:"status"` // "tailscale" | "subnet" | "lan_only"
	Label                string `json:"label"`
	Hint                 string `json:"hint,omitempty"`
	SuggestedTailscaleIP string `json:"suggestedTailscaleIp,omitempty"`
}

// DiscoveryDeps 显式注入设备发现所需的只读系统数据源（零值回退生产默认）。
type DiscoveryDeps struct {
	LeaseFiles      []string
	ARPFile         string
	HostnameFunc    func() (string, error)
	PrimaryLANIP    func() string
	TailscaleStatus func(ctx context.Context) ([]byte, error)
}

func defaultLeaseFiles() []string {
	return []string{
		"/tmp/dhcp.leases",
		"/var/lib/misc/dnsmasq.leases",
		"/var/lib/dhcp/dhcpd.leases",
	}
}

func defaultTailscaleStatusJSON(ctx context.Context) ([]byte, error) {
	bin, err := exec.LookPath("tailscale")
	if err != nil {
		return nil, err
	}
	qCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	return exec.CommandContext(qCtx, bin, "status", "--json").Output()
}

func firstIPv4(ips []string) string {
	for _, raw := range ips {
		if addr, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil && addr.Unmap().Is4() {
			return addr.Unmap().String()
		}
	}
	for _, raw := range ips {
		if addr, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
			return addr.Unmap().String()
		}
	}
	return ""
}

// DiscoverDevices 聚合本机路由、局域网 DHCP/ARP 终端与 Tailscale 同组网节点。
func DiscoverDevices(ctx context.Context, deps DiscoveryDeps) DiscoverySnapshot {
	if ctx == nil {
		ctx = context.Background()
	}
	var snap DiscoverySnapshot

	hostFn := deps.HostnameFunc
	if hostFn == nil {
		hostFn = os.Hostname
	}
	if h, err := hostFn(); err == nil {
		snap.Self.Hostname = strings.TrimSpace(h)
	}
	lanIPFn := deps.PrimaryLANIP
	if lanIPFn == nil {
		lanIPFn = netx.GetPrimaryLANIPv4
	}
	snap.Self.LANIP = strings.TrimSpace(lanIPFn())

	// 1. 解析 Tailscale status --json（获取本机 TS IP、广播子网与对端节点）
	tsFn := deps.TailscaleStatus
	if tsFn == nil {
		tsFn = defaultTailscaleStatusJSON
	}
	if rawTS, err := tsFn(ctx); err == nil && len(rawTS) > 0 {
		var st struct {
			BackendState string `json:"BackendState"`
			Self         struct {
				HostName         string   `json:"HostName"`
				TailscaleIPs     []string `json:"TailscaleIPs"`
				AdvertisedRoutes []string `json:"AdvertisedRoutes"`
				Online           bool     `json:"Online"`
			} `json:"Self"`
			Peer map[string]struct {
				HostName      string   `json:"HostName"`
				DNSName       string   `json:"DNSName"`
				TailscaleIPs  []string `json:"TailscaleIPs"`
				Online        bool     `json:"Online"`
				OS            string   `json:"OS"`
				PrimaryRoutes []string `json:"PrimaryRoutes"`
			} `json:"Peer"`
		}
		if json.Unmarshal(rawTS, &st) == nil {
			if st.Self.HostName != "" && (snap.Self.Hostname == "" || strings.EqualFold(snap.Self.Hostname, "openwrt")) {
				snap.Self.Hostname = strings.TrimSpace(st.Self.HostName)
			}
			snap.Self.TailscaleIP = firstIPv4(st.Self.TailscaleIPs)
			snap.Self.TailscaleOnline = st.BackendState == "Running" && snap.Self.TailscaleIP != ""
			for _, r := range st.Self.AdvertisedRoutes {
				r = strings.TrimSpace(r)
				if r == "" || r == "0.0.0.0/0" || r == "::/0" {
					continue
				}
				if pfx, pErr := netip.ParsePrefix(r); pErr == nil {
					snap.Self.AdvertisedSubnets = append(snap.Self.AdvertisedSubnets, pfx.Masked().String())
				}
			}
			slices.Sort(snap.Self.AdvertisedSubnets)
			snap.Self.AdvertisedSubnets = slices.Compact(snap.Self.AdvertisedSubnets)

			for _, p := range st.Peer {
				tsIP := firstIPv4(p.TailscaleIPs)
				if tsIP == "" {
					continue
				}
				host := strings.TrimSpace(p.HostName)
				dnsName := strings.TrimSuffix(strings.TrimSpace(p.DNSName), ".")
				var subs []string
				for _, r := range p.PrimaryRoutes {
					r = strings.TrimSpace(r)
					if r != "" && r != "0.0.0.0/0" && r != "::/0" {
						subs = append(subs, r)
					}
				}
				snap.TailscalePeers = append(snap.TailscalePeers, DiscoveredTailscalePeer{
					Hostname:       cmp.Or(host, dnsName),
					DNSName:        dnsName,
					SuggestedAlias: config.SanitizeSuggestedAlias(cmp.Or(host, dnsName)),
					TailscaleIP:    tsIP,
					Online:         p.Online,
					OS:             strings.TrimSpace(p.OS),
					Subnets:        subs,
				})
			}
			slices.SortFunc(snap.TailscalePeers, func(a, b DiscoveredTailscalePeer) int {
				if a.Online != b.Online {
					if a.Online {
						return -1
					}
					return 1
				}
				return cmp.Compare(strings.ToLower(a.Hostname), strings.ToLower(b.Hostname))
			})
		}
	}
	snap.Self.SuggestedAlias = cmp.Or(config.SanitizeSuggestedAlias(snap.Self.Hostname), "router")

	// 2. 解析局域网 DHCP 租约与 ARP 表
	leaseFiles := deps.LeaseFiles
	if len(leaseFiles) == 0 {
		leaseFiles = defaultLeaseFiles()
	}
	arpFile := cmp.Or(strings.TrimSpace(deps.ARPFile), "/proc/net/arp")

	byIP := make(map[string]*DiscoveredLANDevice)
	for _, lf := range leaseFiles {
		raw, err := os.ReadFile(lf)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(raw), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 4 {
				continue
			}
			mac := config.NormalizeMAC(fields[1])
			addr, pErr := netip.ParseAddr(fields[2])
			if pErr != nil || !addr.Unmap().Is4() {
				continue
			}
			ipStr := addr.Unmap().String()
			host := strings.TrimSpace(fields[3])
			if host == "*" {
				host = ""
			}
			cur, ok := byIP[ipStr]
			if !ok {
				cur = &DiscoveredLANDevice{IP: ipStr}
				byIP[ipStr] = cur
			}
			cur.MAC = cmp.Or(cur.MAC, mac)
			cur.Hostname = cmp.Or(cur.Hostname, host)
		}
	}

	if rawARP, err := os.ReadFile(arpFile); err == nil {
		for line := range strings.SplitSeq(string(rawARP), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 6 {
				continue
			}
			addr, pErr := netip.ParseAddr(fields[0])
			if pErr != nil || !addr.Unmap().Is4() {
				continue
			}
			mac := config.NormalizeMAC(fields[3])
			if mac == "" {
				continue
			}
			ipStr := addr.Unmap().String()
			flags := strings.ToLower(strings.TrimSpace(fields[2]))
			iface := strings.TrimSpace(fields[5])
			// 跳过 WAN 口与回环条目
			if strings.HasPrefix(iface, "pppoe") || strings.HasPrefix(iface, "wan") || iface == "lo" {
				continue
			}
			cur, ok := byIP[ipStr]
			if !ok {
				cur = &DiscoveredLANDevice{IP: ipStr}
				byIP[ipStr] = cur
			}
			cur.MAC = cmp.Or(cur.MAC, mac)
			cur.Interface = cmp.Or(cur.Interface, iface)
			if flags != "0x0" {
				cur.Online = true
			}
		}
	}

	for _, dev := range byIP {
		if dev.IP == snap.Self.LANIP {
			continue
		}
		dev.SuggestedAlias = config.SanitizeSuggestedAlias(dev.Hostname)
		snap.LANDevices = append(snap.LANDevices, *dev)
	}
	slices.SortFunc(snap.LANDevices, func(a, b DiscoveredLANDevice) int {
		if a.Online != b.Online {
			if a.Online {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.IP, b.IP)
	})
	return snap
}

// ParseAdvertisedPrefixes 将字符串 CIDR 列表解析为有效 netip.Prefix 切片。
func ParseAdvertisedPrefixes(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// EvaluateReachability 评估指定设备在外部网络（咖啡馆/5G 经 Tailscale）的可达性，并为未广播子网的跨路由设备匹配推荐 Tailscale IP。
func EvaluateReachability(dev config.HomeDomainDevice, advertisedSubnets []netip.Prefix, tsPeers []DiscoveredTailscalePeer) ReachabilityInfo {
	addr, err := netip.ParseAddr(strings.TrimSpace(dev.IP))
	if err != nil {
		return ReachabilityInfo{Status: "lan_only", Label: "地址无效"}
	}
	addr = addr.Unmap()
	if tailscale.IsTailscaleAddr(addr.String()) {
		return ReachabilityInfo{
			Status: "tailscale",
			Label:  "外网直达 (Tailscale)",
		}
	}
	for _, pfx := range advertisedSubnets {
		if pfx.Contains(addr) {
			return ReachabilityInfo{
				Status: "subnet",
				Label:  "外网可达 (已广播子网)",
			}
		}
	}
	info := ReachabilityInfo{
		Status: "lan_only",
		Label:  "仅内网可达",
		Hint:   "该设备 IP 未包含在本机 Tailscale 广播子网中，外出连接时可能无法直达",
	}
	aliasLower := strings.ToLower(strings.TrimSpace(dev.Alias))
	for _, p := range tsPeers {
		if p.TailscaleIP == "" {
			continue
		}
		if aliasLower != "" && (strings.EqualFold(p.SuggestedAlias, aliasLower) || strings.EqualFold(p.Hostname, aliasLower)) {
			info.SuggestedTailscaleIP = p.TailscaleIP
			info.Hint = "检测到同名 Tailscale 节点，建议一键改用 Tailscale IP 以实现全网直达"
			break
		}
	}
	return info
}

// ReconcileDHCPAddresses 按 MAC 地址比对最新局域网 DHCP/ARP 快照，当设备更换 IP 时自动跟随更新并返回变更列表。
func ReconcileDHCPAddresses(cfg *config.Config, lanDevices []DiscoveredLANDevice) (bool, []string) {
	if cfg == nil || !cfg.HomeDomain.IsEnabled() || !cfg.HomeDomain.IsFollowDHCPEnabled() || len(cfg.HomeDomain.Devices) == 0 || len(lanDevices) == 0 {
		return false, nil
	}
	ipByMAC := make(map[string]string, len(lanDevices))
	for _, d := range lanDevices {
		mac := config.NormalizeMAC(d.MAC)
		if mac == "" || strings.TrimSpace(d.IP) == "" {
			continue
		}
		if _, exists := ipByMAC[mac]; !exists || d.Online {
			ipByMAC[mac] = strings.TrimSpace(d.IP)
		}
	}

	changed := false
	var updates []string
	for i := range cfg.HomeDomain.Devices {
		dev := &cfg.HomeDomain.Devices[i]
		// 仅自动跟随局域网 IP（绝不覆盖用户主动绑定的 Tailscale 100.x IP）
		if tailscale.IsTailscaleAddr(dev.IP) {
			continue
		}
		mac := config.NormalizeMAC(dev.MAC)
		if mac == "" {
			continue
		}
		newIP, ok := ipByMAC[mac]
		if !ok || newIP == "" || newIP == dev.IP {
			continue
		}
		oldIP := dev.IP
		dev.IP = newIP
		changed = true
		updates = append(updates, dev.Alias+": "+oldIP+" -> "+newIP)
	}
	return changed, updates
}
