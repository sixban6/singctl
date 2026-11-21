// 文件职责：负责读取与解析内核 nftables security 表态势、构建分页黑名单总览及解析内核拦截日志。
package firewall

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/platform/servicemgr"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// QuickStatus 描述防火墙在内核与开机自启层的轻量真实状态。
type QuickStatus struct {
	Supported        bool   `json:"supported"`
	Enabled          bool   `json:"enabled"`
	KernelActive     bool   `json:"kernelActive"`
	AutostartEnabled bool   `json:"autostartEnabled"`
	Drifted          bool   `json:"drifted"`
	Mode             string `json:"mode"`
	NFTAvailable     bool   `json:"nftAvailable"`
	IsOpenWrt        bool   `json:"isOpenWrt"`
}

// CounterStat 记录某类规则的累计丢包次数与字节数。
type CounterStat struct {
	Packets int64 `json:"packets"`
	Bytes   int64 `json:"bytes"`
}

// SecurityStats 汇总 `nftables inet security` 表的实时拦截战果与容量统计。
type SecurityStats struct {
	TotalBlockedPackets int64       `json:"totalBlockedPackets"`
	TotalBlockedBytes   int64       `json:"totalBlockedBytes"`
	ForeverBlocked      CounterStat `json:"foreverBlocked"`
	DynamicV4Blocked    CounterStat `json:"dynamicV4Blocked"`
	DynamicV6Blocked    CounterStat `json:"dynamicV6Blocked"`
	HoneypotTCPV4       CounterStat `json:"honeypotTcpV4"`
	HoneypotUDPv4       CounterStat `json:"honeypotUdpV4"`
	HoneypotTCPV6       CounterStat `json:"honeypotTcpV6"`
	HoneypotUDPv6       CounterStat `json:"honeypotUdpV6"`
	DynamicV4Count      int         `json:"dynamicV4Count"`
	DynamicV6Count      int         `json:"dynamicV6Count"`
	ForeverCount        int         `json:"foreverCount"`
	ProtectedPortCount  int         `json:"protectedPortCount"`
	WhitelistCount      int         `json:"whitelistCount"`
}

// PreflightInfo 提供启用防火墙前的“防自锁透明预检清单”。
type PreflightInfo struct {
	CallerIP           string   `json:"callerIp,omitempty"`
	DetectedSSHPorts   []int    `json:"detectedSSHPorts"`
	ProtectedTunnels   []string `json:"protectedTunnels"`
	ProtectedLANRanges []string `json:"protectedLanRanges"`
	ExemptServicePorts []int    `json:"exemptServicePorts"`
	CoexistingTables   []string `json:"coexistingTables,omitempty"`
}

// BanItem 描述一条黑名单中的 IP 或网段。
type BanItem struct {
	Target     string `json:"target"`
	Scope      string `json:"scope"` // "dynamic_v4" | "dynamic_v6" | "forever"
	ExpiresSec int64  `json:"expiresSec,omitempty"`
	Builtin    bool   `json:"builtin,omitempty"`
}

// PaginatedBans 是服务端过滤分页后的封禁列表视图。
type PaginatedBans struct {
	Items    []BanItem `json:"items"`
	Total    int       `json:"total"`
	Page     int       `json:"page"`
	PageSize int       `json:"pageSize"`
}

// WhitelistView 区分系统内置防锁死段、配置文件持久化段与内核现存附加项。
type WhitelistView struct {
	Builtin   []string `json:"builtin"`
	Custom    []string `json:"custom"`
	LiveExtra []string `json:"liveExtra,omitempty"`
}

// EffectiveFirewallConfig 返回经过默认值归一化的防火墙生效配置视图。
type EffectiveFirewallConfig struct {
	Mode            string   `json:"mode"`
	BanTimeoutDays  int      `json:"banTimeoutDays"`
	PingLimitPerSec int      `json:"pingLimitPerSec"`
	ProtectedPorts  []int    `json:"protectedPorts"`
	Whitelist       []string `json:"whitelist"`
	ExtraForeverBan []string `json:"extraForeverBan"`
}

// OverviewQuery 控制服务端分页检索封禁集合时的筛选条件。
type OverviewQuery struct {
	Scope    string
	Search   string
	SortBy   string
	Page     int
	PageSize int
}

// OverviewResponse 为 WebUI 防火墙加固页提供一站式全透明态势视图。
type OverviewResponse struct {
	Status             QuickStatus             `json:"status"`
	Stats              SecurityStats           `json:"stats"`
	Preflight          PreflightInfo           `json:"preflight"`
	Config             EffectiveFirewallConfig `json:"config"`
	Bans               PaginatedBans           `json:"bans"`
	Whitelist          WhitelistView           `json:"whitelist"`
	ProtectedPortsLive []int                   `json:"protectedPortsLive,omitempty"`
	PortCatalog        []PortCatalogEntry      `json:"portCatalog"`
	CompactRuleText    string                  `json:"compactRuleText,omitempty"`
}

// NFTLogEvent 描述从内核日志提取并脱敏（剥离路由器公网 DST IP）的单条 [NFT] 拦截记录。
type NFTLogEvent struct {
	Time     string `json:"time"`
	Category string `json:"category"`
	Prefix   string `json:"prefix"`
	Iface    string `json:"iface,omitempty"`
	SrcIP    string `json:"srcIp"`
	Proto    string `json:"proto,omitempty"`
	DstPort  int    `json:"dstPort,omitempty"`
}

// KernelSnapshot 存储从 `nft -j list table inet security` 解析出的结构化实时状态。
type KernelSnapshot struct {
	Active          bool
	Mode            string
	BanTimeoutDays  int
	PingLimitPerSec int
	Stats           SecurityStats
	DynamicV4       []BanItem
	DynamicV6       []BanItem
	ForeverV4       []string
	WhitelistV4     []string
	WhitelistV6     []string
	ProtectedPorts  []int
}

var reservedAntiLockPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

var protectedPublicDNSIPs = []string{
	"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
	"223.5.5.5", "223.6.6.6", "119.29.29.29", "1.12.12.12", "120.53.53.53",
	"2400:3200::1", "2400:3200:baba::1", "2001:4860:4860::8888", "2606:4700:4700::1111",
}

// InspectQuickStatus 同时核验开机自启持久化文件与内核 `table inet security` 存活态（识别规则漂移/假开启）。
func InspectQuickStatus() QuickStatus {
	st := QuickStatus{
		Mode:      "standard",
		IsOpenWrt: servicemgr.IsOpenWrt(),
	}
	if runtime.GOOS != "linux" {
		return st
	}
	st.Supported = true
	_, lookErr := exec.LookPath("nft")
	st.NFTAvailable = lookErr == nil
	st.AutostartEnabled = fileExists(constant.SingBoxNftablesFile) ||
		fileExists(constant.FirewallSystemdService) ||
		fileExists(constant.FirewallInitdScript)

	if st.NFTAvailable {
		if snap, err := readLiveSecurityTableTerse(); err == nil && snap != nil && snap.Active {
			st.KernelActive = true
			if snap.Mode != "" {
				st.Mode = snap.Mode
			}
		}
	}
	st.Enabled = st.KernelActive || st.AutostartEnabled
	st.Drifted = (st.AutostartEnabled && !st.KernelActive) || (st.KernelActive && !st.AutostartEnabled)
	return st
}

const defaultNFTReadTimeout = 3 * time.Second

func runCmdWithTimeout(timeout time.Duration, bin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, bin, args...).Output()
}

func readSecurityTableWithArgs(args ...string) (*KernelSnapshot, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("not linux")
	}
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		return nil, err
	}
	out, err := runCmdWithTimeout(defaultNFTReadTimeout, nftBin, args...)
	if err != nil {
		return nil, err
	}
	return ParseSecurityTableJSON(out)
}

func readLiveSecurityTable() (*KernelSnapshot, error) {
	return readSecurityTableWithArgs("-j", "list", "table", "inet", "security")
}

func readLiveSecurityTableTerse() (*KernelSnapshot, error) {
	return readSecurityTableWithArgs("-t", "-j", "list", "table", "inet", "security")
}

func readLiveSecurityText() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		return ""
	}
	out, err := runCmdWithTimeout(defaultNFTReadTimeout, nftBin, "list", "table", "inet", "security")
	if err != nil {
		return ""
	}
	return string(out)
}

func listCoexistingTables() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		return nil
	}
	out, err := runCmdWithTimeout(defaultNFTReadTimeout, nftBin, "list", "tables")
	if err != nil {
		return nil
	}
	var tables []string
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			tables = append(tables, line)
		}
	}
	return tables
}

// ParseSecurityTableJSON 解析 `nft -j list table inet security` 的官方 JSON 输出，提取各集合元素、TTL 与流量计数器。
func ParseSecurityTableJSON(raw []byte) (*KernelSnapshot, error) {
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode nft json: %w", err)
	}
	snap := &KernelSnapshot{
		Mode:            "minimal",
		BanTimeoutDays:  7,
		PingLimitPerSec: 10,
	}

	builtinForeverSet := make(map[string]struct{}, len(defaultForeverBlocklistV4))
	for _, c := range defaultForeverBlocklistV4 {
		builtinForeverSet[c] = struct{}{}
	}
	if _, ok := builtinForeverSet["167.94.145.0/24"]; ok {
		// 内核 auto-merge 会将相邻 167.94.145.0/24 + 167.94.146.0/24 合并为 range
		builtinForeverSet["167.94.145.0-167.94.146.255"] = struct{}{}
	}

	hasProtectedPortsSet := false
	for _, entry := range doc.NFTables {
		if rawTable, ok := entry["table"]; ok {
			var tbl struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(rawTable, &tbl) == nil && tbl.Name == "security" {
				snap.Active = true
			}
		}

		if rawSet, ok := entry["set"]; ok {
			var s struct {
				Name    string            `json:"name"`
				Timeout int64             `json:"timeout"`
				Elem    []json.RawMessage `json:"elem"`
			}
			if err := json.Unmarshal(rawSet, &s); err != nil {
				continue
			}
			switch s.Name {
			case "blocklist_ip4_forever":
				for _, re := range s.Elem {
					val, _ := parseNFTAddrElem(re)
					if val != "" {
						snap.ForeverV4 = append(snap.ForeverV4, val)
					}
				}
			case "blocklist_ip4":
				if s.Timeout > 0 {
					snap.BanTimeoutDays = max(1, int(s.Timeout/86400))
				}
				for _, re := range s.Elem {
					val, exp := parseNFTAddrElem(re)
					if val != "" {
						snap.DynamicV4 = append(snap.DynamicV4, BanItem{
							Target:     val,
							Scope:      "dynamic_v4",
							ExpiresSec: exp,
						})
					}
				}
			case "blocklist_ip6":
				if s.Timeout > 0 {
					snap.BanTimeoutDays = max(1, int(s.Timeout/86400))
				}
				for _, re := range s.Elem {
					val, exp := parseNFTAddrElem(re)
					if val != "" {
						snap.DynamicV6 = append(snap.DynamicV6, BanItem{
							Target:     val,
							Scope:      "dynamic_v6",
							ExpiresSec: exp,
						})
					}
				}
			case "whitelist_ip":
				for _, re := range s.Elem {
					val, _ := parseNFTAddrElem(re)
					if val != "" {
						snap.WhitelistV4 = append(snap.WhitelistV4, val)
					}
				}
			case "whitelist_ip6":
				for _, re := range s.Elem {
					val, _ := parseNFTAddrElem(re)
					if val != "" {
						snap.WhitelistV6 = append(snap.WhitelistV6, val)
					}
				}
			case "protected_ports":
				hasProtectedPortsSet = true
				for _, re := range s.Elem {
					snap.ProtectedPorts = append(snap.ProtectedPorts, parseNFTPortElem(re)...)
				}
			}
		}

		if rawRule, ok := entry["rule"]; ok {
			var r struct {
				Chain string            `json:"chain"`
				Expr  []json.RawMessage `json:"expr"`
			}
			if json.Unmarshal(rawRule, &r) != nil || r.Chain != "input" {
				continue
			}
			var prefix string
			var ctr CounterStat
			var hasDrop bool
			var icmpRate int
			for _, ex := range r.Expr {
				var m map[string]json.RawMessage
				if json.Unmarshal(ex, &m) != nil {
					continue
				}
				if rawLog, ok := m["log"]; ok {
					var l struct {
						Prefix string `json:"prefix"`
					}
					if json.Unmarshal(rawLog, &l) == nil {
						prefix = l.Prefix
					}
				}
				if rawCtr, ok := m["counter"]; ok {
					_ = json.Unmarshal(rawCtr, &ctr)
				}
				if _, ok := m["drop"]; ok {
					hasDrop = true
				}
				if rawLim, ok := m["limit"]; ok {
					var lim struct {
						Rate int    `json:"rate"`
						Per  string `json:"per"`
					}
					if json.Unmarshal(rawLim, &lim) == nil && lim.Per == "second" && lim.Rate > 0 {
						icmpRate = lim.Rate
					}
				}
			}
			if icmpRate > 0 && prefix == "" && !hasDrop {
				snap.PingLimitPerSec = icmpRate
			}
			if !hasDrop {
				continue
			}
			switch {
			case strings.Contains(prefix, "Ban Forever IPv4"):
				snap.Stats.ForeverBlocked = addCounterStat(snap.Stats.ForeverBlocked, ctr)
			case strings.Contains(prefix, "Blocked IPv4 (listed)"):
				snap.Stats.DynamicV4Blocked = addCounterStat(snap.Stats.DynamicV4Blocked, ctr)
			case strings.Contains(prefix, "Blocked IPv6 (listed)"):
				snap.Stats.DynamicV6Blocked = addCounterStat(snap.Stats.DynamicV6Blocked, ctr)
			case strings.Contains(prefix, "Blocked IPv4 TCP"):
				snap.Stats.HoneypotTCPV4 = addCounterStat(snap.Stats.HoneypotTCPV4, ctr)
			case strings.Contains(prefix, "Blocked IPv4 UDP"):
				snap.Stats.HoneypotUDPv4 = addCounterStat(snap.Stats.HoneypotUDPv4, ctr)
			case strings.Contains(prefix, "Blocked IPv6 TCP"):
				snap.Stats.HoneypotTCPV6 = addCounterStat(snap.Stats.HoneypotTCPV6, ctr)
			case strings.Contains(prefix, "Blocked IPv6 UDP"):
				snap.Stats.HoneypotUDPv6 = addCounterStat(snap.Stats.HoneypotUDPv6, ctr)
			}
		}
	}

	if hasProtectedPortsSet || snap.Stats.HoneypotTCPV4.Packets > 0 || len(snap.ProtectedPorts) > 0 {
		snap.Mode = "standard"
	}
	sort.Ints(snap.ProtectedPorts)
	snap.Stats.DynamicV4Count = len(snap.DynamicV4)
	snap.Stats.DynamicV6Count = len(snap.DynamicV6)
	snap.Stats.ForeverCount = len(snap.ForeverV4)
	snap.Stats.ProtectedPortCount = len(snap.ProtectedPorts)
	snap.Stats.WhitelistCount = len(snap.WhitelistV4) + len(snap.WhitelistV6)
	for _, s := range []CounterStat{
		snap.Stats.ForeverBlocked,
		snap.Stats.DynamicV4Blocked,
		snap.Stats.DynamicV6Blocked,
		snap.Stats.HoneypotTCPV4,
		snap.Stats.HoneypotUDPv4,
		snap.Stats.HoneypotTCPV6,
		snap.Stats.HoneypotUDPv6,
	} {
		snap.Stats.TotalBlockedPackets += s.Packets
		snap.Stats.TotalBlockedBytes += s.Bytes
	}
	return snap, nil
}

func addCounterStat(a, b CounterStat) CounterStat {
	return CounterStat{
		Packets: a.Packets + b.Packets,
		Bytes:   a.Bytes + b.Bytes,
	}
}

func parseNFTAddrElem(raw json.RawMessage) (string, int64) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", 0
	}
	if trimmed[0] == '"' {
		var s string
		if json.Unmarshal(trimmed, &s) == nil {
			return s, 0
		}
		return "", 0
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(trimmed, &obj) != nil {
		return "", 0
	}
	if rawElem, ok := obj["elem"]; ok {
		var inner struct {
			Val     json.RawMessage `json:"val"`
			Expires int64           `json:"expires"`
		}
		if json.Unmarshal(rawElem, &inner) == nil {
			val, _ := parseNFTAddrElem(inner.Val)
			return val, inner.Expires
		}
	}
	if rawPrefix, ok := obj["prefix"]; ok {
		var p struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		}
		if json.Unmarshal(rawPrefix, &p) == nil && p.Addr != "" {
			return fmt.Sprintf("%s/%d", p.Addr, p.Len), 0
		}
	}
	if rawRange, ok := obj["range"]; ok {
		var pair []string
		if json.Unmarshal(rawRange, &pair) == nil && len(pair) == 2 {
			return pair[0] + "-" + pair[1], 0
		}
	}
	return "", 0
}

func parseNFTPortElem(raw json.RawMessage) []int {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	if n, err := strconv.Atoi(string(trimmed)); err == nil {
		if n > 0 && n <= 65535 {
			return []int{n}
		}
		return nil
	}
	var obj struct {
		Range []int `json:"range"`
	}
	if json.Unmarshal(trimmed, &obj) == nil && len(obj.Range) == 2 {
		lo, hi := obj.Range[0], obj.Range[1]
		if lo > hi || lo < 1 || hi > 65535 || hi-lo > 512 {
			return nil
		}
		out := make([]int, 0, hi-lo+1)
		for p := lo; p <= hi; p++ {
			out = append(out, p)
		}
		return out
	}
	return nil
}

// BuildOverview 汇总防火墙实时态势、预检护栏、分页黑名单、白名单与端口配置。
func BuildOverview(_ context.Context, cfg *config.Config, callerIP string, q OverviewQuery) *OverviewResponse {
	st := InspectQuickStatus()
	opts := OptionsFromConfig(cfg, callerIP)
	sshPorts := opts.ActiveSSHPorts
	if len(sshPorts) == 0 {
		sshPorts = DetectSSHPorts()
	}

	effPorts := slices.Clone(defaultBaseProtectedPorts)
	if cfg != nil && len(cfg.Firewall.ProtectedPorts) > 0 {
		effPorts = slices.Clone(cfg.Firewall.ProtectedPorts)
	}
	sort.Ints(effPorts)

	resp := &OverviewResponse{
		Status: st,
		Preflight: PreflightInfo{
			CallerIP:           strings.TrimSpace(callerIP),
			DetectedSSHPorts:   sshPorts,
			ProtectedTunnels:   []string{"lo", "tailscale0", "wg*", "tun*", "100.64.0.0/10"},
			ProtectedLANRanges: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			ExemptServicePorts: slices.Clone(criticalServiceExemptPorts),
			CoexistingTables:   listCoexistingTables(),
		},
		Config: EffectiveFirewallConfig{
			Mode:            opts.Mode,
			BanTimeoutDays:  opts.BanTimeoutDays,
			PingLimitPerSec: opts.PingLimitPerSec,
			ProtectedPorts:  effPorts,
			Whitelist:       slices.Clone(opts.CustomWhitelist),
			ExtraForeverBan: slices.Clone(opts.ExtraForeverBan),
		},
		PortCatalog: PortCatalog(),
	}

	if cfg != nil {
		sort.Strings(resp.Config.Whitelist)
	}

	resp.Whitelist.Builtin = slices.Clone(defaultWhitelistV4)
	resp.Whitelist.Custom = slices.Clone(resp.Config.Whitelist)

	var allBans []BanItem
	builtinForever := make(map[string]struct{}, len(defaultForeverBlocklistV4)+1)
	for _, c := range defaultForeverBlocklistV4 {
		builtinForever[c] = struct{}{}
	}
	builtinForever["167.94.145.0-167.94.146.255"] = struct{}{}

	if st.KernelActive {
		if snap, err := readLiveSecurityTable(); err == nil && snap != nil && snap.Active {
			resp.Stats = snap.Stats
			resp.ProtectedPortsLive = slices.Clone(snap.ProtectedPorts)
			resp.Status.Mode = cmp.Or(snap.Mode, resp.Status.Mode)
			for _, it := range snap.DynamicV4 {
				allBans = append(allBans, it)
			}
			for _, it := range snap.DynamicV6 {
				allBans = append(allBans, it)
			}
			for _, f := range snap.ForeverV4 {
				_, isBuiltin := builtinForever[f]
				allBans = append(allBans, BanItem{
					Target:  f,
					Scope:   "forever",
					Builtin: isBuiltin,
				})
			}

			customSet := make(map[string]struct{}, len(resp.Whitelist.Custom))
			for _, cw := range resp.Whitelist.Custom {
				if norm, _, vErr := ValidateWhitelistTarget(cw); vErr == nil {
					customSet[norm] = struct{}{}
				}
			}
			for _, liveW := range slices.Concat(snap.WhitelistV4, snap.WhitelistV6) {
				if IsBuiltinWhitelist(liveW) {
					continue
				}
				if _, inCfg := customSet[liveW]; inCfg {
					continue
				}
				resp.Whitelist.LiveExtra = append(resp.Whitelist.LiveExtra, liveW)
			}

			if rawText := readLiveSecurityText(); rawText != "" {
				resp.CompactRuleText = CollapseLargeSetsInNFTText(rawText, snap)
			}
		}
	}

	resp.Bans = filterAndPaginateBans(allBans, q)
	return resp
}

func filterAndPaginateBans(all []BanItem, q OverviewQuery) PaginatedBans {
	scope := strings.ToLower(strings.TrimSpace(q.Scope))
	search := strings.ToLower(strings.TrimSpace(q.Search))
	filtered := make([]BanItem, 0, len(all))
	for _, it := range all {
		if scope != "" && scope != "all" && it.Scope != scope {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(it.Target), search) {
			continue
		}
		filtered = append(filtered, it)
	}

	switch strings.ToLower(strings.TrimSpace(q.SortBy)) {
	case "target":
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].Target < filtered[j].Target
		})
	case "scope":
		sort.Slice(filtered, func(i, j int) bool {
			if filtered[i].Scope != filtered[j].Scope {
				return filtered[i].Scope < filtered[j].Scope
			}
			return filtered[i].ExpiresSec > filtered[j].ExpiresSec
		})
	default:
		// 默认：动态新近命中（剩余 TTL 最长）排最前，永久威胁段随后
		sort.Slice(filtered, func(i, j int) bool {
			aDyn := filtered[i].Scope != "forever"
			bDyn := filtered[j].Scope != "forever"
			if aDyn != bDyn {
				return aDyn
			}
			if filtered[i].ExpiresSec != filtered[j].ExpiresSec {
				return filtered[i].ExpiresSec > filtered[j].ExpiresSec
			}
			return filtered[i].Target < filtered[j].Target
		})
	}

	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = 25
	}
	pageSize = min(100, pageSize)
	page := max(1, q.Page)

	total := len(filtered)
	start := (page - 1) * pageSize
	if start >= total {
		start = 0
		if total > 0 && page > 1 {
			lastPage := (total + pageSize - 1) / pageSize
			start = (lastPage - 1) * pageSize
			page = lastPage
		} else {
			page = 1
		}
	}
	end := min(total, start+pageSize)
	var pageItems []BanItem
	if start < end {
		pageItems = filtered[start:end]
	} else {
		pageItems = []BanItem{}
	}
	return PaginatedBans{
		Items:    pageItems,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}
}

var setCollapseBlockRe = regexp.MustCompile(`(?s)(set\s+(?:blocklist_ip4|blocklist_ip6)\s*\{.*?elements\s*=\s*\{).*?(\})`)

// CollapseLargeSetsInNFTText 将 `nft list table inet security` 中超长的动态黑名单集合折叠为摘要，便于前端轻量预览全表骨架。
func CollapseLargeSetsInNFTText(raw string, snap *KernelSnapshot) string {
	v4Count, v6Count := 0, 0
	if snap != nil {
		v4Count = len(snap.DynamicV4)
		v6Count = len(snap.DynamicV6)
	}
	return setCollapseBlockRe.ReplaceAllStringFunc(raw, func(block string) string {
		count := v4Count
		if strings.Contains(block, "set blocklist_ip6") {
			count = v6Count
		}
		if count <= 12 {
			return block
		}
		idx := strings.Index(block, "elements = {")
		if idx < 0 {
			return block
		}
		head := block[:idx+len("elements = {")]
		return fmt.Sprintf("%s /* 共 %d 条动态封禁 IP，请在「封禁名单」标签分页检索与解封 */ }", head, count)
	})
}

// ReadRecentNFTLogs 读取本机系统日志中的 `[NFT]` 拦截事件并剥离 WAN 目的 IP。
func ReadRecentNFTLogs(limit int) []NFTLogEvent {
	if limit <= 0 {
		limit = 50
	}
	if runtime.GOOS != "linux" {
		return []NFTLogEvent{}
	}
	var raw []byte
	if bin, err := exec.LookPath("logread"); err == nil {
		if out, err := runCmdWithTimeout(defaultNFTReadTimeout, bin); err == nil && len(out) > 0 {
			raw = out
		}
	}
	if len(raw) == 0 {
		if bin, err := exec.LookPath("dmesg"); err == nil {
			if out, err := runCmdWithTimeout(defaultNFTReadTimeout, bin, "-T"); err == nil && len(out) > 0 {
				raw = out
			} else if out, err := runCmdWithTimeout(defaultNFTReadTimeout, bin); err == nil && len(out) > 0 {
				raw = out
			}
		}
	}
	if len(raw) == 0 {
		if bin, err := exec.LookPath("journalctl"); err == nil {
			if out, err := runCmdWithTimeout(defaultNFTReadTimeout, bin, "-k", "-n", "300", "--no-pager"); err == nil {
				raw = out
			}
		}
	}
	return ParseNFTLogLines(string(raw), limit)
}

var nftPrefixTimeRe = regexp.MustCompile(`^(?:[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?|\[[^\]]+\]|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})`)

// ParseNFTLogLines 解析原始内核日志文本中的 `[NFT]` 行，故意不保留目的公网 IP (`DST=`) 以保护路由器外网隐私。
func ParseNFTLogLines(raw string, limit int) []NFTLogEvent {
	if limit <= 0 {
		limit = 50
	}
	var events []NFTLogEvent
	for line := range strings.SplitSeq(raw, "\n") {
		if !strings.Contains(line, "[NFT]") {
			continue
		}
		ev := NFTLogEvent{
			Category: "拦截",
		}
		if m := nftPrefixTimeRe.FindString(strings.TrimSpace(line)); m != "" {
			ev.Time = strings.Trim(m, "[] ")
		}

		idx := strings.Index(line, "[NFT]")
		rest := line[idx:]
		if colon := strings.Index(rest, ":"); colon > 0 {
			ev.Prefix = strings.TrimSpace(rest[:colon+1])
			rest = rest[colon+1:]
		} else {
			ev.Prefix = "[NFT]"
		}

		switch {
		case strings.Contains(ev.Prefix, "Ban Forever"):
			ev.Category = "永久黑段拦截"
		case strings.Contains(ev.Prefix, "Blocked IPv4 (listed)"):
			ev.Category = "IPv4 黑名单阻断"
		case strings.Contains(ev.Prefix, "Blocked IPv6 (listed)"):
			ev.Category = "IPv6 黑名单阻断"
		case strings.Contains(ev.Prefix, "Blocked IPv4 TCP"):
			ev.Category = "IPv4 高危 TCP 诱捕"
		case strings.Contains(ev.Prefix, "Blocked IPv4 UDP"):
			ev.Category = "IPv4 高危 UDP 诱捕"
		case strings.Contains(ev.Prefix, "Blocked IPv6 TCP"):
			ev.Category = "IPv6 高危 TCP 诱捕"
		case strings.Contains(ev.Prefix, "Blocked IPv6 UDP"):
			ev.Category = "IPv6 高危 UDP 诱捕"
		}

		for _, tok := range strings.Fields(rest) {
			switch {
			case strings.HasPrefix(tok, "IN="):
				ev.Iface = strings.TrimPrefix(tok, "IN=")
			case strings.HasPrefix(tok, "SRC="):
				ev.SrcIP = strings.TrimPrefix(tok, "SRC=")
			case strings.HasPrefix(tok, "PROTO="):
				ev.Proto = strings.TrimPrefix(tok, "PROTO=")
			case strings.HasPrefix(tok, "DPT="):
				if p, err := strconv.Atoi(strings.TrimPrefix(tok, "DPT=")); err == nil {
					ev.DstPort = p
				}
			}
		}
		if ev.SrcIP == "" {
			continue
		}
		events = append(events, ev)
	}

	if len(events) == 0 {
		return []NFTLogEvent{}
	}
	slices.Reverse(events)
	if len(events) > limit {
		events = events[:limit]
	}
	return events
}
