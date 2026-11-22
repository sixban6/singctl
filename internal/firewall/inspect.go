// 文件职责：定义防火墙态势数据结构，并负责读取与解析内核 `nftables inet security` 表 JSON 快照。
package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"singctl/internal/constant"
	"singctl/internal/platform/servicemgr"
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
