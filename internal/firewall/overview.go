// 文件职责：组装防火墙全透明态势总览、分页过滤封禁名单、折叠长规则集合文本并解析脱敏内核 [NFT] 拦截日志。
package firewall

import (
	"cmp"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"singctl/internal/config"
	"slices"
	"sort"
	"strconv"
	"strings"
)

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
