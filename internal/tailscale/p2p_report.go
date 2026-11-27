// 文件职责：提供 Tailscale P2P 防线配置归一化校验与管理面板状态报告视图合并构建。
package tailscale

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"time"

	"singctl/internal/config"
)

// P2PPeerView 描述管理面板单节点 P2P 直连状态、公网候选数与双向授权视图。
type P2PPeerView struct {
	ID                        string   `json:"id"`
	Name                      string   `json:"name"`
	ShortName                 string   `json:"shortName"`
	DNSName                   string   `json:"dnsName,omitempty"`
	HostName                  string   `json:"hostName,omitempty"`
	TailscaleIPs              []string `json:"tailscaleIPs,omitempty"`
	PrimaryRoutes             []string `json:"primaryRoutes,omitempty"`
	Online                    bool     `json:"online"`
	Active                    bool     `json:"active"`
	Direct                    bool     `json:"direct"`
	CurAddr                   string   `json:"curAddr,omitempty"`
	Relay                     string   `json:"relay,omitempty"`
	CandidatePublicCount      int      `json:"candidatePublicCount"`
	Configured                bool     `json:"configured"`
	JITEnabled                bool     `json:"jitEnabled"`
	AccessMode                string   `json:"accessMode"`
	EffectiveAccessMode       string   `json:"effectiveAccessMode"`
	BidirectionalUntil        string   `json:"bidirectionalUntil,omitempty"`
	BidirectionalRemainingSec int      `json:"bidirectionalRemainingSec"`
	AllowedLANTargets         []string `json:"allowedLanTargets,omitempty"`
	PinholeActive             bool     `json:"pinholeActive"`
	CooldownRemainingSec      int      `json:"cooldownRemainingSec"`
	LastUpgradeAt             string   `json:"lastUpgradeAt,omitempty"`
	LastResult                string   `json:"lastResult,omitempty"`
}

// P2PReportOptions 封装构建 Tailscale P2P 防线管理面板报告所需的全部显式输入。
type P2PReportOptions struct {
	Config         *config.Config
	Controller     *P2PAssistController
	DaemonRuntime  *P2PRuntimeSnapshot
	DaemonRunning  bool
	Supported      bool
	IsOpenWrt      bool
	FW4Available   bool
	UjailAvailable bool
	DefaultLANCIDR string
	Now            time.Time
}

// NormalizeAndValidateP2PAssistConfig 校验并归一化 Tailscale P2P 防线配置。
func NormalizeAndValidateP2PAssistConfig(raw config.TailscaleP2PAssistConfig) (config.TailscaleP2PAssistConfig, error) {
	roleMode := strings.ToLower(strings.TrimSpace(raw.RoleMode))
	switch roleMode {
	case "", "client", "router", "exit", "gateway":
	default:
		return config.TailscaleP2PAssistConfig{}, fmt.Errorf("运行角色 %q 无效（仅支持 client / router / exit / gateway）", raw.RoleMode)
	}

	pf := true
	da := raw.EffectiveDownstreamAssist()
	out := config.TailscaleP2PAssistConfig{
		Enabled:          true,
		RoleMode:         roleMode,
		JITWindowSec:     min(max(3, cmp.Or(raw.JITWindowSec, 5)), 10),
		CooldownSec:      min(max(30, cmp.Or(raw.CooldownSec, 300)), 3600),
		SandboxUjail:     raw.SandboxUjail,
		ListenPort:       raw.EffectiveListenPort(),
		PayloadFilter:    &pf,
		DownstreamAssist: &da,
	}

	ruleSeen := make(map[string]struct{}, len(raw.LocalRules))
	for _, r := range raw.LocalRules {
		rawCIDR := strings.TrimSpace(r.CIDR)
		if rawCIDR == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(rawCIDR)
		if err != nil {
			return out, fmt.Errorf("本地网段规则 %q 格式无效: %w", r.CIDR, err)
		}
		pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()).Masked()
		cidrStr := pfx.String()
		if _, dup := ruleSeen[cidrStr]; dup {
			continue
		}
		ruleSeen[cidrStr] = struct{}{}

		normScope, ok := config.NormalizeTailscaleSubnetScope(r.Scope)
		if !ok {
			return out, fmt.Errorf("网段 %s 的设备限制模式 %q 无效（仅支持 all / allowlist / denylist）", cidrStr, r.Scope)
		}

		var devs []string
		devSeen := make(map[string]struct{}, len(r.Devices))
		for _, rawDev := range r.Devices {
			dStr := strings.TrimSpace(rawDev)
			if dStr == "" {
				continue
			}
			addr, err := netip.ParseAddr(dStr)
			if err != nil {
				return out, fmt.Errorf("网段 %s 内的设备 IP %q 格式无效: %w", cidrStr, rawDev, err)
			}
			addr = addr.Unmap()
			if !pfx.Contains(addr) {
				return out, fmt.Errorf("设备 IP %s 不属于网段 %s", addr.String(), cidrStr)
			}
			normIP := addr.String()
			if _, dup := devSeen[normIP]; dup {
				continue
			}
			devSeen[normIP] = struct{}{}
			devs = append(devs, normIP)
		}

		out.LocalRules = append(out.LocalRules, config.TailscaleLocalSubnetRule{
			CIDR:    cidrStr,
			Scope:   normScope,
			Devices: devs,
		})
	}

	seen := make(map[string]struct{}, len(raw.Peers))
	for _, p := range raw.Peers {
		id := strings.TrimSpace(p.ID)
		name := strings.TrimSpace(p.Name)
		tsIP := strings.TrimSpace(p.TailscaleIP)
		if id == "" && name == "" && tsIP == "" {
			continue
		}
		if tsIP != "" {
			addr, err := netip.ParseAddr(tsIP)
			if err != nil {
				return out, fmt.Errorf("节点 %q 的 tailscale_ip %q 格式无效: %w", cmp.Or(name, id), tsIP, err)
			}
			tsIP = addr.Unmap().String()
		}

		normMode, ok := config.NormalizeTailscaleAccessMode(p.AccessMode)
		if !ok {
			return out, fmt.Errorf("节点 %q 的访问模式 %q 无效（仅支持 outbound_only / bidirectional_timed / bidirectional）", cmp.Or(name, id), p.AccessMode)
		}

		until := strings.TrimSpace(p.BidirectionalUntil)
		if normMode == config.TailscaleAccessBidirectionalTimed {
			if until == "" {
				return out, fmt.Errorf("节点 %q 启用限时双向互访时必须设置失效时间 bidirectional_until (RFC3339)", cmp.Or(name, id))
			}
			parsed, err := time.Parse(time.RFC3339, until)
			if err != nil {
				return out, fmt.Errorf("节点 %q 的 bidirectional_until %q 须为 RFC3339 时间格式", cmp.Or(name, id), until)
			}
			until = parsed.UTC().Format(time.RFC3339)
		} else {
			until = ""
		}

		var targets []string
		for _, rawTarget := range p.AllowedLANTargets {
			parsedTarget, err := ParseAllowedLANTarget(rawTarget)
			if err != nil {
				return out, fmt.Errorf("节点 %q 的 allowed_lan_targets 无效: %w", cmp.Or(name, id), err)
			}
			targets = append(targets, parsedTarget.Raw)
		}

		dedupKey := cmp.Or(id, tsIP, strings.ToLower(name))
		if _, dup := seen[dedupKey]; dup {
			continue
		}
		seen[dedupKey] = struct{}{}

		out.Peers = append(out.Peers, config.TailscaleP2PPeerConfig{
			ID:                 id,
			Name:               cmp.Or(name, id, tsIP),
			TailscaleIP:        tsIP,
			JITEnabled:         p.JITEnabled,
			AccessMode:         normMode,
			BidirectionalUntil: until,
			AllowedLANTargets:  targets,
		})
	}
	return out, nil
}

// BuildP2PReport 合并 LocalAPI 拓扑、fw4 实时开孔、看门狗持久化状态与用户配置生成管理报告。
func BuildP2PReport(ctx context.Context, opts P2PReportOptions) map[string]any {
	cfg := opts.Config
	if cfg == nil {
		cfg = &config.Config{}
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	ctrl := opts.Controller
	if ctrl == nil {
		ctrl = &P2PAssistController{}
	}
	p2pCfg := cfg.Tailscale.P2PAssist

	api := ctrl.EffectiveLocalAPI()
	statusSnap, statusErr := api.Status(ctx)
	var netmapSnap *NetMapSnapshot
	if statusErr == nil && statusSnap != nil {
		netmapSnap, _ = api.NetMap(ctx)
	}

	selfIPs := resolveReportSelfIPs(statusSnap, netmapSnap, ctrl)
	fw4Mgr := ctrl.FW4
	if fw4Mgr == nil {
		fw4Mgr = &FW4Manager{}
	}
	openCount, openIPs := fw4Mgr.CountOpenPinholes(ctx)

	mergedStates, runtimeSummary := mergePeerRuntimeStates(p2pCfg.Enabled, openCount, openIPs, opts.DaemonRuntime, ctrl.PeerStates())

	var livePeers []PeerStatus
	selfID := ""
	tsRunning := false
	if statusSnap != nil {
		livePeers = statusSnap.Peers
		selfID = statusSnap.Self.ID
		tsRunning = strings.EqualFold(statusSnap.BackendState, "Running")
	}

	ruleByPeerID := make(map[string]config.TailscaleP2PPeerConfig)
	matchedRuleIdx := make(map[int]bool)
	for i, rule := range p2pCfg.Peers {
		if m, ok := MatchConfiguredPeer(rule, livePeers, selfID); ok && m != nil {
			ruleByPeerID[m.ID] = rule
			matchedRuleIdx[i] = true
		}
	}

	views := buildLivePeerViews(livePeers, netmapSnap, selfIPs, ruleByPeerID, mergedStates, now)
	views = appendAbsentConfiguredPeers(views, p2pCfg.Peers, matchedRuleIdx, mergedStates, now)

	return map[string]any{
		"supported":        opts.Supported,
		"isOpenWrt":        opts.IsOpenWrt,
		"fw4Available":     opts.FW4Available,
		"ujailAvailable":   opts.UjailAvailable,
		"daemonRunning":    opts.DaemonRunning,
		"tailscaleRunning": tsRunning,
		"defaultLanCidr":   opts.DefaultLANCIDR,
		"openPinholes":     openCount,
		"openPinholeIPs":   openIPs,
		"config":           p2pCfg,
		"runtime":          runtimeSummary,
		"peers":            views,
	}
}

func resolveReportSelfIPs(statusSnap *StatusSnapshot, netmapSnap *NetMapSnapshot, ctrl *P2PAssistController) []netip.Addr {
	if statusSnap == nil {
		return nil
	}
	var ifaceAddrs []netip.Addr
	if ctrl != nil && ctrl.HostSelfIPs != nil {
		ifaceAddrs = ctrl.HostSelfIPs()
	} else {
		ifaceAddrs = HostInterfaceAddrs()
	}
	return ExtractSelfIPs(statusSnap, netmapSnap, ifaceAddrs)
}

func mergePeerRuntimeStates(
	enabled bool,
	openCount int,
	openIPs []string,
	dmSnap *P2PRuntimeSnapshot,
	ctrlStates map[string]P2PPeerRuntimeState,
) (map[string]P2PPeerRuntimeState, P2PRuntimeSnapshot) {
	merged := make(map[string]P2PPeerRuntimeState)
	if dmSnap != nil {
		maps.Copy(merged, dmSnap.PeerStates)
	}
	maps.Copy(merged, ctrlStates)

	summary := P2PRuntimeSnapshot{
		Enabled:        enabled,
		OpenPinholes:   openCount,
		OpenPinholeIPs: openIPs,
		PeerStates:     merged,
	}
	if dmSnap != nil {
		summary.ApplyMode = dmSnap.ApplyMode
		summary.UpdatedAt = dmSnap.UpdatedAt
		summary.LastError = dmSnap.LastError
	}
	return merged, summary
}

func buildLivePeerViews(
	livePeers []PeerStatus,
	netmapSnap *NetMapSnapshot,
	selfIPs []netip.Addr,
	ruleByPeerID map[string]config.TailscaleP2PPeerConfig,
	mergedStates map[string]P2PPeerRuntimeState,
	now time.Time,
) []P2PPeerView {
	views := make([]P2PPeerView, 0, len(livePeers))
	for _, lp := range livePeers {
		var eps []string
		eps = append(eps, lp.Addrs...)
		if netmapSnap != nil {
			eps = append(eps, netmapSnap.PeerEndpoints[lp.ID]...)
		}
		v4, v6 := FilterPublicCandidateIPs(eps, selfIPs)

		v := P2PPeerView{
			ID:                   lp.ID,
			Name:                 cmp.Or(lp.ShortName, lp.HostName, lp.ID),
			ShortName:            lp.ShortName,
			DNSName:              lp.DNSName,
			HostName:             lp.HostName,
			TailscaleIPs:         lp.TailscaleIPs,
			PrimaryRoutes:        lp.PrimaryRoutes,
			Online:               lp.Online,
			Active:               lp.Active,
			Direct:               lp.CurAddr != "",
			CurAddr:              lp.CurAddr,
			Relay:                lp.Relay,
			CandidatePublicCount: len(v4) + len(v6),
			AccessMode:           config.TailscaleAccessOutboundOnly,
			EffectiveAccessMode:  config.TailscaleAccessOutboundOnly,
		}
		if rule, ok := ruleByPeerID[lp.ID]; ok {
			applyRuleToPeerView(&v, rule, now)
		}
		if st, ok := mergedStates[lp.ID]; ok {
			applyRuntimeStateToPeerView(&v, st)
		}
		views = append(views, v)
	}
	return views
}

func appendAbsentConfiguredPeers(
	views []P2PPeerView,
	rules []config.TailscaleP2PPeerConfig,
	matchedRuleIdx map[int]bool,
	mergedStates map[string]P2PPeerRuntimeState,
	now time.Time,
) []P2PPeerView {
	for i, rule := range rules {
		if matchedRuleIdx[i] {
			continue
		}
		var ips []string
		if tsIP := strings.TrimSpace(rule.TailscaleIP); tsIP != "" {
			ips = []string{tsIP}
		}
		key := cmp.Or(strings.TrimSpace(rule.ID), strings.TrimSpace(rule.TailscaleIP), strings.ToLower(strings.TrimSpace(rule.Name)))
		v := P2PPeerView{
			ID:           strings.TrimSpace(rule.ID),
			Name:         cmp.Or(strings.TrimSpace(rule.Name), strings.TrimSpace(rule.ID), strings.TrimSpace(rule.TailscaleIP)),
			ShortName:    strings.TrimSpace(rule.Name),
			TailscaleIPs: ips,
			Online:       false,
		}
		applyRuleToPeerView(&v, rule, now)
		if st, ok := mergedStates[key]; ok {
			applyRuntimeStateToPeerView(&v, st)
		}
		views = append(views, v)
	}
	return views
}

func applyRuleToPeerView(v *P2PPeerView, rule config.TailscaleP2PPeerConfig, now time.Time) {
	v.Configured = true
	v.JITEnabled = rule.JITEnabled
	v.AccessMode = cmp.Or(strings.TrimSpace(rule.AccessMode), config.TailscaleAccessOutboundOnly)
	v.EffectiveAccessMode = rule.EffectiveAccessMode(now)
	v.BidirectionalUntil = strings.TrimSpace(rule.BidirectionalUntil)
	v.BidirectionalRemainingSec = int(rule.RemainingBidirectional(now).Seconds())
	v.AllowedLANTargets = rule.AllowedLANTargets
}

func applyRuntimeStateToPeerView(v *P2PPeerView, st P2PPeerRuntimeState) {
	v.PinholeActive = st.PinholeOpen
	v.CooldownRemainingSec = st.CooldownRemainingSec
	v.LastUpgradeAt = st.LastUpgradeAt
	v.LastResult = st.LastResult
}
