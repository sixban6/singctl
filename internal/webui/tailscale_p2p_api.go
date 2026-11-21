package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/tailscale"
	"singctl/internal/util/netinfo"
)

// TailscaleP2PTestHooks 仅供离线单元测试注入可控的 Tailscale / fw4 / ujail 依赖。
type TailscaleP2PTestHooks struct {
	Controller     *tailscale.P2PAssistController
	FW4Available   bool
	UjailAvailable bool
	UjailApply     func(ctx context.Context, enable bool) (bool, error)
	Now            func() time.Time
	DefaultLANCIDR string
}

type tailscaleP2PPeerView struct {
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

func (s *Server) tailscaleP2PNow() time.Time {
	if s.opts.TailscaleP2PForTest != nil && s.opts.TailscaleP2PForTest.Now != nil {
		return s.opts.TailscaleP2PForTest.Now()
	}
	return time.Now()
}

func (s *Server) defaultLANCIDR() string {
	if s.opts.TailscaleP2PForTest != nil && strings.TrimSpace(s.opts.TailscaleP2PForTest.DefaultLANCIDR) != "" {
		return strings.TrimSpace(s.opts.TailscaleP2PForTest.DefaultLANCIDR)
	}
	if sub, err := netinfo.GetLANSubnet(); err == nil {
		return sub
	}
	return ""
}

func (s *Server) tailscaleP2PController() *tailscale.P2PAssistController {
	if s.opts.TailscaleP2PForTest != nil && s.opts.TailscaleP2PForTest.Controller != nil {
		return s.opts.TailscaleP2PForTest.Controller
	}
	s.tsP2PMu.Lock()
	defer s.tsP2PMu.Unlock()
	if s.tsP2PCtrl == nil {
		s.tsP2PCtrl = &tailscale.P2PAssistController{
			DefaultLANCIDR: s.defaultLANCIDR,
		}
	}
	return s.tsP2PCtrl
}

func (s *Server) fw4Available() bool {
	if s.opts.TailscaleP2PForTest != nil {
		return s.opts.TailscaleP2PForTest.FW4Available
	}
	return runtime.GOOS == "linux" && tailscale.IsFW4Available()
}

func (s *Server) ujailAvailable() bool {
	if s.opts.TailscaleP2PForTest != nil {
		return s.opts.TailscaleP2PForTest.UjailAvailable
	}
	return runtime.GOOS == "linux" && tailscale.IsUjailAvailable()
}

func (s *Server) buildTailscaleP2PReport(ctx context.Context, cfg *config.Config) map[string]any {
	if cfg == nil {
		cfg = &config.Config{}
	}
	now := s.tailscaleP2PNow()
	p2pCfg := cfg.Tailscale.P2PAssist
	ctrl := s.tailscaleP2PController()

	api := ctrl.LocalAPI
	if api == nil {
		api = tailscale.DefaultLocalAPIClient()
	}
	statusSnap, statusErr := api.Status(ctx)
	var netmapSnap *tailscale.NetMapSnapshot
	if statusErr == nil && statusSnap != nil {
		netmapSnap, _ = api.NetMap(ctx)
	}

	var selfIPs []netip.Addr
	if statusSnap != nil {
		var ifaceAddrs []netip.Addr
		if ctrl.HostSelfIPs != nil {
			ifaceAddrs = ctrl.HostSelfIPs()
		} else {
			ifaceAddrs = tailscale.HostInterfaceAddrs()
		}
		selfIPs = tailscale.ExtractSelfIPs(statusSnap, netmapSnap, ifaceAddrs)
	}

	fw4Mgr := ctrl.FW4
	if fw4Mgr == nil {
		fw4Mgr = &tailscale.FW4Manager{}
	}
	openCount, openIPs := fw4Mgr.CountOpenPinholes(ctx)

	dmSnap := daemon.LoadRuntimeSnapshot()
	ctrlStates := ctrl.PeerStates()
	mergedStates := make(map[string]tailscale.P2PPeerRuntimeState)
	if dmSnap.TailscaleP2P != nil {
		for k, v := range dmSnap.TailscaleP2P.PeerStates {
			mergedStates[k] = v
		}
	}
	for k, v := range ctrlStates {
		mergedStates[k] = v
	}

	runtimeSummary := tailscale.P2PRuntimeSnapshot{
		Enabled:        p2pCfg.Enabled,
		OpenPinholes:   openCount,
		OpenPinholeIPs: openIPs,
		PeerStates:     mergedStates,
	}
	if dmSnap.TailscaleP2P != nil {
		runtimeSummary.ApplyMode = dmSnap.TailscaleP2P.ApplyMode
		runtimeSummary.UpdatedAt = dmSnap.TailscaleP2P.UpdatedAt
		runtimeSummary.LastError = dmSnap.TailscaleP2P.LastError
	}

	var livePeers []tailscale.PeerStatus
	selfID := ""
	tsRunning := false
	if statusSnap != nil {
		livePeers = statusSnap.Peers
		selfID = statusSnap.Self.ID
		tsRunning = strings.EqualFold(statusSnap.BackendState, "Running")
	}

	// Match configured rules to discovered live peers (one-to-one).
	ruleByPeerID := make(map[string]config.TailscaleP2PPeerConfig)
	matchedRuleIdx := make(map[int]bool)
	for i, rule := range p2pCfg.Peers {
		if m, ok := tailscale.MatchConfiguredPeer(rule, livePeers, selfID); ok && m != nil {
			ruleByPeerID[m.ID] = rule
			matchedRuleIdx[i] = true
		}
	}

	var views []tailscaleP2PPeerView
	for _, lp := range livePeers {
		var eps []string
		eps = append(eps, lp.Addrs...)
		if netmapSnap != nil {
			eps = append(eps, netmapSnap.PeerEndpoints[lp.ID]...)
		}
		v4, v6 := tailscale.FilterPublicCandidateIPs(eps, selfIPs)

		v := tailscaleP2PPeerView{
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
			v.Configured = true
			v.JITEnabled = rule.JITEnabled
			v.AccessMode = cmp.Or(strings.TrimSpace(rule.AccessMode), config.TailscaleAccessOutboundOnly)
			v.EffectiveAccessMode = rule.EffectiveAccessMode(now)
			v.BidirectionalUntil = strings.TrimSpace(rule.BidirectionalUntil)
			v.BidirectionalRemainingSec = int(rule.RemainingBidirectional(now).Seconds())
			v.AllowedLANTargets = rule.AllowedLANTargets
		}
		if st, ok := mergedStates[lp.ID]; ok {
			v.PinholeActive = st.PinholeOpen
			v.CooldownRemainingSec = st.CooldownRemainingSec
			v.LastUpgradeAt = st.LastUpgradeAt
			v.LastResult = st.LastResult
		}
		views = append(views, v)
	}

	// Preserve configured-but-currently-absent peers in the management view.
	for i, rule := range p2pCfg.Peers {
		if matchedRuleIdx[i] {
			continue
		}
		var ips []string
		if strings.TrimSpace(rule.TailscaleIP) != "" {
			ips = []string{strings.TrimSpace(rule.TailscaleIP)}
		}
		key := cmp.Or(strings.TrimSpace(rule.ID), strings.TrimSpace(rule.TailscaleIP), strings.ToLower(strings.TrimSpace(rule.Name)))
		v := tailscaleP2PPeerView{
			ID:                        strings.TrimSpace(rule.ID),
			Name:                      cmp.Or(strings.TrimSpace(rule.Name), strings.TrimSpace(rule.ID), strings.TrimSpace(rule.TailscaleIP)),
			ShortName:                 strings.TrimSpace(rule.Name),
			TailscaleIPs:              ips,
			Online:                    false,
			Configured:                true,
			JITEnabled:                rule.JITEnabled,
			AccessMode:                cmp.Or(strings.TrimSpace(rule.AccessMode), config.TailscaleAccessOutboundOnly),
			EffectiveAccessMode:       rule.EffectiveAccessMode(now),
			BidirectionalUntil:        strings.TrimSpace(rule.BidirectionalUntil),
			BidirectionalRemainingSec: int(rule.RemainingBidirectional(now).Seconds()),
			AllowedLANTargets:         rule.AllowedLANTargets,
		}
		if st, ok := mergedStates[key]; ok {
			v.PinholeActive = st.PinholeOpen
			v.CooldownRemainingSec = st.CooldownRemainingSec
			v.LastUpgradeAt = st.LastUpgradeAt
			v.LastResult = st.LastResult
		}
		views = append(views, v)
	}

	return map[string]any{
		"supported":        runtime.GOOS == "linux" || s.opts.TailscaleP2PForTest != nil,
		"isOpenWrt":        isOpenWrtSystem() || s.fw4Available(),
		"fw4Available":     s.fw4Available(),
		"ujailAvailable":   s.ujailAvailable(),
		"daemonRunning":    daemon.IsDaemonRunning(),
		"tailscaleRunning": tsRunning,
		"defaultLanCidr":   s.defaultLANCIDR(),
		"openPinholes":     openCount,
		"openPinholeIPs":   openIPs,
		"config":           p2pCfg,
		"runtime":          runtimeSummary,
		"peers":            views,
	}
}

func (s *Server) handleTailscaleP2PGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(configPathFor(s))
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.buildTailscaleP2PReport(ctx, cfg))
}

func (s *Server) handleTailscaleP2PPut(w http.ResponseWriter, r *http.Request) {
	var req config.TailscaleP2PAssistConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	normalized, err := normalizeAndValidateP2PAssistConfig(req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfgPath := configPathFor(s)
	origBytes, origReadErr := os.ReadFile(cfgPath)
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	prevP2P := cfg.Tailscale.P2PAssist
	cfg.Tailscale.P2PAssist = normalized

	if err := backupConfig(cfgPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份配置失败: "+err.Error())
		return
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}

	rollbackConfig := func() {
		if origReadErr == nil {
			_ = os.WriteFile(cfgPath, origBytes, 0600)
		}
	}

	appliedLive := false
	var applyMode string
	shouldApplyLive := (runtime.GOOS == "linux" && s.fw4Available()) || s.opts.TailscaleP2PForTest != nil
	if shouldApplyLive {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		snap, applyErr := s.tailscaleP2PController().Reconcile(ctx, normalized)
		if applyErr != nil {
			rollbackConfig()
			writeJSONError(w, http.StatusInternalServerError, "应用防火墙防线规则失败（已自动回滚配置）: "+applyErr.Error())
			return
		}
		appliedLive = true
		applyMode = snap.ApplyMode

		if prevP2P.SandboxUjail != normalized.SandboxUjail {
			var ujailErr error
			if s.opts.TailscaleP2PForTest != nil && s.opts.TailscaleP2PForTest.UjailApply != nil {
				_, ujailErr = s.opts.TailscaleP2PForTest.UjailApply(ctx, normalized.SandboxUjail)
			} else if runtime.GOOS == "linux" && s.opts.TailscaleP2PForTest == nil {
				_, ujailErr = tailscale.ApplyUjailSandbox(ctx, normalized.SandboxUjail, tailscale.UjailOptions{})
			}
			if ujailErr != nil {
				rollbackConfig()
				_, _ = s.tailscaleP2PController().Reconcile(ctx, prevP2P)
				writeJSONError(w, http.StatusInternalServerError, "切换 ujail 沙盒失败（已自动回滚）: "+ujailErr.Error())
				return
			}
		}
	}

	_ = daemon.NotifyReload()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	resp := s.buildTailscaleP2PReport(ctx, cfg)
	if applyMode != "" {
		if rt, ok := resp["runtime"].(tailscale.P2PRuntimeSnapshot); ok {
			rt.ApplyMode = applyMode
			resp["runtime"] = rt
		}
	}
	resp["ok"] = true
	resp["appliedLive"] = appliedLive
	resp["applyMode"] = applyMode
	if normalized.Enabled {
		resp["message"] = "已保存并实时生效 Tailscale P2P 零常驻暴露防线"
	} else {
		resp["message"] = "已关闭 Tailscale P2P 防线并清理相关规则"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTailscaleP2PPokePost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	target := cmp.Or(strings.TrimSpace(body.ID), strings.TrimSpace(body.Name))
	if target == "" {
		writeJSONError(w, http.StatusBadRequest, "请指定要测试瞬时打洞的目标节点 ID 或名称")
		return
	}

	cfg, err := config.Load(configPathFor(s))
	if err != nil || cfg == nil {
		writeJSONError(w, http.StatusInternalServerError, "读取配置失败")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	res, err := s.tailscaleP2PController().PokePeer(ctx, cfg.Tailscale.P2PAssist, target)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	report := s.buildTailscaleP2PReport(ctx, cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"direct":         res.Direct,
		"curAddr":        res.CurAddr,
		"relay":          res.Relay,
		"latencyMs":      res.LatencyMs,
		"pinholeMs":      res.PinholeMs,
		"candidateCount": res.CandidateCount,
		"message":        res.Message,
		"report":         report,
	})
}

func normalizeAndValidateP2PAssistConfig(raw config.TailscaleP2PAssistConfig) (config.TailscaleP2PAssistConfig, error) {
	out := config.TailscaleP2PAssistConfig{
		Enabled:       raw.Enabled,
		JITWindowSec:  min(max(3, cmp.Or(raw.JITWindowSec, 5)), 10),
		CooldownSec:   min(max(30, cmp.Or(raw.CooldownSec, 300)), 3600),
		SandboxUjail:  raw.SandboxUjail,
		ListenPort:    raw.EffectiveListenPort(),
		PayloadFilter: raw.PayloadFilter,
	}
	if out.PayloadFilter == nil {
		pf := true
		out.PayloadFilter = &pf
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
			if addr, err := netip.ParseAddr(tsIP); err != nil {
				return out, fmt.Errorf("节点 %q 的 tailscale_ip %q 格式无效: %w", cmp.Or(name, id), tsIP, err)
			} else {
				tsIP = addr.Unmap().String()
			}
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
			parsedTarget, err := tailscale.ParseAllowedLANTarget(rawTarget)
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
