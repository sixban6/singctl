// 文件职责：提供面向“网段 + 单台设备两级权限”的 Tailscale 统一组网拓扑查询与一键实时生效接口。
package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

type tailscaleMeshSaveRequest struct {
	Mode             string                            `json:"mode,omitempty"`
	Subnets          []string                          `json:"subnets"`
	LocalRules       []config.TailscaleLocalSubnetRule `json:"local_rules,omitempty"`
	Peers            []config.TailscaleP2PPeerConfig   `json:"peers"`
	JITWindowSec     *int                              `json:"jit_window_sec,omitempty"`
	CooldownSec      *int                              `json:"cooldown_sec,omitempty"`
	SandboxUjail     *bool                             `json:"sandbox_ujail,omitempty"`
	DownstreamAssist *bool                             `json:"downstream_assist,omitempty"`
}

func (s *Server) handleTailscaleMeshGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfigOrEmpty()
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.buildTailscaleMeshPayload(ctx, cfg))
}

func (s *Server) handleTailscaleMeshPut(w http.ResponseWriter, r *http.Request) {
	var body tailscaleMeshSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	reqMode, err := normalizeMeshRoleMode(body.Mode)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	subnetsCSV, hasGatewaysOrBidir, err := normalizeMeshSubnetsAndPolicy(body.Subnets, body.Peers)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	curCfg := s.readConfigOrEmpty()
	curP2P := curCfg.Tailscale.P2PAssist
	localRules := body.LocalRules
	if localRules == nil && len(body.Subnets) == 0 && (reqMode == "client" || reqMode == "exit") {
		localRules = curP2P.LocalRules
	}
	p2pReq := config.TailscaleP2PAssistConfig{
		Enabled:          true,
		RoleMode:         reqMode,
		JITWindowSec:     curP2P.JITWindowSec,
		CooldownSec:      curP2P.CooldownSec,
		PayloadFilter:    new(true),
		DownstreamAssist: curP2P.DownstreamAssist,
		SandboxUjail:     curP2P.SandboxUjail,
		ListenPort:       curP2P.ListenPort,
		LocalRules:       localRules,
		Peers:            body.Peers,
	}
	if body.JITWindowSec != nil {
		p2pReq.JITWindowSec = *body.JITWindowSec
	}
	if body.CooldownSec != nil {
		p2pReq.CooldownSec = *body.CooldownSec
	}
	if body.SandboxUjail != nil {
		p2pReq.SandboxUjail = *body.SandboxUjail
	}
	if body.DownstreamAssist != nil {
		v := *body.DownstreamAssist
		p2pReq.DownstreamAssist = &v
	}

	normalizedP2P, err := tailscale.NormalizeAndValidateP2PAssistConfig(p2pReq)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	var (
		prevP2P     config.TailscaleP2PAssistConfig
		appliedLive bool
		applyMode   string
	)
	cfg, txErr := s.updateConfigTx(configTxOptions{
		LiveApply: func(cfg *config.Config) error {
			shouldApplyFW := (runtime.GOOS == "linux" && s.fw4Available()) || s.opts.TailscaleP2PForTest != nil
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()

			if shouldApplyFW {
				snap, applyErr := s.tailscaleP2PController().Reconcile(ctx, normalizedP2P)
				if applyErr != nil {
					return &apiStatusError{
						status: http.StatusInternalServerError,
						msg:    "应用组网访问防火墙规则失败（已自动回滚配置）: " + applyErr.Error(),
					}
				}
				appliedLive = true
				applyMode = snap.ApplyMode
			}

			if err := s.applyMeshRuntimeRouting(ctx, cfg, reqMode, subnetsCSV, hasGatewaysOrBidir); err != nil {
				if shouldApplyFW {
					_, _ = s.tailscaleP2PController().Reconcile(ctx, prevP2P)
				}
				return &apiStatusError{
					status: http.StatusInternalServerError,
					msg:    "同步运行中 Tailscale 路由失败（已自动回滚）: " + err.Error(),
				}
			}

			if prevP2P.SandboxUjail != normalizedP2P.SandboxUjail && s.opts.TailscaleP2PForTest == nil && runtime.GOOS == "linux" {
				if _, uErr := tailscale.ApplyUjailSandbox(ctx, normalizedP2P.SandboxUjail, tailscale.UjailOptions{}); uErr != nil {
					_, _ = s.tailscaleP2PController().Reconcile(ctx, prevP2P)
					return &apiStatusError{
						status: http.StatusInternalServerError,
						msg:    "切换 ujail 沙盒失败（已自动回滚）: " + uErr.Error(),
					}
				}
			}
			return nil
		},
	}, func(cfg *config.Config) error {
		prevP2P = cfg.Tailscale.P2PAssist
		if subnetsCSV != "" || (reqMode != "client" && reqMode != "exit") {
			cfg.Tailscale.Subnets = subnetsCSV
		}
		cfg.Tailscale.P2PAssist = normalizedP2P
		return nil
	})
	if txErr != nil {
		writePartialSaveError(w, txErr)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	meshPayload := s.buildTailscaleMeshPayload(ctx, cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"appliedLive": appliedLive,
		"applyMode":   applyMode,
		"message":     "已保存并立即生效组网角色、网段设备权限与互信策略",
		"mesh":        meshPayload,
	})
}

func normalizeMeshRoleMode(raw string) (string, error) {
	m := strings.ToLower(strings.TrimSpace(raw))
	switch m {
	case "", "client", "router", "exit", "gateway":
		return m, nil
	default:
		return "", &apiStatusError{status: http.StatusBadRequest, msg: "运行角色无效（仅支持 client / router / exit / gateway）"}
	}
}

func resolveLiveModeTargets(reqMode, subnetsCSV, currentLiveMode string) (liveSubnets string, exitNode bool) {
	switch reqMode {
	case "client":
		return "", false
	case "exit":
		return "", true
	case "router":
		return subnetsCSV, false
	case "gateway":
		return subnetsCSV, true
	default:
		return subnetsCSV, currentLiveMode == "gateway" || currentLiveMode == "exit"
	}
}

func (s *Server) applyMeshRuntimeRouting(ctx context.Context, cfg *config.Config, reqMode, subnetsCSV string, acceptRoutes bool) error {
	if s.opts.TailscaleP2PForTest != nil {
		liveSubnets, exitActive := resolveLiveModeTargets(reqMode, subnetsCSV, "")
		if s.opts.TailscaleP2PForTest.MeshSync != nil {
			if err := s.opts.TailscaleP2PForTest.MeshSync(ctx, liveSubnets, acceptRoutes); err != nil {
				return err
			}
		}
		if s.opts.TailscaleP2PForTest.MeshSyncWithMode != nil {
			return s.opts.TailscaleP2PForTest.MeshSyncWithMode(ctx, reqMode, liveSubnets, acceptRoutes, exitActive)
		}
		return nil
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	bin := tailscale.FindInstalledTailscaleBin()
	if bin == "" {
		return nil
	}
	bs := tailscale.QueryBackendStatus(ctx, bin, nil)
	if !bs.Running || !strings.EqualFold(bs.State, "Running") {
		return nil
	}
	isOW := isOpenWrtSystem()
	liveSubnets, exitActive := resolveLiveModeTargets(reqMode, subnetsCSV, bs.Mode)
	if err := tailscale.SyncLiveTailscaleMesh(ctx, tailscale.SyncLiveMeshOptions{
		BinPath:           bin,
		SubnetsCSV:        liveSubnets,
		AcceptRoutes:      acceptRoutes,
		IsOpenWrt:         isOW,
		AdvertiseExitNode: &exitActive,
	}); err != nil {
		return err
	}
	var shieldCIDRs []string
	if def := s.defaultLANCIDR(); def != "" {
		shieldCIDRs = append(shieldCIDRs, def)
	}
	if liveSubnets != "" {
		shieldCIDRs = append(shieldCIDRs, liveSubnets)
	}
	lanIP := lanIPv4()
	if err := tailscale.SyncLANCoexistenceShield(ctx, tailscale.LANShieldOptions{
		BinPath:            bin,
		LocalCIDRs:         shieldCIDRs,
		LocalLANIP:         lanIP,
		AdvertiseLocalLAN:  liveSubnets != "",
		IsOpenWrt:          isOW,
		EnsureNetfilterOff: isOW,
	}); err != nil {
		return err
	}
	return nil
}

func normalizeMeshSubnetsAndPolicy(rawSubnets []string, peers []config.TailscaleP2PPeerConfig) (string, bool, error) {
	seen := make(map[string]struct{}, len(rawSubnets))
	var out []string
	for _, raw := range rawSubnets {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if p == "0.0.0.0/0" || p == "::/0" {
			return "", false, &apiStatusError{status: http.StatusBadRequest, msg: "组网范围仅允许填写本地私网 CIDR（出口节点请直接选择「出口节点」或「全能网关」）"}
		}
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			return "", false, &apiStatusError{status: http.StatusBadRequest, msg: "通告子网格式无效 " + p + "（示例: 192.168.1.0/24）"}
		}
		norm := netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()).Masked().String()
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}

	shouldAcceptRoutes := len(peers) > 0
	for _, p := range peers {
		if m, ok := config.NormalizeTailscaleAccessMode(p.AccessMode); ok && (m == config.TailscaleAccessBidirectional || m == config.TailscaleAccessBidirectionalTimed) {
			shouldAcceptRoutes = true
			break
		}
	}
	return strings.Join(out, ","), shouldAcceptRoutes, nil
}

func (s *Server) collectVLANHints(ctx context.Context) []tailscale.VLANHint {
	if s.opts.TailscaleP2PForTest != nil && s.opts.VLANServiceForTest == nil {
		return nil
	}
	if runtime.GOOS != "linux" && s.opts.VLANServiceForTest == nil {
		return nil
	}
	ov, err := s.vlanService().Overview(ctx, "")
	if err != nil || ov == nil {
		return nil
	}
	hints := make([]tailscale.VLANHint, 0, len(ov.Segments))
	for _, seg := range ov.Segments {
		ssid := ""
		if seg.Wireless != nil && seg.Wireless.Enabled {
			ssid = strings.TrimSpace(seg.Wireless.SSID)
		}
		hints = append(hints, tailscale.VLANHint{
			ID:            seg.ID,
			DisplayName:   seg.DisplayName,
			CIDR:          seg.CIDR,
			VLANID:        seg.VLANID,
			SSID:          ssid,
			IsPrimaryLAN:  seg.IsPrimaryLAN,
			OnlineClients: seg.OnlineClients,
		})
	}
	return hints
}

func buildDeviceNicknamesMap(cfg *config.Config) map[string]string {
	if cfg == nil || len(cfg.HomeDomain.Devices) == 0 {
		return nil
	}
	out := make(map[string]string, len(cfg.HomeDomain.Devices))
	for _, d := range cfg.HomeDomain.Devices {
		ip := strings.TrimSpace(d.IP)
		name := strings.TrimSpace(d.DisplayName)
		if name == "" {
			name = strings.TrimSpace(d.Alias)
		}
		if ip != "" && name != "" {
			out[ip] = name
		}
	}
	return out
}

func (s *Server) buildTailscaleMeshPayload(ctx context.Context, cfg *config.Config) map[string]any {
	if cfg == nil {
		cfg = &config.Config{}
	}
	tsStatus := s.tailscaleStatus(configPathFor(s))
	liveSubnets := ""
	tsRunning := false
	if v, ok := tsStatus["liveSubnets"].(string); ok {
		liveSubnets = v
	}
	if v, ok := tsStatus["running"].(bool); ok {
		tsRunning = v
	}

	var routeOut, leaseText, neighText string
	if s.opts.TailscaleP2PForTest != nil {
		routeOut = s.opts.TailscaleP2PForTest.RouteOutput
		leaseText = s.opts.TailscaleP2PForTest.LeaseText
		neighText = s.opts.TailscaleP2PForTest.NeighText
	}
	roleMode := strings.ToLower(strings.TrimSpace(cfg.Tailscale.P2PAssist.RoleMode))
	localNets := tailscale.DiscoverLocalNetworks(ctx, tailscale.DiscoverOptions{
		PrimaryLANCIDR:        s.defaultLANCIDR(),
		ConfiguredSubnets:     cfg.Tailscale.Subnets,
		LiveAdvertisedSubnets: liveSubnets,
		ExplicitEmptySubnets:  roleMode == "client" || roleMode == "exit",
		SelfLANIP:             lanIPv4(),
		LocalRules:            cfg.Tailscale.P2PAssist.LocalRules,
		DeviceNicknames:       buildDeviceNicknamesMap(cfg),
		VLANHints:             s.collectVLANHints(ctx),
		RouteOutput:           routeOut,
		LeaseText:             leaseText,
		NeighText:             neighText,
	})

	p2pReport := s.buildTailscaleP2PReport(ctx, cfg)
	var allPeers []tailscale.P2PPeerView
	if rawPeers, ok := p2pReport["peers"].([]tailscale.P2PPeerView); ok {
		allPeers = rawPeers
	}
	if !tsRunning {
		if r, ok := p2pReport["tailscaleRunning"].(bool); ok && r {
			tsRunning = true
		}
	}

	gatewayPeers := make([]tailscale.P2PPeerView, 0)
	personalDevices := make([]tailscale.P2PPeerView, 0)
	for _, p := range allPeers {
		if len(p.PrimaryRoutes) > 0 || p.Configured {
			gatewayPeers = append(gatewayPeers, p)
		} else {
			personalDevices = append(personalDevices, p)
		}
	}

	return map[string]any{
		"gatewayRole":           cfg.Gateway.EffectiveMode(),
		"roleMode":              roleMode,
		"webPasswordConfigured": s.currentPassword() != "",
		"lanShieldActive":       tsRunning && (runtime.GOOS == "linux" || s.opts.TailscaleP2PForTest != nil),
		"tailscaleStatus":       tsStatus,
		"config":                tailscaleConfigResponse(cfg),
		"localNetworks":         localNets,
		"p2p":                   p2pReport,
		"gatewayPeers":          gatewayPeers,
		"personalDevices":       personalDevices,
	}
}
