// 文件职责：提供客户端 WebUI 本地域名与设备名册（/api/home-domain*）的增删改查、三源设备发现聚合与四项端到端自检接口。
package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/homedomain"
	"singctl/internal/singbox"
)

// HomeDomainTestHooks 仅供离线单元测试显式注入发现、dnsmasq、探活与应答器状态替身。
type HomeDomainTestHooks struct {
	Discovery       func(ctx context.Context) homedomain.DiscoverySnapshot
	DnsmasqDeps     homedomain.DnsmasqDeps
	ProbeFunc       func(ctx context.Context, addr, domain string, timeout time.Duration) ([]string, time.Duration, error)
	ResponderStatus func() homedomain.ResponderStatus
	ReloadSingBox   func(ctx context.Context) error
}

type homeDomainDeviceView struct {
	config.HomeDomainDevice
	FQDN         string                      `json:"fqdn"`
	Online       bool                        `json:"online"`
	Reachability homedomain.ReachabilityInfo `json:"reachability"`
}

type homeDomainSplitDNSGuide struct {
	NameserverIP   string `json:"nameserverIp,omitempty"`
	Domain         string `json:"domain"`
	AdminDNSURL    string `json:"adminDnsUrl"`
	TailscaleReady bool   `json:"tailscaleReady"`
}

type homeDomainOverviewResponse struct {
	Enabled             bool                                 `json:"enabled"`
	Suffix              string                               `json:"suffix"`
	TailscaleDNS        bool                                 `json:"tailscaleDns"`
	FollowDHCP          bool                                 `json:"followDhcp"`
	Self                homedomain.SelfRouterInfo            `json:"self"`
	Devices             []homeDomainDeviceView               `json:"devices"`
	DiscoveredLAN       []homedomain.DiscoveredLANDevice     `json:"discoveredLan"`
	DiscoveredTailscale []homedomain.DiscoveredTailscalePeer `json:"discoveredTailscale"`
	DNSEngine           string                               `json:"dnsEngine"`
	DNSEngineLabel      string                               `json:"dnsEngineLabel"`
	DNSHealthy          bool                                 `json:"dnsHealthy"`
	Responder           homedomain.ResponderStatus           `json:"responder"`
	SplitDNSGuide       homeDomainSplitDNSGuide              `json:"splitDnsGuide"`
	Warnings            []string                             `json:"warnings,omitempty"`
}

func (s *Server) discoverHomeDomain(ctx context.Context) homedomain.DiscoverySnapshot {
	if s.opts.HomeDomainForTest != nil && s.opts.HomeDomainForTest.Discovery != nil {
		return s.opts.HomeDomainForTest.Discovery(ctx)
	}
	return homedomain.DiscoverDevices(ctx, homedomain.DiscoveryDeps{})
}

func (s *Server) readHomeDomainResponderStatus(cfg *config.Config) homedomain.ResponderStatus {
	if s.opts.HomeDomainForTest != nil && s.opts.HomeDomainForTest.ResponderStatus != nil {
		return s.opts.HomeDomainForTest.ResponderStatus()
	}
	snap := daemon.LoadRuntimeSnapshot()
	if snap.HomeDomainDNS != nil {
		return *snap.HomeDomainDNS
	}
	return homedomain.ResponderStatus{
		Suffix:      cfg.HomeDomain.EffectiveSuffix(),
		RecordCount: len(cfg.HomeDomain.BuildManagedRewrites()),
	}
}

func (s *Server) buildHomeDomainOverview(ctx context.Context, cfg *config.Config, warnings []string) homeDomainOverviewResponse {
	disc := s.discoverHomeDomain(ctx)
	suffix := cfg.HomeDomain.EffectiveSuffix()
	advPrefixes := homedomain.ParseAdvertisedPrefixes(disc.Self.AdvertisedSubnets)

	onlineByIP := make(map[string]bool, len(disc.LANDevices)+len(disc.TailscalePeers)+2)
	onlineByMAC := make(map[string]bool, len(disc.LANDevices))
	if disc.Self.LANIP != "" {
		onlineByIP[disc.Self.LANIP] = true
	}
	if disc.Self.TailscaleIP != "" {
		onlineByIP[disc.Self.TailscaleIP] = true
	}
	for _, d := range disc.LANDevices {
		if d.Online {
			onlineByIP[d.IP] = true
			if mac := config.NormalizeMAC(d.MAC); mac != "" {
				onlineByMAC[mac] = true
			}
		}
	}
	for _, p := range disc.TailscalePeers {
		if p.Online && p.TailscaleIP != "" {
			onlineByIP[p.TailscaleIP] = true
		}
	}

	namedIPs := make(map[string]bool, len(cfg.HomeDomain.Devices))
	namedMACs := make(map[string]bool, len(cfg.HomeDomain.Devices))
	devices := make([]homeDomainDeviceView, 0, len(cfg.HomeDomain.Devices))
	for _, d := range cfg.HomeDomain.Devices {
		alias := strings.ToLower(strings.TrimSpace(d.Alias))
		ip := strings.TrimSpace(d.IP)
		mac := config.NormalizeMAC(d.MAC)
		if ip != "" {
			namedIPs[ip] = true
		}
		if mac != "" {
			namedMACs[mac] = true
		}
		online := onlineByIP[ip] || (mac != "" && onlineByMAC[mac])
		devices = append(devices, homeDomainDeviceView{
			HomeDomainDevice: d,
			FQDN:             alias + "." + suffix,
			Online:           online,
			Reachability:     homedomain.EvaluateReachability(d, advPrefixes, disc.TailscalePeers),
		})
	}
	slices.SortFunc(devices, func(a, b homeDomainDeviceView) int {
		return cmp.Compare(a.Alias, b.Alias)
	})

	// 过滤掉已命名的设备，仅保留待命名发现项供一键命名
	unmatchedLAN := make([]homedomain.DiscoveredLANDevice, 0, len(disc.LANDevices))
	for _, d := range disc.LANDevices {
		mac := config.NormalizeMAC(d.MAC)
		if namedIPs[d.IP] || (mac != "" && namedMACs[mac]) {
			continue
		}
		unmatchedLAN = append(unmatchedLAN, d)
	}
	unmatchedTS := make([]homedomain.DiscoveredTailscalePeer, 0, len(disc.TailscalePeers))
	for _, p := range disc.TailscalePeers {
		if namedIPs[p.TailscaleIP] {
			continue
		}
		unmatchedTS = append(unmatchedTS, p)
	}

	reg := s.newDNSRegistry(cfg)
	activeEng := reg.ActiveEngine()
	dnsEngID := ""
	dnsEngLabel := "内置 DoH 兜底"
	dnsHealthy := false
	if activeEng != nil {
		dnsEngID = activeEng.ID()
		dnsEngLabel = activeEng.Meta().Name
		st := activeEng.Status(ctx)
		dnsHealthy = st.DNSHealthy
	}

	return homeDomainOverviewResponse{
		Enabled:             cfg.HomeDomain.IsEnabled(),
		Suffix:              suffix,
		TailscaleDNS:        cfg.HomeDomain.IsTailscaleDNSEnabled(),
		FollowDHCP:          cfg.HomeDomain.IsFollowDHCPEnabled(),
		Self:                disc.Self,
		Devices:             devices,
		DiscoveredLAN:       unmatchedLAN,
		DiscoveredTailscale: unmatchedTS,
		DNSEngine:           dnsEngID,
		DNSEngineLabel:      dnsEngLabel,
		DNSHealthy:          dnsHealthy,
		Responder:           s.readHomeDomainResponderStatus(cfg),
		SplitDNSGuide: homeDomainSplitDNSGuide{
			NameserverIP:   disc.Self.TailscaleIP,
			Domain:         suffix,
			AdminDNSURL:    "https://login.tailscale.com/admin/dns",
			TailscaleReady: disc.Self.TailscaleOnline && disc.Self.TailscaleIP != "",
		},
		Warnings: warnings,
	}
}

func (s *Server) syncHomeDomainAll(ctx context.Context, cfg *config.Config, prevManaged []config.DNSRewriteRule, prevSuffix string) homedomain.SyncResult {
	var (
		dmDeps   homedomain.DnsmasqDeps
		applySB  func(ctx context.Context, sbPath, updatedJSON string) error
		reloadSB func(context.Context) error
	)
	if s.opts.HomeDomainForTest != nil {
		dmDeps = s.opts.HomeDomainForTest.DnsmasqDeps
		reloadSB = s.opts.HomeDomainForTest.ReloadSingBox
	} else {
		workPath := s.sbWorkConfigPath()
		applySB = func(aCtx context.Context, sbPath, updatedJSON string) error {
			return singbox.ApplyLiveSingBoxConfig(aCtx, sbPath, workPath, updatedJSON, "homedomain")
		}
	}
	eng := s.newDNSRegistry(cfg).ActiveEngine()
	return homedomain.SyncAllReconcile(ctx, cfg, prevManaged, prevSuffix, homedomain.SyncAllDeps{
		Engine:             eng,
		SingBoxConfigPath:  s.sbConfigPath(),
		DnsmasqDeps:        dmDeps,
		ApplySingBoxConfig: applySB,
		ReloadSingBox:      reloadSB,
	})
}

func (s *Server) handleHomeDomainGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfigOrEmpty()
	writeJSON(w, http.StatusOK, s.buildHomeDomainOverview(r.Context(), cfg, nil))
}

func (s *Server) handleHomeDomainSettingsPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled      *bool  `json:"enabled"`
		Suffix       string `json:"suffix"`
		TailscaleDNS *bool  `json:"tailscaleDns"`
		FollowDHCP   *bool  `json:"followDhcp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	normSuffix, err := config.NormalizeHomeDomainSuffix(req.Suffix)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	prevManaged := cfg.HomeDomain.BuildManagedRewrites()
	prevSuffix := cfg.HomeDomain.EffectiveSuffix()

	if req.Enabled != nil {
		cfg.HomeDomain.SetEnabled(*req.Enabled)
	}
	cfg.HomeDomain.Suffix = normSuffix
	if req.TailscaleDNS != nil {
		cfg.HomeDomain.SetTailscaleDNSEnabled(*req.TailscaleDNS)
	}
	if req.FollowDHCP != nil {
		cfg.HomeDomain.SetFollowDHCPEnabled(*req.FollowDHCP)
	}
	if err := cfg.HomeDomain.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	syncRes := s.syncHomeDomainAll(r.Context(), cfg, prevManaged, prevSuffix)
	if err := s.saveConfig(cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, s.buildHomeDomainOverview(r.Context(), cfg, syncRes.Warnings))
}

func (s *Server) handleHomeDomainDeviceUpsertPost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OriginalAlias string                     `json:"originalAlias"`
		Alias         string                     `json:"alias"`
		DisplayName   string                     `json:"displayName"`
		IP            string                     `json:"ip"`
		MAC           string                     `json:"mac"`
		Source        string                     `json:"source"`
		Wildcard      bool                       `json:"wildcard"`
		Services      []config.HomeDomainService `json:"services"`
		Note          string                     `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	alias, err := config.NormalizeDeviceAlias(req.Alias)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ipAddr, ipErr := netip.ParseAddr(strings.TrimSpace(req.IP))
	if ipErr != nil || ipAddr.IsUnspecified() || ipAddr.IsMulticast() {
		writeJSONError(w, http.StatusBadRequest, "请输入合法的目标 IPv4 或 IPv6 地址")
		return
	}
	mac := config.NormalizeMAC(req.MAC)
	if strings.TrimSpace(req.MAC) != "" && mac == "" {
		writeJSONError(w, http.StatusBadRequest, "MAC 地址格式不合法（示例 aa:bb:cc:dd:ee:ff）")
		return
	}

	cleanSvcs := make([]config.HomeDomainService, 0, len(req.Services))
	for _, svc := range req.Services {
		scheme := strings.ToLower(strings.TrimSpace(svc.Scheme))
		if scheme == "" {
			scheme = "http"
		}
		if scheme != "http" && scheme != "https" && scheme != "ssh" {
			writeJSONError(w, http.StatusBadRequest, "快捷服务协议仅支持 http / https / ssh")
			return
		}
		if svc.Port < 0 || svc.Port > 65535 {
			writeJSONError(w, http.StatusBadRequest, "快捷服务端口超出合法范围 (0~65535)")
			return
		}
		cleanSvcs = append(cleanSvcs, config.HomeDomainService{
			Label:  cmp.Or(strings.TrimSpace(svc.Label), strings.ToUpper(scheme)),
			Scheme: scheme,
			Port:   svc.Port,
		})
	}

	dev := config.HomeDomainDevice{
		Alias:       alias,
		DisplayName: strings.TrimSpace(req.DisplayName),
		IP:          ipAddr.Unmap().String(),
		MAC:         mac,
		Source:      cmp.Or(strings.ToLower(strings.TrimSpace(req.Source)), "manual"),
		Wildcard:    req.Wildcard,
		Services:    cleanSvcs,
		Note:        strings.TrimSpace(req.Note),
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	prevManaged := cfg.HomeDomain.BuildManagedRewrites()
	prevSuffix := cfg.HomeDomain.EffectiveSuffix()

	origKey := strings.ToLower(strings.TrimSpace(req.OriginalAlias))
	if origKey == "" {
		origKey = alias
	}

	replaced := false
	for i := range cfg.HomeDomain.Devices {
		curAlias := strings.ToLower(strings.TrimSpace(cfg.HomeDomain.Devices[i].Alias))
		if curAlias == alias && curAlias != origKey {
			writeJSONError(w, http.StatusBadRequest, "短域名 "+alias+" 已被其他设备占用，请换一个名称")
			return
		}
		if curAlias == origKey {
			cfg.HomeDomain.Devices[i] = dev
			replaced = true
		}
	}
	if !replaced {
		cfg.HomeDomain.Devices = append(cfg.HomeDomain.Devices, dev)
	}
	if err := cfg.HomeDomain.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	syncRes := s.syncHomeDomainAll(r.Context(), cfg, prevManaged, prevSuffix)
	if err := s.saveConfig(cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, s.buildHomeDomainOverview(r.Context(), cfg, syncRes.Warnings))
}

func (s *Server) handleHomeDomainDeviceDelete(w http.ResponseWriter, r *http.Request) {
	targetAlias := strings.ToLower(strings.TrimSpace(r.PathValue("alias")))
	if targetAlias == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少待删除的设备短域名")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	prevManaged := cfg.HomeDomain.BuildManagedRewrites()
	prevSuffix := cfg.HomeDomain.EffectiveSuffix()

	before := len(cfg.HomeDomain.Devices)
	cfg.HomeDomain.Devices = slices.DeleteFunc(slices.Clone(cfg.HomeDomain.Devices), func(d config.HomeDomainDevice) bool {
		return strings.EqualFold(strings.TrimSpace(d.Alias), targetAlias)
	})
	if len(cfg.HomeDomain.Devices) == before {
		writeJSONError(w, http.StatusNotFound, "未找到指定设备: "+targetAlias)
		return
	}

	syncRes := s.syncHomeDomainAll(r.Context(), cfg, prevManaged, prevSuffix)
	if err := s.saveConfig(cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, s.buildHomeDomainOverview(r.Context(), cfg, syncRes.Warnings))
}

func (s *Server) handleHomeDomainVerifyPost(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfigOrEmpty()
	disc := s.discoverHomeDomain(r.Context())

	lanDNSAddr := ""
	if disc.Self.LANIP != "" {
		lanDNSAddr = net.JoinHostPort(disc.Self.LANIP, "53")
	}
	tsDNSAddr := ""
	if disc.Self.TailscaleIP != "" {
		tsDNSAddr = net.JoinHostPort(disc.Self.TailscaleIP, "53")
	}
	var probeFn func(ctx context.Context, addr, domain string, timeout time.Duration) ([]string, time.Duration, error)
	if s.opts.HomeDomainForTest != nil {
		probeFn = s.opts.HomeDomainForTest.ProbeFunc
	}

	rep := homedomain.Verify(r.Context(), cfg, homedomain.VerifyDeps{
		LocalDNSAddr:      net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.DNS.GetDNSPort())),
		LanDNSAddr:        lanDNSAddr,
		TailscaleDNSAddr:  tsDNSAddr,
		AdvertisedSubnets: disc.Self.AdvertisedSubnets,
		TailscalePeers:    disc.TailscalePeers,
		ProbeFunc:         probeFn,
	})
	writeJSON(w, http.StatusOK, rep)
}
