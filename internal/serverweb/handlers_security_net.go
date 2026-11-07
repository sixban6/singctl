package serverweb

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/doctor"
	"singctl/internal/gfw"
	"singctl/internal/logger"
	"singctl/internal/netdiag"
)

func (s *Server) handleNetReturn(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	summary, err := netdiag.RunReturnRoute(ctx, 3)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "三网回程测试失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleWarpDiagnose(w http.ResponseWriter, r *http.Request) {
	res := diagnoseWARP()
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleRegeneratePath(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}

	newPath := config.GenerateRandomAdminPath()
	cfg.Server.WebAdmin.Path = newPath
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存新随机路径失败: "+err.Error())
		return
	}
	s.mu.Lock()
	s.gatewayToken = config.DeriveGatewayToken(newPath)
	s.mu.Unlock()

	if err := deploy.DeployCaddy(cfg); err != nil {
		logger.Warn("重新应用 Caddyfile 警告: %v", err)
	}

	subDomain := cfg.Server.GetSubstoreDomain()
	if subDomain == "" {
		subDomain = cfg.Server.GetNodeDomain()
	}
	newHTTPS := fmt.Sprintf("https://%s%s/", subDomain, newPath)

	s.recordAudit(r, fmt.Sprintf("重新生成随机安全管理路径为 [%s]", newPath))
	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "全新隐蔽访问路径已生成并生效",
		"path":     newPath,
		"httpsUrl": newHTTPS,
	})
}

func (s *Server) handleRegenerateMaskSite(w http.ResponseWriter, r *http.Request) {
	meta, err := deploy.RegenerateMaskSite()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "重新生成伪装站点失败: "+err.Error())
		return
	}

	s.recordAudit(r, "重新生成随机伪装站")
	writeJSON(w, http.StatusOK, map[string]any{
		"message": fmt.Sprintf("已成功重新生成伪装博客：%s（作者：%s，主题：%s）", meta.BlogTitle, meta.AuthorName, meta.Category),
		"meta":    meta,
	})
}

func (s *Server) handleUpdateSNI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SNI string `json:"sni"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.SNI) == "" {
		writeJSONError(w, http.StatusBadRequest, "SNI 域名不能为空")
		return
	}

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}

	cfg.Server.Sni = strings.TrimSpace(body.SNI)
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}

	if err := deploy.DeployCaddy(cfg); err != nil {
		logger.Warn("更新 Caddy SNI 警告: %v", err)
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err == nil {
		_ = sbs.LoadExistingCredentials()
		_ = sbs.DeploySingbox()

		sbt := deploy.NewSubstore(cfg, "")
		_ = sbt.UpdateSubstoreConfig(sbs)
	}

	s.recordAudit(r, fmt.Sprintf("更新 Reality SNI 伪装域名为 [%s]", cfg.Server.Sni))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Reality SNI 已成功更新为 " + cfg.Server.Sni + " 并自动重载服务与订阅",
		"sni":     cfg.Server.Sni,
	})
}

func (s *Server) handleEnableBBR(w http.ResponseWriter, r *http.Request) {
	if err := deploy.EnableBBR(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "启用 TCP BBR 失败: "+err.Error())
		return
	}
	bbrOk := isBBREnabled()
	s.recordAudit(r, "启用 Google TCP BBR 加速")
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Google TCP BBR 拥塞控制算法已成功开启并立即生效",
		"bbr":     bbrOk,
	})
}

func (s *Server) handleUpdateCFToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Token) == "" {
		writeJSONError(w, http.StatusBadRequest, "Cloudflare Token 不能为空")
		return
	}

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}

	cfg.Server.CFDNSKey = strings.TrimSpace(body.Token)
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}

	if err := deploy.RotateCloudflareToken(cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "轮换 Token 失败: "+err.Error())
		return
	}

	s.recordAudit(r, "轮换 Cloudflare API Token")
	writeJSON(w, http.StatusOK, map[string]string{"message": "Cloudflare Token 已成功更新并重载 Caddy"})
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	cfg, _ := config.Load(s.opts.ConfigPath)
	report := doctor.RunServerDoctor(cfg)
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleUnlockDiagnose(w http.ResponseWriter, r *http.Request) {
	report := doctor.CheckMediaUnlock()
	writeJSON(w, http.StatusOK, report)
}

type camouflagePreset struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Domain string `json:"domain"`
	SNI    string `json:"sni"`
}

func (s *Server) resolveLocalCamouflageDefaults(ctx context.Context) (ip, domain, sni string) {
	cfg, _ := config.Load(s.opts.ConfigPath)
	if cfg != nil {
		domain = cfg.Server.GetNodeDomain()
		if domain == "" {
			domain = cfg.Server.GetSubstoreDomain()
		}
		sni = cfg.Server.Sni
		ip = strings.TrimSpace(cfg.Server.ServerIP)
	}
	if ip == "" && domain != "" {
		rCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if ips, err := net.DefaultResolver.LookupHost(rCtx, domain); err == nil && len(ips) > 0 {
			ip = ips[0]
		}
		cancel()
	}
	if ip == "" {
		ip = "127.0.0.1"
	}
	return ip, domain, sni
}

func (s *Server) handleCamouflageDefaults(w http.ResponseWriter, r *http.Request) {
	ip, domain, sni := s.resolveLocalCamouflageDefaults(r.Context())
	presets := []camouflagePreset{
		{
			ID:     "local",
			Name:   "本机节点 (当前网关)",
			IP:     ip,
			Domain: domain,
			SNI:    sni,
		},
	}
	if s.fleet != nil && s.fleet.Store != nil {
		if nodes, err := s.fleet.Store.ListPublic(); err == nil {
			for _, n := range nodes {
				if strings.TrimSpace(n.Host) == "" {
					continue
				}
				presets = append(presets, camouflagePreset{
					ID:     n.ID,
					Name:   cmp.Or(n.Name, n.ID),
					IP:     n.Host,
					Domain: n.Domain,
					SNI:    sni,
				})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ip":      ip,
		"domain":  domain,
		"sni":     sni,
		"ports":   "80,443",
		"presets": presets,
	})
}

func (s *Server) handleCamouflageProbe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP         string `json:"ip"`
		Domain     string `json:"domain"`
		SNI        string `json:"sni"`
		Ports      string `json:"ports"`
		TimeoutSec int    `json:"timeoutSec"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	defaultIP, defaultDomain, defaultSNI := s.resolveLocalCamouflageDefaults(r.Context())
	targetIP := strings.TrimSpace(body.IP)
	targetDomain := strings.TrimSpace(body.Domain)
	targetSNI := strings.TrimSpace(body.SNI)

	if targetIP == "" {
		targetIP = defaultIP
		if targetDomain == "" {
			targetDomain = defaultDomain
		}
		if targetSNI == "" {
			targetSNI = defaultSNI
		}
	}

	// 若用户在 IP 栏输入了域名，自动解析为 IP 并回填 Domain
	if net.ParseIP(targetIP) == nil {
		hostCandidate := targetIP
		rCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		ips, err := net.DefaultResolver.LookupHost(rCtx, hostCandidate)
		cancel()
		if err != nil || len(ips) == 0 {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("无法解析目标地址 %q: %v", hostCandidate, err))
			return
		}
		if targetDomain == "" {
			targetDomain = hostCandidate
		}
		targetIP = ips[0]
	}

	var ports []int
	portsRaw := cmp.Or(strings.TrimSpace(body.Ports), "80,443")
	for pStr := range strings.SplitSeq(portsRaw, ",") {
		pStr = strings.TrimSpace(pStr)
		if pStr == "" {
			continue
		}
		p, err := strconv.Atoi(pStr)
		if err != nil || p < 1 || p > 65535 {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("无效的端口号: %s", pStr))
			return
		}
		ports = append(ports, p)
	}
	if len(ports) == 0 {
		ports = []int{80, 443}
	}

	timeoutSec := body.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = 4
	}
	if timeoutSec > 10 {
		timeoutSec = 10
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutSec*4)*time.Second)
	defer cancel()

	detector := gfw.NewDetector(gfw.ProbeOptions{
		IP:      targetIP,
		Ports:   ports,
		SNI:     targetSNI,
		Domain:  targetDomain,
		Timeout: time.Duration(timeoutSec) * time.Second,
	})

	rep, err := detector.Run(ctx)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "伪装与抗探测评估执行失败: "+err.Error())
		return
	}

	s.recordAudit(r, fmt.Sprintf("执行伪装与抗探测评估 [目标=%s, 域名=%s, 风险分=%d/100]",
		targetIP, cmp.Or(targetDomain, "-"), rep.TotalScore))
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) collectProtectedIPs(ctx context.Context) []string {
	var out []string
	localIP, _, _ := s.resolveLocalCamouflageDefaults(ctx)
	if localIP != "" && localIP != "127.0.0.1" {
		out = append(out, localIP)
	}
	if s.fleet != nil && s.fleet.Store != nil {
		if nodes, err := s.fleet.Store.ListPublic(); err == nil {
			for _, n := range nodes {
				if strings.TrimSpace(n.Host) != "" {
					out = append(out, strings.TrimSpace(n.Host))
				}
			}
		}
	}
	return out
}

func (s *Server) handleGetSniffers(w http.ResponseWriter, r *http.Request) {
	nodeScope := cmp.Or(strings.TrimSpace(r.URL.Query().Get("node")), "all")
	forceRefresh := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("refresh") == "true"

	if s.sniff == nil {
		writeJSON(w, http.StatusOK, SniffSummary{
			SelectedNode: nodeScope,
			TopIPs:       []SniffIPStat{},
			TopSubnets:   []SniffSubnetStat{},
			TopCountries: []SniffCountryStat{},
		})
		return
	}
	clientIP := s.getClientIPAndSeedGeo(r)
	protected := s.collectProtectedIPs(r.Context())
	if clientIP != "" && clientIP != "loopback-direct" {
		protected = append(protected, clientIP)
	}
	if len(protected) > 0 {
		s.sniff.MarkTrustedClientIPs(protected...)
	}
	var activeProxyClients []string
	if s.telemetry != nil {
		tSnap := s.telemetry.Collect(r.Context())
		activeProxyClients = tSnap.ActiveClientIPs
	}
	summary := s.sniff.SnapshotForNode(r.Context(), nodeScope, forceRefresh, activeProxyClients...)
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleBlockSniffer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target   string `json:"target"`
		Node     string `json:"node"`
		ViewNode string `json:"viewNode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Target) == "" {
		writeJSONError(w, http.StatusBadRequest, "请提供要封禁的 IP 地址或 /24 网段")
		return
	}
	if s.sniff == nil {
		writeJSONError(w, http.StatusInternalServerError, "嗅探追踪器未初始化")
		return
	}

	nodeScope := cmp.Or(strings.TrimSpace(body.Node), "all")
	viewScope := cmp.Or(strings.TrimSpace(body.ViewNode), nodeScope)

	operatorIP := s.getClientIPAndSeedGeo(r)
	protected := s.collectProtectedIPs(r.Context())
	blockedTarget, appliedNodes, err := s.sniff.BlockTargetForNode(r.Context(), body.Target, nodeScope, operatorIP, protected...)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	scopeDesc := "全集群"
	if nodeScope == "local" {
		scopeDesc = "本机网关"
	} else if nodeScope != "all" {
		scopeDesc = "节点 " + nodeScope
	}
	s.recordAudit(r, fmt.Sprintf("手动拉黑外部嗅探源 [%s] (范围: %s, 生效主机: %d 台)", blockedTarget, scopeDesc, max(1, appliedNodes)))
	summary := s.sniff.SnapshotForNode(r.Context(), viewScope, false)
	writeJSON(w, http.StatusOK, map[string]any{
		"message":      fmt.Sprintf("已成功封禁嗅探目标 [%s]（生效范围: %s，共 %d 台主机已同步防火墙黑名单）", blockedTarget, scopeDesc, max(1, appliedNodes)),
		"target":       blockedTarget,
		"appliedNodes": max(1, appliedNodes),
		"summary":      summary,
	})
}
