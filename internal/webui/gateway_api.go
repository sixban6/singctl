// 文件职责：提供客户端主/旁路由网关拓扑探测、IPv6 智能双栈分流配置与热应用回滚接口。
package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/gateway"
	"singctl/internal/localdns"
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

type gatewayPutRequest struct {
	Mode             string  `json:"mode"`
	WorkMode         *string `json:"workMode,omitempty"`
	MainRouterIP     string  `json:"mainRouterIP"`
	LANIface         string  `json:"lanIface,omitempty"`
	IPv6Mode         *string `json:"ipv6Mode,omitempty"`
	SafeCommit       bool    `json:"safeCommit,omitempty"`
	SafeCommitTTLSec int     `json:"safeCommitTtlSec,omitempty"`
}

func (s *Server) probeGatewayTopology() gateway.TopologyInfo {
	if s.opts.GatewayProberForTest != nil {
		return s.opts.GatewayProberForTest()
	}
	return gateway.ProbeTopology()
}

func (s *Server) probeGatewayIPv6Status(ctx context.Context, gwCfg config.GatewayConfig, topo gateway.TopologyInfo) gateway.IPv6StatusInfo {
	if s.opts.GatewayProberForTest != nil {
		return gateway.IPv6StatusInfo{
			Supported: runtime.GOOS == "linux",
		}
	}
	return gateway.ProbeIPv6Status(ctx, gwCfg, topo)
}

func (s *Server) gatewayStatusSummary() map[string]any {
	mode := gateway.ModeMain
	workMode := config.WorkModeAuto
	effectiveWorkMode := config.WorkModeBasic
	hasSubs := false
	mainRouterIP := ""
	ipv6Mode := config.GatewayIPv6Off
	if cfg, err := s.loadConfigSnapshot(); err == nil && cfg != nil {
		mode = cfg.Gateway.EffectiveMode()
		workMode = cfg.ConfiguredWorkMode()
		effectiveWorkMode = cfg.EffectiveWorkMode()
		hasSubs = cfg.HasRealSubs()
		mainRouterIP = strings.TrimSpace(cfg.Gateway.MainRouterIP)
		ipv6Mode = cfg.Gateway.EffectiveIPv6Mode()
	}
	return map[string]any{
		"supported":         runtime.GOOS == "linux",
		"mode":              mode,
		"workMode":          workMode,
		"effectiveWorkMode": effectiveWorkMode,
		"hasSubs":           hasSubs,
		"mainRouterIP":      mainRouterIP,
		"ipv6Mode":          ipv6Mode,
	}
}

func (s *Server) handleGatewayGet(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.readConfigOrEmpty()
	topo := s.probeGatewayTopology()
	ipv6Status := s.probeGatewayIPv6Status(r.Context(), cfg.Gateway, topo)

	writeJSON(w, http.StatusOK, map[string]any{
		"supported":         runtime.GOOS == "linux" || s.opts.GatewayProberForTest != nil,
		"mode":              cfg.Gateway.EffectiveMode(),
		"workMode":          cfg.ConfiguredWorkMode(),
		"effectiveWorkMode": cfg.EffectiveWorkMode(),
		"hasSubs":           cfg.HasRealSubs(),
		"mainRouterIP":      strings.TrimSpace(cfg.Gateway.MainRouterIP),
		"lanIface":          strings.TrimSpace(cfg.Gateway.LANIface),
		"ipv6Mode":          cfg.Gateway.EffectiveIPv6Mode(),
		"ipv6Status":        ipv6Status,
		"topology":          topo,
	})
}

func (s *Server) handleGatewayPut(w http.ResponseWriter, r *http.Request) {
	var body gatewayPutRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfgPath := configPathFor(s)
	origCfgBytes, origReadErr := os.ReadFile(cfgPath)
	cfg := s.loadMutableConfig()
	prevIPv6Mode := cfg.Gateway.EffectiveIPv6Mode()
	prevWorkMode := cfg.EffectiveWorkMode()

	topo := s.probeGatewayTopology()
	rawMode := strings.ToLower(strings.TrimSpace(body.Mode))
	if rawMode == "" {
		rawMode = cfg.Gateway.EffectiveMode()
	}

	desiredWorkMode := cfg.ConfiguredWorkMode()
	workModeRequested := false
	if body.WorkMode != nil {
		normWM, ok := config.NormalizeWorkMode(*body.WorkMode)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "无效的工作模式参数（仅支持 auto / basic / audit / proxy）")
			return
		}
		if normWM == config.WorkModeProxy && !cfg.HasRealSubs() {
			writeJSONError(w, http.StatusBadRequest, "切换到「代理模式」需要先添加至少一条订阅链接；无需订阅请选择「基础模式」或「审计模式」")
			return
		}
		desiredWorkMode = normWM
		workModeRequested = true
	}

	desiredIPv6 := prevIPv6Mode
	if body.IPv6Mode != nil {
		normV6, ok := config.NormalizeGatewayIPv6Mode(*body.IPv6Mode)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "无效的 ipv6Mode 参数（仅支持 off / cn_only / full）")
			return
		}
		desiredIPv6 = normV6
	} else if rawMode == gateway.ModeSide {
		desiredIPv6 = config.GatewayIPv6Off
	}

	if rawMode == gateway.ModeSide && desiredIPv6 != config.GatewayIPv6Off {
		writeJSONError(w, http.StatusBadRequest, "旁路由模式下不支持开启 IPv6 透明代理（主路由会广播 IPv6 网关并绕过旁路由，请先将 IPv6 模式设为关闭或切回主路由模式）")
		return
	}

	nextGw := config.GatewayConfig{
		Mode:         rawMode,
		WorkMode:     desiredWorkMode,
		MainRouterIP: strings.TrimSpace(body.MainRouterIP),
		LANIface:     strings.TrimSpace(body.LANIface),
		IPv6Mode:     desiredIPv6,
	}
	if _, err := gateway.ResolveAndValidate(nextGw, topo); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if body.SafeCommit {
		if _, err := s.armSafeCommit(r.Context(), body.SafeCommitTTLSec, "网关模式/工作模式变更"); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if nextGw.EffectiveMode() == gateway.ModeMain {
		nextGw.Mode = gateway.ModeMain
		nextGw.MainRouterIP = ""
		nextGw.LANIface = ""
	}
	if nextGw.EffectiveIPv6Mode() == config.GatewayIPv6Off {
		nextGw.IPv6Mode = config.GatewayIPv6Off
	}
	if nextGw.ConfiguredWorkMode() == config.WorkModeAuto {
		nextGw.WorkMode = ""
	}
	cfg.Gateway = nextGw

	if err := backupConfig(cfgPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份配置失败: "+err.Error())
		return
	}
	if err := s.saveConfig(cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存 singctl.yaml 失败: "+err.Error())
		return
	}
	s.invalidateIOSCache()

	if syncErr := s.newAdGuardManager(cfg).SyncGatewayMode(topo.LANIP); syncErr != nil {
		// 本地 AdGuardHome 配置同步异常不阻断网关规则应用，仅记录日志
		_ = syncErr
	}

	ipv6Changed := prevIPv6Mode != nextGw.EffectiveIPv6Mode()
	var ipv6Actions []string
	var ipv6Status gateway.IPv6StatusInfo

	appliedLive := false
	isRealHost := runtime.GOOS == "linux" && s.opts.GatewayProberForTest == nil
	if isRealHost && daemon.IsSingBoxRunning() {
		var gwErr error
		if nextGw.IsSideRouter() {
			gwErr = gateway.NewController().Apply(r.Context(), nextGw)
		} else {
			gwErr = gateway.NewController().Teardown(r.Context())
		}
		if gwErr != nil {
			writeJSONError(w, http.StatusInternalServerError, "配置已保存，但热应用网关规则失败: "+gwErr.Error())
			return
		}
		appliedLive = true
	}

	if isRealHost && (ipv6Changed || nextGw.EffectiveIPv6Mode() != config.GatewayIPv6Off) {
		if v6Res, v6Err := gateway.NewController().SyncIPv6Host(r.Context(), nextGw); v6Err != nil {
			s.rollbackSavedConfigFile(cfgPath, origCfgBytes, origReadErr)
			writeJSONError(w, http.StatusInternalServerError, "自动配置宿主 IPv6 失败（已回滚）: "+v6Err.Error())
			return
		} else if v6Res != nil {
			ipv6Actions = v6Res.Actions
			ipv6Status = v6Res.Status
		}
	} else {
		ipv6Status = s.probeGatewayIPv6Status(r.Context(), nextGw, topo)
	}

	// 同步热更新 /etc/sing-box/config.json 中的 IPv6 DNS 策略（存在即生效）。
	// 若本次请求正在切换工作模式（将停用或全新重编译 config.json），或在真实宿主机基础模式且 sing-box 未运行时，
	// 跳过对磁盘旧 config.json 的校验与改写，避免历史废弃配置阻断模式切换。
	newEffectiveWorkMode := cfg.EffectiveWorkMode()
	willApplyWorkMode := workModeRequested && (newEffectiveWorkMode != prevWorkMode || s.opts.WorkModeApplyForTest != nil)
	skipLegacySBIPv6Patch := willApplyWorkMode ||
		(isRealHost && newEffectiveWorkMode == config.WorkModeBasic && !daemon.IsSingBoxRunning())
	sbPath := s.sbConfigPath()
	if !skipLegacySBIPv6Patch {
		if rawSBBytes, sbErr := os.ReadFile(sbPath); sbErr == nil && strings.TrimSpace(string(rawSBBytes)) != "" {
			if ipv6Changed || nextGw.EffectiveIPv6Mode() != config.GatewayIPv6Off || body.IPv6Mode != nil {
				updatedJSON, convErr := singbox.ApplyIPv6ModeToConfigJSON(string(rawSBBytes), nextGw.EffectiveIPv6Mode())
				if convErr != nil {
					s.rollbackSavedConfigFile(cfgPath, origCfgBytes, origReadErr)
					writeJSONError(w, http.StatusInternalServerError, "编译 sing-box IPv6 规则失败: "+convErr.Error())
					return
				}
				if liveErr := singbox.ApplyLiveSingBoxConfig(r.Context(), sbPath, s.sbWorkConfigPath(), updatedJSON, "ipv6"); liveErr != nil {
					s.rollbackSavedConfigFile(cfgPath, origCfgBytes, origReadErr)
					writeJSONError(w, http.StatusBadRequest, "sing-box 配置校验或热重载失败: "+liveErr.Error())
					return
				}
				if daemon.IsSingBoxRunning() {
					appliedLive = true
				}
			}
		}
	}

	// 同步 SmartDNS 的 force-AAAA-SOA 策略（唯一真相源为 gateway.ipv6_mode：off -> 屏蔽 AAAA，cn_only/full -> 放行）
	if ipv6Changed || body.IPv6Mode != nil {
		if active := s.newDNSRegistry(cfg).ActiveEngine(); active != nil &&
			active.ID() == constant.DNSEngineSmartDNS && active.IsInstalled() {
			if syncErr := active.SyncCommonConfig(r.Context()); syncErr != nil {
				logger.Warn("[Gateway] 同步 SmartDNS AAAA 策略失败: %v", syncErr)
			}
		}
	}

	// 若请求切换了工作模式（基础模式 / 审计模式 / 代理模式），执行热切换
	workModeMsg := ""
	if willApplyWorkMode {
		liveOK, wmMsg, wmErr := s.applyWorkModeLive(r.Context(), cfg, prevWorkMode, newEffectiveWorkMode)
		if wmErr != nil {
			s.rollbackSavedConfigFile(cfgPath, origCfgBytes, origReadErr)
			writeJSONError(w, http.StatusInternalServerError, "切换工作模式失败（已回滚）: "+wmErr.Error())
			return
		}
		if liveOK {
			appliedLive = true
		}
		workModeMsg = wmMsg
		_ = daemon.NotifyReload()
	}

	msg := "已保存网关设置"
	if workModeMsg != "" {
		msg = workModeMsg
	} else if body.IPv6Mode != nil || ipv6Changed {
		switch nextGw.EffectiveIPv6Mode() {
		case config.GatewayIPv6CNOnly:
			msg = "已启用 IPv6 智能双栈分流（国内原生 IPv6 + 海外纯 IPv4 零泄漏）并自动完成宿主配置"
		case config.GatewayIPv6Full:
			msg = "已启用 IPv6 全量双栈并自动完成宿主配置"
		default:
			if nextGw.IsSideRouter() {
				msg = "已切换为旁路由模式并关闭 IPv6"
			} else {
				msg = "已关闭 IPv6 分流并恢复纯 IPv4 模式"
			}
		}
	} else if nextGw.IsSideRouter() {
		if appliedLive {
			msg = "已切换为旁路由模式并即时热生效"
		} else {
			msg = "已保存为旁路由模式，启动 sing-box 时自动生效"
		}
	} else if appliedLive {
		msg = "已切回主路由模式并移除旁路由附加规则"
	} else {
		msg = "已保存为主路由模式 (main)"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"appliedLive":       appliedLive,
		"message":           msg,
		"mode":              nextGw.EffectiveMode(),
		"workMode":          cfg.ConfiguredWorkMode(),
		"effectiveWorkMode": newEffectiveWorkMode,
		"hasSubs":           cfg.HasRealSubs(),
		"mainRouterIP":      nextGw.MainRouterIP,
		"lanIface":          nextGw.LANIface,
		"ipv6Mode":          nextGw.EffectiveIPv6Mode(),
		"ipv6Status":        ipv6Status,
		"ipv6Actions":       ipv6Actions,
		"topology":          topo,
	})
}

func (s *Server) applyWorkModeLive(ctx context.Context, cfg *config.Config, prevMode, targetMode string) (bool, string, error) {
	if s.opts.WorkModeApplyForTest != nil {
		return s.opts.WorkModeApplyForTest(ctx, cfg, targetMode)
	}
	if runtime.GOOS != "linux" {
		return false, "已保存工作模式（非 Linux 宿主机仅更新配置）", nil
	}

	dnsPort := cfg.DNS.GetDNSPort()
	restoreBasicBridgeIfNeeded := func() {
		if prevMode == config.WorkModeBasic && cfg.DNS.IsEnabled() {
			_, _ = localdns.SyncOpenWrtDnsmasqBridge(ctx, true, dnsPort, localdns.DnsmasqBridgeDeps{})
		}
	}

	switch targetMode {
	case config.WorkModeBasic:
		if daemon.IsSingBoxRunning() {
			if err := singbox.New(cfg).Stop(); err != nil {
				return false, "", fmt.Errorf("停止 sing-box 失败: %w", err)
			}
		}
		if active := s.newDNSRegistry(cfg).ActiveEngine(); active != nil && active.IsInstalled() && cfg.DNS.IsEnabled() {
			_ = active.EnsureHealthy(ctx)
			if _, err := localdns.SyncOpenWrtDnsmasqBridge(ctx, true, dnsPort, localdns.DnsmasqBridgeDeps{}); err != nil {
				logger.Warn("[WorkMode] 接管 dnsmasq 桥接告警: %v", err)
			}
		}
		return true, "已切换为「基础模式」（已停止代理内核，防劫持 DNS 与隔离网零损耗生效）", nil

	case config.WorkModeAudit:
		sb := singbox.New(cfg)
		if err := sb.GenerateConfig(); err != nil {
			return false, "", fmt.Errorf("生成免订阅审计配置失败: %w", err)
		}
		if daemon.IsSingBoxRunning() {
			_ = sb.Stop()
		}
		_, _ = localdns.SyncOpenWrtDnsmasqBridge(ctx, false, dnsPort, localdns.DnsmasqBridgeDeps{})
		if err := sb.Start(); err != nil {
			restoreBasicBridgeIfNeeded()
			return false, "", fmt.Errorf("启动免订阅审计内核失败: %w", err)
		}
		return true, "已切换为「审计模式」（无需订阅，实时行为审计、PCDN 拦截与防劫持 DNS 已激活）", nil

	case config.WorkModeProxy:
		sb := singbox.New(cfg)
		if err := sb.GenerateConfig(); err != nil {
			return false, "", fmt.Errorf("生成代理配置失败: %w", err)
		}
		if daemon.IsSingBoxRunning() {
			_ = sb.Stop()
		}
		_, _ = localdns.SyncOpenWrtDnsmasqBridge(ctx, false, dnsPort, localdns.DnsmasqBridgeDeps{})
		if err := sb.Start(); err != nil {
			restoreBasicBridgeIfNeeded()
			return false, "", fmt.Errorf("启动代理内核失败: %w", err)
		}
		return true, "已切换为「代理模式」（透明代理智能分流与完整审计已生效）", nil

	default:
		return false, "已保存工作模式", nil
	}
}
