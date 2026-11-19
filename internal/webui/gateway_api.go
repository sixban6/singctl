package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"

	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/gateway"
	"singctl/internal/singbox"
)

type gatewayPutRequest struct {
	Mode         string  `json:"mode"`
	MainRouterIP string  `json:"mainRouterIP"`
	LANIface     string  `json:"lanIface,omitempty"`
	IPv6Mode     *string `json:"ipv6Mode,omitempty"`
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
	mainRouterIP := ""
	ipv6Mode := config.GatewayIPv6Off
	if cfg, err := config.Load(configPathFor(s)); err == nil && cfg != nil {
		mode = cfg.Gateway.EffectiveMode()
		mainRouterIP = strings.TrimSpace(cfg.Gateway.MainRouterIP)
		ipv6Mode = cfg.Gateway.EffectiveIPv6Mode()
	}
	return map[string]any{
		"supported":    runtime.GOOS == "linux",
		"mode":         mode,
		"mainRouterIP": mainRouterIP,
		"ipv6Mode":     ipv6Mode,
	}
}

func (s *Server) handleGatewayGet(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg, err := config.Load(configPathFor(s))
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	topo := s.probeGatewayTopology()
	ipv6Status := s.probeGatewayIPv6Status(r.Context(), cfg.Gateway, topo)

	writeJSON(w, http.StatusOK, map[string]any{
		"supported":    runtime.GOOS == "linux" || s.opts.GatewayProberForTest != nil,
		"mode":         cfg.Gateway.EffectiveMode(),
		"mainRouterIP": strings.TrimSpace(cfg.Gateway.MainRouterIP),
		"lanIface":     strings.TrimSpace(cfg.Gateway.LANIface),
		"ipv6Mode":     cfg.Gateway.EffectiveIPv6Mode(),
		"ipv6Status":   ipv6Status,
		"topology":     topo,
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
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	prevIPv6Mode := cfg.Gateway.EffectiveIPv6Mode()

	topo := s.probeGatewayTopology()
	rawMode := strings.ToLower(strings.TrimSpace(body.Mode))
	if rawMode == "" {
		rawMode = gateway.ModeMain
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
		MainRouterIP: strings.TrimSpace(body.MainRouterIP),
		LANIface:     strings.TrimSpace(body.LANIface),
		IPv6Mode:     desiredIPv6,
	}
	if _, err := gateway.ResolveAndValidate(nextGw, topo); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if nextGw.EffectiveMode() == gateway.ModeMain {
		nextGw.Mode = gateway.ModeMain
		nextGw.MainRouterIP = ""
		nextGw.LANIface = ""
	}
	if nextGw.EffectiveIPv6Mode() == config.GatewayIPv6Off {
		nextGw.IPv6Mode = config.GatewayIPv6Off
	}
	cfg.Gateway = nextGw

	if err := backupConfig(cfgPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份配置失败: "+err.Error())
		return
	}
	if err := config.Save(cfgPath, cfg); err != nil {
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
			if origReadErr == nil {
				_ = os.WriteFile(cfgPath, origCfgBytes, 0600)
			}
			writeJSONError(w, http.StatusInternalServerError, "自动配置宿主 IPv6 失败（已回滚）: "+v6Err.Error())
			return
		} else if v6Res != nil {
			ipv6Actions = v6Res.Actions
			ipv6Status = v6Res.Status
		}
	} else {
		ipv6Status = s.probeGatewayIPv6Status(r.Context(), nextGw, topo)
	}

	// 同步热更新 /etc/sing-box/config.json 中的 IPv6 DNS 策略（存在即生效）
	sbPath := s.sbConfigPath()
	if rawSBBytes, sbErr := os.ReadFile(sbPath); sbErr == nil && strings.TrimSpace(string(rawSBBytes)) != "" {
		if ipv6Changed || nextGw.EffectiveIPv6Mode() != config.GatewayIPv6Off || body.IPv6Mode != nil {
			updatedJSON, convErr := singbox.ApplyIPv6ModeToConfigJSON(string(rawSBBytes), nextGw.EffectiveIPv6Mode())
			if convErr != nil {
				if origReadErr == nil {
					_ = os.WriteFile(cfgPath, origCfgBytes, 0600)
				}
				writeJSONError(w, http.StatusInternalServerError, "编译 sing-box IPv6 规则失败: "+convErr.Error())
				return
			}
			if liveErr := singbox.ApplyLiveSingBoxConfig(r.Context(), sbPath, s.sbWorkConfigPath(), updatedJSON, "ipv6"); liveErr != nil {
				if origReadErr == nil {
					_ = os.WriteFile(cfgPath, origCfgBytes, 0600)
				}
				writeJSONError(w, http.StatusBadRequest, "sing-box 配置校验或热重载失败: "+liveErr.Error())
				return
			}
			if daemon.IsSingBoxRunning() {
				appliedLive = true
			}
		}
	}

	msg := "已保存网关设置"
	if body.IPv6Mode != nil || ipv6Changed {
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
		"ok":           true,
		"appliedLive":  appliedLive,
		"message":      msg,
		"mode":         nextGw.EffectiveMode(),
		"mainRouterIP": nextGw.MainRouterIP,
		"lanIface":     nextGw.LANIface,
		"ipv6Mode":     nextGw.EffectiveIPv6Mode(),
		"ipv6Status":   ipv6Status,
		"ipv6Actions":  ipv6Actions,
		"topology":     topo,
	})
}
