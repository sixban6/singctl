package webui

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strings"

	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/gateway"
)

type gatewayPutRequest struct {
	Mode         string `json:"mode"`
	MainRouterIP string `json:"mainRouterIP"`
	LANIface     string `json:"lanIface,omitempty"`
}

func (s *Server) probeGatewayTopology() gateway.TopologyInfo {
	if s.opts.GatewayProberForTest != nil {
		return s.opts.GatewayProberForTest()
	}
	return gateway.ProbeTopology()
}

func (s *Server) gatewayStatusSummary() map[string]any {
	mode := gateway.ModeMain
	mainRouterIP := ""
	if cfg, err := config.Load(configPathFor(s)); err == nil && cfg != nil {
		mode = cfg.Gateway.EffectiveMode()
		mainRouterIP = strings.TrimSpace(cfg.Gateway.MainRouterIP)
	}
	return map[string]any{
		"supported":    runtime.GOOS == "linux",
		"mode":         mode,
		"mainRouterIP": mainRouterIP,
	}
}

func (s *Server) handleGatewayGet(w http.ResponseWriter, _ *http.Request) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg, err := config.Load(configPathFor(s))
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	topo := s.probeGatewayTopology()

	writeJSON(w, http.StatusOK, map[string]any{
		"supported":    runtime.GOOS == "linux" || s.opts.GatewayProberForTest != nil,
		"mode":         cfg.Gateway.EffectiveMode(),
		"mainRouterIP": strings.TrimSpace(cfg.Gateway.MainRouterIP),
		"lanIface":     strings.TrimSpace(cfg.Gateway.LANIface),
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

	topo := s.probeGatewayTopology()
	rawMode := strings.ToLower(strings.TrimSpace(body.Mode))
	if rawMode == "" {
		rawMode = gateway.ModeMain
	}
	nextGw := config.GatewayConfig{
		Mode:         rawMode,
		MainRouterIP: strings.TrimSpace(body.MainRouterIP),
		LANIface:     strings.TrimSpace(body.LANIface),
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

	cfgPath := configPathFor(s)
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
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

	if syncErr := s.newAdGuardManager(cfg).SyncGatewayMode(topo.LANIP); syncErr != nil {
		// 本地 AdGuardHome 配置同步异常不阻断网关规则应用，仅记录日志
		_ = syncErr
	}

	appliedLive := false
	if runtime.GOOS == "linux" && s.opts.GatewayProberForTest == nil && daemon.IsSingBoxRunning() {
		if err := gateway.NewController().Apply(r.Context(), nextGw); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "配置已保存，但热应用网关规则失败: "+err.Error())
			return
		}
		appliedLive = true
	}

	msg := "已保存为主路由模式 (main)"
	if nextGw.IsSideRouter() {
		if appliedLive {
			msg = "已切换为旁路由模式并即时热生效"
		} else {
			msg = "已保存为旁路由模式，启动 sing-box 时自动生效"
		}
	} else if appliedLive {
		msg = "已切回主路由模式并移除旁路由附加规则"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"appliedLive":  appliedLive,
		"message":      msg,
		"mode":         nextGw.EffectiveMode(),
		"mainRouterIP": nextGw.MainRouterIP,
		"lanIface":     nextGw.LANIface,
		"topology":     topo,
	})
}
