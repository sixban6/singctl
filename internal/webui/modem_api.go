// 文件职责：提供客户端上游光猫探测、桥接免插线辅助口开关及按需内嵌反向代理控制台 Web API。
package webui

import (
	"cmp"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"singctl/internal/gateway"
)

type modemStatusHTTPResponse struct {
	gateway.ModemStatus
	Console     gateway.ModemProxyStatus        `json:"console"`
	Credentials gateway.ModemCredentialsSummary `json:"credentials"`
}

func (s *Server) modemDeps() gateway.ModemDeps {
	if s.opts.ModemDepsForTest != nil {
		return *s.opts.ModemDepsForTest
	}
	return gateway.ModemDeps{}
}

func (s *Server) preferredModemConsolePort() int {
	if s.opts.ModemConsolePort != nil {
		return *s.opts.ModemConsolePort
	}
	return gateway.DefaultModemConsolePort
}

func (s *Server) modemVaultPath() string {
	return gateway.ModemVaultPath(configPathFor(s))
}

func (s *Server) buildModemStatusResponse(st gateway.ModemStatus) modemStatusHTTPResponse {
	return modemStatusHTTPResponse{
		ModemStatus: st,
		Console:     s.modemProxy.Status(),
		Credentials: gateway.LoadModemCredentialsSummary(s.modemVaultPath()),
	}
}

func (s *Server) handleModemStatusGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfigOrEmpty()
	topo := s.probeGatewayTopology()
	st := gateway.ProbeModemStatus(r.Context(), cfg.Gateway, topo, s.modemDeps())
	writeJSON(w, http.StatusOK, s.buildModemStatusResponse(st))
}

func (s *Server) handleModemConfigPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ModemIP string `json:"modemIP"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfgPath := configPathFor(s)
	cfg := s.loadMutableConfig()
	topo := s.probeGatewayTopology()
	validIP, err := gateway.ValidateModemIP(
		body.ModemIP,
		topo.LANIP,
		cfg.Gateway.MainRouterIP,
		cfg.Gateway.SideRouterIP,
	)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	cfg.Gateway.ModemIP = validIP
	if err := backupConfig(cfgPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份配置失败: "+err.Error())
		return
	}
	if err := s.saveConfig(cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}

	st := gateway.ProbeModemStatus(r.Context(), cfg.Gateway, topo, s.modemDeps())
	msg := "已恢复自动探测上游光猫地址"
	if validIP != "" {
		msg = "已保存上游光猫地址 " + validIP
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": msg,
		"status":  s.buildModemStatusResponse(st),
	})
}

func (s *Server) handleModemBridgePut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled *bool  `json:"enabled"`
		ModemIP string `json:"modemIP"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if body.Enabled == nil {
		writeJSONError(w, http.StatusBadRequest, "缺少必需参数 enabled (true/false)")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	topo := s.probeGatewayTopology()
	deps := s.modemDeps()

	targetIP := strings.TrimSpace(body.ModemIP)
	if *body.Enabled {
		if targetIP == "" {
			probe := gateway.ProbeModemStatus(r.Context(), cfg.Gateway, topo, deps)
			targetIP = cmp.Or(strings.TrimSpace(cfg.Gateway.ModemIP), probe.EffectiveModemIP, "192.168.1.1")
		}
		validIP, vErr := gateway.ValidateModemIP(targetIP, topo.LANIP, cfg.Gateway.MainRouterIP, cfg.Gateway.SideRouterIP)
		if vErr != nil {
			writeJSONError(w, http.StatusBadRequest, vErr.Error())
			return
		}
		targetIP = validIP
	}

	msg, err := gateway.ApplyModemBridgeHelper(r.Context(), *body.Enabled, targetIP, topo, deps)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if *body.Enabled && strings.TrimSpace(body.ModemIP) != "" && cfg.Gateway.ModemIP != targetIP {
		cfgPath := configPathFor(s)
		cfg.Gateway.ModemIP = targetIP
		if backupConfig(cfgPath) == nil {
			_ = s.saveConfig(cfg)
		}
	}

	st := gateway.ProbeModemStatus(r.Context(), cfg.Gateway, topo, deps)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": msg,
		"status":  s.buildModemStatusResponse(st),
	})
}

func (s *Server) handleModemConsoleOpenPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scheme string `json:"scheme"`
		IP     string `json:"ip"`
		Port   int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	cfg := s.readConfigOrEmpty()
	topo := s.probeGatewayTopology()
	targetIP := strings.TrimSpace(body.IP)
	scheme := strings.TrimSpace(body.Scheme)
	port := body.Port

	if targetIP == "" || port == 0 {
		st := gateway.ProbeModemStatus(r.Context(), cfg.Gateway, topo, s.modemDeps())
		targetIP = cmp.Or(targetIP, st.EffectiveModemIP)
		scheme = cmp.Or(scheme, st.Scheme, "http")
		if port == 0 {
			port = st.Port
		}
	}
	if targetIP == "" {
		writeJSONError(w, http.StatusBadRequest, "未探测到可用的上游光猫地址，请先手动填写光猫 IP")
		return
	}

	sess, err := s.modemProxy.Open(gateway.ModemProxyTarget{
		Scheme: scheme,
		IP:     targetIP,
		Port:   port,
	}, s.preferredModemConsolePort())
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"session": sess,
		"console": s.modemProxy.Status(),
	})
}

func (s *Server) handleModemConsoleClosePost(w http.ResponseWriter, r *http.Request) {
	_ = s.modemProxy.Close()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"running": false,
		"console": s.modemProxy.Status(),
	})
}

func (s *Server) handleModemCredentialsPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slot     string `json:"slot"`
		Username string `json:"username"`
		Password string `json:"password"`
		Clear    bool   `json:"clear"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.modemVaultMu.Lock()
	summary, err := gateway.SaveModemCredentialSlot(
		s.modemVaultPath(),
		body.Slot,
		body.Username,
		body.Password,
		body.Clear,
		time.Now(),
	)
	s.modemVaultMu.Unlock()
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	msg := "已安全保存光猫凭据 (0600 加密落盘)"
	if body.Clear {
		msg = "已清空该槽位保存的光猫凭据"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"message":     msg,
		"credentials": summary,
	})
}

func (s *Server) handleModemCredentialsUsePost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slot string `json:"slot"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	slot := strings.ToLower(strings.TrimSpace(body.Slot))
	if slot != gateway.ModemCredentialSlotSuper && slot != gateway.ModemCredentialSlotUser {
		writeJSONError(w, http.StatusBadRequest, "不支持的光猫凭据槽位（仅允许 super 或 user）")
		return
	}

	s.modemVaultMu.Lock()
	user, pass, err := gateway.ReadModemCredentialSecret(s.modemVaultPath(), slot)
	s.modemVaultMu.Unlock()
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"slot":     slot,
		"username": user,
		"password": pass,
	})
}
