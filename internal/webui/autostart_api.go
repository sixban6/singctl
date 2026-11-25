// 文件职责：提供客户端 WebUI 开机自启动与掉电恢复开关 API（GET /api/system/autostart 与 PUT /api/system/autostart）。
package webui

import (
	"context"
	"encoding/json"
	"net/http"

	"singctl/internal/daemon"
)

func (s *Server) autoStartDeps() daemon.AutoStartDeps {
	return daemon.AutoStartDeps{
		ConfigPath:     configPathFor(s),
		ExecutablePath: s.opts.ExecutablePath,
		ProcdInitDir:   s.opts.AutoStartProcdDir,
		ServiceMgr:     s.opts.AutoStartServiceMgr,
	}
}

func (s *Server) autoStartStatusSummary(ctx context.Context) daemon.AutoStartStatus {
	cfg := s.readConfigOrEmpty()
	return daemon.InspectAutoStartStatus(ctx, cfg, s.autoStartDeps())
}

func (s *Server) handleAutoStartGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.autoStartStatusSummary(r.Context()))
}

func (s *Server) handleAutoStartPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	if err := dec.Decode(&req); err != nil || req.Enabled == nil {
		writeJSONError(w, http.StatusBadRequest, "请求参数无效：缺少 enabled 布尔开关")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	nextCfg := s.loadMutableConfig()
	nextCfg.Watchdog.SetAutoStart(*req.Enabled)
	if err := s.saveConfig(nextCfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存 singctl.yaml 自启动配置失败: "+err.Error())
		return
	}

	st, err := daemon.ReconcileAutoStart(r.Context(), nextCfg, *req.Enabled, s.autoStartDeps())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "同步系统开机自启服务失败: "+err.Error())
		return
	}
	daemon.NotifyReload()

	msg := "已开启路由器开机自启动与掉电恢复"
	if !*req.Enabled {
		msg = "已关闭路由器开机自启动与掉电恢复"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": msg,
		"status":  st,
	})
}
