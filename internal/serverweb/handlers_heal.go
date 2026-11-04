package serverweb

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"singctl/internal/fleet"
	"singctl/internal/heal"
)

func (s *Server) handleHealStatus(w http.ResponseWriter, r *http.Request) {
	rep := heal.Scan(r.Context(), s.opts.ConfigPath, s.opts.Version)
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleHealPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AutoHealEnabled bool   `json:"autoHealEnabled"`
		Schedule        string `json:"schedule"`
		AutoReboot      bool   `json:"autoReboot"`
		ApplyToFleet    bool   `json:"applyToFleet"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求: "+err.Error())
		return
	}

	policy := heal.HealPolicy{
		AutoHealEnabled: body.AutoHealEnabled,
		Schedule:        cmp.Or(strings.TrimSpace(body.Schedule), heal.DefaultPolicy().Schedule),
		AutoReboot:      body.AutoReboot,
	}
	timerSt, err := heal.ApplyPolicy(s.opts.ConfigPath, policy)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	var fleetMsg string
	if body.ApplyToFleet && policy.AutoHealEnabled {
		fRep, fErr := s.fleet.HealFleet(r.Context(), fleet.FleetHealOptions{
			CheckOnly:    true,
			EnableTimers: true,
			Schedule:     policy.Schedule,
		})
		if fErr == nil && fRep.TotalNodes > 0 {
			fleetMsg = fmt.Sprintf("（已同步下发定时策略至 %d 台舰队子节点）", fRep.TotalNodes)
		}
	}

	stateWord := "关闭"
	if policy.AutoHealEnabled {
		stateWord = "开启 (" + policy.Schedule + ")"
	}
	s.recordAudit(r, fmt.Sprintf("更新自动安全自愈策略: %s%s", stateWord, fleetMsg))

	rep := heal.Scan(r.Context(), s.opts.ConfigPath, s.opts.Version)
	rep.Timer = timerSt
	writeJSON(w, http.StatusOK, map[string]any{
		"message": fmt.Sprintf("自动安全自愈守护已%s%s", stateWord, fleetMsg),
		"status":  rep,
	})
}

func (s *Server) handleHealRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope        string   `json:"scope"` // "local" | "fleet"
		CheckOnly    bool     `json:"checkOnly"`
		AllowReboot  bool     `json:"allowReboot"`
		EnableTimers bool     `json:"enableTimers"`
		TargetIDs    []string `json:"targetIds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	scope := strings.ToLower(strings.TrimSpace(body.Scope))
	if scope == "" {
		scope = "local"
	}

	if scope == "fleet" {
		fleetRep, err := s.fleet.HealFleet(r.Context(), fleet.FleetHealOptions{
			CheckOnly:    body.CheckOnly,
			AllowReboot:  body.AllowReboot,
			EnableTimers: body.EnableTimers,
			TargetIDs:    body.TargetIDs,
		})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "舰队安全自愈执行失败: "+err.Error())
			return
		}

		// Run local Master self-healing (never auto-rebooting Master mid-WebUI session unless explicitly local)
		localRes, _ := heal.Run(r.Context(), heal.RunOptions{
			ConfigPath:        s.opts.ConfigPath,
			CurrentSingctlVer: s.opts.Version,
			CheckOnly:         body.CheckOnly,
			AllowReboot:       false,
			Trigger:           "fleet",
			AsyncWebRestart:   true,
		})

		s.recordAudit(r, fmt.Sprintf("执行全舰队三层安全自愈 (子节点=%d, 滚动重启=%d, 熔断=%v)",
			fleetRep.TotalNodes, fleetRep.RebootedNodes, fleetRep.CircuitBreakerHit))

		msg := fmt.Sprintf("全舰队安全自愈完成：%d/%d 子节点健康，主控: %s",
			fleetRep.HealthyNodes, fleetRep.TotalNodes, localRes.Execution.Summary)
		if fleetRep.CircuitBreakerHit {
			msg = fleetRep.CircuitBreakerNote
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"message":     msg,
			"scope":       "fleet",
			"fleetReport": fleetRep,
			"execution":   localRes.Execution,
			"status":      localRes.Status,
		})
		return
	}

	res, err := heal.Run(r.Context(), heal.RunOptions{
		ConfigPath:        s.opts.ConfigPath,
		CurrentSingctlVer: s.opts.Version,
		CheckOnly:         body.CheckOnly,
		AllowReboot:       body.AllowReboot,
		Trigger:           "manual",
		AsyncWebRestart:   true,
	})
	if err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	if !body.CheckOnly {
		s.recordAudit(r, "执行本机三层安全自愈: "+res.Execution.Summary)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":   res.Execution.Summary,
		"scope":     "local",
		"execution": res.Execution,
		"status":    res.Status,
	})
}
