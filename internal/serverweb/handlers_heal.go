// 文件职责：提供三层自动化安全自愈中心的状态 SWR 缓存查询、策略配置与本机/舰队自愈执行薄 HTTP 接口。
package serverweb

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/common/httpx"
	"singctl/internal/fleet"
	"singctl/internal/heal"
)

const healStatusCacheTTL = 3 * time.Minute

type healCacheState struct {
	cacheMu    sync.Mutex
	scanMu     sync.Mutex
	cached     *heal.StatusReport
	cachedAt   time.Time
	refreshing atomic.Bool
}

func (h *healCacheState) set(rep *heal.StatusReport, at time.Time) {
	if h == nil || rep == nil {
		return
	}
	cp := *rep
	h.cacheMu.Lock()
	h.cached = &cp
	h.cachedAt = at
	h.cacheMu.Unlock()
}

func (s *Server) storeHealStatusCache(rep *heal.StatusReport) {
	if s.caches != nil && s.caches.heal != nil {
		s.caches.heal.set(rep, time.Now())
	}
}

func (s *Server) runHealScanSync(ctx context.Context) heal.StatusReport {
	s.caches.heal.scanMu.Lock()
	defer s.caches.heal.scanMu.Unlock()

	scanFn := s.snapshotDeps().HealScanner
	if scanFn == nil {
		scanFn = heal.Scan
	}
	rep := scanFn(ctx, s.opts.ConfigPath, s.opts.Version)
	s.storeHealStatusCache(&rep)
	return rep
}

func (s *Server) scanAndCacheHealStatus(ctx context.Context, force bool) heal.StatusReport {
	if !force {
		s.caches.heal.cacheMu.Lock()
		if s.caches.heal.cached != nil {
			rep := *s.caches.heal.cached
			fresh := time.Since(s.caches.heal.cachedAt) < healStatusCacheTTL
			s.caches.heal.cacheMu.Unlock()
			if !fresh {
				tryRunSingleFlight(&s.caches.heal.refreshing, 45*time.Second, func(bgCtx context.Context) {
					s.runHealScanSync(bgCtx)
				})
			}
			return rep
		}
		s.caches.heal.cacheMu.Unlock()
	}
	return s.runHealScanSync(ctx)
}

func (s *Server) handleHealStatus(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("refresh") == "true"
	writeJSON(w, http.StatusOK, s.scanAndCacheHealStatus(r.Context(), force))
}

func (s *Server) handleHealPolicy(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		AutoHealEnabled bool   `json:"autoHealEnabled"`
		Schedule        string `json:"schedule"`
		AutoReboot      bool   `json:"autoReboot"`
		ApplyToFleet    bool   `json:"applyToFleet"`
	}
	body, ok := decodeBodyJSON[reqBody](w, r, httpx.DefaultMaxBodyBytes, false, "")
	if !ok {
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
	s.storeHealStatusCache(&rep)
	writeJSON(w, http.StatusOK, map[string]any{
		"message": fmt.Sprintf("自动安全自愈守护已%s%s", stateWord, fleetMsg),
		"status":  rep,
	})
}

func (s *Server) handleHealRun(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Scope        string   `json:"scope"`
		CheckOnly    bool     `json:"checkOnly"`
		AllowReboot  bool     `json:"allowReboot"`
		EnableTimers bool     `json:"enableTimers"`
		TargetIDs    []string `json:"targetIds"`
	}
	body, ok := decodeBodyJSON[reqBody](w, r, httpx.DefaultMaxBodyBytes, true, "")
	if !ok {
		return
	}
	scope := cmp.Or(strings.ToLower(strings.TrimSpace(body.Scope)), "local")

	execCtx := r.Context()
	var cancel context.CancelFunc
	if !body.CheckOnly {
		execCtx, cancel = context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Minute)
		defer cancel()
	}

	if scope == "fleet" {
		fleetRep, err := s.fleet.HealFleet(execCtx, fleet.FleetHealOptions{
			CheckOnly:    body.CheckOnly,
			AllowReboot:  body.AllowReboot,
			EnableTimers: body.EnableTimers,
			TargetIDs:    body.TargetIDs,
		})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "舰队安全自愈执行失败: "+err.Error())
			return
		}

		localRes, _ := heal.Run(execCtx, heal.RunOptions{
			ConfigPath:        s.opts.ConfigPath,
			CurrentSingctlVer: s.opts.Version,
			CheckOnly:         body.CheckOnly,
			AllowReboot:       false,
			Trigger:           "fleet",
			AsyncWebRestart:   true,
		})
		s.storeHealStatusCache(&localRes.Status)
		if !body.CheckOnly {
			s.invalidateStatusCaches()
		}

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
	s.storeHealStatusCache(&res.Status)
	if !body.CheckOnly {
		s.invalidateStatusCaches()
		s.recordAudit(r, "执行本机三层安全自愈: "+res.Execution.Summary)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":   res.Execution.Summary,
		"scope":     "local",
		"execution": res.Execution,
		"status":    res.Status,
	})
}
