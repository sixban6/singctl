// 文件职责：提供客户端 WebUI 对 Tailscale P2P 零常驻暴露防线的状态查询、配置热下发与瞬时打洞接口。
package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"time"

	"singctl/internal/common/netx"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/tailscale"
)

// TailscaleP2PTestHooks 仅供离线单元测试注入可控的 Tailscale / fw4 / ujail 依赖。
type TailscaleP2PTestHooks struct {
	Controller       *tailscale.P2PAssistController
	FW4Available     bool
	UjailAvailable   bool
	UjailApply       func(ctx context.Context, enable bool) (bool, error)
	Now              func() time.Time
	DefaultLANCIDR   string
	LiveSubnets      string
	RouteOutput      string
	LeaseText        string
	NeighText        string
	MeshSync         func(ctx context.Context, subnetsCSV string, acceptRoutes bool) error
	MeshSyncWithMode func(ctx context.Context, mode, subnetsCSV string, acceptRoutes, exitNode bool) error
}

func (s *Server) tailscaleP2PNow() time.Time {
	if s.opts.TailscaleP2PForTest != nil && s.opts.TailscaleP2PForTest.Now != nil {
		return s.opts.TailscaleP2PForTest.Now()
	}
	return time.Now()
}

func (s *Server) defaultLANCIDR() string {
	if s.opts.TailscaleP2PForTest != nil && strings.TrimSpace(s.opts.TailscaleP2PForTest.DefaultLANCIDR) != "" {
		return strings.TrimSpace(s.opts.TailscaleP2PForTest.DefaultLANCIDR)
	}
	if sub, err := netx.GetLANSubnet(); err == nil {
		return sub
	}
	return ""
}

func (s *Server) effectiveProtectedLANCIDRs() string {
	if cfg, err := s.loadConfigSnapshot(); err == nil && cfg != nil {
		rm := strings.ToLower(strings.TrimSpace(cfg.Tailscale.P2PAssist.RoleMode))
		if rm == "client" || rm == "exit" {
			return ""
		}
		if strings.TrimSpace(cfg.Tailscale.Subnets) != "" {
			return strings.TrimSpace(cfg.Tailscale.Subnets)
		}
	}
	if s.opts.TailscaleP2PForTest != nil && strings.TrimSpace(s.opts.TailscaleP2PForTest.DefaultLANCIDR) != "" {
		return strings.TrimSpace(s.opts.TailscaleP2PForTest.DefaultLANCIDR)
	}
	return s.defaultLANCIDR()
}

func (s *Server) tailscaleP2PController() *tailscale.P2PAssistController {
	if s.opts.TailscaleP2PForTest != nil && s.opts.TailscaleP2PForTest.Controller != nil {
		return s.opts.TailscaleP2PForTest.Controller
	}
	s.tsP2PMu.Lock()
	defer s.tsP2PMu.Unlock()
	if s.tsP2PCtrl == nil {
		s.tsP2PCtrl = &tailscale.P2PAssistController{
			DefaultLANCIDR: s.effectiveProtectedLANCIDRs,
		}
	}
	return s.tsP2PCtrl
}

func (s *Server) fw4Available() bool {
	if s.opts.TailscaleP2PForTest != nil {
		return s.opts.TailscaleP2PForTest.FW4Available
	}
	return runtime.GOOS == "linux" && tailscale.IsFW4Available()
}

func (s *Server) ujailAvailable() bool {
	if s.opts.TailscaleP2PForTest != nil {
		return s.opts.TailscaleP2PForTest.UjailAvailable
	}
	return runtime.GOOS == "linux" && tailscale.IsUjailAvailable()
}

func (s *Server) buildTailscaleP2PReportWithNetMap(ctx context.Context, cfg *config.Config) (map[string]any, *tailscale.NetMapSnapshot) {
	dmSnap := daemon.LoadRuntimeSnapshot()
	fw4OK := s.fw4Available()
	var netmapSnap *tailscale.NetMapSnapshot
	report := tailscale.BuildP2PReport(ctx, tailscale.P2PReportOptions{
		Config:         cfg,
		Controller:     s.tailscaleP2PController(),
		DaemonRuntime:  dmSnap.TailscaleP2P,
		DaemonRunning:  daemon.IsDaemonRunning(),
		Supported:      runtime.GOOS == "linux" || s.opts.TailscaleP2PForTest != nil,
		IsOpenWrt:      isOpenWrtSystem() || fw4OK,
		FW4Available:   fw4OK,
		UjailAvailable: s.ujailAvailable(),
		DefaultLANCIDR: s.effectiveProtectedLANCIDRs(),
		Now:            s.tailscaleP2PNow(),
		OnNetMap: func(nm *tailscale.NetMapSnapshot) {
			netmapSnap = nm
		},
	})
	return report, netmapSnap
}

func (s *Server) buildTailscaleP2PReport(ctx context.Context, cfg *config.Config) map[string]any {
	report, _ := s.buildTailscaleP2PReportWithNetMap(ctx, cfg)
	return report
}

func (s *Server) handleTailscaleP2PGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfigOrEmpty()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.buildTailscaleP2PReport(ctx, cfg))
}

func (s *Server) handleTailscaleP2PPut(w http.ResponseWriter, r *http.Request) {
	var req config.TailscaleP2PAssistConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	normalized, err := tailscale.NormalizeAndValidateP2PAssistConfig(req)
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
			shouldApplyLive := (runtime.GOOS == "linux" && s.fw4Available()) || s.opts.TailscaleP2PForTest != nil
			if !shouldApplyLive {
				return nil
			}
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()

			snap, applyErr := s.tailscaleP2PController().Reconcile(ctx, normalized)
			if applyErr != nil {
				return &apiStatusError{
					status: http.StatusInternalServerError,
					msg:    "应用防火墙防线规则失败（已自动回滚配置）: " + applyErr.Error(),
				}
			}
			appliedLive = true
			applyMode = snap.ApplyMode

			if prevP2P.SandboxUjail != normalized.SandboxUjail || (normalized.SandboxUjail && s.opts.TailscaleP2PForTest == nil) {
				var ujailErr error
				if s.opts.TailscaleP2PForTest != nil && s.opts.TailscaleP2PForTest.UjailApply != nil {
					_, ujailErr = s.opts.TailscaleP2PForTest.UjailApply(ctx, normalized.SandboxUjail)
				} else if runtime.GOOS == "linux" && s.opts.TailscaleP2PForTest == nil {
					_, ujailErr = tailscale.ApplyUjailSandbox(ctx, normalized.SandboxUjail, tailscale.UjailOptions{})
				}
				if ujailErr != nil {
					_, _ = s.tailscaleP2PController().Reconcile(ctx, prevP2P)
					return &apiStatusError{
						status: http.StatusInternalServerError,
						msg:    "切换 ujail 沙盒失败（已自动回滚）: " + ujailErr.Error(),
					}
				}
			}
			return nil
		},
	}, func(cfg *config.Config) error {
		prevP2P = cfg.Tailscale.P2PAssist
		cfg.Tailscale.P2PAssist = normalized
		return nil
	})
	if txErr != nil {
		writePartialSaveError(w, txErr)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	resp := s.buildTailscaleP2PReport(ctx, cfg)
	if applyMode != "" {
		if rt, ok := resp["runtime"].(tailscale.P2PRuntimeSnapshot); ok {
			rt.ApplyMode = applyMode
			resp["runtime"] = rt
		}
	}
	resp["ok"] = true
	resp["appliedLive"] = appliedLive
	resp["applyMode"] = applyMode
	if normalized.Enabled {
		resp["message"] = "已保存并实时生效 Tailscale P2P 零常驻暴露防线"
	} else {
		resp["message"] = "已关闭 Tailscale P2P 防线并清理相关规则"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTailscaleP2PPokePost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	target := cmp.Or(strings.TrimSpace(body.ID), strings.TrimSpace(body.Name))
	if target == "" {
		writeJSONError(w, http.StatusBadRequest, "请指定要测试瞬时打洞的目标节点 ID 或名称")
		return
	}

	cfg, err := s.loadConfigSnapshot()
	if err != nil || cfg == nil {
		writeJSONError(w, http.StatusInternalServerError, "读取配置失败")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	res, err := s.tailscaleP2PController().PokePeer(ctx, cfg.Tailscale.P2PAssist, target)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	report := s.buildTailscaleP2PReport(ctx, cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"direct":         res.Direct,
		"curAddr":        res.CurAddr,
		"relay":          res.Relay,
		"latencyMs":      res.LatencyMs,
		"pinholeMs":      res.PinholeMs,
		"candidateCount": res.CandidateCount,
		"message":        res.Message,
		"report":         report,
	})
}
