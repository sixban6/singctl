// 文件职责：提供 Tailscale 零失联升级前体检与异步切换状态查询接口。
package webui

import (
	"context"
	"net/http"
	"time"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

// TailscaleUpgradeTestHooks 仅供离线单元测试注入 Tailscale 升级体检与状态依赖。
type TailscaleUpgradeTestHooks struct {
	Preflight func(ctx context.Context) (*tailscale.UpgradePreflight, error)
	ReadState func() (*tailscale.UpgradeState, error)
	StatusFn  func(configPath string) map[string]any
	Paths     tailscale.UpgradePaths
}

func (s *Server) upgradePaths() tailscale.UpgradePaths {
	if s.opts.TailscaleUpgradeForTest != nil {
		return s.opts.TailscaleUpgradeForTest.Paths
	}
	return tailscale.UpgradePaths{}
}

func (s *Server) readTailscaleUpgradeState() (*tailscale.UpgradeState, error) {
	if s.opts.TailscaleUpgradeForTest != nil && s.opts.TailscaleUpgradeForTest.ReadState != nil {
		return s.opts.TailscaleUpgradeForTest.ReadState()
	}
	return tailscale.ReadUpgradeState(s.upgradePaths())
}

func (s *Server) handleTailscaleUpgradePreflightGet(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 22*time.Second)
	defer cancel()

	var (
		pre *tailscale.UpgradePreflight
		err error
	)
	if s.opts.TailscaleUpgradeForTest != nil && s.opts.TailscaleUpgradeForTest.Preflight != nil {
		pre, err = s.opts.TailscaleUpgradeForTest.Preflight(ctx)
	} else {
		mirror := ""
		var tsCfg config.TailscaleConfig
		if cfg, loadErr := s.loadConfigSnapshot(); loadErr == nil && cfg != nil {
			mirror = cfg.GitHub.MirrorURL
			tsCfg = cfg.Tailscale
		}
		ts := tailscale.New(mirror, &tsCfg)
		pre, err = ts.PreflightUpgrade(ctx, tailscale.UpgradeOptions{
			Paths: s.upgradePaths(),
		})
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "执行 Tailscale 升级前体检失败: "+err.Error())
		return
	}
	if pre == nil {
		writeJSONError(w, http.StatusInternalServerError, "Tailscale 升级体检返回空结果")
		return
	}

	pre.ViaTailscale = tailscale.IsTailscaleRequest(r)
	if pre.ActiveSwap == nil {
		if st, readErr := s.readTailscaleUpgradeState(); readErr == nil && st != nil {
			pre.ActiveSwap = st
		}
	}
	writeJSON(w, http.StatusOK, pre)
}

func (s *Server) handleTailscaleUpgradeStatusGet(w http.ResponseWriter, r *http.Request) {
	st, err := s.readTailscaleUpgradeState()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取 Tailscale 升级状态失败: "+err.Error())
		return
	}
	if st == nil {
		st = &tailscale.UpgradeState{Phase: tailscale.UpgradePhaseIdle}
	}

	var tsStatus map[string]any
	if s.opts.TailscaleUpgradeForTest != nil && s.opts.TailscaleUpgradeForTest.StatusFn != nil {
		tsStatus = s.opts.TailscaleUpgradeForTest.StatusFn(configPathFor(s))
	} else {
		tsStatus = s.tailscaleStatus(configPathFor(s))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"state":     st,
		"tailscale": tsStatus,
	})
}
