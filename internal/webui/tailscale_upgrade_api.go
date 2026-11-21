package webui

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

var (
	tsCGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")
	tsULA6Prefix  = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// TailscaleUpgradeTestHooks 仅供离线单元测试注入 Tailscale 升级体检与状态依赖。
type TailscaleUpgradeTestHooks struct {
	Preflight func(ctx context.Context) (*tailscale.UpgradePreflight, error)
	ReadState func() (*tailscale.UpgradeState, error)
	StatusFn  func(configPath string) map[string]any
	Paths     tailscale.UpgradePaths
}

func isTailscaleAddr(rawIP string) bool {
	s := strings.TrimSpace(rawIP)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if i := strings.LastIndexByte(s, '%'); i > 0 {
		s = s[:i]
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return tsCGNATPrefix.Contains(addr) || tsULA6Prefix.Contains(addr)
}

func isTailscaleRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	remote := remoteClientIP(r)
	if isTailscaleAddr(remote) {
		return true
	}
	// 仅当直连来源是本机回环（如反代场景）时才参考 X-Forwarded-For / X-Real-IP，防伪造。
	if addr, err := netip.ParseAddr(strings.TrimSpace(remote)); err == nil && addr.Unmap().IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if isTailscaleAddr(first) {
				return true
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" && isTailscaleAddr(xri) {
			return true
		}
	}
	return false
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
		if cfg, loadErr := config.Load(configPathFor(s)); loadErr == nil && cfg != nil {
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

	pre.ViaTailscale = isTailscaleRequest(r)
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
