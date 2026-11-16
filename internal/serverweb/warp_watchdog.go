package serverweb

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/logger"
)

// DefaultWarpWatchdogInterval 定义 WARP 后台健康巡检周期。
const DefaultWarpWatchdogInterval = 45 * time.Second

// WarpWatchdogDeps 允许测试注入 WARP 后台巡检自愈与熔断逻辑的外部依赖。
type WarpWatchdogDeps struct {
	HasLegacyFscarmen func() bool
	PurgeAndDeploy    func(cfg *config.Config) error
	ProbeRealTargets  func(timeout time.Duration) (ip, loc string, err error)
	SwitchEndpoint    func() (endpoint, ip, loc string, err error)
	RotateIdentity    func() (ip, loc string, err error)
}

func (s *Server) resolveWarpWatchdogDeps() WarpWatchdogDeps {
	d := WarpWatchdogDeps{
		HasLegacyFscarmen: deploy.HasLegacyFscarmenWarp,
		PurgeAndDeploy:    deploy.DeployWarpWithConfig,
		ProbeRealTargets:  deploy.ProbeWarpRealTargets,
		SwitchEndpoint:    deploy.SwitchWarpEndpoint,
		RotateIdentity:    deploy.RotateWarpIdentity,
	}
	if s.warpWatchdogDeps != nil {
		if s.warpWatchdogDeps.HasLegacyFscarmen != nil {
			d.HasLegacyFscarmen = s.warpWatchdogDeps.HasLegacyFscarmen
		}
		if s.warpWatchdogDeps.PurgeAndDeploy != nil {
			d.PurgeAndDeploy = s.warpWatchdogDeps.PurgeAndDeploy
		}
		if s.warpWatchdogDeps.ProbeRealTargets != nil {
			d.ProbeRealTargets = s.warpWatchdogDeps.ProbeRealTargets
		}
		if s.warpWatchdogDeps.SwitchEndpoint != nil {
			d.SwitchEndpoint = s.warpWatchdogDeps.SwitchEndpoint
		}
		if s.warpWatchdogDeps.RotateIdentity != nil {
			d.RotateIdentity = s.warpWatchdogDeps.RotateIdentity
		}
	}
	return d
}

// StartWarpWatchdog 在服务端后台持续巡检 WARP 真实出口连通性，支持自动切换 Endpoint、自动换 IP、
// 老版 fscarmen 迁移清理与 3 阶段兜底熔断降级（自动回切）。
func (s *Server) StartWarpWatchdog(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultWarpWatchdogInterval
	}
	go func() {
		bootTimer := time.NewTimer(6 * time.Second)
		defer bootTimer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-bootTimer.C:
			s.RunWarpWatchdogTick(ctx)
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.RunWarpWatchdogTick(ctx)
			}
		}
	}()
}

// RunWarpWatchdogTick 执行单次 WARP 健康巡检、旧版 fscarmen 迁移及三阶段自动自愈。
func (s *Server) RunWarpWatchdogTick(ctx context.Context) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		return
	}

	d := s.resolveWarpWatchdogDeps()
	s.syncBootWarpAndPurgeLegacy(ctx, cfg, d)

	s.warpWatchdogMu.Lock()
	isDegraded := s.warpDegraded
	s.warpWatchdogMu.Unlock()

	if !deploy.NeedsWarpTunnel(cfg.Server.WarpRouting) && !isDegraded {
		s.warpWatchdogMu.Lock()
		s.warpFailStreak = 0
		s.warpWatchdogMu.Unlock()
		return
	}

	if ip, loc, probeErr := d.ProbeRealTargets(4 * time.Second); probeErr == nil {
		s.handleWarpHealthyTick(ctx, cfg, ip, loc)
		return
	}

	s.handleWarpUnhealthyTick(ctx, cfg, d, isDegraded)
}

func (s *Server) syncBootWarpAndPurgeLegacy(ctx context.Context, cfg *config.Config, d WarpWatchdogDeps) {
	if d.HasLegacyFscarmen() {
		s.warpMu.Lock()
		deployErr := d.PurgeAndDeploy(cfg)
		s.warpMu.Unlock()
		if deployErr == nil {
			_ = s.evictAllWarpConnections(ctx)
			s.recordWatchdogAudit("检测到旧版 fscarmen WARP 残留，已自动清理并迁移至内置纯 Go wireproxy 引擎 (MTU=1280)")
			logger.Success("已自动清理旧版 fscarmen WARP 并迁移至纯 Go wireproxy")
		} else {
			logger.Warn("WARP Watchdog 迁移旧版 fscarmen 失败: %v", deployErr)
		}
	}

	s.warpWatchdogMu.Lock()
	alreadySynced := s.warpBootSynced || s.warpDegraded
	s.warpWatchdogMu.Unlock()
	if alreadySynced {
		return
	}

	sbCfgPath := cmp.Or(strings.TrimSpace(s.opts.SingBoxConfigPath), constant.SingBoxConfigFile)
	if _, stErr := os.Stat(sbCfgPath); stErr != nil {
		return
	}

	s.warpMu.Lock()
	liveDeps := s.liveWarpDepsForConfig(cfg)
	checkPort := deploy.CheckWarpSocksPort
	if liveDeps.CheckWarpPort != nil {
		checkPort = liveDeps.CheckWarpPort
	}
	if deploy.NeedsWarpTunnel(cfg.Server.WarpRouting) && !checkPort() {
		s.warpMu.Unlock()
		return
	}
	_, applyErr := deploy.ApplyLiveWarpRouting(sbCfgPath, cfg.Server.WarpRouting, liveDeps)
	s.warpMu.Unlock()

	if applyErr == nil {
		s.warpWatchdogMu.Lock()
		s.warpBootSynced = true
		s.warpWatchdogMu.Unlock()
	}
}

func (s *Server) handleWarpHealthyTick(ctx context.Context, cfg *config.Config, ip, loc string) {
	if ip != "" {
		s.warpCacheMu.Lock()
		s.warpCachedIP = ip
		s.warpCachedLoc = loc
		s.warpCachedAt = time.Now()
		s.warpCacheMu.Unlock()
	}

	s.warpWatchdogMu.Lock()
	wasDegraded := s.warpDegraded
	needBootSync := !s.warpBootSynced
	s.warpFailStreak = 0
	s.warpWatchdogMu.Unlock()

	if !wasDegraded && !needBootSync {
		return
	}

	sbCfgPath := cmp.Or(strings.TrimSpace(s.opts.SingBoxConfigPath), constant.SingBoxConfigFile)
	s.warpMu.Lock()
	_, applyErr := deploy.ApplyLiveWarpRouting(sbCfgPath, cfg.Server.WarpRouting, s.liveWarpDepsForConfig(cfg))
	s.warpMu.Unlock()

	if applyErr != nil && !errors.Is(applyErr, os.ErrNotExist) {
		return
	}

	nowStr := time.Now().Format("2006-01-02 15:04:05")
	s.warpWatchdogMu.Lock()
	s.warpBootSynced = true
	if wasDegraded {
		s.warpDegraded = false
		s.warpAutoHealStatus = fmt.Sprintf("WARP 隧道已恢复健康 (%s)，已自动切回原有分流策略", cmp.Or(ip, "Connected"))
		s.warpLastHealedAt = nowStr
	}
	s.warpWatchdogMu.Unlock()

	if wasDegraded {
		if s.telemetry != nil {
			protected := deploy.CollectServerProtectedDomains(cfg)
			_, _ = s.telemetry.EvictMismatchedConnections(ctx, func(host, dstIP, ruleTag, currentOutbound string) bool {
				expected := deploy.ExpectedTargetOutbound(cfg.Server.WarpRouting, host, dstIP, ruleTag, protected...)
				return expected != currentOutbound
			})
		}
		s.recordWatchdogAudit(fmt.Sprintf("WARP 巡检确认隧道已恢复健康 [%s (%s)]，自动解除直出降级并恢复原有分流策略", cmp.Or(ip, "OK"), cmp.Or(loc, "Anycast")))
		logger.Success("WARP 隧道已恢复健康 (%s)，已自动恢复分流策略", ip)
	}
}

func (s *Server) handleWarpUnhealthyTick(ctx context.Context, cfg *config.Config, d WarpWatchdogDeps, isDegraded bool) {
	s.warpWatchdogMu.Lock()
	s.warpFailStreak++
	streak := s.warpFailStreak
	s.warpWatchdogMu.Unlock()

	if isDegraded {
		// 降级直出期间每 4 个周期静默尝试恢复底层 wireproxy，一旦恢复将在下个周期自动回切分流
		if streak%4 == 0 {
			s.warpMu.Lock()
			if _, _, _, swErr := d.SwitchEndpoint(); swErr != nil {
				_, _, _ = d.RotateIdentity()
			}
			s.warpMu.Unlock()
		}
		return
	}

	if streak < 2 {
		return
	}

	s.warpMu.Lock()
	defer s.warpMu.Unlock()

	sbCfgPath := cmp.Or(strings.TrimSpace(s.opts.SingBoxConfigPath), constant.SingBoxConfigFile)
	nowStr := time.Now().Format("2006-01-02 15:04:05")

	// 阶段 1：轮换 Cloudflare WARP Endpoint 节点恢复连通
	if ep, epIP, epLoc, swErr := d.SwitchEndpoint(); swErr == nil {
		s.markWatchdogHealed(epIP, epLoc, fmt.Sprintf("自动自愈成功：已切换优选节点 %s 恢复连通", ep), nowStr)
		s.ensureHardExemptionsAfterHeal(sbCfgPath, cfg)
		evicted := s.evictAllWarpConnections(ctx)
		s.recordWatchdogAudit(fmt.Sprintf("WARP 巡检自愈 [阶段1]：自动切换优选 Endpoint [%s] 恢复连通 (踢断旧流:%d)", ep, evicted))
		logger.Success("WARP 巡检自愈阶段 1 成功：Endpoint=%s", ep)
		return
	}

	// 阶段 2：重新注册 WireGuard 身份与出口 IP 并实测外网 HTTPS 连通
	if rotIP, rotLoc, rotErr := d.RotateIdentity(); rotErr == nil {
		if probeIP, probeLoc, pErr := d.ProbeRealTargets(4 * time.Second); pErr == nil {
			finalIP := cmp.Or(probeIP, rotIP)
			finalLoc := cmp.Or(probeLoc, rotLoc, "Anycast")
			s.markWatchdogHealed(finalIP, finalLoc, fmt.Sprintf("自动自愈成功：已更换 WARP IP %s (%s)", finalIP, finalLoc), nowStr)
			s.ensureHardExemptionsAfterHeal(sbCfgPath, cfg)
			evicted := s.evictAllWarpConnections(ctx)
			s.recordWatchdogAudit(fmt.Sprintf("WARP 巡检自愈 [阶段2]：自动更换全新 WARP 出口 IP [%s (%s)] 恢复连通 (踢断旧流:%d)", finalIP, finalLoc, evicted))
			logger.Success("WARP 巡检自愈阶段 2 成功：IP=%s (%s)", finalIP, finalLoc)
			return
		}
	}

	// 阶段 3：熔断保护 —— 仅对现网 sing-box config.json 临时写入旁路全直出 (DC)，绝不覆盖 singctl.yaml 用户原分流意向
	bypassWR := config.WarpRoutingConfig{Mode: config.WarpModeBypass}
	if _, applyErr := deploy.ApplyLiveWarpRouting(sbCfgPath, bypassWR, s.liveWarpDepsForConfig(cfg)); applyErr != nil && !errors.Is(applyErr, os.ErrNotExist) {
		logger.Warn("WARP Watchdog 阶段 3 熔断降级写入失败: %v", applyErr)
		return
	}

	s.warpWatchdogMu.Lock()
	s.warpDegraded = true
	s.warpBootSynced = true
	s.warpFailStreak = 0
	s.warpAutoHealStatus = "WARP 出口异常，已自动熔断降级至原生直出 (DC) 保障不断网，后台正持续探测自动回切"
	s.warpLastHealedAt = nowStr
	s.warpWatchdogMu.Unlock()

	evicted := s.evictAllWarpConnections(ctx)
	s.recordWatchdogAudit(fmt.Sprintf("WARP 巡检自愈 [阶段3·熔断保护]：切换节点与换 IP 均未恢复，已临时降级至原生直出 (DC) 保障不断网，待恢复后自动回切 (踢断旧流:%d)", evicted))
	logger.Warn("WARP 多次自愈未恢复，已触发阶段 3 熔断降级至 DC 直出 (singctl.yaml 已完整保留)")
}

func (s *Server) markWatchdogHealed(ip, loc, statusMsg, nowStr string) {
	if ip != "" {
		s.warpCacheMu.Lock()
		s.warpCachedIP = ip
		s.warpCachedLoc = loc
		s.warpCachedAt = time.Now()
		s.warpCacheMu.Unlock()
	}
	s.warpWatchdogMu.Lock()
	s.warpDegraded = false
	s.warpFailStreak = 0
	s.warpAutoHealStatus = statusMsg
	s.warpLastHealedAt = nowStr
	s.warpWatchdogMu.Unlock()
}

func (s *Server) ensureHardExemptionsAfterHeal(sbCfgPath string, cfg *config.Config) {
	s.warpWatchdogMu.Lock()
	synced := s.warpBootSynced
	s.warpWatchdogMu.Unlock()
	if synced {
		return
	}
	if _, err := deploy.ApplyLiveWarpRouting(sbCfgPath, cfg.Server.WarpRouting, s.liveWarpDepsForConfig(cfg)); err == nil {
		s.warpWatchdogMu.Lock()
		s.warpBootSynced = true
		s.warpWatchdogMu.Unlock()
	}
}

func (s *Server) recordWatchdogAudit(action string) {
	if s.audit != nil {
		s.audit.Record("127.0.0.1", action)
	}
}
