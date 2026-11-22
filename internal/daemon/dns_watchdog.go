// 文件职责：实现守护进程三引擎本地 DNS 统一巡检（外部引擎容灾降级/恢复、singbox 主上游失活热切、暂停到期自动恢复与 SmartDNS 审计日志采集）。
package daemon

import (
	"cmp"
	"context"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/localdns"
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

func (d *Daemon) buildLocalDNSRegistry(cfg *config.Config) *localdns.Registry {
	var deps localdns.EngineDeps
	if d.dnsDeps != nil {
		deps = *d.dnsDeps
	}
	if deps.ConfigPath == "" {
		deps.ConfigPath = d.configPath
	}
	if deps.SingBoxStats == nil {
		deps.SingBoxStats = d.dnsSingBoxStats
	}
	if deps.SmartDNSStats == nil {
		deps.SmartDNSStats = d.dnsSmartStats
	}
	if deps.SmartDNSTailer == nil {
		deps.SmartDNSTailer = d.smartDNSTailer
	}
	if deps.SaveConfig == nil {
		deps.SaveConfig = func(updated *config.Config) error {
			if strings.TrimSpace(deps.ConfigPath) != "" {
				if err := config.Save(deps.ConfigPath, updated); err != nil {
					return err
				}
			}
			if d.cfgStore != nil {
				d.cfgStore.Set(updated)
			}
			return nil
		}
	}
	return localdns.NewRegistry(cfg, deps)
}

func (d *Daemon) dnsNow() time.Time {
	if d.dnsDeps != nil && d.dnsDeps.NowFunc != nil {
		return d.dnsDeps.NowFunc()
	}
	return time.Now()
}

func (d *Daemon) dnsSBConfigPath() string {
	if d.dnsDeps != nil && strings.TrimSpace(d.dnsDeps.SingBoxConfigPath) != "" {
		return strings.TrimSpace(d.dnsDeps.SingBoxConfigPath)
	}
	return constant.SingBoxConfigFile
}

func (d *Daemon) dnsSBWorkConfigPath() string {
	if d.dnsDeps != nil && strings.TrimSpace(d.dnsDeps.SingBoxWorkConfigPath) != "" {
		return strings.TrimSpace(d.dnsDeps.SingBoxWorkConfigPath)
	}
	if d.dnsSBConfigPath() == constant.SingBoxConfigFile {
		return constant.SingBoxWorkConfigFile
	}
	return ""
}

func (d *Daemon) syncLiveSingBoxDNSLocal(ctx context.Context, useExternal bool, dnsPort int) {
	sbPath := d.dnsSBConfigPath()
	workPath := d.dnsSBWorkConfigPath()
	if d.dnsDeps != nil && d.dnsDeps.SyncSingBoxDNSLocalFunc != nil {
		_, _ = d.dnsDeps.SyncSingBoxDNSLocalFunc(ctx, sbPath, workPath, useExternal, dnsPort)
		return
	}
	_, _ = singbox.SyncLiveSingBoxDNSLocal(ctx, sbPath, workPath, useExternal, dnsPort)
}

// GuardLocalDNSOnce 执行单轮三引擎本地 DNS 巡检与自愈编排（供看门狗主循环与单元测试直接驱动）。
func (d *Daemon) GuardLocalDNSOnce(ctx context.Context) {
	if d == nil {
		return
	}
	if ctx == nil {
		ctx = d.ctx
	}
	// 非 Linux 生产宿主不干预系统 DNS；显式注入 DNSDeps 的离线单测放行验证完整状态机。
	if runtime.GOOS != "linux" && d.dnsDeps == nil {
		return
	}
	snap := d.currentConfig()
	if snap == nil {
		return
	}
	cfg := snap.Clone()
	reg := d.buildLocalDNSRegistry(cfg)

	// 1. 增量拉取 SmartDNS tmpfs 审计日志喂入 24h 环形统计器
	reg.DrainSmartDNSAuditLog()

	// 2. 自动恢复到期的临时暂停去广告定时器（适用于 singbox 与 smartdns）
	d.reconcileLocalDNSAdblockExpiry(ctx, cfg, reg)

	active := reg.ActiveEngine()
	if active == nil {
		return
	}

	// 3. 按当前活跃引擎分派守护策略
	switch active.ID() {
	case constant.DNSEngineAdGuard, constant.DNSEngineSmartDNS:
		d.guardExternalDNSEngine(ctx, cfg, reg, active)
	case constant.DNSEngineSingBox:
		d.guardSingBoxEnhancedUpstreams(ctx, cfg, reg, active)
	}
}

func (d *Daemon) reconcileLocalDNSAdblockExpiry(ctx context.Context, cfg *config.Config, reg *localdns.Registry) {
	if cfg == nil || cfg.DNS.AdblockDisabledUntil <= 0 {
		return
	}
	now := d.dnsNow()
	if now.Unix() < cfg.DNS.AdblockDisabledUntil {
		return
	}
	active := reg.ActiveEngine()
	if active == nil || active.ID() == constant.DNSEngineAdGuard {
		return
	}
	if err := active.SetProtection(ctx, true, 0); err != nil {
		logger.Warn("[Watchdog] 去广告临时暂停到期自动恢复失败 (%s): %v", active.ID(), err)
		return
	}
	logger.Info("[Watchdog] 去广告临时暂停已到期，已自动恢复 %s 广告拦截保护", active.Meta().Name)
}

func (d *Daemon) guardExternalDNSEngine(ctx context.Context, cfg *config.Config, reg *localdns.Registry, eng localdns.Engine) {
	if !cfg.DNS.IsEnabled() || !eng.IsInstalled() {
		return
	}
	dnsPort := cfg.DNS.GetDNSPort()
	linked, _ := singbox.InspectSingBoxDNSLocal(d.dnsSBConfigPath())

	if err := eng.EnsureHealthy(ctx); err != nil {
		logger.Warn("[Watchdog] %s 自愈恢复失败: %v", eng.Meta().Name, err)
		if linked {
			logger.Warn("[Watchdog] 触发 DNS 应急降级：将 sing-box dns_local 临时切回 sing-box 加强版纯 IP 加密 DoH，保障全屋不断网")
			if sbEng, ok := reg.Get(constant.DNSEngineSingBox); ok {
				if syncErr := sbEng.SyncCommonConfig(ctx); syncErr != nil {
					d.syncLiveSingBoxDNSLocal(ctx, false, dnsPort)
				}
			} else {
				d.syncLiveSingBoxDNSLocal(ctx, false, dnsPort)
			}
		}
		return
	}

	if !linked {
		logger.Info("[Watchdog] %s 已恢复在线，自动将 sing-box dns_local 切回本地防劫持引擎 (127.0.0.1:%d)", eng.Meta().Name, dnsPort)
		d.syncLiveSingBoxDNSLocal(ctx, true, dnsPort)
	}
}

func (d *Daemon) guardSingBoxEnhancedUpstreams(ctx context.Context, cfg *config.Config, reg *localdns.Registry, eng localdns.Engine) {
	ups := cfg.DNS.Upstreams
	if len(ups) == 0 {
		ups = adguard.DefaultUpstreams()
	}
	primary := strings.TrimSpace(ups[0])
	if primary == "" {
		return
	}

	probeList := adguard.ProbeUpstreamList
	if d.dnsDeps != nil && d.dnsDeps.ProbeUpstreamListFunc != nil {
		probeList = d.dnsDeps.ProbeUpstreamListFunc
	}

	primaryRes := probeList(ctx, []string{primary}, "qq.com", 2500*time.Millisecond)
	if len(primaryRes) > 0 && primaryRes[0].Healthy {
		d.dnsPrimaryFailMu.Lock()
		d.dnsPrimaryFailCount = 0
		d.dnsPrimaryFailMu.Unlock()
		return
	}

	d.dnsPrimaryFailMu.Lock()
	d.dnsPrimaryFailCount++
	fails := d.dnsPrimaryFailCount
	d.dnsPrimaryFailMu.Unlock()

	if fails < 2 {
		logger.Warn("[Watchdog] sing-box 主加密上游 %s 本轮探测失活 (%d/2)，等待下轮复测确认", primary, fails)
		return
	}

	candidates := make([]string, 0, len(ups)+4)
	seen := map[string]struct{}{strings.ToLower(primary): {}}
	for _, u := range append(slices.Clone(ups), adguard.DefaultUpstreams()...) {
		clean := strings.TrimSpace(u)
		if clean == "" {
			continue
		}
		key := strings.ToLower(clean)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, clean)
	}
	if len(candidates) == 0 {
		return
	}

	items := probeList(ctx, candidates, "qq.com", 2800*time.Millisecond)
	bestIdx := -1
	for i := range items {
		if items[i].Healthy && (bestIdx == -1 || items[i].LatencyMs < items[bestIdx].LatencyMs) {
			bestIdx = i
		}
	}
	if bestIdx < 0 {
		logger.Warn("[Watchdog] sing-box 主加密上游 %s 连续失活，且备用加密上游探测均不可达，维持当前配置等待网络恢复", primary)
		return
	}

	bestAddr := items[bestIdx].Address
	reordered := make([]string, 0, len(ups)+1)
	reordered = append(reordered, bestAddr)
	for _, u := range ups {
		if !strings.EqualFold(strings.TrimSpace(u), bestAddr) {
			reordered = append(reordered, u)
		}
	}
	cfg.DNS.Upstreams = reordered
	if strings.TrimSpace(d.configPath) != "" {
		_ = config.Save(d.configPath, cfg)
	}
	if d.cfgStore != nil {
		d.cfgStore.Set(cfg)
	}
	if err := eng.SyncCommonConfig(ctx); err != nil {
		logger.Warn("[Watchdog] sing-box 加密上游自动热切至 %s 失败: %v", bestAddr, err)
		return
	}

	d.dnsPrimaryFailMu.Lock()
	d.dnsPrimaryFailCount = 0
	d.dnsPrimaryFailMu.Unlock()

	summary := fmt.Sprintf("主上游 %s 连续失活，已热切至最快备用加密上游 %s (%dms)", primary, bestAddr, items[bestIdx].LatencyMs)
	logger.Success("[Watchdog] sing-box 加强版 DNS 自动容灾: %s", summary)
	d.effectiveStateStore().AppendEvent(WatchdogEventRecord{
		Time:    cmp.Or(d.dnsNow().Format(time.DateTime), time.Now().Format(time.DateTime)),
		Action:  "DNS_UPSTREAM_FAILOVER",
		Healthy: true,
		Summary: summary,
	})
}

func (d *Daemon) maybeTickLocalDNSAuditAndExpiryAsync() {
	if d == nil {
		return
	}
	if runtime.GOOS != "linux" && d.dnsDeps == nil {
		return
	}
	if !d.dnsTickRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.dnsTickRunning.Store(false)
		ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
		defer cancel()
		snap := d.currentConfig()
		if snap == nil {
			return
		}
		cfg := snap.Clone()
		reg := d.buildLocalDNSRegistry(cfg)
		reg.DrainSmartDNSAuditLog()
		d.reconcileLocalDNSAdblockExpiry(ctx, cfg, reg)
	}()
}
