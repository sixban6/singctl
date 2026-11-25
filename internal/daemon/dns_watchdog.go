// 文件职责：实现守护进程双引擎本地 DNS 统一巡检（AdGuard Home / SmartDNS 容灾降级与自动回切、暂停到期自动恢复与 SmartDNS 审计日志采集）。
package daemon

import (
	"context"
	"runtime"
	"strings"
	"time"

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

func (d *Daemon) syncLiveSingBoxDNSLocal(ctx context.Context, _ *config.Config, useExternal bool, dnsPort int) {
	sbPath := d.dnsSBConfigPath()
	workPath := d.dnsSBWorkConfigPath()
	if d.dnsDeps != nil && d.dnsDeps.SyncSingBoxDNSLocalFunc != nil {
		_, _ = d.dnsDeps.SyncSingBoxDNSLocalFunc(ctx, sbPath, workPath, useExternal, dnsPort)
		return
	}
	fallbackIP := ""
	if !useExternal {
		fallbackIP = singbox.ProbeSafeWANFallbackDNS(nil, nil)
	}
	_, _ = singbox.SyncLiveSingBoxDNSLocalWithFallback(ctx, sbPath, workPath, useExternal, dnsPort, fallbackIP)
}

// GuardLocalDNSOnce 执行单轮双引擎本地 DNS 巡检与自愈编排（供看门狗主循环与单元测试直接驱动）。
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

	// 2. 自动恢复到期的临时暂停去广告定时器（适用于已安装的 SmartDNS）
	d.reconcileLocalDNSAdblockExpiry(ctx, cfg, reg)

	active := reg.ActiveEngine()
	if active == nil {
		return
	}

	// 3. 守护当前活跃外部引擎（AdGuard Home 或 SmartDNS），失活时临时降级至安全公网运营商 DNS，恢复后自动回切
	switch active.ID() {
	case constant.DNSEngineAdGuard, constant.DNSEngineSmartDNS:
		d.guardExternalDNSEngine(ctx, cfg, active)
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
	if active == nil || !active.IsInstalled() || active.ID() == constant.DNSEngineAdGuard {
		return
	}
	if err := active.SetProtection(ctx, true, 0); err != nil {
		logger.Warn("[Watchdog] 去广告临时暂停到期自动恢复失败 (%s): %v", active.ID(), err)
		return
	}
	logger.Info("[Watchdog] 去广告临时暂停已到期，已自动恢复 %s 广告拦截保护", active.Meta().Name)
}

func (d *Daemon) guardExternalDNSEngine(ctx context.Context, cfg *config.Config, eng localdns.Engine) {
	if !cfg.DNS.IsEnabled() || !eng.IsInstalled() {
		return
	}
	dnsPort := cfg.DNS.GetDNSPort()
	linked, _ := singbox.InspectSingBoxDNSLocal(d.dnsSBConfigPath())

	if err := eng.EnsureHealthy(ctx); err != nil {
		logger.Warn("[Watchdog] %s 自愈恢复失败: %v", eng.Meta().Name, err)
		if linked {
			logger.Warn("[Watchdog] 触发 DNS 应急降级：将 sing-box dns_local 临时切回安全应急上游 (optimistic: false)，保障全屋不断网")
			d.syncLiveSingBoxDNSLocal(ctx, cfg, false, dnsPort)
		}
		return
	}

	if !linked {
		logger.Info("[Watchdog] %s 已恢复在线，自动将 sing-box dns_local 切回本地防劫持引擎 (127.0.0.1:%d)", eng.Meta().Name, dnsPort)
		d.syncLiveSingBoxDNSLocal(ctx, cfg, true, dnsPort)
	}
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
