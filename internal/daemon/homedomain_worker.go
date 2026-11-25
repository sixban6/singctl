// 文件职责：托管守护进程中的本地域名 Tailscale Split-DNS 应答器生命周期、配置热对账与 DHCP MAC 自动跟随同步。
package daemon

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/homedomain"
	"singctl/internal/localdns"
	"singctl/internal/logger"
)

// HomeDomainWorkerDeps 显式注入本地域名工作器的配置仓库、状态快照存储与离线测试替身。
type HomeDomainWorkerDeps struct {
	ServeCtx          context.Context
	ConfigStore       *config.Store
	StateStore        *StateStore
	ListenAddrForTest string
	DiscoveryDeps     homedomain.DiscoveryDeps
	DnsmasqDeps       homedomain.DnsmasqDeps
	DNSDeps           *localdns.EngineDeps
}

// HomeDomainWorker 在守护进程中负责维护 Tailscale Split-DNS 权威应答器及 MAC->IP DHCP 自动跟随。
type HomeDomainWorker struct {
	deps      HomeDomainWorkerDeps
	responder *homedomain.TailscaleDNSResponder

	mu         sync.Mutex
	lastSuffix string
}

// NewHomeDomainWorker 创建本地域名守护工作器实例。
func NewHomeDomainWorker(deps HomeDomainWorkerDeps) *HomeDomainWorker {
	return &HomeDomainWorker{
		deps:      deps,
		responder: homedomain.NewResponder(homedomain.ResponderDeps{}),
	}
}

func (w *HomeDomainWorker) publishStatus() {
	if w == nil || w.deps.StateStore == nil {
		return
	}
	st := w.responder.Status()
	w.deps.StateStore.Update(func(snap *DaemonRuntimeSnapshot) {
		snap.HomeDomainDNS = &st
	})
}

func (w *HomeDomainWorker) resolveListenAddr(ctx context.Context) string {
	if addr := strings.TrimSpace(w.deps.ListenAddrForTest); addr != "" {
		return addr
	}
	disc := homedomain.DiscoverDevices(ctx, w.deps.DiscoveryDeps)
	if tsIP := strings.TrimSpace(disc.Self.TailscaleIP); tsIP != "" {
		return net.JoinHostPort(tsIP, "53")
	}
	return ""
}

func (w *HomeDomainWorker) serveCtx() context.Context {
	if w != nil && w.deps.ServeCtx != nil {
		return w.deps.ServeCtx
	}
	return context.Background()
}

// Reconcile 按最新配置对账内存记录、OpenWrt dnsmasq 协同规则及 Tailscale Split-DNS 监听套接字。
func (w *HomeDomainWorker) Reconcile(ctx context.Context, cfg *config.Config) error {
	if w == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg == nil {
		cfg = &config.Config{}
	}

	w.mu.Lock()
	prevSuffix := w.lastSuffix
	suffix := cfg.HomeDomain.EffectiveSuffix()
	active := cfg.HomeDomain.IsEnabled() && len(cfg.HomeDomain.Devices) > 0
	wantTSDNS := active && cfg.HomeDomain.IsTailscaleDNSEnabled()
	managed := cfg.HomeDomain.BuildManagedRewrites()
	w.lastSuffix = suffix
	w.mu.Unlock()

	w.responder.UpdateRecords(suffix, managed)

	// 先确保 OpenWrt dnsmasq 同步 rebind_domain / server / notinterface=tailscale0，再绑定 <TS_IP>:53 避免端口冲突
	if _, err := homedomain.ReconcileOpenWrtDnsmasq(ctx, homedomain.DnsmasqDesired{
		Enabled:          active,
		Suffix:           suffix,
		PrevSuffix:       prevSuffix,
		LocalDNSPort:     cfg.DNS.GetDNSPort(),
		ExcludeTailscale: wantTSDNS,
	}, w.deps.DnsmasqDeps); err != nil {
		logger.Warn("[HomeDomain] 同步 OpenWrt dnsmasq 本地域名协同配置失败: %v", err)
	}

	if !wantTSDNS {
		_ = w.responder.Close()
		w.publishStatus()
		return nil
	}

	listenAddr := w.resolveListenAddr(ctx)
	if listenAddr == "" {
		_ = w.responder.Close()
		w.publishStatus()
		return nil
	}

	// 监听套接字必须绑定长驻 ServeCtx（随守护进程/Close 释放），严禁绑定短生命周期的对账超时 ctx！
	serveCtx := w.serveCtx()
	if err := w.responder.Start(serveCtx, listenAddr); err != nil {
		// OpenWrt dnsmasq 刚重载释放端口时可能存在极短占用窗口，短暂重试一次
		select {
		case <-ctx.Done():
			w.publishStatus()
			return ctx.Err()
		case <-time.After(350 * time.Millisecond):
		}
		if retryErr := w.responder.Start(serveCtx, listenAddr); retryErr != nil {
			logger.Warn("[HomeDomain] 启动 Tailscale Split-DNS 应答器 (%s) 失败: %v", listenAddr, retryErr)
			w.publishStatus()
			return retryErr
		}
	}
	w.publishStatus()
	return nil
}

// ReconcileDHCP 扫描最新局域网 DHCP/ARP 租约，若已绑定 MAC 的设备更换 IP 则自动更新配置、重写与应答器索引。
func (w *HomeDomainWorker) ReconcileDHCP(ctx context.Context) bool {
	if w == nil || w.deps.ConfigStore == nil {
		return false
	}
	cur := w.deps.ConfigStore.Get()
	if cur == nil || !cur.HomeDomain.IsEnabled() || !cur.HomeDomain.IsFollowDHCPEnabled() || len(cur.HomeDomain.Devices) == 0 {
		return false
	}

	disc := homedomain.DiscoverDevices(ctx, w.deps.DiscoveryDeps)
	var (
		changed bool
		updates []string
		updated *config.Config
	)
	err := w.deps.ConfigStore.Update(func(nextCfg *config.Config) error {
		prevManaged := nextCfg.HomeDomain.BuildManagedRewrites()
		prevSuffix := nextCfg.HomeDomain.EffectiveSuffix()
		c, u := homedomain.ReconcileDHCPAddresses(nextCfg, disc.LANDevices)
		if !c {
			return nil
		}
		changed = true
		updates = u
		var activeEng localdns.Engine
		if w.deps.DNSDeps != nil {
			activeEng = localdns.NewRegistry(nextCfg, *w.deps.DNSDeps).ActiveEngine()
		}
		homedomain.SyncAllReconcile(ctx, nextCfg, prevManaged, prevSuffix, homedomain.SyncAllDeps{
			Engine:      activeEng,
			DnsmasqDeps: w.deps.DnsmasqDeps,
		})
		updated = nextCfg.Clone()
		return nil
	})
	if err != nil {
		logger.Warn("[HomeDomain] DHCP 自动跟随保存配置失败: %v", err)
		return false
	}
	if !changed || updated == nil {
		return false
	}
	w.responder.UpdateRecords(updated.HomeDomain.EffectiveSuffix(), updated.HomeDomain.BuildManagedRewrites())
	w.publishStatus()
	logger.Info("[HomeDomain] DHCP 自动跟随已更新设备解析: %s", strings.Join(updates, ", "))
	return true
}

// Close 优雅关闭 Tailscale Split-DNS 应答器并更新状态快照。
func (w *HomeDomainWorker) Close() error {
	if w == nil {
		return nil
	}
	err := w.responder.Close()
	w.publishStatus()
	return err
}

func (d *Daemon) ensureHomeDomainWorker() *HomeDomainWorker {
	if d.homeDomainWorker != nil {
		return d.homeDomainWorker
	}
	d.homeDomainWorker = NewHomeDomainWorker(HomeDomainWorkerDeps{
		ServeCtx:    d.ctx,
		ConfigStore: d.cfgStore,
		StateStore:  d.effectiveStateStore(),
		DNSDeps:     d.dnsDeps,
	})
	return d.homeDomainWorker
}

func (d *Daemon) reconcileHomeDomainAsync() {
	if d.skipSignalSetup || d.homeDomainWorker == nil {
		return
	}
	if !d.homeDomainReconciling.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.homeDomainReconciling.Store(false)
		rCtx, cancel := context.WithTimeout(d.ctx, 12*time.Second)
		defer cancel()
		_ = d.homeDomainWorker.Reconcile(rCtx, d.currentConfig())
	}()
}
