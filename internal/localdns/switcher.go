// 文件职责：实现双引擎（SmartDNS / AdGuard Home）零断网两阶段原子切换、端口冲突避让、公共配置迁移与失败自动回滚编排器。
package localdns

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/common/proc"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/singbox"
	"singctl/internal/smartdns"
)

// SwitchRequest 描述切换底层防劫持 DNS 引擎的请求参数。
type SwitchRequest struct {
	TargetEngine   string `json:"engine"`
	ForceLowMemory bool   `json:"forceLowMemory"`
	NonInteractive bool   `json:"-"`
	SkipInstall    bool   `json:"-"`
}

// SwitchResult 汇总引擎切换完成后的生效引擎、迁移项、告警与最新工作台快照。
type SwitchResult struct {
	OK               bool              `json:"ok"`
	ConfiguredEngine string            `json:"configuredEngine"`
	ActiveEngine     string            `json:"activeEngine"`
	Switched         bool              `json:"switched"`
	MigratedItems    []string          `json:"migratedItems,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	Overview         *OverviewSnapshot `json:"overview,omitempty"`
}

var externalDNSFallbackPorts = []int{5354, 5355, 5335, 15353, 15354}

func isLoopbackDNSPortFree(port int) bool {
	if port <= 0 || port > 65535 || port == 53 {
		return false
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	_ = pc.Close()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func (r *Registry) isTargetEngineRunning(ctx context.Context, desiredEngine string, targetEng Engine) bool {
	if targetEng == nil || !targetEng.IsInstalled() {
		return false
	}
	if desiredEngine == constant.DNSEngineSmartDNS {
		svcMgr := r.deps.ServiceMgr
		if svcMgr == nil {
			svcMgr = servicemgr.Detect(nil)
		}
		if svcMgr != nil {
			svcName := cmp.Or(strings.TrimSpace(r.deps.SmartDNSServiceName), constant.SmartDNSServiceName)
			return svcMgr.IsActive(ctx, svcName)
		}
	}
	return targetEng.Status(ctx).Running
}

func (r *Registry) ensureAvailableExternalDNSPort(
	ctx context.Context,
	origActive string,
	desiredEngine string,
	targetEng Engine,
	currentPort int,
	waitForRelease bool,
) (int, string, error) {
	// 仅当目标引擎服务本身已在运行且健康响应时保留原端口（避免把其他进程占用的 5353 误判为自身）
	if origActive == desiredEngine && r.isTargetEngineRunning(ctx, desiredEngine, targetEng) && targetEng.Status(ctx).DNSHealthy {
		return currentPort, "", nil
	}
	checkFree := r.deps.CheckPortAvailableFunc
	if checkFree == nil {
		// 使用注入 Mock ServiceMgr 的隔离单测环境不探测宿主机真实端口
		if r.deps.ServiceMgr != nil {
			return currentPort, "", nil
		}
		checkFree = isLoopbackDNSPortFree
	}
	if checkFree(currentPort) {
		return currentPort, "", nil
	}
	// 刚停用旧引擎（如 procd 异步停止 smartdns/AdGuardHome）时，等待最多 1.5s 让原进程彻底释放回环端口，
	// 避免误判为 mDNS 占用而无故将 5353 顺延至 5354。
	if waitForRelease {
		pollInterval := r.deps.PortReleasePollInterval
		if pollInterval <= 0 {
			pollInterval = 100 * time.Millisecond
		}
		for range 15 {
			select {
			case <-ctx.Done():
				return currentPort, "", ctx.Err()
			case <-time.After(pollInterval):
			}
			if checkFree(currentPort) {
				return currentPort, "", nil
			}
		}
	}
	for _, cand := range externalDNSFallbackPorts {
		if cand == currentPort {
			continue
		}
		if checkFree(cand) {
			warn := fmt.Sprintf("检测到本地端口 127.0.0.1:%d 已被其他服务（如 avahi-daemon mDNS）占用，已自动顺延至空闲回环端口 127.0.0.1:%d", currentPort, cand)
			return cand, warn, nil
		}
	}
	return currentPort, "", fmt.Errorf("本地回环 DNS 端口 127.0.0.1:%d 及全部备选端口均被占用，请在 singctl.yaml 中手动指定空闲 dns.dns_port", currentPort)
}

func (r *Registry) saveConfig() error {
	if r.deps.SaveConfig != nil {
		return r.deps.SaveConfig(r.cfg)
	}
	if strings.TrimSpace(r.deps.ConfigPath) == "" {
		return nil
	}
	return config.Save(r.deps.ConfigPath, r.cfg)
}

func (r *Registry) shouldSyncSingBox() bool {
	if !r.cfg.IsBasicMode() {
		return true
	}
	if r.deps.IsSingBoxRunningFunc != nil {
		return r.deps.IsSingBoxRunningFunc()
	}
	if r.deps.SyncSingBoxDNSLocalFunc != nil {
		return true
	}
	return proc.PgrepMatch("sing-box")
}

func (r *Registry) syncSingBoxDNSLocal(ctx context.Context, useExternal bool, dnsPort int) error {
	sbPath := r.sbConfigPath()
	workPath := r.sbWorkConfigPath()
	if r.deps.SyncSingBoxDNSLocalFunc != nil {
		_, err := r.deps.SyncSingBoxDNSLocalFunc(ctx, sbPath, workPath, useExternal, dnsPort)
		return err
	}
	_, err := singbox.SyncLiveSingBoxDNSLocal(ctx, sbPath, workPath, useExternal, dnsPort)
	return err
}

func (r *Registry) verifyExternalDNSReady(ctx context.Context, engineID string, dnsPort int) error {
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort))
	probeDNS := r.deps.ProbeDNSFunc
	if probeDNS == nil {
		if engineID == constant.DNSEngineSmartDNS {
			probeDNS = smartdns.ProbeDNS
		} else {
			probeDNS = adguard.ProbeDNS
		}
	}
	probeRes := r.deps.ProbeResolutionFunc
	if probeRes == nil {
		probeRes = adguard.ProbeUpstreamResolution
	}

	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for attempts := 0; attempts < 16; attempts++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := probeDNS(dnsAddr, 800*time.Millisecond); err != nil {
			lastErr = fmt.Errorf("端口 %s 未就绪: %w", dnsAddr, err)
		} else if r.deps.SkipProbeForTest && r.deps.ProbeResolutionFunc == nil {
			return nil
		} else if ips, _, resErr := probeRes(dnsAddr, "qq.com", 3*time.Second); resErr != nil || len(ips) == 0 {
			if resErr != nil {
				lastErr = fmt.Errorf("实测解析 qq.com 失败: %w", resErr)
			} else {
				lastErr = fmt.Errorf("实测解析 qq.com 未返回有效记录")
			}
			// 外部查询已连上但解析失败（非短暂启动期）快速退出重试
			if attempts >= 2 {
				return lastErr
			}
		} else {
			return nil
		}
		if !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("%s (%s) 健康验收失败: %w", engineID, dnsAddr, lastErr)
}

func (r *Registry) describeMigratedItems(harvested []string) []string {
	items := append([]string{}, harvested...)
	hasPrefix := func(prefix string) bool {
		for _, it := range items {
			if strings.HasPrefix(it, prefix) {
				return true
			}
		}
		return false
	}
	if len(r.cfg.DNS.Upstreams) > 0 && !hasPrefix("加密上游") {
		items = append(items, fmt.Sprintf("加密上游 (%d 条)", len(r.cfg.DNS.Upstreams)))
	}
	if len(r.cfg.DNS.Whitelist) > 0 && !hasPrefix("域名白名单") {
		items = append(items, fmt.Sprintf("域名白名单 (%d 条)", len(r.cfg.DNS.Whitelist)))
	}
	if len(r.cfg.DNS.Rewrites) > 0 && !hasPrefix("内网解析重写") {
		items = append(items, fmt.Sprintf("内网解析重写 (%d 条)", len(r.cfg.DNS.Rewrites)))
	}
	if len(r.cfg.CustomRules.Block) > 0 {
		items = append(items, fmt.Sprintf("审计封禁规则 (%d 条)", len(r.cfg.CustomRules.Block)))
	}
	return items
}

// SwitchEngine 执行两阶段零断网原子引擎切换与公共配置迁移，任意步骤失败自动回滚。
func (r *Registry) SwitchEngine(ctx context.Context, req SwitchRequest) (*SwitchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	targetPref := strings.ToLower(strings.TrimSpace(req.TargetEngine))
	if targetPref == "" {
		targetPref = constant.DNSEngineAuto
	}
	if !config.IsValidDNSEngine(targetPref) {
		return nil, fmt.Errorf("不支持的目标 DNS 引擎 %q（仅允许 auto / smartdns / adguard）", req.TargetEngine)
	}

	hw := r.ProbeHardware()
	installed := r.InstalledMap()
	origSel := ResolveActiveEngine(r.cfg.DNS.GetEngine(), r.cfg.DNS.IsEnabled(), hw, installed)
	origConfigured := r.cfg.DNS.GetEngine()
	origEnabled := r.cfg.DNS.IsEnabled()
	origActive := origSel.ActiveEngine

	desiredEngine := targetPref
	if targetPref == constant.DNSEngineAuto {
		autoSel := RecommendEngine(hw, installed)
		desiredEngine = autoSel.RecommendedEngine
	}

	targetEng, ok := r.Get(desiredEngine)
	if !ok {
		return nil, fmt.Errorf("未注册的 DNS 引擎: %s", desiredEngine)
	}

	// 1. 硬件准入校验（闪存不足硬拦截绝不可绕过；仅内存偏低允许 ForceLowMemory 覆盖）
	elig := origSel.Eligibility[desiredEngine]
	if elig.DiskBlocked && !installed[desiredEngine] {
		return nil, fmt.Errorf("硬件闪存护栏拦截：%s", elig.BlockedReason)
	}
	if elig.MemoryBlocked && !req.ForceLowMemory && !installed[desiredEngine] {
		return nil, fmt.Errorf("硬件内存护栏拦截：%s（如需强行安装请启用 ForceLowMemory）", elig.BlockedReason)
	}

	// 2. 切出前无损收集当前活跃 AdGuard Home 公共配置
	var harvested []string
	if origActive == constant.DNSEngineAdGuard && installed[constant.DNSEngineAdGuard] && desiredEngine != constant.DNSEngineAdGuard {
		harvested = r.aghEng.HarvestCommonConfig(ctx)
	}
	migratedItems := r.describeMigratedItems(harvested)

	dnsPort := r.cfg.DNS.GetDNSPort()
	origDNSPort := r.cfg.DNS.DNSPort
	targetWasRunning := r.isTargetEngineRunning(ctx, desiredEngine, targetEng)
	targetWasHealthy := targetWasRunning && targetEng.Status(ctx).DNSHealthy
	var warnings []string
	stoppedOrigExternal := false
	startedTargetExternal := false
	syncSB := r.shouldSyncSingBox()

	rollback := func(cause error) (*SwitchResult, error) {
		logger.Warn("[LocalDNS] 切换至 %s 失败 (%v)，正在执行零断网自动回滚...", desiredEngine, cause)
		if startedTargetExternal && (!targetWasRunning || desiredEngine != origActive) {
			_ = targetEng.Disable(ctx)
		}
		r.cfg.DNS.SetEngine(origConfigured)
		r.cfg.DNS.SetEnabled(origEnabled)
		r.cfg.DNS.DNSPort = origDNSPort
		_ = r.saveConfig()
		restorePort := r.cfg.DNS.GetDNSPort()

		if stoppedOrigExternal && installed[origActive] {
			if origEng, hasOrig := r.Get(origActive); hasOrig {
				if startErr := origEng.Start(ctx); startErr == nil {
					if verifyErr := r.verifyExternalDNSReady(ctx, origActive, restorePort); verifyErr == nil {
						if syncSB {
							_ = r.syncSingBoxDNSLocal(ctx, true, restorePort)
						} else if r.cfg.IsBasicMode() {
							_, _ = SyncOpenWrtDnsmasqBridge(ctx, true, restorePort, r.dnsmasqBridgeDeps())
						}
						return nil, fmt.Errorf("切换至 %s 失败（已自动回滚恢复至 %s）: %w", desiredEngine, origActive, cause)
					}
				}
			}
		}
		if syncSB {
			_ = r.syncSingBoxDNSLocal(ctx, false, restorePort)
			return nil, fmt.Errorf("切换至 %s 失败（已维持 sing-box 纯 IP 加密 DoH 零断网兜底）: %w", desiredEngine, cause)
		}
		return nil, fmt.Errorf("切换至 %s 失败（已保持原有路由器 DNS 不变）: %w", desiredEngine, cause)
	}

	// 3. 零断网安全桥：仅在需联动 sing-box 时先将其 dns_local 原子热切至纯 IP 加密 DoH
	if syncSB && (origActive != desiredEngine || !targetWasHealthy) {
		if err := r.syncSingBoxDNSLocal(ctx, false, dnsPort); err != nil {
			warnings = append(warnings, fmt.Sprintf("切换 sing-box 纯 IP 加密 DoH 安全桥告警: %v", err))
		}
	}

	// 4. 若原活跃外部引擎与目标不同且已安装，先停止并禁用自启释放 127.0.0.1:<dnsPort>（完整保留原配置文件不删）
	if origActive != desiredEngine && installed[origActive] {
		if origEng, hasOrig := r.Get(origActive); hasOrig {
			if err := origEng.Disable(ctx); err != nil {
				warnings = append(warnings, fmt.Sprintf("停用旧引擎 %s 告警: %v", origActive, err))
			}
			stoppedOrigExternal = true
		}
	}

	// 5. 检测回环端口冲突（如 avahi-daemon 占用 5353 mDNS）自动顺延 -> 按需安装 -> 同步公共配置 -> 启动 -> 实测解析 -> 原子切换接管
	chosenPort, portWarn, portErr := r.ensureAvailableExternalDNSPort(ctx, origActive, desiredEngine, targetEng, dnsPort, stoppedOrigExternal)
	if portErr != nil {
		return rollback(portErr)
	}
	if chosenPort != dnsPort {
		dnsPort = chosenPort
		r.cfg.DNS.DNSPort = chosenPort
		if portWarn != "" {
			logger.Warn("[LocalDNS] %s", portWarn)
			warnings = append(warnings, portWarn)
		}
	}
	if !targetEng.IsInstalled() && !req.SkipInstall {
		if syncSB {
			logger.Info("[LocalDNS] 正在安装目标防劫持 DNS 引擎: %s（当前由 sing-box 纯 IP 加密 DoH 兜底不断网）...", desiredEngine)
		} else {
			logger.Info("[LocalDNS] 正在安装目标防劫持 DNS 引擎: %s（基础模式，验活后将自动接管路由器 dnsmasq）...", desiredEngine)
		}
		if err := targetEng.Install(ctx, InstallOptions{
			NonInteractive: true,
			ForceLowMemory: req.ForceLowMemory,
			SkipWaitReady:  true,
		}); err != nil {
			return rollback(fmt.Errorf("安装 %s 失败: %w", desiredEngine, err))
		}
	}
	if err := targetEng.SyncCommonConfig(ctx); err != nil {
		return rollback(fmt.Errorf("同步公共配置至 %s 失败: %w", desiredEngine, err))
	}
	if err := targetEng.Start(ctx); err != nil {
		return rollback(fmt.Errorf("启动 %s 失败: %w", desiredEngine, err))
	}
	startedTargetExternal = true

	if err := r.verifyExternalDNSReady(ctx, desiredEngine, dnsPort); err != nil {
		return rollback(err)
	}
	if r.cfg.IsBasicMode() {
		if _, brErr := SyncOpenWrtDnsmasqBridge(ctx, true, dnsPort, r.dnsmasqBridgeDeps()); brErr != nil {
			warnings = append(warnings, fmt.Sprintf("接管 OpenWrt dnsmasq 指向 %s 告警: %v", desiredEngine, brErr))
		}
		if syncSB {
			if _, statErr := os.Stat(r.sbConfigPath()); statErr == nil {
				if err := r.syncSingBoxDNSLocal(ctx, true, dnsPort); err != nil {
					warnings = append(warnings, fmt.Sprintf("同步本地 sing-box dns_local 告警: %v", err))
				}
			}
		}
	} else {
		_, _ = SyncOpenWrtDnsmasqBridge(ctx, false, dnsPort, r.dnsmasqBridgeDeps())
		if err := r.syncSingBoxDNSLocal(ctx, true, dnsPort); err != nil {
			return rollback(fmt.Errorf("切换 sing-box dns_local 指向 %s 失败: %w", desiredEngine, err))
		}
	}

	// 6. 原子持久化 cfg.DNS.Engine 至 singctl.yaml (0600)
	r.cfg.DNS.SetEngine(targetPref)
	r.cfg.DNS.SetEnabled(true)
	if err := r.saveConfig(); err != nil {
		return rollback(fmt.Errorf("持久化引擎配置至 singctl.yaml 失败: %w", err))
	}

	ov := r.Overview(ctx)
	return &SwitchResult{
		OK:               true,
		ConfiguredEngine: targetPref,
		ActiveEngine:     desiredEngine,
		Switched:         origActive != desiredEngine || origConfigured != targetPref || !origEnabled,
		MigratedItems:    migratedItems,
		Warnings:         warnings,
		Overview:         ov,
	}, nil
}
