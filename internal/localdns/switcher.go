// 文件职责：实现三引擎零断网两阶段原子切换、公共配置迁移与任意步骤失败自动回滚编排器。
package localdns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
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

func isExternalEngine(id string) bool {
	return id == constant.DNSEngineSmartDNS || id == constant.DNSEngineAdGuard
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

func (r *Registry) syncSingBoxDNSLocal(ctx context.Context, useExternal bool, dnsPort int) error {
	sbPath := r.sbConfigPath()
	workPath := r.sbEng.sbWorkConfigPath()
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
	if r.cfg.DNS.BlockAAAA {
		items = append(items, "AAAA 屏蔽策略")
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
	if !config.IsValidDNSEngine(targetPref) {
		return nil, fmt.Errorf("不支持的目标 DNS 引擎 %q（仅允许 auto / singbox / smartdns / adguard）", req.TargetEngine)
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
		desiredEngine = autoSel.ActiveEngine
	}

	targetEng, ok := r.Get(desiredEngine)
	if !ok {
		return nil, fmt.Errorf("未注册的 DNS 引擎: %s", desiredEngine)
	}

	// 1. 硬件准入校验（闪存不足硬拦截绝不可绕过；仅内存偏低允许 ForceLowMemory 覆盖）
	if isExternalEngine(desiredEngine) {
		elig := origSel.Eligibility[desiredEngine]
		if elig.DiskBlocked && !installed[desiredEngine] {
			return nil, fmt.Errorf("硬件闪存护栏拦截：%s", elig.BlockedReason)
		}
		if elig.MemoryBlocked && !req.ForceLowMemory && !installed[desiredEngine] {
			return nil, fmt.Errorf("硬件内存护栏拦截：%s（如需强行安装请启用 ForceLowMemory）", elig.BlockedReason)
		}
	}

	// 2. 切出前无损收集当前活跃引擎公共配置
	var harvested []string
	if origActive == constant.DNSEngineAdGuard && desiredEngine != constant.DNSEngineAdGuard {
		harvested = r.aghEng.HarvestCommonConfig(ctx)
	}
	migratedItems := r.describeMigratedItems(harvested)

	dnsPort := r.cfg.DNS.GetDNSPort()
	var warnings []string
	stoppedOrigExternal := false
	startedTargetExternal := false

	rollback := func(cause error) (*SwitchResult, error) {
		logger.Warn("[LocalDNS] 切换至 %s 失败 (%v)，正在执行零断网自动回滚...", desiredEngine, cause)
		if startedTargetExternal && isExternalEngine(desiredEngine) && desiredEngine != origActive {
			_ = targetEng.Disable(ctx)
		}
		r.cfg.DNS.SetEngine(origConfigured)
		r.cfg.DNS.SetEnabled(origEnabled)
		_ = r.saveConfig()

		if stoppedOrigExternal && isExternalEngine(origActive) {
			if origEng, hasOrig := r.Get(origActive); hasOrig {
				if startErr := origEng.Start(ctx); startErr == nil {
					if verifyErr := r.verifyExternalDNSReady(ctx, origActive, dnsPort); verifyErr == nil {
						_ = r.syncSingBoxDNSLocal(ctx, true, dnsPort)
						return nil, fmt.Errorf("切换至 %s 失败（已自动回滚恢复至 %s）: %w", desiredEngine, origActive, cause)
					}
				}
			}
		}
		_ = r.sbEng.SyncCommonConfig(ctx)
		return nil, fmt.Errorf("切换至 %s 失败（已维持 sing-box 加密 DoH 零断网兜底）: %w", desiredEngine, cause)
	}

	// 3. 零断网安全区：先将 sing-box dns_local 原子热切至 sing-box 加强版纯 IP 加密 DoH
	if origActive != desiredEngine || desiredEngine == constant.DNSEngineSingBox {
		if err := r.sbEng.SyncCommonConfig(ctx); err != nil {
			warnings = append(warnings, fmt.Sprintf("同步 sing-box 加强版安全区配置告警: %v", err))
		}
	}

	// 4. 若原活跃引擎为其它外部引擎，先停止并禁用自启释放 127.0.0.1:<dnsPort>（完整保留原配置文件不删）
	if isExternalEngine(origActive) && origActive != desiredEngine {
		if origEng, hasOrig := r.Get(origActive); hasOrig {
			if err := origEng.Disable(ctx); err != nil {
				warnings = append(warnings, fmt.Sprintf("停用旧引擎 %s 告警: %v", origActive, err))
			}
			stoppedOrigExternal = true
		}
	}

	// 5. 若目标为外部引擎：按需安装 -> 同步公共配置 -> 启动 -> 实测 127.0.0.1:<dnsPort> 解析 qq.com -> 原子切换 sing-box
	if isExternalEngine(desiredEngine) {
		if !targetEng.IsInstalled() && !req.SkipInstall {
			logger.Info("[LocalDNS] 正在安装目标防劫持 DNS 引擎: %s（当前由 sing-box 加密 DoH 兜底不断网）...", desiredEngine)
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
		if err := r.syncSingBoxDNSLocal(ctx, true, dnsPort); err != nil {
			return rollback(fmt.Errorf("切换 sing-box dns_local 指向 %s 失败: %w", desiredEngine, err))
		}
	} else {
		// 目标为 singbox 加强版：确保增强 DNS 规则与 .singctl-base 已落盘生效
		if err := r.sbEng.SyncCommonConfig(ctx); err != nil {
			return rollback(fmt.Errorf("应用 sing-box 加强版加密 DNS 失败: %w", err))
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
		Switched:         origActive != desiredEngine || origConfigured != targetPref,
		MigratedItems:    migratedItems,
		Warnings:         warnings,
		Overview:         ov,
	}, nil
}
