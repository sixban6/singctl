// 文件职责：提供三引擎防劫持 DNS 声明式注册表、活跃引擎路由、状态聚合与 sing-box 探测桥接。
package localdns

import (
	"cmp"
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
	"singctl/internal/smartdns"
)

var engineOrder = []string{
	constant.DNSEngineSingBox,
	constant.DNSEngineSmartDNS,
	constant.DNSEngineAdGuard,
}

// Registry 维护 singbox / smartdns / adguard 三引擎声明式注册与统一调度。
type Registry struct {
	cfg     *config.Config
	deps    EngineDeps
	engines map[string]Engine
	order   []string
	sbEng   *SingBoxEngine
	sdEng   *SmartDNSEngine
	aghEng  *AdGuardEngine
}

// NewRegistry 创建并注册三引擎防劫持 DNS 注册表。
func NewRegistry(cfg *config.Config, deps EngineDeps) *Registry {
	if cfg == nil {
		cfg = &config.Config{}
	}
	sbEng := NewSingBoxEngine(cfg, deps)
	sdEng := NewSmartDNSEngine(cfg, deps)
	aghEng := NewAdGuardEngine(cfg, deps)

	r := &Registry{
		cfg:   cfg,
		deps:  deps,
		sbEng: sbEng,
		sdEng: sdEng,
		aghEng: aghEng,
		engines: map[string]Engine{
			constant.DNSEngineSingBox:  sbEng,
			constant.DNSEngineSmartDNS: sdEng,
			constant.DNSEngineAdGuard:  aghEng,
		},
		order: engineOrder,
	}
	return r
}

// Get 按引擎标识获取对应实现。
func (r *Registry) Get(id string) (Engine, bool) {
	if r == nil {
		return nil, false
	}
	eng, ok := r.engines[strings.ToLower(strings.TrimSpace(id))]
	return eng, ok
}

// All 按固定展示顺序返回全部已注册引擎。
func (r *Registry) All() []Engine {
	if r == nil {
		return nil
	}
	out := make([]Engine, 0, len(r.order))
	for _, id := range r.order {
		if eng, ok := r.engines[id]; ok {
			out = append(out, eng)
		}
	}
	return out
}

// InstalledMap 返回三引擎的安装状态映射。
func (r *Registry) InstalledMap() map[string]bool {
	all := r.All()
	out := make(map[string]bool, len(all))
	for _, eng := range all {
		out[eng.ID()] = eng.IsInstalled()
	}
	return out
}

// ProbeHardware 返回当前宿主机硬件画像（内存 + 二进制分区剩余闪存）。
func (r *Registry) ProbeHardware() HardwareProfile {
	probeTarget := cmp.Or(strings.TrimSpace(r.deps.SmartDNSBinPath), strings.TrimSpace(r.deps.AdGuardBinPath), "/usr/bin")
	return ProbeHardwareProfile(probeTarget, r.deps.ReadMemInfo, r.deps.ReadDiskSpace)
}

// ResolveSelection 结合配置与硬件状态解析推荐引擎与当前活跃引擎。
func (r *Registry) ResolveSelection() SelectionResult {
	return ResolveActiveEngine(r.cfg.DNS.GetEngine(), r.cfg.DNS.IsEnabled(), r.ProbeHardware(), r.InstalledMap())
}

// ActiveEngine 返回当前活跃生效的 DNS 引擎实例（兜底始终返回 singbox）。
func (r *Registry) ActiveEngine() Engine {
	sel := r.ResolveSelection()
	if eng, ok := r.engines[sel.ActiveEngine]; ok {
		return eng
	}
	return r.sbEng
}

// DrainSmartDNSAuditLog 增量拉取 SmartDNS 内存盘审计日志喂入 24h 环形统计器。
func (r *Registry) DrainSmartDNSAuditLog() int {
	if r == nil || r.sdEng == nil {
		return 0
	}
	return r.sdEng.DrainAuditLog()
}

func (r *Registry) sbConfigPath() string {
	return cmp.Or(strings.TrimSpace(r.deps.SingBoxConfigPath), constant.SingBoxConfigFile)
}

func (r *Registry) buildEngineOptions(ctx context.Context, sel SelectionResult, activeID string, activeVersion string) []EngineOption {
	opts := make([]EngineOption, 0, len(r.order))
	for _, id := range r.order {
		eng := r.engines[id]
		meta := eng.Meta()
		installed := eng.IsInstalled()
		elig := sel.Eligibility[id]
		ver := ""
		if id == activeID {
			ver = activeVersion
		} else if installed && id != constant.DNSEngineSingBox {
			ver = eng.Status(ctx).Version
		}
		opts = append(opts, EngineOption{
			ID:            meta.ID,
			Name:          meta.Name,
			Tagline:       meta.Tagline,
			Installed:     installed,
			Active:        id == activeID,
			Recommended:   id == sel.RecommendedEngine,
			Eligible:      elig.Eligible,
			BlockedReason: elig.BlockedReason,
			DiskHint:      meta.DiskHint,
			RAMHint:       meta.RAMHint,
			Version:       ver,
		})
	}
	return opts
}

// Overview 聚合当前活跃引擎完整工作台快照与三引擎卡片状态。
func (r *Registry) Overview(ctx context.Context) *OverviewSnapshot {
	sel := r.ResolveSelection()
	active := r.engines[sel.ActiveEngine]
	if active == nil {
		active = r.sbEng
	}

	linked, _ := singbox.InspectSingBoxDNSLocal(r.sbConfigPath())
	snap := active.Overview(ctx, linked)
	if snap == nil {
		snap = &OverviewSnapshot{}
	}

	// 兼容既有 AdGuard 低内存防呆字段，确保前端和存量调用方持续感知 AdGuard OOM 门槛
	if aghWarn := r.aghEng.LowMemoryGuardWarning(); aghWarn != "" {
		snap.LowMemoryBlocked = true
		snap.LowMemoryWarning = aghWarn
	}

	snap.ConfiguredEngine = r.cfg.DNS.GetEngine()
	snap.ActiveEngine = active.ID()
	snap.ActiveEngineLabel = active.Meta().Name
	snap.RecommendedEngine = sel.RecommendedEngine
	snap.RecommendedReason = sel.RecommendedReason
	snap.Capabilities = active.Capabilities()
	snap.Engines = r.buildEngineOptions(ctx, sel, active.ID(), snap.Version)
	return snap
}

// StatusSummary 返回轻量级 /api/status 摘要（同时兼容 dns 与 adguard 字段）。
func (r *Registry) StatusSummary(ctx context.Context) map[string]any {
	sel := r.ResolveSelection()
	active := r.engines[sel.ActiveEngine]
	if active == nil {
		active = r.sbEng
	}
	st := active.Status(ctx)
	linked, _ := singbox.InspectSingBoxDNSLocal(r.sbConfigPath())
	if active.ID() == constant.DNSEngineSingBox {
		linked = !linked
	}
	aghWarn := r.aghEng.LowMemoryGuardWarning()

	return map[string]any{
		"supported":         st.Supported,
		"installed":         st.Installed,
		"enabled":           r.cfg.DNS.IsEnabled(),
		"running":           st.Running,
		"dnsHealthy":        st.DNSHealthy,
		"webHealthy":        st.WebHealthy,
		"singboxLinked":     linked,
		"lowMemoryBlocked":  aghWarn != "",
		"lowMemoryWarning":  aghWarn,
		"version":           st.Version,
		"dnsAddr":           st.DNSAddr,
		"webUrl":            st.WebURL,
		"configuredEngine":  r.cfg.DNS.GetEngine(),
		"activeEngine":      active.ID(),
		"activeEngineLabel": active.Meta().Name,
		"recommendedEngine": sel.RecommendedEngine,
	}
}

// MakeSingBoxProbe 生成供 singbox.ConfigGenerator.SetLocalDNSProbe 注入的外部引擎探活回调。
func (r *Registry) MakeSingBoxProbe() func(engine string, dnsPort int) bool {
	return func(engine string, dnsPort int) bool {
		eng, ok := r.Get(engine)
		if !ok || !eng.IsInstalled() {
			return false
		}
		if dnsPort <= 0 || dnsPort > 65535 {
			dnsPort = r.cfg.DNS.GetDNSPort()
		}
		dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort))
		probeFn := r.deps.ProbeDNSFunc
		if probeFn == nil {
			if engine == constant.DNSEngineSmartDNS {
				probeFn = smartdns.ProbeDNS
			} else {
				probeFn = adguard.ProbeDNS
			}
		}
		if probeFn(dnsAddr, 800*time.Millisecond) == nil {
			return true
		}
		if err := eng.EnsureHealthy(context.Background()); err == nil {
			return probeFn(dnsAddr, 800*time.Millisecond) == nil
		}
		return false
	}
}
