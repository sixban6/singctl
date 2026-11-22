// 文件职责：负责 sing-box 配置生成后的分阶段强类型编译流水线调度与单树内存状态复用（*sboption.Document）。
//
// 架构设计原则：
//   - 开闭原则（OCP）：将出站去重、本地 AdGuard DNS、策略组编排、自定义规则/黑名单、智能分流预设、
//     IPv6 孪生规则、私网 PTR 防环、日志降噪、控制面加固与 iOS 沙盒适配统一建模为 configCompileStage 注册表。
//   - 全链路单树强类型变换：全程 1 次反序列化为 *sboption.Document → 10 个纯内存类型化 Stage 连续变换 → 1 次格式化输出，
//     彻底消除中途回退 JSON 文本反复序列化/反序列化开销。
package singbox

import (
	"fmt"

	"singctl/internal/config"
	"singctl/internal/singbox/sboption"
)

// CompileDoc 在编译流水线各 Stage 之间传递唯一的 *sboption.Document 内存树。
type CompileDoc struct {
	initialRaw     string
	doc            *sboption.Document
	dirty          bool
	platform       string
	isIOS          bool
	unmarshalCount int
	marshalCount   int
}

// CompileStage 描述编译流水线中的单个可扩展阶段（OCP 扩展点）。
type CompileStage struct {
	Name      string
	AppliesTo func(g *ConfigGenerator, doc *CompileDoc) bool
	Apply     func(g *ConfigGenerator, doc *CompileDoc) error
}

// NewCompileDoc 创建承载单树变换状态的编译文档上下文。
func NewCompileDoc(initialJSON, platform string) *CompileDoc {
	return &CompileDoc{
		initialRaw: initialJSON,
		platform:   platform,
		isIOS:      platform == PlatformIOS,
	}
}

// EnsureDoc 惰性解析并返回唯一的 *sboption.Document 实例。
func (d *CompileDoc) EnsureDoc() (*sboption.Document, error) {
	if d.doc != nil {
		return d.doc, nil
	}
	parsed, err := sboption.ParseDocument([]byte(d.initialRaw))
	if err != nil {
		return nil, err
	}
	d.unmarshalCount++
	d.doc = parsed
	return d.doc, nil
}

// MarkDirty 标记内存配置树已发生修改。
func (d *CompileDoc) MarkDirty() { d.dirty = true }

// IsIOS 返回目标平台是否为 iOS 沙盒环境。
func (d *CompileDoc) IsIOS() bool { return d.isIOS }

// UnmarshalCount 返回编译期间执行的 JSON 反序列化次数（单树复用 invariant 断言用）。
func (d *CompileDoc) UnmarshalCount() int { return d.unmarshalCount }

// MarshalCount 返回编译期间执行的中间态 JSON 序列化次数（单树复用 invariant 断言用）。
func (d *CompileDoc) MarshalCount() int { return d.marshalCount }

// defaultConfigCompileStages 按依赖先后顺序定义标准编译阶段：
// 1. 出站去重 → 2. 策略分组 → 3. 自定义规则/黑名单 → 4. 智能分流预设 →
// 5. IPv6 孪生规则 → 6. 私网 PTR NXDOMAIN 防环（非 iOS） → 7. 低内存规则集裁剪 →
// 8. 本地双引擎防劫持 DNS（Linux：AdGuard/SmartDNS 或应急纯 IP 加密 DoH，强制关闭 optimistic） →
// 9. 日志级别收敛 → 10. Clash API 回环加固（非 iOS） → 11. iOS SFI 沙盒裁剪。
var defaultConfigCompileStages = []CompileStage{
	{
		Name: "deduplicate_outbounds",
		Apply: func(_ *ConfigGenerator, doc *CompileDoc) error {
			d, err := doc.EnsureDoc()
			if err != nil {
				return fmt.Errorf("dedup: invalid JSON: %w", err)
			}
			changed, err := deduplicateOutboundsInDoc(d)
			if err != nil {
				return err
			}
			if changed {
				doc.dirty = true
			}
			return nil
		},
	},
	{
		Name: "inject_groups",
		AppliesTo: func(g *ConfigGenerator, _ *CompileDoc) bool {
			return g != nil
		},
		Apply: func(g *ConfigGenerator, doc *CompileDoc) error {
			d, err := doc.EnsureDoc()
			if err != nil {
				return err
			}
			changed, err := g.injectGroupsInDoc(d)
			if err != nil {
				return err
			}
			if changed {
				doc.dirty = true
			}
			return nil
		},
	},
	{
		Name: "inject_custom_rules",
		AppliesTo: func(g *ConfigGenerator, _ *CompileDoc) bool {
			return g != nil && hasAnyCustomRules(g.config)
		},
		Apply: func(g *ConfigGenerator, doc *CompileDoc) error {
			d, err := doc.EnsureDoc()
			if err != nil {
				return fmt.Errorf("failed to parse config JSON for custom rules: %w", err)
			}
			if err := applyCustomRulesToDoc(g.config, d, doc.platform); err != nil {
				return err
			}
			doc.dirty = true
			return nil
		},
	},
	{
		Name: "inject_traffic_routing",
		AppliesTo: func(g *ConfigGenerator, _ *CompileDoc) bool {
			return g != nil && g.config != nil
		},
		Apply: func(g *ConfigGenerator, doc *CompileDoc) error {
			d, err := doc.EnsureDoc()
			if err != nil {
				return err
			}
			applyTrafficRoutingToDoc(d, g.config.TrafficRouting, g.config.CustomRules, doc.platform)
			doc.dirty = true
			return nil
		},
	},
	{
		Name: "apply_ipv6_mode",
		Apply: func(g *ConfigGenerator, doc *CompileDoc) error {
			ipv6Mode := config.GatewayIPv6Off
			if g != nil && g.config != nil {
				ipv6Mode = g.config.Gateway.EffectiveIPv6Mode()
			}
			d, err := doc.EnsureDoc()
			if err != nil {
				return err
			}
			if err := applyIPv6ModeToDoc(d, ipv6Mode); err != nil {
				return err
			}
			doc.dirty = true
			return nil
		},
	},
	{
		Name: "inject_private_ptr_block",
		AppliesTo: func(_ *ConfigGenerator, doc *CompileDoc) bool {
			return !doc.isIOS
		},
		Apply: func(_ *ConfigGenerator, doc *CompileDoc) error {
			d, err := doc.EnsureDoc()
			if err != nil {
				return err
			}
			if ensurePrivatePTRBlockRulesInDoc(d) {
				doc.dirty = true
			}
			return nil
		},
	},
	{
		Name: "prune_low_memory_rulesets",
		AppliesTo: func(g *ConfigGenerator, doc *CompileDoc) bool {
			return !doc.isIOS && g != nil && g.EffectiveLowMemory()
		},
		Apply: func(_ *ConfigGenerator, doc *CompileDoc) error {
			d, err := doc.EnsureDoc()
			if err != nil {
				return err
			}
			if pruneLowMemoryRuleSetsInDoc(d) {
				doc.dirty = true
			}
			return nil
		},
	},
	{
		Name: "inject_local_dns",
		AppliesTo: func(_ *ConfigGenerator, doc *CompileDoc) bool {
			return doc.platform == "linux"
		},
		Apply: func(g *ConfigGenerator, doc *CompileDoc) error {
			d, err := doc.EnsureDoc()
			if err != nil {
				return fmt.Errorf("failed to parse config JSON for local DNS injection: %w", err)
			}
			if injectLocalDNSInDoc(g, d, doc.platform) {
				doc.dirty = true
			}
			return nil
		},
	},
	{
		Name: "normalize_client_log_level",
		Apply: func(_ *ConfigGenerator, doc *CompileDoc) error {
			d, err := doc.EnsureDoc()
			if err != nil {
				return fmt.Errorf("failed to parse config JSON for log level normalization: %w", err)
			}
			if NormalizeClientLogLevelInDoc(d) {
				doc.dirty = true
			}
			return nil
		},
	},
	{
		Name: "harden_client_clash_api",
		AppliesTo: func(_ *ConfigGenerator, doc *CompileDoc) bool {
			return !doc.isIOS
		},
		Apply: func(_ *ConfigGenerator, doc *CompileDoc) error {
			d, err := doc.EnsureDoc()
			if err != nil {
				return fmt.Errorf("failed to parse config JSON for Clash API hardening: %w", err)
			}
			changed, err := HardenClientClashAPIInDoc(d)
			if err != nil {
				return err
			}
			if changed {
				doc.dirty = true
			}
			return nil
		},
	},
	{
		Name: "adapt_ios_config",
		AppliesTo: func(_ *ConfigGenerator, doc *CompileDoc) bool {
			return doc.isIOS
		},
		Apply: func(g *ConfigGenerator, doc *CompileDoc) error {
			d, err := doc.EnsureDoc()
			if err != nil {
				return fmt.Errorf("ios adapt: parse config JSON: %w", err)
			}
			mirrorURL := ""
			if g != nil && g.config != nil {
				mirrorURL = g.config.GitHub.MirrorURL
			}
			adaptIOSConfigInDoc(d, mirrorURL, "v1.14")
			doc.dirty = true
			return nil
		},
	},
}

// DefaultCompileStages 返回内置 10 阶段编译流水线副本。
func DefaultCompileStages() []CompileStage {
	out := make([]CompileStage, len(defaultConfigCompileStages))
	copy(out, defaultConfigCompileStages)
	return out
}

// RunCompileStages 依次执行给定的编译 Stage（可单独注入阶段列表进行单树复用测试）。
func RunCompileStages(g *ConfigGenerator, doc *CompileDoc, stages []CompileStage) error {
	if _, err := doc.EnsureDoc(); err != nil {
		return err
	}
	for _, stage := range stages {
		if stage.AppliesTo != nil && !stage.AppliesTo(g, doc) {
			continue
		}
		if stage.Apply == nil {
			continue
		}
		if err := stage.Apply(g, doc); err != nil {
			return fmt.Errorf("compile stage %s: %w", stage.Name, err)
		}
	}
	return nil
}

// RunCompilePipeline 执行标准 sing-box 配置编译流水线（支持追加 extraStages 扩展阶段），并输出缩进 JSON。
func (g *ConfigGenerator) RunCompilePipeline(initialJSON, platform string, extraStages ...CompileStage) (string, error) {
	resolved, err := ResolvePlatform(platform)
	if err != nil {
		return "", err
	}
	doc := NewCompileDoc(initialJSON, resolved)
	if err := RunCompileStages(g, doc, defaultConfigCompileStages); err != nil {
		return "", err
	}
	if len(extraStages) > 0 {
		if err := RunCompileStages(g, doc, extraStages); err != nil {
			return "", err
		}
	}
	parsedDoc, err := doc.EnsureDoc()
	if err != nil {
		return "", err
	}
	return parsedDoc.MarshalPretty()
}
