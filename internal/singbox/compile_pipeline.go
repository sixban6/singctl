// 文件职责：负责 sing-box 配置生成后的分阶段编译流水线调度与单树内存状态复用（compileDoc）。
//
// 架构设计原则：
//   - 开闭原则（OCP）：将规则注入、DNS 接管、IPv6 模式、私网 PTR 防环、日志降噪、
//     控制面加固与 iOS 沙盒适配建模为独立的 configCompileStage 阶段注册表，
//     后续新增平台差异或后处理步骤只需追加 Stage，无需修改 GenerateForPlatform 核心主干。
//   - 单树复用优化：相邻的 map[string]any 内存修改阶段共享同一棵已解析 JSON 树，
//     仅当需要跨越外部字符串接口阶段时按需序列化，大幅减少大配置反复 Marshal/Unmarshal 开销。
package singbox

import (
	"encoding/json"
	"fmt"

	"singctl/internal/config"
)

// compileDoc 在编译流水线各 Stage 之间传递配置文档，并维护「内存树 vs JSON 文本」的一致性。
//
// 学习提示（为何同时保存 raw 与 root）：
//   - root 存解析后的 map[string]any，连续的内存修改 Stage（如日志降噪 → Clash API 加固 → iOS 适配）
//     可直接原地改树并标记 dirty = true，全程只需 1 次反序列化与 1 次最终格式化输出；
//   - 若中途遇到仍以 string JSON 作为边界的外部模块（如分组编排、IPv6 孪生规则），
//     rawJSON() 仅在 dirty 时回写文本，setRawJSON() 再置空 root 以便后续按需惰性重解析。
type compileDoc struct {
	raw            string
	root           map[string]any
	dirty          bool
	platform       string
	isIOS          bool
	unmarshalCount int
	marshalCount   int
}

// configCompileStage 描述编译流水线中的单个可扩展阶段（OCP 扩展点）。
type configCompileStage struct {
	Name      string
	AppliesTo func(g *ConfigGenerator, doc *compileDoc) bool
	Apply     func(g *ConfigGenerator, doc *compileDoc) error
}

func newCompileDoc(initialJSON, platform string) *compileDoc {
	return &compileDoc{
		raw:      initialJSON,
		platform: platform,
		isIOS:    platform == PlatformIOS,
	}
}

func (d *compileDoc) ensureRoot() (map[string]any, error) {
	if d.root != nil {
		return d.root, nil
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(d.raw), &root); err != nil {
		return nil, err
	}
	d.unmarshalCount++
	if root == nil {
		root = make(map[string]any)
	}
	d.root = root
	d.dirty = false
	return d.root, nil
}

func (d *compileDoc) rawJSON() (string, error) {
	if d.dirty && d.root != nil {
		b, err := json.Marshal(d.root)
		if err != nil {
			return "", err
		}
		d.marshalCount++
		d.raw = string(b)
		d.dirty = false
	}
	return d.raw, nil
}

func (d *compileDoc) setRawJSON(next string) {
	d.raw = next
	d.root = nil
	d.dirty = false
}

// defaultConfigCompileStages 按依赖先后顺序定义标准编译阶段：
// 1. 出站去重 → 2. 本地 AdGuard DNS → 3. 策略分组 → 4. 自定义规则/黑名单 →
// 5. 智能分流预设 → 6. IPv6 孪生规则 → 7. 私网 PTR NXDOMAIN 防环（非 iOS） →
// 8. 日志级别收敛 → 9. Clash API 回环加固（非 iOS） → 10. iOS SFI 沙盒裁剪。
var defaultConfigCompileStages = []configCompileStage{
	{
		Name: "deduplicate_outbounds",
		Apply: func(_ *ConfigGenerator, doc *compileDoc) error {
			root, err := doc.ensureRoot()
			if err != nil {
				return fmt.Errorf("dedup: invalid JSON: %w", err)
			}
			changed, err := deduplicateOutboundsInRoot(root)
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
		Name: "inject_local_dns",
		AppliesTo: func(g *ConfigGenerator, doc *compileDoc) bool {
			return g != nil && shouldInjectLocalAdGuardDNS(g.config, doc.platform)
		},
		Apply: func(g *ConfigGenerator, doc *compileDoc) error {
			root, err := doc.ensureRoot()
			if err != nil {
				return fmt.Errorf("failed to parse config JSON for local DNS injection: %w", err)
			}
			changed := injectLocalDNSInRoot(g, root)
			if changed {
				doc.dirty = true
			}
			return nil
		},
	},
	{
		Name: "inject_groups",
		AppliesTo: func(g *ConfigGenerator, _ *compileDoc) bool {
			return g != nil
		},
		Apply: func(g *ConfigGenerator, doc *compileDoc) error {
			raw, err := doc.rawJSON()
			if err != nil {
				return err
			}
			next, err := g.InjectGroupsForPlatform(raw, doc.platform)
			if err != nil {
				return err
			}
			if next != raw {
				doc.setRawJSON(next)
			}
			return nil
		},
	},
	{
		Name: "inject_custom_rules",
		AppliesTo: func(g *ConfigGenerator, _ *compileDoc) bool {
			return g != nil && hasAnyCustomRules(g.config)
		},
		Apply: func(g *ConfigGenerator, doc *compileDoc) error {
			root, err := doc.ensureRoot()
			if err != nil {
				return fmt.Errorf("failed to parse config JSON for custom rules: %w", err)
			}
			if err := applyCustomRulesToRoot(g.config, root, doc.platform); err != nil {
				return err
			}
			doc.dirty = true
			return nil
		},
	},
	{
		Name: "inject_traffic_routing",
		AppliesTo: func(g *ConfigGenerator, _ *compileDoc) bool {
			return g != nil
		},
		Apply: func(g *ConfigGenerator, doc *compileDoc) error {
			raw, err := doc.rawJSON()
			if err != nil {
				return err
			}
			next, err := g.InjectTrafficRoutingForPlatform(raw, doc.platform)
			if err != nil {
				return err
			}
			if next != raw {
				doc.setRawJSON(next)
			}
			return nil
		},
	},
	{
		Name: "apply_ipv6_mode",
		Apply: func(g *ConfigGenerator, doc *compileDoc) error {
			ipv6Mode := config.GatewayIPv6Off
			if g != nil && g.config != nil {
				ipv6Mode = g.config.Gateway.EffectiveIPv6Mode()
			}
			raw, err := doc.rawJSON()
			if err != nil {
				return err
			}
			next, err := ApplyIPv6ModeToConfigJSON(raw, ipv6Mode)
			if err != nil {
				return err
			}
			if next != raw {
				doc.setRawJSON(next)
			}
			return nil
		},
	},
	{
		Name: "inject_private_ptr_block",
		AppliesTo: func(_ *ConfigGenerator, doc *compileDoc) bool {
			return !doc.isIOS
		},
		Apply: func(_ *ConfigGenerator, doc *compileDoc) error {
			raw, err := doc.rawJSON()
			if err != nil {
				return err
			}
			next, err := InjectPrivatePTRBlockRules(raw)
			if err != nil {
				return err
			}
			if next != raw {
				doc.setRawJSON(next)
			}
			return nil
		},
	},
	{
		Name: "normalize_client_log_level",
		Apply: func(_ *ConfigGenerator, doc *compileDoc) error {
			root, err := doc.ensureRoot()
			if err != nil {
				return fmt.Errorf("failed to parse config JSON for log level normalization: %w", err)
			}
			if changed, _ := normalizeClientLogLevelInRoot(root); changed {
				doc.dirty = true
			}
			return nil
		},
	},
	{
		Name: "harden_client_clash_api",
		AppliesTo: func(_ *ConfigGenerator, doc *compileDoc) bool {
			return !doc.isIOS
		},
		Apply: func(_ *ConfigGenerator, doc *compileDoc) error {
			root, err := doc.ensureRoot()
			if err != nil {
				return fmt.Errorf("failed to parse config JSON for Clash API hardening: %w", err)
			}
			changed, err := hardenClientClashAPIInRoot(root)
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
		AppliesTo: func(_ *ConfigGenerator, doc *compileDoc) bool {
			return doc.isIOS
		},
		Apply: func(g *ConfigGenerator, doc *compileDoc) error {
			root, err := doc.ensureRoot()
			if err != nil {
				return fmt.Errorf("ios adapt: parse config JSON: %w", err)
			}
			mirrorURL := ""
			if g != nil && g.config != nil {
				mirrorURL = g.config.GitHub.MirrorURL
			}
			adaptIOSConfigInRoot(root, mirrorURL, "v1.14")
			doc.dirty = true
			return nil
		},
	},
}

// runCompileStages 依次执行给定的编译 Stage（可单独注入纯树阶段列表进行单树复用测试）。
func runCompileStages(g *ConfigGenerator, doc *compileDoc, stages []configCompileStage) error {
	if _, err := doc.ensureRoot(); err != nil {
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

// runCompilePipeline 执行标准 sing-box 配置编译流水线（支持追加 extraStages 扩展阶段），并输出缩进 JSON。
func (g *ConfigGenerator) runCompilePipeline(initialJSON, platform string, extraStages ...configCompileStage) (string, error) {
	resolved, err := ResolvePlatform(platform)
	if err != nil {
		return "", err
	}
	doc := newCompileDoc(initialJSON, resolved)
	if err := runCompileStages(g, doc, defaultConfigCompileStages); err != nil {
		return "", err
	}
	if len(extraStages) > 0 {
		if err := runCompileStages(g, doc, extraStages); err != nil {
			return "", err
		}
	}
	outRaw, err := doc.rawJSON()
	if err != nil {
		return "", err
	}
	return PrettyJSON(outRaw)
}
