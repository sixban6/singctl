// 文件职责：负责 YAML AST 注释无损合并保存（Save）、声明式角色字段清理规则（astSubtreeCleanupRule）与 Hy2 带宽原地更新。
//
// 架构设计原则：
//   - 开闭原则（OCP）：通过声明式规则表 defaultSaveCleanupRules 描述"空值/置零字段何时从磁盘 AST 清除"，
//     替代原有 260 行嵌套循环拷贝；后续新增配置区块只需在规则表中追加条目，无需修改 AST 遍历核心逻辑。
//   - 函数式内核 + 命令式薄外壳（Functional Core / Imperative Shell）：saveConfigBytesAST 在纯内存中完成
//     YAML 序列化与 AST 合并，便于表驱动单测覆盖；Save 与 UpdateHy2Bandwidth 负责临时文件原子替换与 0600 强制落盘。
package config

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"singctl/configs"

	"gopkg.in/yaml.v3"
)

// ASTSubtreeCleanupRule 声明单条 YAML AST 清理规则，用于在 Save 合并前清除已在 Go 结构体中清空或失效的旧节点。
type ASTSubtreeCleanupRule struct {
	Name                string
	When                func(cfg *Config, isServerDoc, isClientDoc bool) bool
	TargetDoc           string // "dst" | "src" | "both"
	ParentKey           string
	DropChild           func(cfg *Config, childKey string) bool
	DropParentWhenEmpty func(cfg *Config) bool
	RemoveTopLevel      bool
}

func dropChildKey(targetKey string) func(cfg *Config, childKey string) bool {
	return func(_ *Config, childKey string) bool {
		return childKey == targetKey
	}
}

// defaultSaveCleanupRules 集中维护各子配置块在 AST 合并前需要清理的陈旧键规则表。
var defaultSaveCleanupRules = []ASTSubtreeCleanupRule{
	{
		Name:      "custom_rules_empty_block",
		When:      func(cfg *Config, _, _ bool) bool { return cfg != nil && len(cfg.CustomRules.Block) == 0 },
		TargetDoc: "dst",
		ParentKey: "custom_rules",
		DropChild: dropChildKey("block"),
		DropParentWhenEmpty: func(cfg *Config) bool {
			return cfg.CustomRules.IsEmpty()
		},
	},
	{
		// 当 gateway 模式切换（如从 side 切回 main 并清空 main_router_ip）时，先清理 dstDoc 旧的 gateway 映射节点，由 srcDoc 最新值完整覆盖
		Name:           "gateway_replace_subtree",
		When:           func(cfg *Config, _, _ bool) bool { return cfg != nil },
		TargetDoc:      "dst",
		ParentKey:      "gateway",
		RemoveTopLevel: true,
	},
	{
		// 当 audit 子字段被修改或清空时，移除 dstDoc 中旧的子节点以保证置空字段或清空最后一条白名单真实生效
		Name:      "audit_stale_children",
		When:      func(cfg *Config, _, _ bool) bool { return cfg != nil },
		TargetDoc: "dst",
		ParentKey: "audit",
		DropChild: func(cfg *Config, childKey string) bool {
			switch childKey {
			case "ai":
				return true
			case "whitelist":
				return len(cfg.Audit.Whitelist) == 0
			case "throttles":
				return len(cfg.Audit.Throttles) == 0
			case "pcdn_block":
				return cfg.Audit.PCDNBlock == nil
			default:
				return false
			}
		},
		DropParentWhenEmpty: func(cfg *Config) bool {
			return cfg.Audit.IsEmpty()
		},
	},
	{
		Name:      "firewall_stale_children",
		When:      func(cfg *Config, _, _ bool) bool { return cfg != nil },
		TargetDoc: "dst",
		ParentKey: "firewall",
		DropChild: func(cfg *Config, childKey string) bool {
			switch childKey {
			case "whitelist":
				return len(cfg.Firewall.Whitelist) == 0
			case "extra_forever_ban":
				return len(cfg.Firewall.ExtraForeverBan) == 0
			case "protected_ports":
				return len(cfg.Firewall.ProtectedPorts) == 0
			default:
				return false
			}
		},
		DropParentWhenEmpty: func(cfg *Config) bool {
			return cfg.Firewall.IsEmpty()
		},
	},
	{
		// 当 watchdog.failover 被修改或恢复默认时，清理 dstDoc 与 srcDoc 中旧的 failover 子节点以保证置空字段真实生效
		Name:      "watchdog_failover_src",
		When:      func(cfg *Config, _, _ bool) bool { return cfg != nil && cfg.Watchdog.Failover.IsEmpty() },
		TargetDoc: "src",
		ParentKey: "watchdog",
		DropChild: dropChildKey("failover"),
	},
	{
		Name:      "watchdog_failover_dst",
		When:      func(cfg *Config, _, _ bool) bool { return cfg != nil },
		TargetDoc: "dst",
		ParentKey: "watchdog",
		DropChild: dropChildKey("failover"),
	},
	{
		// 当 tailscale.p2p_assist 被修改或清空时，清理 dstDoc 与 srcDoc 中旧的 p2p_assist 子节点以保证置空字段和删除 peer 真实生效
		Name:      "tailscale_p2p_assist_src",
		When:      func(cfg *Config, _, _ bool) bool { return cfg != nil && cfg.Tailscale.P2PAssist.IsZero() },
		TargetDoc: "src",
		ParentKey: "tailscale",
		DropChild: dropChildKey("p2p_assist"),
	},
	{
		Name:      "tailscale_p2p_assist_dst",
		When:      func(cfg *Config, _, _ bool) bool { return cfg != nil },
		TargetDoc: "dst",
		ParentKey: "tailscale",
		DropChild: dropChildKey("p2p_assist"),
	},
	{
		// 当 server.warp_routing 被修改、清空列表或恢复默认时，清理 dstDoc 与 srcDoc 中旧的 warp_routing 子节点以防止合并残留
		Name: "server_warp_routing_src",
		When: func(cfg *Config, _, isClientDoc bool) bool {
			return cfg != nil && !isClientDoc && cfg.Server.WarpRouting.IsEmpty()
		},
		TargetDoc: "src",
		ParentKey: "server",
		DropChild: dropChildKey("warp_routing"),
	},
	{
		Name:      "server_warp_routing_dst",
		When:      func(cfg *Config, _, isClientDoc bool) bool { return cfg != nil && !isClientDoc },
		TargetDoc: "dst",
		ParentKey: "server",
		DropChild: dropChildKey("warp_routing"),
	},
	{
		// 当 traffic_routing 被修改或恢复默认时，清理 dstDoc 中旧的 traffic_routing 节点，防止被删除的预设键在合并时残留
		Name:           "traffic_routing_replace",
		When:           func(cfg *Config, isServerDoc, _ bool) bool { return cfg != nil && !isServerDoc },
		TargetDoc:      "dst",
		ParentKey:      "traffic_routing",
		RemoveTopLevel: true,
	},
	{
		// 当 dns 可选双引擎/规则/开关字段被清空或恢复默认时，从 dstDoc 移除陈旧键以防合并残留
		Name:      "dns_stale_children",
		When:      func(cfg *Config, _, _ bool) bool { return cfg != nil },
		TargetDoc: "dst",
		ParentKey: "dns",
		DropChild: func(cfg *Config, childKey string) bool {
			switch childKey {
			case "engine":
				return strings.TrimSpace(cfg.DNS.Engine) == ""
			case "upstreams":
				return len(cfg.DNS.Upstreams) == 0
			case "upstream_mode":
				return strings.TrimSpace(cfg.DNS.UpstreamMode) == ""
			case "whitelist":
				return len(cfg.DNS.Whitelist) == 0
			case "rewrites":
				return len(cfg.DNS.Rewrites) == 0
			case "block_aaaa":
				return !cfg.DNS.BlockAAAA
			case "adblock_disabled_until":
				return cfg.DNS.AdblockDisabledUntil == 0
			case "disabled_ad_rule_sets":
				return len(cfg.DNS.DisabledAdRuleSets) == 0
			case "smartdns_filters":
				return len(cfg.DNS.SmartDNSFilters) == 0
			default:
				return false
			}
		},
	},
	{
		// 当 low_memory 清空恢复默认自动档时，从 dstDoc 移除陈旧的顶层 low_memory 键
		Name:           "low_memory_clear",
		When:           func(cfg *Config, _, _ bool) bool { return cfg != nil && strings.TrimSpace(string(cfg.LowMemory)) == "" },
		TargetDoc:      "dst",
		ParentKey:      "low_memory",
		RemoveTopLevel: true,
	},
	{
		// 当 notify 被修改、禁用某渠道或恢复默认空值时，清理 dstDoc 旧的 notify 子树，由 srcDoc 最新值完整覆盖（为空时彻底移除）
		Name:           "notify_replace_subtree",
		When:           func(cfg *Config, _, _ bool) bool { return cfg != nil },
		TargetDoc:      "dst",
		ParentKey:      "notify",
		RemoveTopLevel: true,
	},
	{
		// 当 safe_commit 被修改或恢复默认空值时，清理 dstDoc 旧的 safe_commit 子树，由 srcDoc 最新值完整覆盖（为空时彻底移除）
		Name:           "safe_commit_replace_subtree",
		When:           func(cfg *Config, _, _ bool) bool { return cfg != nil },
		TargetDoc:      "dst",
		ParentKey:      "safe_commit",
		RemoveTopLevel: true,
	},
}

// SaveConfigBytesAST 是纯内存 YAML AST 注释保留合并引擎；extraRules 会先于内置规则执行，便于调用方或单测扩展局部清理策略。
func SaveConfigBytesAST(existingData []byte, cfg *Config, extraRules ...ASTSubtreeCleanupRule) ([]byte, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	if len(existingData) == 0 {
		switch {
		case cfg != nil && cfg.HasActiveServerConfig() && !cfg.HasRealSubs():
			existingData = configs.ServerConfigYAML
		case cfg != nil && !cfg.HasActiveServerConfig():
			existingData = configs.ClientConfigYAML
		default:
			existingData = configs.DefaultConfigYAML
		}
	}

	if len(existingData) > 0 {
		var oldRoot, newRoot yaml.Node
		if errOld := yaml.Unmarshal(existingData, &oldRoot); errOld == nil {
			if errNew := yaml.Unmarshal(data, &newRoot); errNew == nil {
				rules := make([]ASTSubtreeCleanupRule, 0, len(extraRules)+len(defaultSaveCleanupRules))
				rules = append(rules, extraRules...)
				rules = append(rules, defaultSaveCleanupRules...)
				filterRoleNodesBeforeMergeWithRules(&oldRoot, &newRoot, cfg, rules)
				if mergeYAMLDocument(&oldRoot, &newRoot) {
					if mergedData, errMarshal := yaml.Marshal(&oldRoot); errMarshal == nil {
						data = mergedData
					}
				}
			}
		}
	}

	return data, nil
}

// Save serializes cfg to YAML and writes it to path.
// When path already exists and contains a valid YAML mapping document, Save merges
// the updated fields into the existing YAML AST so comments and unreferenced keys are preserved.
// When path does not exist, Save initializes from the role-specific template (ServerConfigYAML or ClientConfigYAML).
func Save(path string, cfg *Config) error {
	existingData, _ := os.ReadFile(path)
	data, err := SaveConfigBytesAST(existingData, cfg)
	if err != nil {
		return err
	}

	// 原子替换并显式加固为 0600，防止进程 umask 或旧文件遗留宽权限泄漏敏感 token/密码
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err == nil {
		_ = os.Chmod(tmpPath, 0600)
		if err := os.Rename(tmpPath, path); err == nil {
			_ = os.Chmod(path, 0600)
			return nil
		}
		_ = os.Remove(tmpPath)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	_ = os.Chmod(path, 0600)
	return nil
}

func filterRoleNodesBeforeMergeWithRules(dstRoot, srcRoot *yaml.Node, cfg *Config, rules []ASTSubtreeCleanupRule) {
	if len(dstRoot.Content) == 0 || len(srcRoot.Content) == 0 {
		return
	}
	dstDoc := dstRoot.Content[0]
	srcDoc := srcRoot.Content[0]
	if dstDoc.Kind != yaml.MappingNode || srcDoc.Kind != yaml.MappingNode {
		return
	}

	hasKey := func(m *yaml.Node, key string) bool {
		if m == nil || m.Kind != yaml.MappingNode {
			return false
		}
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == key {
				return true
			}
		}
		return false
	}

	dstHasServer := hasKey(dstDoc, "server")
	dstHasSubs := hasKey(dstDoc, "subs")

	isServerDoc := dstHasServer && !dstHasSubs && (cfg == nil || !cfg.HasRealSubs())
	isClientDoc := !dstHasServer && (cfg == nil || !cfg.HasActiveServerConfig())

	filtered := make([]*yaml.Node, 0, len(srcDoc.Content))
	for i := 0; i+1 < len(srcDoc.Content); i += 2 {
		k := srcDoc.Content[i]
		v := srcDoc.Content[i+1]
		key := k.Value

		if key == "audit" && (cfg == nil || cfg.Audit.IsEmpty()) {
			continue
		}
		if key == "custom_rules" && (cfg == nil || cfg.CustomRules.IsEmpty()) {
			continue
		}
		if key == "traffic_routing" && (cfg == nil || cfg.TrafficRouting.IsEmpty()) {
			continue
		}
		if key == "gateway" && (cfg == nil || cfg.Gateway.IsEmpty()) {
			continue
		}
		if key == "low_memory" && (cfg == nil || strings.TrimSpace(string(cfg.LowMemory)) == "") {
			continue
		}
		if key == "notify" && (cfg == nil || cfg.Notify.IsEmpty()) {
			continue
		}
		if key == "safe_commit" && (cfg == nil || cfg.SafeCommit.IsEmpty()) {
			continue
		}
		if isServerDoc {
			// 纯服务端配置：只保留原文件已有的顶层键、server 以及非空的 custom_rules / notify / safe_commit
			allowActive := (key == "custom_rules" && cfg != nil && !cfg.CustomRules.IsEmpty()) ||
				(key == "notify" && cfg != nil && !cfg.Notify.IsEmpty()) ||
				(key == "safe_commit" && cfg != nil && !cfg.SafeCommit.IsEmpty())
			if !hasKey(dstDoc, key) && key != "server" && !allowActive {
				continue
			}
		}
		if isClientDoc && key == "server" {
			// 纯客户端配置：不注入 server 块
			continue
		}
		filtered = append(filtered, k, v)
	}
	srcDoc.Content = filtered

	applyASTCleanupRules(dstDoc, srcDoc, cfg, isServerDoc, isClientDoc, rules)

	// 若 server.web_admin 已激活，清理 dstDoc 中 sni 节点尾部残留的 `# web_admin:` 注释块，避免重复
	for i := 0; i+1 < len(dstDoc.Content); i += 2 {
		if dstDoc.Content[i].Value == "server" && dstDoc.Content[i+1].Kind == yaml.MappingNode {
			srvMap := dstDoc.Content[i+1]
			if cfg != nil && (cfg.Server.WebAdmin.Enabled || cfg.Server.WebAdmin.Path != "" || cfg.Server.WebAdmin.Password != "") {
				for j := 0; j+1 < len(srvMap.Content); j += 2 {
					if strings.Contains(srvMap.Content[j+1].FootComment, "web_admin:") {
						srvMap.Content[j+1].FootComment = ""
					}
				}
			}
		}
	}
}

func applyASTCleanupRules(dstDoc, srcDoc *yaml.Node, cfg *Config, isServerDoc, isClientDoc bool, rules []ASTSubtreeCleanupRule) {
	for _, rule := range rules {
		_ = rule.Name
		if rule.When != nil && !rule.When(cfg, isServerDoc, isClientDoc) {
			continue
		}
		var targets []*yaml.Node
		switch rule.TargetDoc {
		case "", "dst":
			targets = []*yaml.Node{dstDoc}
		case "src":
			targets = []*yaml.Node{srcDoc}
		case "both":
			targets = slices.Clone([]*yaml.Node{dstDoc, srcDoc})
		}
		for _, doc := range targets {
			if rule.RemoveTopLevel {
				removeTopLevelKey(doc, rule.ParentKey)
				continue
			}
			if rule.DropChild != nil {
				dropParent := rule.DropParentWhenEmpty != nil && cfg != nil && rule.DropParentWhenEmpty(cfg)
				stripMappingChildKeys(doc, rule.ParentKey, func(childKey string) bool {
					return rule.DropChild(cfg, childKey)
				}, dropParent)
			}
		}
	}
}

func removeTopLevelKey(doc *yaml.Node, key string) {
	if doc == nil || doc.Kind != yaml.MappingNode {
		return
	}
	next := make([]*yaml.Node, 0, len(doc.Content))
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == key {
			continue
		}
		next = append(next, doc.Content[i], doc.Content[i+1])
	}
	doc.Content = next
}

func stripMappingChildKeys(doc *yaml.Node, parentKey string, shouldDrop func(childKey string) bool, dropParentWhenEmpty bool) {
	if doc == nil || doc.Kind != yaml.MappingNode || shouldDrop == nil {
		return
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value != parentKey || doc.Content[i+1].Kind != yaml.MappingNode {
			continue
		}
		sub := doc.Content[i+1]
		next := make([]*yaml.Node, 0, len(sub.Content))
		for j := 0; j+1 < len(sub.Content); j += 2 {
			if shouldDrop(sub.Content[j].Value) {
				continue
			}
			next = append(next, sub.Content[j], sub.Content[j+1])
		}
		sub.Content = next
		if len(sub.Content) == 0 && dropParentWhenEmpty {
			doc.Content = append(doc.Content[:i], doc.Content[i+2:]...)
		}
		break
	}
}

func mergeYAMLDocument(dstRoot, srcRoot *yaml.Node) bool {
	if dstRoot.Kind != yaml.DocumentNode || srcRoot.Kind != yaml.DocumentNode {
		return false
	}
	if len(dstRoot.Content) == 0 || len(srcRoot.Content) == 0 {
		return false
	}
	dstDoc := dstRoot.Content[0]
	srcDoc := srcRoot.Content[0]
	if dstDoc.Kind != yaml.MappingNode || srcDoc.Kind != yaml.MappingNode {
		return false
	}
	mergeYAMLMapping(dstDoc, srcDoc)
	return true
}

func mergeYAMLMapping(dst, src *yaml.Node) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		srcKey := src.Content[i]
		srcVal := src.Content[i+1]

		found := false
		for j := 0; j+1 < len(dst.Content); j += 2 {
			dstKey := dst.Content[j]
			dstVal := dst.Content[j+1]
			if dstKey.Value == srcKey.Value {
				found = true
				if dstVal.Kind == yaml.MappingNode && srcVal.Kind == yaml.MappingNode {
					mergeYAMLMapping(dstVal, srcVal)
				} else {
					head, line, foot := dstVal.HeadComment, dstVal.LineComment, dstVal.FootComment
					*dstVal = *srcVal
					if dstVal.HeadComment == "" {
						dstVal.HeadComment = head
					}
					if dstVal.LineComment == "" {
						dstVal.LineComment = line
					}
					if dstVal.FootComment == "" {
						dstVal.FootComment = foot
					}
				}
				break
			}
		}
		if !found {
			dst.Content = append(dst.Content, srcKey, srcVal)
		}
	}
}

// UpdateHy2Bandwidth updates hy2.up and hy2.down in the given YAML file while preserving comments and structure.
func UpdateHy2Bandwidth(configPath string, up, down int) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	var rootNode yaml.Node
	if err := yaml.Unmarshal(data, &rootNode); err != nil {
		return fmt.Errorf("parse yaml AST: %w", err)
	}

	if len(rootNode.Content) == 0 {
		return fmt.Errorf("empty yaml document")
	}

	docNode := rootNode.Content[0]
	if docNode.Kind != yaml.MappingNode {
		return fmt.Errorf("invalid yaml root kind")
	}

	// 查找或新建 hy2 映射节点
	var hy2Map *yaml.Node
	for i := 0; i < len(docNode.Content); i += 2 {
		if docNode.Content[i].Value == "hy2" {
			hy2Map = docNode.Content[i+1]
			break
		}
	}

	if hy2Map == nil {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "hy2"}
		hy2Map = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		docNode.Content = append(docNode.Content, keyNode, hy2Map)
	}

	setScalar := func(m *yaml.Node, key, val string) {
		for j := 0; j < len(m.Content); j += 2 {
			if m.Content[j].Value == key {
				m.Content[j+1].Value = val
				m.Content[j+1].Tag = "!!int"
				return
			}
		}
		k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
		v := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: val}
		m.Content = append(m.Content, k, v)
	}

	setScalar(hy2Map, "up", strconv.Itoa(up))
	setScalar(hy2Map, "down", strconv.Itoa(down))

	newData, err := yaml.Marshal(&rootNode)
	if err != nil {
		return fmt.Errorf("marshal updated AST: %w", err)
	}

	tempPath := configPath + ".tmp"
	if err := os.WriteFile(tempPath, newData, 0600); err != nil {
		return fmt.Errorf("write tmp config: %w", err)
	}
	_ = os.Chmod(tempPath, 0600)
	if err := os.Rename(tempPath, configPath); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	_ = os.Chmod(configPath, 0600)
	return nil
}
