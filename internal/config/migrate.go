// 文件职责：负责基于 YAML AST 的配置结构与注释无损迁移引擎（MigrateConfigBytes）及可扩展迁移阶段（ConfigMigrationStage）。
package config

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"singctl/configs"
)

// ConfigMigrationStage defines an extensible configuration migration step.
type ConfigMigrationStage struct {
	Name  string
	Apply func(mc *MigrationContext)
}

// MigrationContext 承载单次 YAML AST 配置迁移过程中的新旧文档节点上下文。
type MigrationContext struct {
	oldCfg     Config
	oldDocNode *yaml.Node
	rootNode   yaml.Node
	docNode    *yaml.Node
}

var defaultMigrationStages = []ConfigMigrationStage{
	{Name: "subs", Apply: migrateSubsStage},
	{Name: "github", Apply: migrateGitHubStage},
	{Name: "hy2", Apply: migrateHy2Stage},
	{Name: "dns", Apply: migrateDNSStage},
	{Name: "tailscale", Apply: migrateTailscaleStage},
	{Name: "server", Apply: migrateServerStage},
	{Name: "watchdog", Apply: migrateWatchdogStage},
	{Name: "client_top_level", Apply: migrateClientTopLevelStage},
	{Name: "shared_top_level", Apply: migrateSharedTopLevelStage},
}

// MigrateConfigBytes merges oldData into templateData using YAML AST while preserving
// template structure, comments, intentional zero values, and extra OCP stages.
func MigrateConfigBytes(oldData, templateData []byte, extraStages ...ConfigMigrationStage) ([]byte, error) {
	// Pre-process the old YAML to heal mixed gateway indentation and fix missing spaces after colons.
	cleanOldData := preprocessConfigYAML(oldData)

	var oldCfg Config
	if err := yaml.Unmarshal(cleanOldData, &oldCfg); err != nil {
		return nil, fmt.Errorf("failed to parse old config: %w", err)
	}

	var oldRootNode yaml.Node
	if err := yaml.Unmarshal(cleanOldData, &oldRootNode); err != nil {
		return nil, fmt.Errorf("failed to parse old config AST: %w", err)
	}
	var oldDocNode *yaml.Node
	if len(oldRootNode.Content) > 0 && oldRootNode.Content[0].Kind == yaml.MappingNode {
		oldDocNode = oldRootNode.Content[0]
	}

	var rootNode yaml.Node
	if err := yaml.Unmarshal(templateData, &rootNode); err != nil {
		return nil, fmt.Errorf("failed to parse template AST: %w", err)
	}
	if len(rootNode.Content) == 0 || rootNode.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("template AST is empty")
	}

	mc := &MigrationContext{
		oldCfg:     oldCfg,
		oldDocNode: oldDocNode,
		rootNode:   rootNode,
		docNode:    rootNode.Content[0],
	}
	mc.selectRoleTemplate()

	for _, stage := range defaultMigrationStages {
		if stage.Apply != nil {
			stage.Apply(mc)
		}
	}
	for _, stage := range extraStages {
		if stage.Apply != nil {
			stage.Apply(mc)
		}
	}

	newData, err := yaml.Marshal(&mc.rootNode)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal merged AST: %w", err)
	}
	return newData, nil
}

func hasYAMLKey(mapNode *yaml.Node, key string) bool {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		if mapNode.Content[i].Value == key {
			return true
		}
	}
	return false
}

func getYAMLSubMap(mapNode *yaml.Node, key string) *yaml.Node {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		if mapNode.Content[i].Value == key && mapNode.Content[i+1].Kind == yaml.MappingNode {
			return mapNode.Content[i+1]
		}
	}
	return nil
}

// selectRoleTemplate switches generic dual-role templates to the single-role baseline
// matching the existing config so server/client fields never cross-pollinate on upgrade.
func (mc *MigrationContext) selectRoleTemplate() {
	if !hasYAMLKey(mc.docNode, "subs") || !hasYAMLKey(mc.docNode, "server") {
		return
	}
	oldHasServer := hasYAMLKey(mc.oldDocNode, "server")
	oldHasClient := hasYAMLKey(mc.oldDocNode, "subs") || hasYAMLKey(mc.oldDocNode, "dns") || hasYAMLKey(mc.oldDocNode, "gateway") ||
		hasYAMLKey(mc.oldDocNode, "tailscale") || hasYAMLKey(mc.oldDocNode, "watchdog") || hasYAMLKey(mc.oldDocNode, "hy2") ||
		hasYAMLKey(mc.oldDocNode, "low_memory")
	hasRealSub := mc.oldCfg.HasRealSubs()
	hasRealServer := mc.oldCfg.HasActiveServerConfig()
	hasCustomClientFields := strings.TrimSpace(mc.oldCfg.Tailscale.AuthKey) != "" ||
		!mc.oldCfg.Gateway.IsEmpty() ||
		strings.TrimSpace(string(mc.oldCfg.LowMemory)) != "" ||
		strings.TrimSpace(mc.oldCfg.DNS.Password) != "" ||
		(mc.oldCfg.DNS.Enabled != nil && !*mc.oldCfg.DNS.Enabled)

	isServerOnly := (oldHasServer && !oldHasClient) || (hasRealServer && !hasRealSub && !hasCustomClientFields)
	isClientOnly := (!oldHasServer && oldHasClient) || (!hasRealServer && (hasRealSub || hasCustomClientFields))

	var overrideYAML []byte
	switch {
	case isServerOnly:
		overrideYAML = configs.ServerConfigYAML
	case isClientOnly:
		overrideYAML = configs.ClientConfigYAML
	default:
		return
	}

	var overrideRoot yaml.Node
	if err := yaml.Unmarshal(overrideYAML, &overrideRoot); err == nil && len(overrideRoot.Content) > 0 {
		mc.rootNode = overrideRoot
		mc.docNode = mc.rootNode.Content[0]
	}
}

func (mc *MigrationContext) replaceNode(key string, val any) {
	var newNode yaml.Node
	b, err := yaml.Marshal(val)
	if err != nil {
		return
	}
	if err := yaml.Unmarshal(b, &newNode); err != nil || len(newNode.Content) == 0 {
		return
	}
	newNodeChild := newNode.Content[0]

	parent := mc.docNode
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			originalNode := parent.Content[i+1]
			newNodeChild.HeadComment = originalNode.HeadComment
			newNodeChild.LineComment = originalNode.LineComment
			newNodeChild.FootComment = originalNode.FootComment

			if originalNode.Kind == yaml.ScalarNode && newNodeChild.Kind == yaml.ScalarNode {
				originalNode.Value = newNodeChild.Value
			} else {
				parent.Content[i+1] = newNodeChild
			}
			return
		}
	}

	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	parent.Content = append(parent.Content, keyNode, newNodeChild)
}

func inferScalarTag(val string) string {
	if _, err := strconv.ParseInt(val, 10, 64); err == nil {
		return "!!int"
	}
	if val == "true" || val == "false" {
		return "!!bool"
	}
	return "!!str"
}

func (mc *MigrationContext) SetOrAddField(parentKey, childKey, childVal string) {
	mapNode := getYAMLSubMap(mc.docNode, parentKey)
	if mapNode == nil {
		return
	}
	for j := 0; j+1 < len(mapNode.Content); j += 2 {
		if mapNode.Content[j].Value == childKey {
			mapNode.Content[j+1].Value = childVal
			if tag := inferScalarTag(childVal); tag != "!!str" {
				mapNode.Content[j+1].Tag = tag
			}
			return
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: childKey}
	valNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: inferScalarTag(childVal), Value: childVal}
	mapNode.Content = append(mapNode.Content, keyNode, valNode)
}

func (mc *MigrationContext) setOrAddMapping(parentKey, childKey string, val any) {
	mapNode := getYAMLSubMap(mc.docNode, parentKey)
	if mapNode == nil {
		return
	}
	var newNode yaml.Node
	b, _ := yaml.Marshal(val)
	_ = yaml.Unmarshal(b, &newNode)
	if len(newNode.Content) == 0 {
		return
	}
	childNode := newNode.Content[0]
	for j := 0; j+1 < len(mapNode.Content); j += 2 {
		if mapNode.Content[j].Value == childKey {
			mapNode.Content[j+1] = childNode
			return
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: childKey}
	mapNode.Content = append(mapNode.Content, keyNode, childNode)
}

func (mc *MigrationContext) removeField(parentKey, childKey string) {
	mapNode := getYAMLSubMap(mc.docNode, parentKey)
	if mapNode == nil {
		return
	}
	for j := 0; j+1 < len(mapNode.Content); j += 2 {
		if mapNode.Content[j].Value == childKey {
			mapNode.Content = append(mapNode.Content[:j], mapNode.Content[j+2:]...)
			return
		}
	}
}

func migrateSubsStage(mc *MigrationContext) {
	for _, s := range mc.oldCfg.Subs {
		if s.URL != "" || s.Name != "" {
			mc.replaceNode("subs", mc.oldCfg.Subs)
			return
		}
	}
}

func migrateGitHubStage(mc *MigrationContext) {
	if oldGitHub := getYAMLSubMap(mc.oldDocNode, "github"); hasYAMLKey(oldGitHub, "mirror_url") {
		mc.SetOrAddField("github", "mirror_url", mc.oldCfg.GitHub.MirrorURL)
	}
}

func migrateHy2Stage(mc *MigrationContext) {
	oldHy2 := getYAMLSubMap(mc.oldDocNode, "hy2")
	if oldHy2 == nil {
		return
	}
	if hasYAMLKey(oldHy2, "up") {
		mc.SetOrAddField("hy2", "up", strconv.Itoa(mc.oldCfg.Hy2.Up))
	}
	if hasYAMLKey(oldHy2, "down") {
		mc.SetOrAddField("hy2", "down", strconv.Itoa(mc.oldCfg.Hy2.Down))
	}
}

func migrateDNSStage(mc *MigrationContext) {
	oldDNS := getYAMLSubMap(mc.oldDocNode, "dns")
	if oldDNS == nil {
		return
	}
	if hasYAMLKey(oldDNS, "enabled") && mc.oldCfg.DNS.Enabled != nil {
		mc.SetOrAddField("dns", "enabled", strconv.FormatBool(*mc.oldCfg.DNS.Enabled))
	}
	if hasYAMLKey(oldDNS, "engine") && mc.oldCfg.DNS.Engine != "" {
		mc.SetOrAddField("dns", "engine", mc.oldCfg.DNS.Engine)
	}
	if hasYAMLKey(oldDNS, "dns_port") && mc.oldCfg.DNS.DNSPort > 0 {
		mc.SetOrAddField("dns", "dns_port", strconv.Itoa(mc.oldCfg.DNS.DNSPort))
	}
	if hasYAMLKey(oldDNS, "web_port") && mc.oldCfg.DNS.WebPort > 0 {
		mc.SetOrAddField("dns", "web_port", strconv.Itoa(mc.oldCfg.DNS.WebPort))
	}
	if hasYAMLKey(oldDNS, "username") && mc.oldCfg.DNS.Username != "" {
		mc.SetOrAddField("dns", "username", mc.oldCfg.DNS.Username)
	}
	if hasYAMLKey(oldDNS, "password") && mc.oldCfg.DNS.Password != "" {
		mc.SetOrAddField("dns", "password", mc.oldCfg.DNS.Password)
	}
	if hasYAMLKey(oldDNS, "upstreams") && len(mc.oldCfg.DNS.Upstreams) > 0 {
		mc.setOrAddMapping("dns", "upstreams", mc.oldCfg.DNS.Upstreams)
	}
	if hasYAMLKey(oldDNS, "upstream_mode") && mc.oldCfg.DNS.UpstreamMode != "" {
		mc.SetOrAddField("dns", "upstream_mode", mc.oldCfg.DNS.UpstreamMode)
	}
	if hasYAMLKey(oldDNS, "whitelist") && len(mc.oldCfg.DNS.Whitelist) > 0 {
		mc.setOrAddMapping("dns", "whitelist", mc.oldCfg.DNS.Whitelist)
	}
	if hasYAMLKey(oldDNS, "rewrites") && len(mc.oldCfg.DNS.Rewrites) > 0 {
		mc.setOrAddMapping("dns", "rewrites", mc.oldCfg.DNS.Rewrites)
	}
	if hasYAMLKey(oldDNS, "block_aaaa") && mc.oldCfg.DNS.BlockAAAA {
		mc.SetOrAddField("dns", "block_aaaa", "true")
	}
	if hasYAMLKey(oldDNS, "adblock_disabled_until") && mc.oldCfg.DNS.AdblockDisabledUntil != 0 {
		mc.SetOrAddField("dns", "adblock_disabled_until", strconv.FormatInt(mc.oldCfg.DNS.AdblockDisabledUntil, 10))
	}
	if hasYAMLKey(oldDNS, "disabled_ad_rule_sets") && len(mc.oldCfg.DNS.DisabledAdRuleSets) > 0 {
		mc.setOrAddMapping("dns", "disabled_ad_rule_sets", mc.oldCfg.DNS.DisabledAdRuleSets)
	}
	if hasYAMLKey(oldDNS, "smartdns_filters") && len(mc.oldCfg.DNS.SmartDNSFilters) > 0 {
		mc.setOrAddMapping("dns", "smartdns_filters", mc.oldCfg.DNS.SmartDNSFilters)
	}
}

func migrateTailscaleStage(mc *MigrationContext) {
	oldTS := getYAMLSubMap(mc.oldDocNode, "tailscale")
	if oldTS == nil {
		return
	}
	if hasYAMLKey(oldTS, "auth_key") {
		mc.SetOrAddField("tailscale", "auth_key", mc.oldCfg.Tailscale.AuthKey)
	}
	if hasYAMLKey(oldTS, "subnets") {
		mc.SetOrAddField("tailscale", "subnets", mc.oldCfg.Tailscale.Subnets)
	}
	if hasYAMLKey(oldTS, "use_build") {
		mc.SetOrAddField("tailscale", "use_build", strconv.FormatBool(mc.oldCfg.Tailscale.UseBuild))
	}
	if hasYAMLKey(oldTS, "p2p_assist") && !mc.oldCfg.Tailscale.P2PAssist.IsZero() {
		mc.setOrAddMapping("tailscale", "p2p_assist", mc.oldCfg.Tailscale.P2PAssist)
	}
}

func setOrClearServerField(mc *MigrationContext, oldServer *yaml.Node, key, val string) {
	if val != "" {
		mc.SetOrAddField("server", key, val)
	} else if hasYAMLKey(oldServer, key) {
		mc.SetOrAddField("server", key, "")
	}
}

func migrateServerStage(mc *MigrationContext) {
	oldServer := getYAMLSubMap(mc.oldDocNode, "server")
	if oldServer == nil {
		return
	}

	setOrClearServerField(mc, oldServer, "node_tag", mc.oldCfg.Server.NodeTag)

	// 平滑迁移：如果旧配置只有 sb_domain，则将其迁移到 node_domain
	nodeDomain := mc.oldCfg.Server.NodeDomain
	if nodeDomain == "" && mc.oldCfg.Server.SBDomain != "" {
		nodeDomain = mc.oldCfg.Server.SBDomain
	}
	setOrClearServerField(mc, oldServer, "node_domain", nodeDomain)

	if mc.oldCfg.Server.Hy2Port > 0 && mc.oldCfg.Server.Hy2Port <= 65535 {
		mc.SetOrAddField("server", "hy2_port", strconv.Itoa(mc.oldCfg.Server.Hy2Port))
	} else if hasYAMLKey(oldServer, "hy2_port") {
		mc.removeField("server", "hy2_port")
	}
	if mc.oldCfg.Server.VlessPort > 0 && mc.oldCfg.Server.VlessPort <= 65535 {
		mc.SetOrAddField("server", "vless_port", strconv.Itoa(mc.oldCfg.Server.VlessPort))
	} else if hasYAMLKey(oldServer, "vless_port") {
		mc.removeField("server", "vless_port")
	}

	for _, deprecatedKey := range []string{"node_port", "tuic_domain", "tuic_port", "anytls_port"} {
		mc.removeField("server", deprecatedKey)
	}

	setOrClearServerField(mc, oldServer, "substore_domain", mc.oldCfg.Server.SubstoreDomain)
	setOrClearServerField(mc, oldServer, "server_ip", mc.oldCfg.Server.ServerIP)
	setOrClearServerField(mc, oldServer, "cf_dns_key", mc.oldCfg.Server.CFDNSKey)

	if hasYAMLKey(oldServer, "sni") {
		mc.SetOrAddField("server", "sni", mc.oldCfg.Server.Sni)
	}
	if hasYAMLKey(oldServer, "cors_allowed_origins") {
		mc.SetOrAddField("server", "cors_allowed_origins", mc.oldCfg.Server.CorsAllowedOrigins)
	}

	// 处理旧版兼容字段 sb_domain：若旧配置包含则保留，否则从模板中移除，绝不注入虚假默认域名
	if hasYAMLKey(oldServer, "sb_domain") {
		mc.SetOrAddField("server", "sb_domain", mc.oldCfg.Server.SBDomain)
	} else {
		mc.removeField("server", "sb_domain")
	}

	if hasYAMLKey(oldServer, "web_terminal") {
		mc.setOrAddMapping("server", "web_terminal", mc.oldCfg.Server.WebTerminal)
	}
	if hasYAMLKey(oldServer, "web_admin") && (mc.oldCfg.Server.WebAdmin.Path != "" || mc.oldCfg.Server.WebAdmin.Enabled || mc.oldCfg.Server.WebAdmin.Password != "") {
		mc.setOrAddMapping("server", "web_admin", mc.oldCfg.Server.WebAdmin)
	}
	if hasYAMLKey(oldServer, "warp_routing") && !mc.oldCfg.Server.WarpRouting.IsEmpty() {
		mc.setOrAddMapping("server", "warp_routing", mc.oldCfg.Server.WarpRouting)
	}
}

func migrateWatchdogStage(mc *MigrationContext) {
	oldWD := getYAMLSubMap(mc.oldDocNode, "watchdog")
	if oldWD == nil {
		return
	}
	if hasYAMLKey(oldWD, "interval") {
		mc.SetOrAddField("watchdog", "interval", strconv.Itoa(mc.oldCfg.Watchdog.Interval))
	}
	if hasYAMLKey(oldWD, "confirm_wait") {
		mc.SetOrAddField("watchdog", "confirm_wait", strconv.Itoa(mc.oldCfg.Watchdog.ConfirmWait))
	}
	if hasYAMLKey(oldWD, "max_restarts") {
		mc.SetOrAddField("watchdog", "max_restarts", strconv.Itoa(mc.oldCfg.Watchdog.MaxRestarts))
	}
	if hasYAMLKey(oldWD, "sub_sync_interval") {
		mc.SetOrAddField("watchdog", "sub_sync_interval", strconv.Itoa(mc.oldCfg.Watchdog.SubSyncInterval))
	}
	if hasYAMLKey(oldWD, "preserve_manual_config") && mc.oldCfg.Watchdog.PreserveManualConfig != nil {
		mc.SetOrAddField("watchdog", "preserve_manual_config", strconv.FormatBool(*mc.oldCfg.Watchdog.PreserveManualConfig))
	}
	if hasYAMLKey(oldWD, "auto_start") && mc.oldCfg.Watchdog.AutoStart != nil {
		mc.SetOrAddField("watchdog", "auto_start", strconv.FormatBool(*mc.oldCfg.Watchdog.AutoStart))
	}
	if hasYAMLKey(oldWD, "failover") && !mc.oldCfg.Watchdog.Failover.IsEmpty() {
		mc.setOrAddMapping("watchdog", "failover", mc.oldCfg.Watchdog.Failover)
	}
}

func migrateClientTopLevelStage(mc *MigrationContext) {
	if hasYAMLKey(mc.oldDocNode, "custom_rules") && !mc.oldCfg.CustomRules.IsEmpty() {
		mc.replaceNode("custom_rules", mc.oldCfg.CustomRules)
	}
	if hasYAMLKey(mc.oldDocNode, "audit") && !mc.oldCfg.Audit.IsEmpty() {
		mc.replaceNode("audit", mc.oldCfg.Audit)
	}
	if hasYAMLKey(mc.oldDocNode, "traffic_routing") && !mc.oldCfg.TrafficRouting.IsEmpty() {
		mc.replaceNode("traffic_routing", mc.oldCfg.TrafficRouting)
	}
	if hasYAMLKey(mc.oldDocNode, "home_domain") && !mc.oldCfg.HomeDomain.IsEmpty() {
		mc.replaceNode("home_domain", mc.oldCfg.HomeDomain)
	}
	if oldGW := getYAMLSubMap(mc.oldDocNode, "gateway"); oldGW != nil && !mc.oldCfg.Gateway.IsEmpty() {
		if getYAMLSubMap(mc.docNode, "gateway") != nil {
			if hasYAMLKey(oldGW, "mode") && mc.oldCfg.Gateway.Mode != "" {
				mc.SetOrAddField("gateway", "mode", mc.oldCfg.Gateway.Mode)
			}
			if hasYAMLKey(oldGW, "work_mode") && mc.oldCfg.Gateway.WorkMode != "" {
				mc.SetOrAddField("gateway", "work_mode", mc.oldCfg.Gateway.WorkMode)
			}
			if hasYAMLKey(oldGW, "main_router_ip") && mc.oldCfg.Gateway.MainRouterIP != "" {
				mc.SetOrAddField("gateway", "main_router_ip", mc.oldCfg.Gateway.MainRouterIP)
			}
			if hasYAMLKey(oldGW, "lan_iface") && mc.oldCfg.Gateway.LANIface != "" {
				mc.SetOrAddField("gateway", "lan_iface", mc.oldCfg.Gateway.LANIface)
			}
			if hasYAMLKey(oldGW, "ipv6_mode") && mc.oldCfg.Gateway.IPv6Mode != "" {
				mc.SetOrAddField("gateway", "ipv6_mode", mc.oldCfg.Gateway.IPv6Mode)
			}
		} else {
			mc.replaceNode("gateway", mc.oldCfg.Gateway)
		}
	}
	if hasYAMLKey(mc.oldDocNode, "low_memory") && strings.TrimSpace(string(mc.oldCfg.LowMemory)) != "" {
		mc.replaceNode("low_memory", mc.oldCfg.LowMemory)
	}
}

func migrateSharedTopLevelStage(mc *MigrationContext) {
	if hasYAMLKey(mc.oldDocNode, "firewall") && !mc.oldCfg.Firewall.IsEmpty() {
		mc.replaceNode("firewall", mc.oldCfg.Firewall)
	}
	if hasYAMLKey(mc.oldDocNode, "notify") && !mc.oldCfg.Notify.IsEmpty() {
		mc.replaceNode("notify", mc.oldCfg.Notify)
	}
	if hasYAMLKey(mc.oldDocNode, "safe_commit") && !mc.oldCfg.SafeCommit.IsEmpty() {
		mc.replaceNode("safe_commit", mc.oldCfg.SafeCommit)
	}
}
