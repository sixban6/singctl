package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	log "singctl/internal/logger"
	"singctl/internal/util/netinfo"

	"github.com/sixban6/singgen/pkg/model"
	"github.com/sixban6/singgen/pkg/singgen"
)

type ConfigGenerator struct {
	config        *config.Config
	webui         string
	netInfo       *netinfo.NetInfoResult
	defaultTplVer string
	cacheDir      string
}

// 支持的目标平台
const (
	PlatformIOS = "ios"
)

// ResolvePlatform 将平台参数解析为实际值。
// "auto"/空 → 当前系统平台(runtime.GOOS);否则仅接受白名单平台。
// iOS 配置可在任意系统上生成 —— 平台指的是配置的“目标设备”而非本机。
func ResolvePlatform(p string) (string, error) {
	switch p {
	case "", "auto":
		return runtime.GOOS, nil
	case "darwin", "windows", "linux", PlatformIOS:
		return p, nil
	default:
		return "", fmt.Errorf("不支持的目标平台 %q (可选: auto/darwin/windows/linux/ios)", p)
	}
}

func NewConfigGenerator(cfg *config.Config) *ConfigGenerator {
	cg := &ConfigGenerator{
		config:        cfg,
		defaultTplVer: "v1.14",
		cacheDir:      singgen.DefaultCacheDir(),
	}
	netResult, err := netinfo.Get()
	if err != nil {
		log.Error("error getting netResult: %v", err)
	}
	cg.netInfo = netResult
	var lanIP string
	if netResult != nil {
		lanIP = netResult.LANIPv4
	}
	cg.webui = getWebUIAddress(lanIP)
	//log.Info("Network information: %+v", netResult)
	return cg
}

// SetCacheDir 覆盖订阅缓存目录（传空字符串可禁用订阅缓存回退，主要用于测试或无状态场景）。
func (g *ConfigGenerator) SetCacheDir(dir string) {
	g.cacheDir = dir
}

func getWebUIAddress(ipv4 string) string {
	const localhost = "127.0.0.1"
	if runtime.GOOS == "linux" && ipv4 != "" {
		return fmt.Sprintf("%s:9090", ipv4)
	}
	return fmt.Sprintf("%s:9090", localhost)
}

func (g *ConfigGenerator) webuiForPlatform(platform string) string {
	switch platform {
	case PlatformIOS:
		return "127.0.0.1:9095"
	case "linux":
		if g.netInfo != nil && g.netInfo.LANIPv4 != "" {
			return fmt.Sprintf("%s:9090", g.netInfo.LANIPv4)
		}
		return "127.0.0.1:9090"
	default:
		return "127.0.0.1:9090"
	}
}

func (c *ConfigGenerator) getSubnetFromIP(ip string) string {
	return netinfo.ResolveClientSubnet(context.Background(), ip)
}

func (g *ConfigGenerator) Generate() (string, error) {
	return g.GenerateForPlatform(runtime.GOOS)
}

// GenerateForPlatform 生成针对指定目标平台的配置。
// 与桌面端(Linux/macOS/Windows 本机运行)不同, iOS(sing-box 官方 App SFI)有以下平台差异:
//   - DNS/客户端子网不注入探测值, 交给 singgen ios 模板默认(手机离 homesite 后局域网 DNS 无效)
//   - external_controller 保留模板默认(127.0.0.1:9095, 仅 SFI 沙盒内 loopback 可访问,
//     可供 SFI 内置 dashboard 使用; 不注入本机 webui 地址)
//   - 不注入 Tailscale(手机上无 tailscaled)
func (g *ConfigGenerator) GenerateForPlatform(platform string) (string, error) {
	resolved, err := ResolvePlatform(platform)
	if err != nil {
		return "", err
	}
	isIOS := resolved == PlatformIOS

	ctx := context.Background()

	// 检查 DNS 服务器是否可用(iOS 交给模板默认, 不探测本机局域网 DNS)
	var dnsServer string
	if !isIOS {
		if g.netInfo != nil && len(g.netInfo.DNSServers) > 0 {
			dnsServer = g.netInfo.DNSServers[0]
		} else {
			dnsServer = "223.5.5.5" // 默认国内 DNS
		}
	}

	if len(g.config.Subs) == 0 {
		return "", errors.New("配置中未找到任何订阅源 (subs 列表为空)")
	}

	var raw string
	// 如果只有一个订阅，使用单订阅API
	if len(g.config.Subs) == 1 {
		raw, err = g.generateSingleSubscription(ctx, dnsServer, resolved)
	} else {
		// 多订阅使用新的多订阅API
		raw, err = g.generateMultiSubscription(ctx, dnsServer, resolved)
	}
	if err != nil {
		return "", err
	}

	// 统一在此处去重，覆盖单/多订阅两条路径
	deduped, err := DeduplicateOutbounds(raw)
	if err != nil {
		return "", err
	}

	// 若客户端启用且已安装本地 AdGuard Home，将 dns_local 自动指向 127.0.0.1:<dns_port>
	withLocalDNS, err := g.InjectLocalDNS(deduped, resolved)
	if err != nil {
		return "", err
	}

	// 注入自定义规则（DNS 与路由）
	withCustomRules, err := g.InjectCustomRules(withLocalDNS)
	if err != nil {
		return "", err
	}

	// 格式化为可读 JSON
	return PrettyJSON(withCustomRules)
}

// InjectLocalDNS 在 Linux/OpenWrt 客户端网关平台且启用并安装了 AdGuard Home 时，
// 将 sing-box 配置中的 dns_local 解析器指向本地 127.0.0.1:<dns_port>（默认 5353）。
// iOS 等移动端配置永远保持原样，不注入本机回环端口。
func (g *ConfigGenerator) InjectLocalDNS(rawJSON, platform string) (string, error) {
	if platform != "linux" || g.config == nil || !g.config.DNS.IsEnabled() || !adguard.IsInstalled() {
		return rawJSON, nil
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", fmt.Errorf("failed to parse config JSON for local DNS injection: %w", err)
	}

	dnsMap, ok := root["dns"].(map[string]any)
	if !ok {
		return rawJSON, nil
	}
	servers, ok := dnsMap["servers"].([]any)
	if !ok {
		return rawJSON, nil
	}

	dnsPort := g.config.DNS.GetDNSPort()
	updated := false
	for i, item := range servers {
		srvMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if tag, _ := srvMap["tag"].(string); tag == "dns_local" {
			servers[i] = map[string]any{
				"tag":         "dns_local",
				"type":        "udp",
				"server":      "127.0.0.1",
				"server_port": dnsPort,
			}
			updated = true
			break
		}
	}

	if !updated {
		return rawJSON, nil
	}
	dnsMap["servers"] = servers
	// 当本机 AdGuard Home 接管 DNS 时，关闭 sing-box 侧的重复 DNS 缓存、乐观缓存与磁盘持久化，
	// 完全交由 AdGuard Home (127.0.0.1:5353) 集中管理缓存与乐观刷新，防止双层缓存死锁。
	dnsMap["disable_cache"] = true
	dnsMap["optimistic"] = false

	if expMap, ok := root["experimental"].(map[string]any); ok {
		if cfMap, ok := expMap["cache_file"].(map[string]any); ok {
			cfMap["store_dns"] = false
			cfMap["store_fakeip"] = false
		}
	}

	log.Info("已将 sing-box dns_local 指向本地 AdGuard Home (127.0.0.1:%d)，并交由 AdGuard Home 统一管理 DNS 缓存", dnsPort)

	data, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config JSON after local DNS injection: %w", err)
	}
	return string(data), nil
}

// InjectCustomRules 将 singctl.yaml 中声明的 custom_rules（出站组定制、DNS 规则、路由规则）
// 注入到生成的 sing-box 配置中，从而在不污染通用 singgen 模板的前提下实现高可维护性的策略扩展。
func (g *ConfigGenerator) InjectCustomRules(rawJSON string) (string, error) {
	if g.config == nil || g.config.CustomRules.IsEmpty() {
		return rawJSON, nil
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", fmt.Errorf("failed to parse config JSON for custom rules: %w", err)
	}

	// 1. 注入出站策略组定制与过滤 (custom_rules.outbounds)
	if len(g.config.CustomRules.Outbounds) > 0 {
		if err := applyCustomOutboundRules(root, g.config.CustomRules.Outbounds); err != nil {
			return "", err
		}
	}

	// 2. 编译设备审计黑名单规则 (custom_rules.block)，作为最高优先级阻断规则注入
	blockDNS, blockRoute := CompileBlockRules(g.config.CustomRules.Block)

	// 3. 注入 DNS 规则 (custom_rules.block + custom_rules.dns)
	allDNS := append(blockDNS, g.config.CustomRules.DNS...)
	if len(allDNS) > 0 {
		applyCustomDNSRules(root, allDNS)
	}

	// 4. 注入路由规则 (custom_rules.block + custom_rules.route)
	allRoute := append(blockRoute, g.config.CustomRules.Route...)
	if len(allRoute) > 0 {
		applyCustomRouteRules(root, allRoute)
	}

	data, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config JSON with custom rules: %w", err)
	}
	return string(data), nil
}

// NormalizeBlockTarget 规范化拉黑目标（去除协议头、端口、首尾通配符与空格），并判定其是否为 IP/CIDR。
func NormalizeBlockTarget(raw string) (cleaned string, isIPOrCIDR bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimSuffix(s, "^")
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		// 保留合法 CIDR，剥离 URL 路径
		if _, _, err := net.ParseCIDR(s); err == nil {
			return s, true
		}
		s = s[:idx]
	}
	// 若包含端口 (host:port) 则剥离端口
	if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
		s = h
	}
	s = strings.Trim(s, "[]")
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", false
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String() + "/32", true
		}
		return ip.String() + "/128", true
	}
	if _, ipNet, err := net.ParseCIDR(s); err == nil && ipNet != nil {
		return ipNet.String(), true
	}
	return s, false
}

// NormalizeSourceIPCIDR 将可选的内网源设备 IP 规范化为 CIDR 表达式（如 192.168.1.55 -> 192.168.1.55/32）。
func NormalizeSourceIPCIDR(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if _, ipNet, err := net.ParseCIDR(s); err == nil && ipNet != nil {
		return ipNet.String()
	}
	if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
		s = h
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String() + "/32"
		}
		return ip.String() + "/128"
	}
	return ""
}

// CompileBlockRules 将语义化 BlockRule 列表编译为 sing-box 原生 DNS 阻断规则与路由阻断规则。
// 按 source_ip_cidr 分组聚合，保证生成的 JSON 紧凑、高效且完全符合 sing-box v1.12+/v1.14 规范。
func CompileBlockRules(blocks []config.BlockRule) (dnsRules []map[string]any, routeRules []map[string]any) {
	if len(blocks) == 0 {
		return nil, nil
	}

	type groupBucket struct {
		sourceCIDR string
		domains    []string
		ipCIDRs    []string
	}
	var groups []*groupBucket
	bySource := make(map[string]*groupBucket)

	for _, b := range blocks {
		target, isIP := NormalizeBlockTarget(b.Target)
		if target == "" {
			continue
		}
		srcCIDR := NormalizeSourceIPCIDR(b.SourceIP)
		bucket, ok := bySource[srcCIDR]
		if !ok {
			bucket = &groupBucket{sourceCIDR: srcCIDR}
			bySource[srcCIDR] = bucket
			groups = append(groups, bucket)
		}
		if isIP {
			if !slices.Contains(bucket.ipCIDRs, target) {
				bucket.ipCIDRs = append(bucket.ipCIDRs, target)
			}
		} else {
			if !slices.Contains(bucket.domains, target) {
				bucket.domains = append(bucket.domains, target)
			}
		}
	}

	for _, g := range groups {
		if len(g.domains) > 0 {
			dr := map[string]any{
				"action":        "reject",
				"domain_suffix": g.domains,
			}
			rr := map[string]any{
				"action":        "reject",
				"domain_suffix": g.domains,
			}
			if g.sourceCIDR != "" {
				dr["source_ip_cidr"] = []string{g.sourceCIDR}
				rr["source_ip_cidr"] = []string{g.sourceCIDR}
			}
			dnsRules = append(dnsRules, dr)
			routeRules = append(routeRules, rr)
		}
		if len(g.ipCIDRs) > 0 {
			rr := map[string]any{
				"action":  "reject",
				"ip_cidr": g.ipCIDRs,
			}
			if g.sourceCIDR != "" {
				rr["source_ip_cidr"] = []string{g.sourceCIDR}
			}
			routeRules = append(routeRules, rr)
		}
	}
	return dnsRules, routeRules
}

// SyncBlockRulesInConfigJSON 在不重新拉取远程订阅的前提下，对现有 sing-box config.json 原地幂等同步黑名单阻断规则。
func SyncBlockRulesInConfigJSON(rawJSON string, oldBlocks, newBlocks []config.BlockRule) (string, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", fmt.Errorf("failed to parse config.json: %w", err)
	}

	oldDNS, oldRoute := CompileBlockRules(oldBlocks)
	newDNS, newRoute := CompileBlockRules(newBlocks)

	// 先从现有规则集中剔除旧的或重复的受管 block 规则
	removeMatchingRules(root, "dns", append(oldDNS, newDNS...))
	removeMatchingRules(root, "route", append(oldRoute, newRoute...))

	// 再注入最新的受管 block 规则
	if len(newDNS) > 0 {
		applyCustomDNSRules(root, newDNS)
	}
	if len(newRoute) > 0 {
		applyCustomRouteRules(root, newRoute)
	}

	data, err := json.Marshal(root)
	if err != nil {
		return "", err
	}
	return PrettyJSON(string(data))
}

func removeMatchingRules(root map[string]any, section string, toRemove []map[string]any) {
	if len(toRemove) == 0 {
		return
	}
	secMap, ok := root[section].(map[string]any)
	if !ok {
		return
	}
	existing, ok := secMap["rules"].([]any)
	if !ok || len(existing) == 0 {
		return
	}
	signatures := make(map[string]struct{}, len(toRemove))
	for _, r := range toRemove {
		if b, err := json.Marshal(r); err == nil {
			signatures[string(b)] = struct{}{}
		}
	}
	kept := make([]any, 0, len(existing))
	for _, item := range existing {
		if b, err := json.Marshal(item); err == nil {
			if _, hit := signatures[string(b)]; hit {
				continue
			}
		}
		kept = append(kept, item)
	}
	secMap["rules"] = kept
}

func applyCustomOutboundRules(root map[string]any, rules []config.OutboundRule) error {
	rawOutbounds, ok := root["outbounds"].([]any)
	if !ok || len(rawOutbounds) == 0 {
		return nil
	}

	// 收集所有底层代理节点 tag，供 custom_rules.outbounds 中使用 "{all}" 展开
	var allLeafTags []string
	for _, item := range rawOutbounds {
		obMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := obMap["tag"].(string)
		obType, _ := obMap["type"].(string)
		if tag == "" {
			continue
		}
		switch obType {
		case "selector", "urltest", "direct", "block", "dns":
			continue
		default:
			allLeafTags = append(allLeafTags, tag)
		}
	}

	for idx, rule := range rules {
		targetTag := strings.TrimSpace(rule.Tag)
		if targetTag == "" {
			return fmt.Errorf("custom_rules.outbounds[%d]: tag is required", idx)
		}

		var includeRe, excludeRe *regexp.Regexp
		var err error
		if rule.Include != "" {
			includeRe, err = regexp.Compile(rule.Include)
			if err != nil {
				return fmt.Errorf("custom_rules.outbounds[%d] (%s): invalid include regex %q: %w", idx, targetTag, rule.Include, err)
			}
		}
		if rule.Exclude != "" {
			excludeRe, err = regexp.Compile(rule.Exclude)
			if err != nil {
				return fmt.Errorf("custom_rules.outbounds[%d] (%s): invalid exclude regex %q: %w", idx, targetTag, rule.Exclude, err)
			}
		}

		var targetMap map[string]any
		for _, item := range rawOutbounds {
			obMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if tag, _ := obMap["tag"].(string); tag == targetTag {
				targetMap = obMap
				break
			}
		}
		if targetMap == nil {
			log.Warn("custom_rules.outbounds: 未找到目标出站组 [%s]，已跳过", targetTag)
			continue
		}

		// 确定基础候选节点列表
		var candidates []string
		if len(rule.Outbounds) > 0 {
			for _, o := range rule.Outbounds {
				if o == "{all}" {
					candidates = append(candidates, allLeafTags...)
				} else if o != "" {
					candidates = append(candidates, o)
				}
			}
		} else if existing, ok := targetMap["outbounds"].([]any); ok {
			for _, item := range existing {
				if s, ok := item.(string); ok && s != "" {
					candidates = append(candidates, s)
				}
			}
		} else if existingStrs, ok := targetMap["outbounds"].([]string); ok {
			candidates = append(candidates, existingStrs...)
		}

		// 执行 include / exclude 正则过滤（带零节点防断网回退保护）
		finalMembers := candidates
		if (includeRe != nil || excludeRe != nil) && len(candidates) > 0 {
			filtered := make([]string, 0, len(candidates))
			for _, name := range candidates {
				if excludeRe != nil && excludeRe.MatchString(name) {
					continue
				}
				if includeRe != nil && !includeRe.MatchString(name) {
					continue
				}
				filtered = append(filtered, name)
			}
			if len(filtered) > 0 {
				finalMembers = filtered
				log.Info("自定义出站组 [%s] 节点过滤已生效: 保留 %d 个，剔除 %d 个", targetTag, len(filtered), len(candidates)-len(filtered))
			} else {
				log.Warn("⚠️ 自定义出站组 [%s] 过滤规则未匹配到任何节点，已自动回退保留原节点池 (%d 个)", targetTag, len(candidates))
			}
		}

		if len(rule.Outbounds) > 0 || includeRe != nil || excludeRe != nil {
			memberAny := make([]any, len(finalMembers))
			for i, m := range finalMembers {
				memberAny[i] = m
			}
			targetMap["outbounds"] = memberAny

			// 若原 default 节点被过滤剔除，自动修正避免 sing-box 校验失败
			if defTag, ok := targetMap["default"].(string); ok && defTag != "" && len(finalMembers) > 0 {
				foundDef := false
				for _, m := range finalMembers {
					if m == defTag {
						foundDef = true
						break
					}
				}
				if !foundDef {
					targetMap["default"] = finalMembers[0]
				}
			}
		}

		if rule.URL != "" {
			targetMap["url"] = rule.URL
		}
		if rule.Interval != "" {
			targetMap["interval"] = rule.Interval
		}
		if rule.Tolerance > 0 {
			targetMap["tolerance"] = rule.Tolerance
		}
		if rule.InterruptExistConnections != nil {
			targetMap["interrupt_exist_connections"] = *rule.InterruptExistConnections
		}
		if rule.Default != "" {
			foundDef := false
			for _, m := range finalMembers {
				if m == rule.Default {
					foundDef = true
					break
				}
			}
			if foundDef || len(finalMembers) == 0 {
				targetMap["default"] = rule.Default
			} else {
				log.Warn("custom_rules.outbounds [%s]: 指定的 default=%q 不在候选节点池中，已忽略", targetTag, rule.Default)
			}
		}
	}

	return nil
}

func applyCustomDNSRules(root map[string]any, customDNS []map[string]any) {
	dnsMap, ok := root["dns"].(map[string]any)
	if !ok {
		return
	}
	var existingRules []any
	if r, ok := dnsMap["rules"].([]any); ok {
		existingRules = r
	}

	// 插入在 clash_mode 与 dns_tailscale 基础规则之后、所有业务/GeoSite 规则之前
	insertIdx := 0
	for i, r := range existingRules {
		rMap, ok := r.(map[string]any)
		if !ok {
			continue
		}
		_, hasClashMode := rMap["clash_mode"]
		srv, _ := rMap["server"].(string)
		if hasClashMode || srv == "dns_tailscale" {
			insertIdx = i + 1
		}
	}

	newRules := make([]any, 0, len(existingRules)+len(customDNS))
	newRules = append(newRules, existingRules[:insertIdx]...)
	for _, r := range customDNS {
		newRules = append(newRules, r)
	}
	newRules = append(newRules, existingRules[insertIdx:]...)
	dnsMap["rules"] = newRules
}

func applyCustomRouteRules(root map[string]any, customRoute []map[string]any) {
	routeMap, ok := root["route"].(map[string]any)
	if !ok {
		return
	}
	var existingRules []any
	if r, ok := routeMap["rules"].([]any); ok {
		existingRules = r
	}

	// 优先定位在广告拦截规则 (geosite-ad1) 之前插入（即处于私网/SSH/ClashMode/geosite-hok 之后，
	// 广告拦截与所有 GeoIP/GeoSite 大集合规则之前）；若无 geosite-ad1 则回退到 ip_is_private 之后。
	insertIdx := -1
	privateIdx := -1
	for i, r := range existingRules {
		rMap, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if _, hasPrivate := rMap["ip_is_private"]; hasPrivate && privateIdx < 0 {
			privateIdx = i + 1
		}
		if ruleSetContains(rMap["rule_set"], "geosite-ad1") {
			insertIdx = i
			break
		}
	}
	if insertIdx < 0 {
		if privateIdx >= 0 {
			insertIdx = privateIdx
		} else {
			insertIdx = len(existingRules)
		}
	}

	newRules := make([]any, 0, len(existingRules)+len(customRoute))
	newRules = append(newRules, existingRules[:insertIdx]...)
	for _, r := range customRoute {
		newRules = append(newRules, r)
	}
	newRules = append(newRules, existingRules[insertIdx:]...)
	routeMap["rules"] = newRules
}

func ruleSetContains(raw any, target string) bool {
	switch v := raw.(type) {
	case string:
		return v == target
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == target {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == target {
				return true
			}
		}
	}
	return false
}

// generateSingleSubscription 处理单个订阅
func (g *ConfigGenerator) generateSingleSubscription(ctx context.Context, dnsServer, platform string) (string, error) {
	sub := g.config.Subs[0]
	log.Info("Platform for singgen:%s", platform)
	authKey, lanIpcidr := "", ""
	clientSubnet := ""
	webui := g.webuiForPlatform(platform)
	if platform != PlatformIOS {
		authKey, lanIpcidr = g.getTailScaleParmas()
		clientSubnet = g.getSubnetFromIP(dnsServer)
	}

	handler := newSubLogHandler()
	logger := slog.New(handler)

	opts := []singgen.Option{
		singgen.WithTemplate(g.defaultTplVer),
		singgen.WithPlatform(platform),
		singgen.WithOutputFormat("json"),
		singgen.WithDNSServer(dnsServer),
		singgen.WithExternalController(webui),
		singgen.WithClientSubnet(clientSubnet),
		singgen.WithMirrorURL(g.config.GitHub.MirrorURL),
		singgen.WithEmojiRemoval(sub.RemoveEmoji),
		singgen.WithBandwidthParams(g.config.Hy2.Up, g.config.Hy2.Down),
		singgen.WithTSAuthKey(authKey),
		singgen.WithTSLanIPCIDR(lanIpcidr),
		singgen.WithLogger(logger),
	}
	if g.cacheDir != "" {
		opts = append(opts, singgen.WithCacheDir(g.cacheDir))
	}

	var configBytes []byte
	var err error
	if hasSubNodeRules(sub) {
		filterParser, ruleErr := newRuleFilteringParser(sub, logger)
		if ruleErr != nil {
			return "", fmt.Errorf("failed to generate single subscription config (订阅 [%s]): %w", sub.Name, ruleErr)
		}
		pipeline := singgen.NewPipeline(
			singgen.WithPipelineOptions(opts...),
			singgen.WithCustomParser(filterParser),
		)
		configBytes, err = pipeline.ExecuteBytes(ctx, sub.URL)
	} else {
		configBytes, err = singgen.GenerateConfigBytes(ctx, sub.URL, opts...)
	}

	if err != nil {
		return "", fmt.Errorf("failed to generate single subscription config (订阅 [%s]): %w", sub.Name, err)
	}

	return string(configBytes), nil
}

func (g *ConfigGenerator) getTailScaleParmas() (string, string) {

	// 如果不开启内置tailscale则返回空.singgen就不会生成tailscale配置
	if !g.config.Tailscale.UseBuild {
		return "", ""
	}

	subnet := ""
	if g.config.Tailscale.AuthKey != "" {

		s := g.config.Tailscale.Subnets
		err := errors.New("")
		if s == "" {
			s, err = netinfo.GetLANSubnet()
		}
		if err == nil {
			subnet = s
		}
	}
	return g.config.Tailscale.AuthKey, subnet
}

// generateMultiSubscription 处理多订阅
func (g *ConfigGenerator) generateMultiSubscription(ctx context.Context, dnsServer, platform string) (string, error) {
	// 构建多订阅配置
	authKey, lanIpcidr := "", ""
	clientSubnet := ""
	webui := g.webuiForPlatform(platform)
	if platform != PlatformIOS {
		authKey, lanIpcidr = g.getTailScaleParmas()
		clientSubnet = g.getSubnetFromIP(dnsServer)
	}

	multiConfig := &singgen.MultiConfig{
		Global: singgen.GlobalConfig{
			Template:       g.defaultTplVer,
			Platform:       platform,
			MirrorURL:      g.config.GitHub.MirrorURL,
			DNSLocalServer: dnsServer,
			WebUIAddress:   webui,
			ClientSubnet:   clientSubnet,
			RemoveEmoji:    false, // 全局默认不移除，由各订阅控制
			SkipTLSVerify:  false,
			HTTPTimeout:    30 * time.Second,
			Format:         "json",
			UpMbps:         g.config.Hy2.Up,
			DownMbps:       g.config.Hy2.Down,
			TSAuthKey:      authKey,
			TSLanIPCIDR:    lanIpcidr,
		},
		Subscriptions: make([]singgen.SubscriptionConfig, 0, len(g.config.Subs)),
	}

	log.Info("Platform for singgen:%s", platform)

	// 添加所有订阅
	for _, sub := range g.config.Subs {
		removeEmoji := sub.RemoveEmoji
		skipTLS := sub.SkipTlsVerify
		subConfig := singgen.SubscriptionConfig{
			Name:          sub.Name,
			URL:           sub.URL,
			RemoveEmoji:   &removeEmoji, // 每个订阅独立控制emoji
			SkipTLSVerify: &skipTLS,     // 使用订阅的skip_tls_verify设置
		}
		if sub.Include != "" {
			inc := sub.Include
			subConfig.Include = &inc
		}
		if sub.Exclude != "" {
			exc := sub.Exclude
			subConfig.Exclude = &exc
		}
		if len(sub.Rename) > 0 {
			renames := make([]singgen.RenameRule, len(sub.Rename))
			for i, rr := range sub.Rename {
				renames[i] = singgen.RenameRule{Match: rr.Match, Replace: rr.Replace}
			}
			subConfig.Rename = renames
		}
		multiConfig.Subscriptions = append(multiConfig.Subscriptions, subConfig)
	}

	handler := newSubLogHandler()
	logger := slog.New(handler)

	multiOpts := []singgen.Option{singgen.WithLogger(logger)}
	if g.cacheDir != "" {
		multiOpts = append(multiOpts, singgen.WithCacheDir(g.cacheDir))
	}

	// 生成配置
	configData, err := singgen.GenerateConfigBytesFromMulti(ctx, multiConfig, multiOpts...)
	if err != nil {
		handler.mu.Lock()
		defer handler.mu.Unlock()
		if len(handler.failedSubs) > 0 {
			var details []string
			for _, sub := range g.config.Subs {
				if reason, ok := handler.failedSubs[sub.Name]; ok {
					details = append(details, fmt.Sprintf("- 订阅 [%s]: %s", sub.Name, reason))
				}
			}
			return "", fmt.Errorf("所有订阅均未获取到有效节点，配置生成终止。失败详情:\n%s", strings.Join(details, "\n"))
		}
		return "", fmt.Errorf("failed to generate multi-subscription config: %w", err)
	}

	return string(configData), nil
}

type subLogHandler struct {
	mu          sync.Mutex
	failedSubs  map[string]string // sub name -> failure reason
	successSubs map[string]int    // sub name -> node count
}

func newSubLogHandler() *subLogHandler {
	return &subLogHandler{
		failedSubs:  make(map[string]string),
		successSubs: make(map[string]int),
	}
}

func (h *subLogHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *subLogHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := make(map[string]any)
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})

	name, _ := attrs["name"].(string)

	h.mu.Lock()
	defer h.mu.Unlock()

	switch r.Message {
	case "Processing subscription":
		url, _ := attrs["url"].(string)
		log.Info("正在解析订阅 [%s] (%s)...", name, url)
	case "Failed to parse subscription":
		errVal := attrs["error"]
		errStr := fmt.Sprintf("%v", errVal)
		h.failedSubs[name] = errStr
		log.Warn("订阅 [%s] 获取或解析失败 (原因: %v)，已跳过该订阅", name, errVal)
	case "No nodes found in subscription":
		h.failedSubs[name] = "未获取到有效节点"
		log.Warn("订阅 [%s] 未获取到有效节点，已跳过该订阅", name)
	case "Node rules applied":
		dropped := attrInt(attrs, "dropped")
		kept := attrInt(attrs, "kept")
		log.Info("订阅 [%s] 节点过滤规则已生效: 保留 %d 个，剔除 %d 个", name, kept, dropped)
	case "All nodes were filtered out by node rules":
		h.failedSubs[name] = "所有节点均被过滤规则剔除"
		log.Warn("订阅 [%s] 所有节点均被过滤规则剔除，已跳过该订阅", name)
	case "Failed to transform nodes":
		errVal := attrs["error"]
		errStr := fmt.Sprintf("节点转换失败: %v", errVal)
		h.failedSubs[name] = errStr
		log.Warn("订阅 [%s] 节点转换失败 (原因: %v)，已跳过该订阅", name, errVal)
	case "Successfully processed subscription":
		nodeCount := attrInt(attrs, "node_count")
		outboundCount := attrInt(attrs, "outbound_count")
		h.successSubs[name] = nodeCount
		log.Success("订阅 [%s] 成功解析 %d 个有效节点 (生成 %d 个出站)", name, nodeCount, outboundCount)
	case "Removed duplicate nodes across subscriptions":
		removed := attrInt(attrs, "removed")
		log.Info("跨订阅节点去重: 已移除 %d 个重复节点", removed)
	case "Merged all subscriptions":
		total := attrInt(attrs, "total_outbounds")
		log.Info("所有可用订阅合并完成，有效出站节点总计: %d 个", total)
	case "Subscription usage":
		u, _ := attrs["url"].(string)
		used, _ := attrs["used"].(string)
		total, _ := attrs["total"].(string)
		remaining, _ := attrs["remaining"].(string)
		expire, _ := attrs["expire"].(string)
		summary := fmt.Sprintf("已用 %s", used)
		if total != "" {
			summary += fmt.Sprintf(" / 总计 %s (剩余 %s)", total, remaining)
		}
		if expire != "" {
			summary += fmt.Sprintf(", 到期 %s", expire)
		}
		log.Info("订阅用量 (%s): %s", u, summary)
	case "Subscription traffic is running low":
		u, _ := attrs["url"].(string)
		remaining, _ := attrs["remaining"].(string)
		total, _ := attrs["total"].(string)
		log.Warn("⚠️ 订阅流量即将耗尽 (%s): 剩余 %s / 总计 %s", u, remaining, total)
	case "Subscription has expired":
		u, _ := attrs["url"].(string)
		expire, _ := attrs["expire"].(string)
		log.Warn("⚠️ 订阅已过期 (%s): 到期日 %s", u, expire)
	case "Subscription expires soon":
		u, _ := attrs["url"].(string)
		expire, _ := attrs["expire"].(string)
		log.Warn("⚠️ 订阅即将到期 (%s): 到期日 %s", u, expire)
	case "Subscription fetch failed, using cached copy":
		u, _ := attrs["url"].(string)
		age, _ := attrs["age"].(string)
		errVal := attrs["error"]
		log.Warn("⚠️ 订阅拉取失败 (%s)，已回退使用本地缓存副本 (缓存距今 %s, 原因: %v)", u, age, errVal)
	}

	return nil
}

func attrInt(attrs map[string]any, key string) int {
	switch v := attrs[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	default:
		return 0
	}
}

func hasSubNodeRules(sub config.Subscription) bool {
	return sub.Include != "" || sub.Exclude != "" || len(sub.Rename) > 0
}

type compiledRenameRule struct {
	re      *regexp.Regexp
	replace string
}

type ruleFilteringParser struct {
	base    singgen.ContextParser
	subName string
	include *regexp.Regexp
	exclude *regexp.Regexp
	rename  []compiledRenameRule
	logger  *slog.Logger
}

func newRuleFilteringParser(sub config.Subscription, logger *slog.Logger) (*ruleFilteringParser, error) {
	p := &ruleFilteringParser{
		base:    singgen.NewContextParser(singgen.GenerateOptions{Logger: logger}),
		subName: sub.Name,
		logger:  logger,
	}
	var err error
	if sub.Include != "" {
		p.include, err = regexp.Compile(sub.Include)
		if err != nil {
			return nil, fmt.Errorf("%w: subscription %q include %q: %v", singgen.ErrInvalidNodeRule, sub.Name, sub.Include, err)
		}
	}
	if sub.Exclude != "" {
		p.exclude, err = regexp.Compile(sub.Exclude)
		if err != nil {
			return nil, fmt.Errorf("%w: subscription %q exclude %q: %v", singgen.ErrInvalidNodeRule, sub.Name, sub.Exclude, err)
		}
	}
	for i, rr := range sub.Rename {
		if rr.Match == "" {
			continue
		}
		re, err := regexp.Compile(rr.Match)
		if err != nil {
			return nil, fmt.Errorf("%w: subscription %q rename[%d] %q: %v", singgen.ErrInvalidNodeRule, sub.Name, i, rr.Match, err)
		}
		p.rename = append(p.rename, compiledRenameRule{re: re, replace: rr.Replace})
	}
	return p, nil
}

func (p *ruleFilteringParser) DetectFormat(ctx context.Context, data []byte) string {
	return p.base.DetectFormat(ctx, data)
}

func (p *ruleFilteringParser) Parse(ctx context.Context, data []byte) ([]model.Node, error) {
	return p.ParseWithHint(ctx, data, "")
}

func (p *ruleFilteringParser) ParseWithHint(ctx context.Context, data []byte, formatHint string) ([]model.Node, error) {
	nodes, err := p.base.ParseWithHint(ctx, data, formatHint)
	if err != nil || len(nodes) == 0 {
		return nodes, err
	}

	kept := make([]model.Node, 0, len(nodes))
	for _, node := range nodes {
		name := node.Tag
		if name == "" {
			name = node.Addr
		}
		if p.exclude != nil && p.exclude.MatchString(name) {
			continue
		}
		if p.include != nil && !p.include.MatchString(name) {
			continue
		}
		for _, rr := range p.rename {
			name = rr.re.ReplaceAllString(name, rr.replace)
		}
		node.Tag = name
		kept = append(kept, node)
	}

	dropped := len(nodes) - len(kept)
	if dropped > 0 && p.logger != nil {
		p.logger.Info("Node rules applied", "name", p.subName, "dropped", dropped, "kept", len(kept))
	}
	if len(kept) == 0 && p.logger != nil {
		p.logger.Warn("All nodes were filtered out by node rules", "name", p.subName)
	}
	return kept, nil
}

func (h *subLogHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

func (h *subLogHandler) WithGroup(_ string) slog.Handler {
	return h
}

func (g *ConfigGenerator) GetWebUIAddress() string {
	return g.webui
}

// DeduplicateOutbounds 对 sing-box JSON 配置中的 outbounds 进行去重。
//   - Tag 相同且内容完全相同 → 丢弃（完全重复）
//   - Tag 相同但内容不同     → 重命名为 tag_1, tag_2...（冲突保留）
//   - 无 tag 字段的节点      → 直接保留（不参与去重）
func DeduplicateOutbounds(jsonStr string) (string, error) {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return "", fmt.Errorf("dedup: invalid JSON: %w", err)
	}

	rawOutbounds, ok := cfg["outbounds"]
	if !ok {
		return jsonStr, nil // 没有 outbounds 字段，原样返回
	}
	outbounds, ok := rawOutbounds.([]any)
	if !ok {
		return jsonStr, nil
	}

	// fingerprints: tag → canonical JSON bytes，用于内容比较
	fingerprints := make(map[string]string)
	// counter: originalTag → 冲突计数，用于生成 tag_1, tag_2...
	counter := make(map[string]int)

	clean := make([]any, 0, len(outbounds))

	for _, item := range outbounds {
		node, ok := item.(map[string]any)
		if !ok {
			// 非 map 节点直接保留
			clean = append(clean, item)
			continue
		}

		// 无 tag 节点直接保留（direct/block/dns 等固定出站）
		tagVal, hasTag := node["tag"]
		if !hasTag {
			clean = append(clean, node)
			continue
		}
		tag, ok := tagVal.(string)
		if !ok || tag == "" {
			clean = append(clean, node)
			continue
		}

		// 序列化当前节点为 fingerprint（canonical JSON）
		fp, err := json.Marshal(node)
		if err != nil {
			return "", fmt.Errorf("dedup: marshal node failed: %w", err)
		}
		fpStr := string(fp)

		existingFP, seen := fingerprints[tag]
		switch {
		case !seen:
			// Case A: 第一次出现，记录并保留
			fingerprints[tag] = fpStr
			clean = append(clean, node)
		case existingFP == fpStr:
			// Case B: 完全相同，丢弃重复节点
			log.Info("dedup: dropping exact duplicate outbound tag=%q", tag)
		default:
			// Case C: Tag 相同但内容不同，重命名
			counter[tag]++
			newTag := fmt.Sprintf("%s_%d", tag, counter[tag])
			// 深拷贝节点，避免修改原始 item
			newNode := maps.Clone(node)
			newNode["tag"] = newTag
			newFP, _ := json.Marshal(newNode)
			fingerprints[newTag] = string(newFP)
			log.Info("dedup: renamed conflicting outbound %q → %q", tag, newTag)
			clean = append(clean, newNode)
		}
	}

	cfg["outbounds"] = clean
	result, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("dedup: re-marshal config failed: %w", err)
	}
	return string(result), nil
}

// PrettyJSON 将紧凑 JSON 字符串格式化为缩进可读格式。
func PrettyJSON(jsonStr string) (string, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(jsonStr), "", "  "); err != nil {
		return "", fmt.Errorf("pretty: invalid JSON: %w", err)
	}
	return buf.String(), nil
}

// CheckIOSCompatibility 校验生成的配置是否适合导入 iOS SFI(沙盒环境)。
// 目前检查: rule_set 不能有 type=local 条目 —— 本地绝对路径在 iPhone 沙盒内不可读,
// 会导致 SFI 启动失败; iOS 配置必须保留远程规则集引用。
func CheckIOSCompatibility(jsonStr string) error {
	var cfg struct {
		Route struct {
			RuleSet []struct {
				Type string `json:"type"`
				Tag  string `json:"tag"`
			} `json:"rule_set"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return fmt.Errorf("ios check: invalid JSON: %w", err)
	}
	for _, rs := range cfg.Route.RuleSet {
		if rs.Type == "local" {
			return fmt.Errorf("ios check: 规则集 %q 使用了 type=local, iPhone 沙盒无法读取本地路径, 请用 --platform ios 重新生成(自动保留远程规则集)", rs.Tag)
		}
	}
	return nil
}
