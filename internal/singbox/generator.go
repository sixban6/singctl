package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"runtime"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	log "singctl/internal/logger"
	"singctl/internal/util/netinfo"

	"github.com/sixban6/singgen/pkg/singgen"
)

type ConfigGenerator struct {
	config        *config.Config
	webui         string
	netInfo       *netinfo.NetInfoResult
	defaultTplVer string
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
	cg := &ConfigGenerator{config: cfg}
	netResult, err := netinfo.Get()
	if err != nil {
		log.Error("error getting netResult: %v", err)
	}
	cg.netInfo = netResult
	cg.webui = getWebUIAddress(netResult.LANIPv4)
	cg.defaultTplVer = "v1.14"
	//log.Info("Network information: %+v", netResult)
	return cg
}

func getWebUIAddress(ipv4 string) string {

	const localhost = "127.0.0.1"
	switch runtime.GOOS {
	case "darwin":
		return fmt.Sprintf("%s:9090", localhost)
	case "linux":
		return fmt.Sprintf("%s:9090", ipv4)
	case "windows":
		return fmt.Sprintf("%s:9090", localhost)
	default:
		return fmt.Sprintf("%s:9090", localhost)
	}
}

func (c *ConfigGenerator) getSubnetFromIP(ip string) string {

	if netinfo.IsPrivateIP(ip) {
		return "202.96.199.1/24" // 如果是私有IP段 subnet直接用上海电信IP
	}
	return fmt.Sprintf("%s/24", ip)
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
			dnsServer = "8.8.8.8" // 默认 DNS
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

	// 注入自定义规则（DNS 与路由）
	withCustomRules, err := g.InjectCustomRules(deduped)
	if err != nil {
		return "", err
	}

	// 格式化为可读 JSON
	return PrettyJSON(withCustomRules)
}

func (g *ConfigGenerator) InjectCustomRules(rawJSON string) (string, error) {
	if g.config == nil || (len(g.config.CustomRules.Route) == 0 && len(g.config.CustomRules.DNS) == 0) {
		return rawJSON, nil
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", fmt.Errorf("failed to parse config JSON for custom rules: %w", err)
	}

	// 注入 DNS 规则
	if len(g.config.CustomRules.DNS) > 0 {
		if dnsMap, ok := root["dns"].(map[string]any); ok {
			var existingRules []any
			if r, ok := dnsMap["rules"].([]any); ok {
				existingRules = r
			}
			newRules := make([]any, 0, len(g.config.CustomRules.DNS)+len(existingRules))
			for _, r := range g.config.CustomRules.DNS {
				newRules = append(newRules, r)
			}
			newRules = append(newRules, existingRules...)
			dnsMap["rules"] = newRules
		}
	}

	// 注入路由规则
	if len(g.config.CustomRules.Route) > 0 {
		if routeMap, ok := root["route"].(map[string]any); ok {
			var existingRules []any
			if r, ok := routeMap["rules"].([]any); ok {
				existingRules = r
			}
			// 找到 private IP 规则之后的位置插入
			insertIdx := 0
			for i, r := range existingRules {
				if rMap, ok := r.(map[string]any); ok {
					if _, hasPrivate := rMap["ip_is_private"]; hasPrivate {
						insertIdx = i + 1
						break
					}
				}
			}
			if insertIdx == 0 {
				insertIdx = len(existingRules)
			}

			newRules := make([]any, 0, len(existingRules)+len(g.config.CustomRules.Route))
			newRules = append(newRules, existingRules[:insertIdx]...)
			for _, r := range g.config.CustomRules.Route {
				newRules = append(newRules, r)
			}
			newRules = append(newRules, existingRules[insertIdx:]...)
			routeMap["rules"] = newRules
		}
	}

	data, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config JSON with custom rules: %w", err)
	}
	return string(data), nil
}

// generateSingleSubscription 处理单个订阅
func (g *ConfigGenerator) generateSingleSubscription(ctx context.Context, dnsServer, platform string) (string, error) {
	sub := g.config.Subs[0]
	log.Info("Platform for singgen:%s", platform)
	authKey, lanIpcidr := "", ""
	webui, clientSubnet := "", ""
	if platform != PlatformIOS {
		authKey, lanIpcidr = g.getTailScaleParmas()
		webui = g.webui
		clientSubnet = g.getSubnetFromIP(dnsServer)
	}

	handler := newSubLogHandler()
	logger := slog.New(handler)

	configBytes, err := singgen.GenerateConfigBytes(ctx, sub.URL,
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
	)

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
	webui, clientSubnet := "", ""
	if platform != PlatformIOS {
		authKey, lanIpcidr = g.getTailScaleParmas()
		webui = g.webui
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
		subConfig := singgen.SubscriptionConfig{
			Name:          sub.Name,
			URL:           sub.URL,
			RemoveEmoji:   &sub.RemoveEmoji,   // 每个订阅独立控制emoji
			SkipTLSVerify: &sub.SkipTlsVerify, // 使用订阅的skip_tls_verify设置
		}
		multiConfig.Subscriptions = append(multiConfig.Subscriptions, subConfig)
	}

	handler := newSubLogHandler()
	logger := slog.New(handler)

	// 生成配置
	configData, err := singgen.GenerateConfigBytesFromMulti(ctx, multiConfig, singgen.WithLogger(logger))
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
	case "Failed to transform nodes":
		errVal := attrs["error"]
		errStr := fmt.Sprintf("节点转换失败: %v", errVal)
		h.failedSubs[name] = errStr
		log.Warn("订阅 [%s] 节点转换失败 (原因: %v)，已跳过该订阅", name, errVal)
	case "Successfully processed subscription":
		nodeCount := 0
		if nc, ok := attrs["node_count"].(int); ok {
			nodeCount = nc
		} else if nc, ok := attrs["node_count"].(int64); ok {
			nodeCount = int(nc)
		}
		outboundCount := 0
		if oc, ok := attrs["outbound_count"].(int); ok {
			outboundCount = oc
		} else if oc, ok := attrs["outbound_count"].(int64); ok {
			outboundCount = int(oc)
		}
		h.successSubs[name] = nodeCount
		log.Success("订阅 [%s] 成功解析 %d 个有效节点 (生成 %d 个出站)", name, nodeCount, outboundCount)
	case "Merged all subscriptions":
		total := 0
		if t, ok := attrs["total_outbounds"].(int); ok {
			total = t
		} else if t, ok := attrs["total_outbounds"].(int64); ok {
			total = int(t)
		}
		log.Info("所有可用订阅合并完成，有效出站节点总计: %d 个", total)
	}

	return nil
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
