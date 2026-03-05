package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"runtime"
	"time"

	"singctl/internal/config"
	log "singctl/internal/logger"
	"singctl/internal/util/netinfo"

	"github.com/sixban6/singgen/pkg/singgen"
)

type ConfigGenerator struct {
	config  *config.Config
	webui   string
	netInfo *netinfo.NetInfoResult
}

func NewConfigGenerator(cfg *config.Config) *ConfigGenerator {
	cg := &ConfigGenerator{config: cfg}
	netResult, err := netinfo.Get()
	if err != nil {
		log.Error("error getting netResult: %v", err)
	}
	cg.netInfo = netResult
	cg.webui = getWebUIAddress(netResult.LANIPv4)
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
	ctx := context.Background()

	// 检查 DNS 服务器是否可用
	var dnsServer string
	if g.netInfo != nil && len(g.netInfo.DNSServers) > 0 {
		dnsServer = g.netInfo.DNSServers[0]
	} else {
		dnsServer = "8.8.8.8" // 默认 DNS
	}

	var (
		raw string
		err error
	)
	// 如果只有一个订阅，使用单订阅API
	if len(g.config.Subs) == 1 {
		raw, err = g.generateSingleSubscription(ctx, dnsServer)
	} else {
		// 多订阅使用新的多订阅API
		raw, err = g.generateMultiSubscription(ctx, dnsServer)
	}
	if err != nil {
		return "", err
	}

	// 统一在此处去重，覆盖单/多订阅两条路径
	return DeduplicateOutbounds(raw)
}

// generateSingleSubscription 处理单个订阅
func (g *ConfigGenerator) generateSingleSubscription(ctx context.Context, dnsServer string) (string, error) {
	sub := g.config.Subs[0]
	log.Info("Platform for singgen:%s", runtime.GOOS)
	authKey, lanIpcidr := g.getTailScaleParmas()

	configBytes, err := singgen.GenerateConfigBytes(ctx, sub.URL,
		singgen.WithTemplate("v1.12"),
		singgen.WithPlatform(runtime.GOOS),
		singgen.WithOutputFormat("json"),
		singgen.WithDNSServer(dnsServer),
		singgen.WithExternalController(g.webui),
		singgen.WithClientSubnet(g.getSubnetFromIP(dnsServer)),
		singgen.WithMirrorURL(g.config.GitHub.MirrorURL),
		singgen.WithEmojiRemoval(sub.RemoveEmoji),
		singgen.WithBandwidthParams(g.config.Hy2.Up, g.config.Hy2.Down),
		singgen.WithTSAuthKey(authKey),
		singgen.WithTSLanIPCIDR(lanIpcidr),
	)

	if err != nil {
		return "", fmt.Errorf("failed to generate single subscription config: %w", err)
	}

	return string(configBytes), nil
}

func (g *ConfigGenerator) getTailScaleParmas() (string, string) {

	// 如果不开启内置tailscale则返回空.singgen就不会生成tailscale配置
	if g.config.Tailscale.UseBuild == false {
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
func (g *ConfigGenerator) generateMultiSubscription(ctx context.Context, dnsServer string) (string, error) {
	// 构建多订阅配置

	authKey, lanIpcidr := g.getTailScaleParmas()

	multiConfig := &singgen.MultiConfig{
		Global: singgen.GlobalConfig{
			Template:       "v1.12",
			Platform:       runtime.GOOS,
			MirrorURL:      g.config.GitHub.MirrorURL,
			DNSLocalServer: dnsServer,
			WebUIAddress:   g.webui,
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

	log.Info("Platform for singgen:%s", runtime.GOOS)

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

	// 生成配置
	configData, err := singgen.GenerateConfigBytesFromMulti(ctx, multiConfig)
	if err != nil {
		return "", fmt.Errorf("failed to generate multi-subscription config: %w", err)
	}

	return string(configData), nil
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
