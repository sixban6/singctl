package singbox

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/sixban6/singgen/pkg/singgen"
	"singctl/internal/config"
	log "singctl/internal/logger"
	"singctl/internal/netinfo"
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

	// 如果只有一个订阅，使用单订阅API
	if len(g.config.Subs) == 1 {
		return g.generateSingleSubscription(ctx, dnsServer)
	}

	// 多订阅使用新的多订阅API
	return g.generateMultiSubscription(ctx, dnsServer)
}

// generateSingleSubscription 处理单个订阅
func (g *ConfigGenerator) generateSingleSubscription(ctx context.Context, dnsServer string) (string, error) {
	sub := g.config.Subs[0]
	log.Info("Platform for singgen:%s", runtime.GOOS)
	// 使用GenerateConfigBytes来直接获取JSON字节
	configBytes, err := singgen.GenerateConfigBytes(ctx, sub.URL,
		singgen.WithTemplate("v1.12"),
		singgen.WithPlatform(runtime.GOOS),
		singgen.WithOutputFormat("json"),
		singgen.WithDNSServer(dnsServer),
		singgen.WithExternalController(g.webui),
		singgen.WithClientSubnet(g.getSubnetFromIP(dnsServer)),
		singgen.WithMirrorURL(g.config.GitHub.MirrorURL),
		singgen.WithEmojiRemoval(sub.RemoveEmoji),
	)

	if err != nil {
		return "", fmt.Errorf("failed to generate single subscription config: %w", err)
	}

	return string(configBytes), nil
}

// generateMultiSubscription 处理多订阅
func (g *ConfigGenerator) generateMultiSubscription(ctx context.Context, dnsServer string) (string, error) {
	// 构建多订阅配置
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
