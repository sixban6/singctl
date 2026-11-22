// 文件职责：sing-box 配置生成器主控入口（ConfigGenerator），负责平台校验、本地基础 DNS 探测、
// 调起单/多订阅拉取并驱动 compile_pipeline.go 中的编译阶段流水线输出最终 JSON。
//
// 架构设计原则（同包高内聚拆文件）：
//   - generator.go（本文件）：核心结构体、平台解析与顶层生成编排；
//   - compile_pipeline.go：OCP 阶段流水线注册表与单树复用文档载体；
//   - generator_subs.go：订阅拉取、节点过滤与出站去重；
//   - generator_rules.go：自定义规则与审计黑名单编译注入；
//   - generator_hardening.go：客户端运行态加固、日志降噪与本地 AdGuard DNS 接管；
//   - ios_adapter.go：iOS SFI 沙盒裁剪与兼容性校验。
package singbox

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"singctl/internal/common/netx"
	"singctl/internal/config"
	log "singctl/internal/logger"

	"github.com/sixban6/singgen/pkg/singgen"
)

// ConfigGenerator 持有配置模板版本、本机网络环境及订阅缓存控制参数。
type ConfigGenerator struct {
	config        *config.Config
	webui         string
	netInfo       *netx.NetInfoResult
	defaultTplVer string
	cacheDir      string
	silent        bool
}

// 支持的目标平台常量。
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

// NewConfigGenerator 初始化 sing-box 配置生成器并探测本机局域网基础网络信息。
func NewConfigGenerator(cfg *config.Config) *ConfigGenerator {
	cg := &ConfigGenerator{
		config:        cfg,
		defaultTplVer: "v1.14",
		cacheDir:      singgen.DefaultCacheDir(),
	}
	netResult, err := netx.Get()
	if err != nil {
		log.Error("error getting netResult: %v", err)
	}
	cg.netInfo = netResult
	var lanIP string
	if netResult != nil {
		lanIP = netResult.LANIPv4
	}
	cg.webui = getWebUIAddress(lanIP)
	return cg
}

// SetCacheDir 覆盖订阅缓存目录（传空字符串可禁用订阅缓存回退，主要用于测试或无状态场景）。
func (g *ConfigGenerator) SetCacheDir(dir string) {
	g.cacheDir = dir
}

// SetSilent 开启静默生成模式（供看门狗后台定时订阅指纹比对调用，避免无变化巡检刷屏守护日志）。
func (g *ConfigGenerator) SetSilent(silent bool) {
	g.silent = silent
}

// NewOfflineConfigGenerator 创建不主动探测宿主机网卡/公网环境的离线配置生成器（供纯内存编译流水线与单测使用）。
func NewOfflineConfigGenerator(cfg *config.Config) *ConfigGenerator {
	return &ConfigGenerator{
		config:        cfg,
		defaultTplVer: "v1.14",
		webui:         "127.0.0.1:9090",
		silent:        true,
	}
}

var sensitiveURLRe = regexp.MustCompile(`https?://[^\s"'<>)\]]+`)

// MaskSensitiveText 将错误消息或文本中可能包含凭据的完整 HTTP(S) URL 脱敏遮蔽。
func MaskSensitiveText(s string) string {
	if s == "" {
		return ""
	}
	return sensitiveURLRe.ReplaceAllStringFunc(s, func(raw string) string {
		if strings.HasPrefix(strings.ToLower(raw), "http://") {
			return "http://******"
		}
		return "https://******"
	})
}

func getWebUIAddress(_ string) string {
	return "127.0.0.1:9090"
}

func (g *ConfigGenerator) webuiForPlatform(platform string) string {
	if platform == PlatformIOS {
		return "127.0.0.1:9095"
	}
	return "127.0.0.1:9090"
}

func (c *ConfigGenerator) getSubnetFromIP(ip string) string {
	return netx.ResolveClientSubnet(context.Background(), ip)
}

func (g *ConfigGenerator) resolveLocalDNSServer(isIOS bool) string {
	if isIOS {
		return ""
	}
	var dnsServer string
	isSideRouter := g.config != nil && g.config.Gateway.IsSideRouter()
	if g.netInfo != nil && len(g.netInfo.DNSServers) > 0 {
		if isSideRouter {
			// 旁路由模式下兜底 dns_local 严禁指向主路由等局域网私网 IP，彻底杜绝主旁 DNS 互指死循环
			for _, cand := range g.netInfo.DNSServers {
				if !netx.IsPrivateIP(cand) {
					dnsServer = cand
					break
				}
			}
		} else {
			dnsServer = g.netInfo.DNSServers[0]
		}
	}
	if dnsServer == "" {
		dnsServer = "223.5.5.5" // 默认国内公共 DNS 兜底
	}
	return dnsServer
}

// Generate 针对当前宿主机操作系统生成完整的 sing-box 配置 JSON。
func (g *ConfigGenerator) Generate() (string, error) {
	return g.GenerateForPlatform(runtime.GOOS)
}

// GenerateForPlatform 生成针对指定目标平台的配置。
// 与桌面端(Linux/macOS/Windows 本机运行)不同, iOS(sing-box 官方 App SFI)有以下平台差异:
//   - DNS/客户端子网不注入探测值, 交给 singgen ios 模板默认(手机离开家庭内网后局域网 DNS 无效)
//   - external_controller 保留模板默认(127.0.0.1:9095, 仅 SFI 沙盒内 loopback 可访问)
//   - 不注入 Tailscale(手机端独立运行官方 App，不启用内置 tailscaled)
func (g *ConfigGenerator) GenerateForPlatform(platform string) (string, error) {
	resolved, err := ResolvePlatform(platform)
	if err != nil {
		return "", err
	}
	if g == nil || g.config == nil || len(g.config.Subs) == 0 {
		return "", errors.New("配置中未找到任何订阅源 (subs 列表为空)")
	}

	ctx := context.Background()
	dnsServer := g.resolveLocalDNSServer(resolved == PlatformIOS)

	var raw string
	if len(g.config.Subs) == 1 {
		raw, err = g.generateSingleSubscription(ctx, dnsServer, resolved)
	} else {
		raw, err = g.generateMultiSubscription(ctx, dnsServer, resolved)
	}
	if err != nil {
		return "", err
	}

	// 交由 compile_pipeline.go 中的可扩展多阶段流水线统一完成加工、加固与格式化输出
	return g.RunCompilePipeline(raw, resolved)
}
