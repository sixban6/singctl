// 文件职责：负责客户端运行态安全加固与本地链路适配，包括 Clash API 回环隔离、
// 日志级别收敛、遗留传输协议字段清洗、本地 AdGuard Home DNS 接管及智能分流开关应用。
//
// 架构设计原则：
//   - 单树强类型变换：normalizeClientLogLevelInDoc、hardenClientClashAPIInDoc 与 injectLocalDNSInDoc
//     均直接在 *sboption.Document 上操作，既可供外部导出函数单独调用，也能在编译流水线中零序列化连续复用。
//   - 安全优先（Rule 02/03）：强制控制面监听 127.0.0.1 并生成随机 secret；接入 AdGuard 前必须探活，
//     防止生成指向未启动端口的“断网配置”。
package singbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	log "singctl/internal/logger"
	"singctl/internal/singbox/sboption"
)

func generateRandomClashSecret() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// HardenClientClashAPIInDoc 在强类型配置树上原地收紧非 iOS 客户端控制面暴露面。
func HardenClientClashAPIInDoc(doc *sboption.Document) (bool, error) {
	if doc == nil {
		return false, nil
	}
	sanitizeLegacyTransportProtocolInDoc(doc)

	changed := false
	sharedSecret := ""
	if doc.Experimental != nil && doc.Experimental.ClashAPI != nil {
		ca := doc.Experimental.ClashAPI
		ca.ExternalController = "127.0.0.1:9090"
		ca.ExternalUI = ""
		ca.ExternalUIDownloadURL = ""
		ca.ExternalUIDownloadDetour = ""

		if sec := strings.TrimSpace(ca.Secret); sec != "" {
			sharedSecret = sec
		} else {
			sec, secErr := generateRandomClashSecret()
			if secErr != nil {
				return false, fmt.Errorf("generate clash api secret: %w", secErr)
			}
			ca.Secret = sec
			sharedSecret = sec
		}
		changed = true
	}

	for i := range doc.Services {
		svc := &doc.Services[i]
		if !strings.EqualFold(strings.TrimSpace(svc.Type), "api") {
			continue
		}
		svc.Listen = "127.0.0.1"
		svc.Dashboard = nil
		if sec := strings.TrimSpace(svc.Secret); sec != "" {
			if sharedSecret == "" {
				sharedSecret = sec
			}
		} else {
			if sharedSecret == "" {
				sec, secErr := generateRandomClashSecret()
				if secErr != nil {
					return false, fmt.Errorf("generate api service secret: %w", secErr)
				}
				sharedSecret = sec
			}
			svc.Secret = sharedSecret
		}
		changed = true
	}
	return changed, nil
}

// HardenClientClashAPI 收紧客户端（非 iOS）sing-box 配置的控制平面暴露面：
//   - 将 clash_api.external_controller 固定为 127.0.0.1:9090，禁止局域网明文监听；
//   - 若未设置 secret，则自动注入随机 24 位十六进制密钥，统一由 SingCtl WebUI 鉴权代理访问；
//   - 移除外置 Clash 面板（external_ui*）及 1.14 api service dashboard，节省路由器内存与闪存。
func HardenClientClashAPI(rawJSON, platform string) (string, error) {
	resolved, err := ResolvePlatform(platform)
	if err != nil {
		resolved = strings.ToLower(strings.TrimSpace(platform))
	}
	if resolved == PlatformIOS {
		return rawJSON, nil
	}

	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", fmt.Errorf("failed to parse config JSON for Clash API hardening: %w", err)
	}
	changed, err := HardenClientClashAPIInDoc(doc)
	if err != nil {
		return "", err
	}
	if !changed {
		return rawJSON, nil
	}
	return doc.MarshalCompact()
}

// InjectTrafficRoutingForPlatform 按目标平台将客户端「智能分流开关中心」预设覆盖策略应用到生成配置中。
func (g *ConfigGenerator) InjectTrafficRoutingForPlatform(rawJSON, platform string) (string, error) {
	if g == nil || g.config == nil {
		return rawJSON, nil
	}
	return ApplyTrafficRoutingForPlatform(rawJSON, g.config.TrafficRouting, g.config.CustomRules, platform)
}

// NormalizeClientLogLevelInDoc 在强类型配置树上原地将默认 log.level 从 info 收敛为 warn 并清洗旧协议字段。
func NormalizeClientLogLevelInDoc(doc *sboption.Document) bool {
	if doc == nil {
		return false
	}
	changedRules := sanitizeLegacyTransportProtocolInDoc(doc)
	changedLog := false

	if doc.Log == nil {
		doc.Log = &sboption.LogOptions{
			Disabled:  new(false),
			Level:     "warn",
			Timestamp: new(true),
		}
		changedLog = true
	} else if doc.Log.Disabled == nil || !*doc.Log.Disabled {
		trimmed := strings.ToLower(strings.TrimSpace(doc.Log.Level))
		if trimmed == "" || trimmed == "info" {
			doc.Log.Level = "warn"
			if doc.Log.Timestamp == nil {
				doc.Log.Timestamp = new(true)
			}
			changedLog = true
		}
	}
	return changedRules || changedLog
}

// NormalizeClientLogLevel 将客户端 sing-box 配置中的默认 log.level 从 "info" 收敛为 "warn"。
func NormalizeClientLogLevel(rawJSON string) (string, error) {
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", fmt.Errorf("failed to parse config JSON for log level normalization: %w", err)
	}
	if !NormalizeClientLogLevelInDoc(doc) {
		return rawJSON, nil
	}
	return doc.MarshalCompact()
}

// sanitizeLegacyTransportProtocolInDoc 将路由规则中误写为 `"protocol": "udp"|"tcp"` 的四层传输字段
// 自动修正为 sing-box 标准 `"network": "udp"|"tcp"`，确保 QUIC (UDP 443) 拦截规则 100% 生效。
func sanitizeLegacyTransportProtocolInDoc(doc *sboption.Document) bool {
	if doc == nil || doc.Route == nil || len(doc.Route.Rules) == 0 {
		return false
	}
	return sanitizeRouteRulesTransportProtocol(doc.Route.Rules)
}

func sanitizeRouteRulesTransportProtocol(rules []sboption.RouteRule) bool {
	changed := false
	for i := range rules {
		r := &rules[i]
		if len(r.Rules) > 0 && sanitizeRouteRulesTransportProtocol(r.Rules) {
			changed = true
		}
		if r.Protocol.Len() == 1 {
			lower := strings.ToLower(strings.TrimSpace(r.Protocol.Items[0]))
			if lower == "udp" || lower == "tcp" {
				r.Protocol = sboption.Listable[string]{}
				if r.Network.IsEmpty() {
					r.Network = sboption.ScalarOf(lower)
				}
				changed = true
			}
		}
	}
	return changed
}

func isAdGuardLocalDNSReady(cfg *config.Config, dnsPort int) bool {
	if !adguard.IsInstalled() {
		return false
	}
	if runtime.GOOS == "linux" && !adguard.HasInstalledCheckOverrideForTest() {
		dnsAddr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
		if adguard.ProbeDNS(dnsAddr, 800*time.Millisecond) != nil {
			if err := adguard.NewManager(cfg, "").EnsureHealthy(); err != nil {
				log.Warn("AdGuard Home (%s) 未就绪 (%v)，本次配置回退内置加密 DoH 以保障不断网", dnsAddr, err)
				return false
			}
		}
	}
	return true
}

func isSmartDNSLocalDNSReady(dnsPort int) bool {
	info, err := os.Stat(constant.SmartDNSInstallPath)
	if err != nil || info.IsDir() {
		return false
	}
	dnsAddr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	if err := adguard.ProbeDNS(dnsAddr, 800*time.Millisecond); err != nil {
		log.Warn("SmartDNS (%s) 未就绪 (%v)，本次配置回退内置加密 DoH 以保障不断网", dnsAddr, err)
		return false
	}
	return true
}

func resolveExternalLocalDNSEngine(g *ConfigGenerator, cfg *config.Config, platform string) (engine string, useExternal bool) {
	if platform != "linux" || cfg == nil || !cfg.DNS.IsEnabled() {
		return "", false
	}
	dnsPort := cfg.DNS.GetDNSPort()
	probe := func(eng string) bool {
		if g != nil && g.localDNSProbe != nil {
			return g.localDNSProbe(eng, dnsPort)
		}
		switch eng {
		case constant.DNSEngineAdGuard:
			return isAdGuardLocalDNSReady(cfg, dnsPort)
		case constant.DNSEngineSmartDNS:
			return isSmartDNSLocalDNSReady(dnsPort)
		default:
			return false
		}
	}

	switch cfg.DNS.GetEngine() {
	case constant.DNSEngineAdGuard:
		if probe(constant.DNSEngineAdGuard) {
			return constant.DNSEngineAdGuard, true
		}
		return "", false
	case constant.DNSEngineSmartDNS:
		if probe(constant.DNSEngineSmartDNS) {
			return constant.DNSEngineSmartDNS, true
		}
		return "", false
	default: // auto
		if probe(constant.DNSEngineAdGuard) {
			return constant.DNSEngineAdGuard, true
		}
		if probe(constant.DNSEngineSmartDNS) {
			return constant.DNSEngineSmartDNS, true
		}
		return "", false
	}
}

func injectLocalDNSInDoc(g *ConfigGenerator, doc *sboption.Document, platform string) bool {
	if platform != "linux" || doc == nil || doc.DNS == nil || len(doc.DNS.Servers) == 0 {
		return false
	}
	var cfg *config.Config
	if g != nil {
		cfg = g.config
	}

	if engine, useExternal := resolveExternalLocalDNSEngine(g, cfg, platform); useExternal {
		dnsPort := cfg.DNS.GetDNSPort()
		if !patchDNSLocalInDoc(doc, true, dnsPort, "") {
			return false
		}
		if g == nil || !g.silent {
			if engine == constant.DNSEngineSmartDNS {
				log.Info("已将 sing-box dns_local 指向本地 SmartDNS (127.0.0.1:%d)，并交由 SmartDNS 统一管理 DNS 缓存与测速", dnsPort)
			} else {
				log.Info("已将 sing-box dns_local 指向本地 AdGuard Home (127.0.0.1:%d)，并交由 AdGuard Home 统一管理 DNS 缓存", dnsPort)
			}
		}
		return true
	}

	// 无外部本地 DNS 引擎就绪时：若处于二级级联网关模式则兜底上级私网网关 (sing-box default_mark:1 零环路)，
	// 否则应急升级为纯 IP 加密 DoH 防劫持，并强制 disable_cache=true / optimistic=false / store_dns=false。
	fallbackGW := ""
	if cfg != nil {
		if gw, ok := ExtractCascadedGatewayUpstream(cfg.DNS.Upstreams); ok {
			fallbackGW = gw
		}
	}
	changed := patchDNSLocalInDoc(doc, false, 0, fallbackGW)
	if changed && (g == nil || !g.silent) {
		if fallbackGW != "" {
			log.Info("未检测到就绪的本地 DNS 引擎，已启用上级主路由网关 (%s:53) 应急零断网兜底", fallbackGW)
		} else {
			log.Info("未检测到就绪的本地 DNS 引擎（AdGuard Home / SmartDNS），已启用应急纯 IP 加密 DoH (https://%s/dns-query) 防劫持兜底", defaultFallbackDoHServer)
		}
	}
	return changed
}

// InjectLocalDNS 在 Linux/OpenWrt 客户端网关平台按双引擎策略配置本地 DNS：
// 外部本地引擎（AdGuard Home / SmartDNS）启用且就绪时指向 127.0.0.1:<dns_port>；
// 否则自动升级为纯 IP 加密 DoH 应急兜底，并始终强制 disable_cache=true、optimistic=false、store_dns=false。
func (g *ConfigGenerator) InjectLocalDNS(rawJSON, platform string) (string, error) {
	if g == nil || platform != "linux" {
		return rawJSON, nil
	}

	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", fmt.Errorf("failed to parse config JSON for local DNS injection: %w", err)
	}
	if !injectLocalDNSInDoc(g, doc, platform) {
		return rawJSON, nil
	}
	return doc.MarshalCompact()
}
