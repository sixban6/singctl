// 文件职责：负责客户端运行态安全加固与本地链路适配，包括 Clash API 回环隔离、
// 日志级别收敛、遗留传输协议字段清洗、本地 AdGuard Home DNS 接管及智能分流开关应用。
//
// 架构设计原则：
//   - 单树复用：normalizeClientLogLevelInRoot 与 hardenClientClashAPIInRoot 等均为纯 JSON 树修改器，
//     既可供外部导出函数单独调用，也能在 compileDoc 编译流水线中零序列化连续复用。
//   - 安全优先（Rule 02/03）：强制控制面监听 127.0.0.1 并生成随机 secret；接入 AdGuard 前必须探活，
//     防止生成指向未启动端口的“断网配置”。
package singbox

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	log "singctl/internal/logger"
)

func generateRandomClashSecret() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// hardenClientClashAPIInRoot 在内存配置树上原地收紧非 iOS 客户端控制面暴露面。
func hardenClientClashAPIInRoot(root map[string]any) (bool, error) {
	if root == nil {
		return false, nil
	}
	sanitizeLegacyTransportProtocolRules(root)

	changed := false
	sharedSecret := ""
	if expMap, ok := root["experimental"].(map[string]any); ok && expMap != nil {
		if clashAPI, ok := expMap["clash_api"].(map[string]any); ok && clashAPI != nil {
			clashAPI["external_controller"] = "127.0.0.1:9090"
			delete(clashAPI, "external_ui")
			delete(clashAPI, "external_ui_download_url")
			delete(clashAPI, "external_ui_download_detour")

			if sec, _ := clashAPI["secret"].(string); strings.TrimSpace(sec) != "" {
				sharedSecret = strings.TrimSpace(sec)
			} else {
				sec, secErr := generateRandomClashSecret()
				if secErr != nil {
					return false, fmt.Errorf("generate clash api secret: %w", secErr)
				}
				clashAPI["secret"] = sec
				sharedSecret = sec
			}
			changed = true
		}
	}

	if services, ok := root["services"].([]any); ok {
		for _, item := range services {
			svc, ok := item.(map[string]any)
			if !ok || svc == nil {
				continue
			}
			typ, _ := svc["type"].(string)
			if strings.EqualFold(strings.TrimSpace(typ), "api") {
				svc["listen"] = "127.0.0.1"
				delete(svc, "dashboard")
				if sec, _ := svc["secret"].(string); strings.TrimSpace(sec) != "" {
					if sharedSecret == "" {
						sharedSecret = strings.TrimSpace(sec)
					}
				} else {
					if sharedSecret == "" {
						sec, secErr := generateRandomClashSecret()
						if secErr != nil {
							return false, fmt.Errorf("generate api service secret: %w", secErr)
						}
						sharedSecret = sec
					}
					svc["secret"] = sharedSecret
				}
				changed = true
			}
		}
	}
	return changed, nil
}

// HardenClientClashAPI 收紧客户端（非 iOS）sing-box 配置的控制平面暴露面：
//   - 将 clash_api.external_controller 固定为 127.0.0.1:9090，禁止局域网明文监听；
//   - 若未设置 secret，则自动注入随机 24 位十六进制密钥，统一由 SingCtl WebUI 鉴权代理访问；
//   - 移除外置 Clash 面板（external_ui*）及 1.14 api service dashboard，节省路由器内存与闪存。
//
// iOS (SFI) 配置保持原样，确保 App 内置控制台兼容。
func HardenClientClashAPI(rawJSON, platform string) (string, error) {
	resolved, err := ResolvePlatform(platform)
	if err != nil {
		resolved = strings.ToLower(strings.TrimSpace(platform))
	}
	if resolved == PlatformIOS {
		return rawJSON, nil
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", fmt.Errorf("failed to parse config JSON for Clash API hardening: %w", err)
	}
	changed, err := hardenClientClashAPIInRoot(root)
	if err != nil {
		return "", err
	}
	if !changed {
		return rawJSON, nil
	}
	data, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config JSON after Clash API hardening: %w", err)
	}
	return string(data), nil
}

// InjectTrafficRoutingForPlatform 按目标平台将客户端「智能分流开关中心」预设覆盖策略应用到生成配置中。
func (g *ConfigGenerator) InjectTrafficRoutingForPlatform(rawJSON, platform string) (string, error) {
	if g == nil || g.config == nil {
		return rawJSON, nil
	}
	return ApplyTrafficRoutingForPlatform(rawJSON, g.config.TrafficRouting, g.config.CustomRules, platform)
}

func normalizeClientLogLevelInRoot(root map[string]any) (bool, error) {
	if root == nil {
		return false, nil
	}
	changedRules := sanitizeLegacyTransportProtocolRules(root)
	changedLog := false

	logMap, ok := root["log"].(map[string]any)
	if !ok || logMap == nil {
		root["log"] = map[string]any{
			"disabled":  false,
			"level":     "warn",
			"timestamp": true,
		}
		changedLog = true
	} else if disabled, _ := logMap["disabled"].(bool); !disabled {
		level, _ := logMap["level"].(string)
		trimmed := strings.TrimSpace(strings.ToLower(level))
		if trimmed == "" || trimmed == "info" {
			logMap["level"] = "warn"
			if _, hasTS := logMap["timestamp"]; !hasTS {
				logMap["timestamp"] = true
			}
			changedLog = true
		}
	}
	return changedRules || changedLog, nil
}

// NormalizeClientLogLevel 将客户端 sing-box 配置中的默认 log.level 从 "info" 收敛为 "warn"，
// 避免路由器网关海量连接/DNS INFO 日志写爆 OpenWrt /tmp (tmpfs) 导致断网，同时保留 warn/error 故障日志。
// 若配置已显式禁用日志或设为非 info 级别（如 debug/warn/error/fatal/panic），则保持原样。
func NormalizeClientLogLevel(rawJSON string) (string, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", fmt.Errorf("failed to parse config JSON for log level normalization: %w", err)
	}
	if root == nil {
		root = make(map[string]any)
	}
	changed, err := normalizeClientLogLevelInRoot(root)
	if err != nil {
		return "", err
	}
	if !changed {
		return rawJSON, nil
	}
	data, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config JSON after log level normalization: %w", err)
	}
	return string(data), nil
}

// sanitizeLegacyTransportProtocolRules 将路由规则中误写为 `"protocol": "udp"|"tcp"` 的四层传输字段
// 自动修正为 sing-box 标准 `"network": "udp"|"tcp"`，确保 QUIC (UDP 443) 拦截规则 100% 生效。
func sanitizeLegacyTransportProtocolRules(root map[string]any) bool {
	if root == nil {
		return false
	}
	routeMap, ok := root["route"].(map[string]any)
	if !ok || routeMap == nil {
		return false
	}
	rules, ok := routeMap["rules"].([]any)
	if !ok || len(rules) == 0 {
		return false
	}
	return sanitizeRuleSliceTransportProtocol(rules)
}

func sanitizeRuleSliceTransportProtocol(rules []any) bool {
	changed := false
	for _, item := range rules {
		rm, ok := item.(map[string]any)
		if !ok || rm == nil {
			continue
		}
		if sub, ok := rm["rules"].([]any); ok && len(sub) > 0 {
			if sanitizeRuleSliceTransportProtocol(sub) {
				changed = true
			}
		}
		if pStr, ok := rm["protocol"].(string); ok {
			lower := strings.ToLower(strings.TrimSpace(pStr))
			if lower == "udp" || lower == "tcp" {
				delete(rm, "protocol")
				if _, hasNet := rm["network"]; !hasNet {
					rm["network"] = lower
				}
				changed = true
			}
		}
	}
	return changed
}

func shouldInjectLocalAdGuardDNS(cfg *config.Config, platform string) bool {
	if platform != "linux" || cfg == nil || !cfg.DNS.IsEnabled() || !adguard.IsInstalled() {
		return false
	}
	dnsPort := cfg.DNS.GetDNSPort()
	// 生产环境（非单测安装桩）下校验 AdGuard Home 本地 DNS 实际可达（未运行时尝试自动拉起），
	// 若拉起仍失败则保留内置加密/直连 dns_local，绝不生成指向死端口的配置导致网关断网。
	if runtime.GOOS == "linux" && !adguard.HasInstalledCheckOverrideForTest() {
		dnsAddr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
		if adguard.ProbeDNS(dnsAddr, 800*time.Millisecond) != nil {
			if err := adguard.NewManager(cfg, "").EnsureHealthy(); err != nil {
				log.Warn("AdGuard Home (%s) 未就绪 (%v)，本次配置保留内置 dns_local 以保障不断网", dnsAddr, err)
				return false
			}
		}
	}
	return true
}

func injectLocalDNSInRoot(g *ConfigGenerator, root map[string]any) bool {
	if g == nil || g.config == nil || root == nil {
		return false
	}
	dnsPort := g.config.DNS.GetDNSPort()

	dnsMap, ok := root["dns"].(map[string]any)
	if !ok {
		return false
	}
	servers, ok := dnsMap["servers"].([]any)
	if !ok {
		return false
	}

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
		return false
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

	if !g.silent {
		log.Info("已将 sing-box dns_local 指向本地 AdGuard Home (127.0.0.1:%d)，并交由 AdGuard Home 统一管理 DNS 缓存", dnsPort)
	}
	return true
}

// InjectLocalDNS 在 Linux/OpenWrt 客户端网关平台且启用并安装了 AdGuard Home 时，
// 将 sing-box 配置中的 dns_local 解析器指向本地 127.0.0.1:<dns_port>（默认 5353）。
// iOS 等移动端配置永远保持原样，不注入本机回环端口。
func (g *ConfigGenerator) InjectLocalDNS(rawJSON, platform string) (string, error) {
	if g == nil || !shouldInjectLocalAdGuardDNS(g.config, platform) {
		return rawJSON, nil
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", fmt.Errorf("failed to parse config JSON for local DNS injection: %w", err)
	}
	if !injectLocalDNSInRoot(g, root) {
		return rawJSON, nil
	}
	data, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config JSON after local DNS injection: %w", err)
	}
	return string(data), nil
}
