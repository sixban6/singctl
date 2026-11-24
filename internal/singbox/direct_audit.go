// 文件职责：为零订阅「审计模式」(WorkModeAudit) 生成极简纯直连 sing-box 透明嗅探/拦截基础配置，无缝复用统一编译流水线。
package singbox

import (
	"cmp"
	"encoding/json"
	"strings"
)

// generateDirectAuditBase 生成零代理节点、零订阅依赖、兼容 sing-box 1.12~1.14 的纯直连透明审计基础配置 JSON。
// 后续会经由 RunCompilePipeline 自动叠加：自定义黑名单/PCDN 规则集、IPv6 策略、私网 PTR 防环、
// 本地防劫持 DNS (SmartDNS/AdGuard 或加密 DoH 兜底) 以及回环 Clash API 鉴权加固。
func generateDirectAuditBase(dnsServer string) (string, error) {
	dnsAddr := cmp.Or(strings.TrimSpace(dnsServer), "223.5.5.5")
	doc := map[string]any{
		"log": map[string]any{
			"level":     "warn",
			"timestamp": true,
		},
		"experimental": map[string]any{
			"clash_api": map[string]any{
				"external_controller": "127.0.0.1:9090",
			},
		},
		"dns": map[string]any{
			"servers": []map[string]any{
				{
					"tag":         "dns_local",
					"type":        "udp",
					"server":      dnsAddr,
					"server_port": 53,
				},
			},
			"rules":    []any{},
			"final":    "dns_local",
			"strategy": "ipv4_only",
		},
		"inbounds": []map[string]any{
			{
				"type":        "tproxy",
				"tag":         "tproxy-in",
				"listen":      "::",
				"listen_port": 7895,
			},
		},
		"outbounds": []map[string]any{
			{
				"type": "direct",
				"tag":  "direct",
			},
		},
		"route": map[string]any{
			"default_domain_resolver": "dns_local",
			"auto_detect_interface":   true,
			"default_mark":            1,
			"rules": []map[string]any{
				{"action": "sniff"},
				{"protocol": "dns", "action": "hijack-dns"},
				{"ip_is_private": true, "outbound": "direct"},
			},
			"final": "direct",
		},
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
