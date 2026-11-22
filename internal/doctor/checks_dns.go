// 文件职责：实现 DNS 防劫持深度体检算子（本地 AdGuard Home/SmartDNS 监听健康、sing-box dns_local 防明文 UDP 53 与 SmartDNS IPv6 策略一致性）。
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"singctl/internal/config"
)

type dnsAntiHijackChecker struct{}

func (dnsAntiHijackChecker) ID() string { return "dns_anti_hijack" }

type dnsLocalInspection struct {
	found          bool
	isPlainUDP53   bool
	isLoopback     bool
	loopbackPort   int
	isEncryptedDoX bool
	desc           string
}

func (dnsAntiHijackChecker) Run(ctx context.Context, env *Env) CheckResult {
	res := CheckResult{
		ID:       "dns_anti_hijack",
		Category: "dns",
		Title:    "DNS 防劫持与 IPv6 策略一致性",
		Status:   StatusPass,
	}

	dnsPort := 5353
	dnsEngine := "auto"
	dnsEnabled := true
	if env.Config != nil {
		dnsPort = env.Config.DNS.GetDNSPort()
		dnsEngine = env.Config.DNS.GetEngine()
		dnsEnabled = env.Config.DNS.IsEnabled()
	}
	ipv6Mode := env.effectiveIPv6Mode()

	localAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort))
	localListening := false
	if dnsEnabled {
		localListening = env.DialTCP(ctx, localAddr) == nil
	}

	var details []string
	var advices []string
	status := StatusPass
	fixAction := ""
	fixLabel := ""

	if localListening {
		details = append(details, fmt.Sprintf("本地防劫持 DNS (%s/%s): 监听正常", dnsEngine, localAddr))
	} else if dnsEnabled {
		details = append(details, fmt.Sprintf("本地防劫持 DNS (%s): 未监听", localAddr))
	} else {
		details = append(details, "本地外部 DNS: 已禁用")
	}

	// 1. 核验 sing-box dns_local 是否存在明文 UDP 53 劫持风险及与本地引擎一致性。
	if rawSB, err := env.ReadFile(env.SingBoxConfigPath); err == nil {
		insp := inspectSingBoxDNSLocal(rawSB)
		if !insp.found {
			status = worstStatus(status, StatusWarn)
			details = append(details, "sing-box 未找到 dns_local 解析器")
			advices = append(advices, "建议重新同步 sing-box 本地 DNS 配置")
			fixAction = "sync-dns-local"
			fixLabel = "一键同步 dns_local"
		} else {
			details = append(details, "dns_local: "+insp.desc)
			switch {
			case insp.isPlainUDP53:
				status = worstStatus(status, StatusFail)
				advices = append(advices, "检测到 dns_local 使用明文 UDP 53，易被运营商劫持或造成透明代理回环死锁，请切换加密 DoH 或本地防劫持引擎")
				fixAction = "sync-dns-local"
				fixLabel = "一键修复 dns_local 防劫持配置"
			case insp.isLoopback && !localListening:
				status = worstStatus(status, StatusFail)
				advices = append(advices, fmt.Sprintf("dns_local 指向 %s 但该本地 DNS 端口未监听，将导致国内域名解析中断", localAddr))
				fixAction = "sync-dns-local"
				fixLabel = "一键切换加密 DoH 兜底"
			case insp.isLoopback && insp.loopbackPort != dnsPort:
				status = worstStatus(status, StatusWarn)
				advices = append(advices, fmt.Sprintf("dns_local 端口 (%d) 与配置的 dns_port (%d) 不一致", insp.loopbackPort, dnsPort))
				fixAction = "sync-dns-local"
				fixLabel = "一键同步 dns_local 端口"
			case insp.isEncryptedDoX && localListening:
				status = worstStatus(status, StatusWarn)
				advices = append(advices, "本地防劫持 DNS 已在线，但 sing-box 仍处于应急 DoH 兜底状态，建议同步接管")
				fixAction = "sync-dns-local"
				fixLabel = "一键接管本地防劫持 DNS"
			}
		}
	} else {
		status = worstStatus(status, StatusWarn)
		details = append(details, "未能读取 sing-box 配置以校验 dns_local")
	}

	// 2. 核验 gateway.ipv6_mode 与 /etc/singctl/smartdns.conf force-AAAA-SOA 一致性。
	if dnsEngine == "smartdns" || dnsEngine == "auto" {
		if rawSD, err := env.ReadFile(env.SmartDNSConfPath); err == nil {
			forceAAAA := parseSmartDNSForceAAAASOA(string(rawSD))
			wantBlockAAAA := ipv6Mode == config.GatewayIPv6Off
			if wantBlockAAAA != forceAAAA {
				status = worstStatus(status, StatusWarn)
				if wantBlockAAAA {
					details = append(details, "SmartDNS 缺少 force-AAAA-SOA yes (与 ipv6_mode=off 不一致)")
					advices = append(advices, "纯 IPv4 模式下 SmartDNS 应开启 force-AAAA-SOA yes 以屏蔽多余 AAAA 解析")
				} else {
					details = append(details, fmt.Sprintf("SmartDNS 残留 force-AAAA-SOA yes (与 ipv6_mode=%s 冲突)", ipv6Mode))
					advices = append(advices, "智能/全局双栈模式下需移除 force-AAAA-SOA yes，否则将阻断国内 IPv6")
				}
				if fixAction == "" {
					fixAction = "sync-smartdns-ipv6"
					fixLabel = "一键同步 SmartDNS IPv6 策略"
				}
			} else {
				details = append(details, fmt.Sprintf("SmartDNS IPv6 策略一致 (ipv6_mode=%s, force-AAAA-SOA=%v)", ipv6Mode, forceAAAA))
			}
		}
	}

	res.Status = status
	res.Detail = strings.Join(details, " | ")
	res.Advice = strings.Join(advices, "；")
	res.FixAction = fixAction
	res.FixLabel = fixLabel

	switch status {
	case StatusFail:
		res.Summary = "DNS 防劫持链路存在严重隐患（明文 UDP 53 或目标本地端口未监听）"
	case StatusWarn:
		res.Summary = "DNS 链路存在策略漂移（SmartDNS IPv6 策略或 dns_local 未同步）"
	default:
		res.Summary = "本地防劫持 DNS、dns_local 与 IPv6 策略全部健康一致"
	}
	return res
}

func inspectSingBoxDNSLocal(rawJSON []byte) dnsLocalInspection {
	var doc struct {
		DNS *struct {
			Servers []struct {
				Tag        string `json:"tag"`
				Type       string `json:"type"`
				Server     string `json:"server"`
				ServerPort int    `json:"server_port"`
				Address    string `json:"address"`
			} `json:"servers"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(rawJSON, &doc); err != nil || doc.DNS == nil {
		return dnsLocalInspection{}
	}

	for _, srv := range doc.DNS.Servers {
		if srv.Tag != "dns_local" {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(srv.Type))
		host := strings.TrimSpace(srv.Server)
		port := srv.ServerPort

		// 兼容 sing-box 1.12+ 强类型字段格式。
		if typ != "" {
			switch typ {
			case "https", "tls", "quic", "h3":
				return dnsLocalInspection{
					found:          true,
					isEncryptedDoX: true,
					desc:           fmt.Sprintf("%s://%s", typ, host),
				}
			case "udp":
				if port == 0 {
					port = 53
				}
				isLoop := isLoopbackHost(host)
				if isLoop && port != 53 {
					return dnsLocalInspection{
						found:        true,
						isLoopback:   true,
						loopbackPort: port,
						desc:         fmt.Sprintf("udp://%s:%d", host, port),
					}
				}
				return dnsLocalInspection{
					found:        true,
					isPlainUDP53: true,
					desc:         fmt.Sprintf("udp://%s:%d (明文)", host, port),
				}
			case "local":
				return dnsLocalInspection{
					found:        true,
					isPlainUDP53: true,
					desc:         "local (明文系统 DNS)",
				}
			default:
				return dnsLocalInspection{found: true, desc: fmt.Sprintf("%s://%s", typ, host)}
			}
		}

		// 兼容旧版 address 字符串格式（如 https://223.5.5.5/dns-query 或 udp://192.0.2.53:53）。
		addr := strings.TrimSpace(srv.Address)
		lowerAddr := strings.ToLower(addr)
		switch {
		case strings.HasPrefix(lowerAddr, "https://"),
			strings.HasPrefix(lowerAddr, "tls://"),
			strings.HasPrefix(lowerAddr, "quic://"),
			strings.HasPrefix(lowerAddr, "h3://"):
			return dnsLocalInspection{found: true, isEncryptedDoX: true, desc: addr}
		case lowerAddr == "local" || lowerAddr == "rcode://success":
			return dnsLocalInspection{found: true, isPlainUDP53: lowerAddr == "local", desc: addr}
		case strings.HasPrefix(lowerAddr, "udp://"):
			u, err := url.Parse(addr)
			if err == nil {
				p := 53
				if ps := u.Port(); ps != "" {
					if v, convErr := strconv.Atoi(ps); convErr == nil {
						p = v
					}
				}
				if isLoopbackHost(u.Hostname()) && p != 53 {
					return dnsLocalInspection{found: true, isLoopback: true, loopbackPort: p, desc: addr}
				}
			}
			return dnsLocalInspection{found: true, isPlainUDP53: true, desc: addr + " (明文)"}
		default:
			// 纯 IP 或 host:port 无协议前缀在 sing-box 中等价于明文 UDP 53。
			return dnsLocalInspection{found: true, isPlainUDP53: true, desc: addr + " (明文)"}
		}
	}
	return dnsLocalInspection{}
}

func isLoopbackHost(host string) bool {
	h := strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func parseSmartDNSForceAAAASOA(raw string) bool {
	enabled := false
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "force-AAAA-SOA") {
			enabled = strings.EqualFold(fields[1], "yes") || fields[1] == "1" || strings.EqualFold(fields[1], "true")
		}
	}
	return enabled
}
