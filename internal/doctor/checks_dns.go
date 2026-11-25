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

	"singctl/internal/common/netx"
	"singctl/internal/config"
)

type dnsAntiHijackChecker struct{}

func (dnsAntiHijackChecker) ID() string { return "dns_anti_hijack" }

type dnsLocalInspection struct {
	found             bool
	isUnsafeUDP53     bool
	isSafePublicUDP53 bool
	isLoopback        bool
	loopbackPort      int
	isEncryptedDoX    bool
	desc              string
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
			case insp.isUnsafeUDP53:
				status = worstStatus(status, StatusFail)
				advices = append(advices, "检测到 dns_local 使用本地/私网明文 DNS，存在自环死锁与劫持风险，请切换本地防劫持引擎或安全公网兜底")
				fixAction = "sync-dns-local"
				fixLabel = "一键修复 dns_local 防劫持配置"
			case insp.isLoopback && !localListening:
				status = worstStatus(status, StatusFail)
				advices = append(advices, fmt.Sprintf("dns_local 指向 %s 但该本地 DNS 端口未监听，将导致国内域名解析中断", localAddr))
				fixAction = "sync-dns-local"
				fixLabel = "一键切换安全公网 DNS 兜底"
			case insp.isLoopback && insp.loopbackPort != dnsPort:
				status = worstStatus(status, StatusWarn)
				advices = append(advices, fmt.Sprintf("dns_local 端口 (%d) 与配置的 dns_port (%d) 不一致", insp.loopbackPort, dnsPort))
				fixAction = "sync-dns-local"
				fixLabel = "一键同步 dns_local 端口"
			case (insp.isEncryptedDoX || insp.isSafePublicUDP53) && localListening:
				status = worstStatus(status, StatusWarn)
				advices = append(advices, "本地防劫持 DNS 已在线，但 sing-box 仍处于应急兜底状态，建议同步接管")
				fixAction = "sync-dns-local"
				fixLabel = "一键接管本地防劫持 DNS"
			}
		}
	} else {
		status = worstStatus(status, StatusWarn)
		details = append(details, "未能读取 sing-box 配置以校验 dns_local")
	}

	// 2. 核验 gateway.ipv6_mode 与 /etc/singctl/smartdns.conf force-AAAA-SOA 一致性。
	// 若 dnsEngine=="auto" 且进程探测确认当前活跃本地 DNS 为 AdGuardHome（SmartDNS 未运行），
	// 则跳过历史残留的 smartdns.conf 校验以避免误报。
	if dnsEngine == "smartdns" || dnsEngine == "auto" {
		adguardRunning, smartdnsRunning := detectActiveLocalDNSProcesses(env.ProcRoot)
		if dnsEngine == "auto" && adguardRunning && !smartdnsRunning {
			details = append(details, "当前活跃引擎: AdGuardHome")
		} else if rawSD, err := env.ReadFile(env.SmartDNSConfPath); err == nil {
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

func classifyUDPTarget(host string, port int, descPrefix string) dnsLocalInspection {
	if port <= 0 {
		port = 53
	}
	desc := cmpDesc(descPrefix, fmt.Sprintf("udp://%s:%d", host, port))
	if isLoopbackHost(host) && port != 53 {
		return dnsLocalInspection{
			found:        true,
			isLoopback:   true,
			loopbackPort: port,
			desc:         desc,
		}
	}
	if port == 53 && netx.IsPublicISPUnicastIPv4(net.ParseIP(strings.TrimSpace(host)), nil) {
		return dnsLocalInspection{
			found:             true,
			isSafePublicUDP53: true,
			desc:              desc + " (安全公网 DNS 兜底)",
		}
	}
	return dnsLocalInspection{
		found:         true,
		isUnsafeUDP53: true,
		desc:          desc + " (私网/回环自环风险)",
	}
}

func cmpDesc(prefix, fallback string) string {
	if strings.TrimSpace(prefix) != "" {
		return prefix
	}
	return fallback
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
				return classifyUDPTarget(host, port, "")
			case "local":
				return dnsLocalInspection{
					found:         true,
					isUnsafeUDP53: true,
					desc:          "local (明文系统 DNS)",
				}
			default:
				return dnsLocalInspection{found: true, desc: fmt.Sprintf("%s://%s", typ, host)}
			}
		}

		// 兼容旧版 address 字符串格式（如 https://223.5.5.5/dns-query 或 udp://114.114.114.114:53）。
		addr := strings.TrimSpace(srv.Address)
		lowerAddr := strings.ToLower(addr)
		switch {
		case strings.HasPrefix(lowerAddr, "https://"),
			strings.HasPrefix(lowerAddr, "tls://"),
			strings.HasPrefix(lowerAddr, "quic://"),
			strings.HasPrefix(lowerAddr, "h3://"):
			return dnsLocalInspection{found: true, isEncryptedDoX: true, desc: addr}
		case lowerAddr == "local" || lowerAddr == "rcode://success":
			return dnsLocalInspection{found: true, isUnsafeUDP53: lowerAddr == "local", desc: addr}
		case strings.HasPrefix(lowerAddr, "udp://"):
			u, err := url.Parse(addr)
			if err == nil {
				p := 53
				if ps := u.Port(); ps != "" {
					if v, convErr := strconv.Atoi(ps); convErr == nil {
						p = v
					}
				}
				return classifyUDPTarget(u.Hostname(), p, addr)
			}
			return dnsLocalInspection{found: true, isUnsafeUDP53: true, desc: addr + " (私网/回环自环风险)"}
		default:
			// 纯 IP 或 host:port 无协议前缀在 sing-box 中等价于明文 UDP 53。
			h, pStr, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				return classifyUDPTarget(addr, 53, addr)
			}
			p, _ := strconv.Atoi(pStr)
			return classifyUDPTarget(h, p, addr)
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

func detectActiveLocalDNSProcesses(procRoot string) (adguardRunning, smartdnsRunning bool) {
	procs, ok := scanProcesses(procRoot)
	if !ok {
		return false, false
	}
	for _, p := range procs {
		commLower := strings.ToLower(p.comm)
		cmdLower := strings.ToLower(p.cmdline)
		if commLower == "adguardhome" || strings.Contains(cmdLower, "adguardhome") {
			adguardRunning = true
		}
		if commLower == "smartdns" {
			smartdnsRunning = true
		}
	}
	return adguardRunning, smartdnsRunning
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
