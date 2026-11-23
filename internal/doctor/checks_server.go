//go:build !lite

// 文件职责：实现服务端模式下的声明式体检算子集合（系统环境、BBR、监听端口、四核心服务、TLS/QUIC 证书、Reality SNI、SubHub、WARP 与 Web 终端 mTLS）。
package doctor

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/subhub"
)

func defaultServerChecks() []Check {
	return []Check{
		{ID: "server.system", Scope: ScopeServer, Run: checkSystemItems},
		{ID: "server.bbr", Scope: ScopeServer, Run: checkBBRItems},
		{ID: "server.ports", Scope: ScopeServer, Run: checkServerPortsItems},
		{ID: "server.services", Scope: ScopeServer, Run: checkServerServicesItems},
		{ID: "server.tls_cert", Scope: ScopeServer, Run: checkTLSCertItems},
		{ID: "server.reality_sni", Scope: ScopeServer, Run: checkRealitySNIItems},
		{ID: "server.subhub", Scope: ScopeServer, Run: checkSubhubItems},
		{ID: "server.warp_unlock", Scope: ScopeServer, Run: checkWARPAndUnlockItems},
		{ID: "server.web_terminal", Scope: ScopeServer, Run: checkWebTerminalItems},
	}
}

func checkSystemItems(_ context.Context, _ *config.Config, deps Deps) []DoctorItem {
	osName := deps.GOOS
	if data, err := deps.ReadFile("/etc/os-release"); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			if after, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				osName = strings.Trim(after, `"`)
				break
			}
		}
	}
	return []DoctorItem{{
		Name:     "基础运行环境",
		Category: "system",
		Status:   "ok",
		Summary:  fmt.Sprintf("%s (%s), CPU: %d 核", osName, deps.GOARCH, deps.NumCPU),
	}}
}

func checkBBRItems(_ context.Context, _ *config.Config, deps Deps) []DoctorItem {
	data, err := deps.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return []DoctorItem{{
			Name:     "TCP 拥塞控制算法",
			Category: "network",
			Status:   "ok",
			Summary:  "容器共享宿主机内核网络栈 (TCP 拥塞控制由宿主机托管)",
		}}
	}
	if err == nil && strings.Contains(strings.TrimSpace(string(data)), "bbr") {
		return []DoctorItem{{
			Name:     "TCP 拥塞控制算法",
			Category: "network",
			Status:   "ok",
			Summary:  "Google BBR 加速 [已激活启用]",
		}}
	}
	return []DoctorItem{{
		Name:     "TCP 拥塞控制算法",
		Category: "network",
		Status:   "warn",
		Summary:  "BBR 未启用 (当前为标准 Reno/Cubic)",
		Detail:   "建议通过控制台或 'sysctl' 启用 BBR 以大幅提升弱网与长距离链路吞吐量",
	}}
}

func checkServerPortsItems(_ context.Context, cfg *config.Config, deps Deps) []DoctorItem {
	ports := []int{80, 443}
	if cfg != nil && cfg.Server.GetVlessPort() != 443 {
		ports = append(ports, cfg.Server.GetVlessPort())
	}
	if cfg != nil && cfg.Server.GetWebAdminPort() > 0 {
		ports = append(ports, cfg.Server.GetWebAdminPort())
	}

	var closed []int
	for _, p := range ports {
		if err := deps.DialTCP(fmt.Sprintf("127.0.0.1:%d", p), 500*time.Millisecond); err != nil {
			closed = append(closed, p)
		}
	}

	if len(closed) == 0 {
		return []DoctorItem{{
			Name:     "网关与管理端口监听",
			Category: "network",
			Status:   "ok",
			Summary:  fmt.Sprintf("核心端口 (%s) 均正常监听运行", joinInts(ports)),
		}}
	}
	return []DoctorItem{{
		Name:     "网关与管理端口监听",
		Category: "network",
		Status:   "warn",
		Summary:  fmt.Sprintf("端口 %v 未检测到本地监听", closed),
		Detail:   "若 Caddy 或服务端尚未启动，此状态属正常现象",
	}}
}

func checkServerServicesItems(_ context.Context, _ *config.Config, deps Deps) []DoctorItem {
	services := []struct {
		id       string
		name     string
		fixGuide string
	}{
		{"caddy", "Caddy 网关", "singctl sr restart"},
		{"sing-box", "sing-box 核心", "singctl sr restart"},
		{"singctl-sub", "SubHub 订阅引擎", "singctl sr sub restart"},
		{"wireproxy", "WARP (wireproxy)", "singctl sr warp restart"},
	}

	items := make([]DoctorItem, 0, len(services))
	for _, s := range services {
		if deps.IsServiceActive(s.id) {
			items = append(items, DoctorItem{
				Name:     s.name,
				Category: "services",
				Status:   "ok",
				Summary:  "服务处于活跃运行状态 (active)",
			})
		} else {
			items = append(items, DoctorItem{
				Name:     s.name,
				Category: "services",
				Status:   "warn",
				Summary:  "服务未运行或未启动 (inactive)",
				Detail:   fmt.Sprintf("可尝试在控制台或终端运行: %s", s.fixGuide),
			})
		}
	}
	return items
}

func checkTLSCertItems(_ context.Context, cfg *config.Config, deps Deps) []DoctorItem {
	if cfg == nil {
		return nil
	}
	domain := cmp.Or(cfg.Server.GetNodeDomain(), cfg.Server.SubstoreDomain)
	if domain == "" {
		return nil
	}

	vlessPort := cfg.Server.GetVlessPort()
	targetAddr := fmt.Sprintf("%s:%d", domain, vlessPort)
	peer, err := deps.ProbeServerTLS(domain, vlessPort)
	if err != nil {
		return []DoctorItem{{
			Name:     "HTTPS 证书与网关",
			Category: "security",
			Status:   "warn",
			Summary:  fmt.Sprintf("无法建立与 %s 的 TLS 握手", targetAddr),
			Detail:   err.Error(),
		}}
	}

	var items []DoctorItem
	if !peer.NotAfter.IsZero() {
		daysRemaining := int(peer.NotAfter.Sub(deps.Now()).Hours() / 24)
		switch {
		case daysRemaining > 15:
			items = append(items, DoctorItem{
				Name:     "HTTPS 证书状态",
				Category: "security",
				Status:   "ok",
				Summary:  fmt.Sprintf("Let's Encrypt / ZeroSSL 证书正常 (剩余有效期 %d 天)", daysRemaining),
			})
		case daysRemaining > 0:
			items = append(items, DoctorItem{
				Name:     "HTTPS 证书状态",
				Category: "security",
				Status:   "warn",
				Summary:  fmt.Sprintf("证书即将到期 (剩余 %d 天)", daysRemaining),
				Detail:   "Caddy 会在到期前自动续签，请保持 80/443 端口畅通",
			})
		default:
			items = append(items, DoctorItem{
				Name:     "HTTPS 证书状态",
				Category: "security",
				Status:   "fail",
				Summary:  "证书已过期！",
				Detail:   "请检查 Caddy 证书续期日志",
			})
		}
	}

	// 校验 sing-box Hysteria2 配置证书文件是否真实存在且为非自签有效 ACME 证书
	if rawCfg, err := deps.ReadFile(constant.SingBoxConfigFile); err == nil {
		s := string(rawCfg)
		if strings.Contains(s, `"hysteria2"`) {
			switch {
			case strings.Contains(s, "/certificates/local/"):
				items = append(items, DoctorItem{
					Name:     "Hysteria2 QUIC 证书",
					Category: "security",
					Status:   "fail",
					Summary:  "Hysteria2 证书误指向 Caddy local 内部自签证书",
					Detail:   "客户端将拒绝自签证书握手，请执行安全自愈或重新同步证书路径",
				})
			default:
				validCrt, _ := deps.LookupValidCaddyCert(domain)
				if validCrt != "" && !strings.Contains(s, validCrt) {
					items = append(items, DoctorItem{
						Name:     "Hysteria2 QUIC 证书",
						Category: "security",
						Status:   "warn",
						Summary:  "Hysteria2 证书路径与最新 ACME 证书不一致",
						Detail:   "可执行安全自愈自动同步至最新 ACME 证书并重载 sing-box",
					})
				} else {
					items = append(items, DoctorItem{
						Name:     "Hysteria2 QUIC 证书",
						Category: "security",
						Status:   "ok",
						Summary:  "UDP 443 (QUIC/H3) 证书链与 TCP 443 保持一致且有效",
					})
				}
			}
		}
	}
	return items
}

func checkRealitySNIItems(_ context.Context, cfg *config.Config, deps Deps) []DoctorItem {
	sni := "swdist.apple.com"
	if cfg != nil && cfg.Server.Sni != "" {
		sni = cfg.Server.Sni
	}

	latency, tlsVer, err := deps.ProbeRealitySNI(sni)
	if err != nil {
		return []DoctorItem{{
			Name:     "Reality 伪装目标探测",
			Category: "security",
			Status:   "warn",
			Summary:  fmt.Sprintf("无法握手伪装域名 %s: %v", sni, err),
			Detail:   "建议更换为响应更快的 Apple/Microsoft 官方域名以保障抗封锁效果",
		}}
	}
	return []DoctorItem{{
		Name:     "Reality 伪装目标探测",
		Category: "security",
		Status:   "ok",
		Summary:  fmt.Sprintf("目标 SNI [%s] 握手正常 (延迟: %d ms, TLS %s)", sni, latency.Milliseconds(), cmp.Or(tlsVer, "未知")),
	}}
}

func checkSubhubItems(_ context.Context, _ *config.Config, deps Deps) []DoctorItem {
	code, _, err := deps.HTTPGetStatus("http://"+subhub.DefaultListenAddr+"/healthz", 2*time.Second)
	if err != nil || code != http.StatusOK {
		code, _, err = deps.HTTPGetStatus("http://"+subhub.DefaultListenAddr+"/", 2*time.Second)
	}
	if err == nil && code == http.StatusOK {
		return []DoctorItem{{
			Name:     "SubHub 订阅聚合",
			Category: "services",
			Status:   "ok",
			Summary:  "本地 3001 端口原生引擎响应正常 (HTTP 200)",
		}}
	}
	return []DoctorItem{{
		Name:     "SubHub 订阅聚合",
		Category: "services",
		Status:   "warn",
		Summary:  "本地 3001 端口未响应",
		Detail:   "可执行 'singctl sr sub restart' 检查 SubHub 订阅聚合服务状态",
	}}
}

func checkWARPAndUnlockItems(_ context.Context, _ *config.Config, deps Deps) []DoctorItem {
	unlock := deps.CheckMediaUnlock()
	if unlock == nil {
		return nil
	}

	items := []DoctorItem{{
		Name:     "VPS 原生出口画像",
		Category: "network",
		Status:   "ok",
		Summary:  FormatProfileSummary(&unlock.Direct),
		Detail:   fmt.Sprintf("出口公网 IP: %s (%s)", unlock.Direct.ExitIP, unlock.Direct.ExitLoc),
	}}

	if unlock.WARP.Available {
		items = append(items, DoctorItem{
			Name:     "WARP 分流出口画像",
			Category: "network",
			Status:   "ok",
			Summary:  FormatProfileSummary(&unlock.WARP),
			Detail:   fmt.Sprintf("出口公网 IP: %s (%s)", unlock.WARP.ExitIP, unlock.WARP.ExitLoc),
		})
	} else {
		items = append(items, DoctorItem{
			Name:     "WARP 分流出口画像",
			Category: "network",
			Status:   "warn",
			Summary:  "WARP 服务未运行或 40000 端口未就绪",
			Detail:   "若需要海外流媒体/AI 解锁增强，可运行 'singctl sr install warp'",
		})
	}
	return items
}

// FormatProfileSummary 将单条出口解锁画像格式化为紧凑单行摘要。
func FormatProfileSummary(p *ExitProfile) string {
	list := make([]string, 0, 4)
	if p.OpenAI.Status == "unlocked" {
		list = append(list, fmt.Sprintf("OpenAI [%s]", cmp.Or(p.OpenAI.Region, "OK")))
	} else {
		list = append(list, "OpenAI [受阻]")
	}

	switch p.Netflix.Status {
	case "unlocked":
		list = append(list, "Netflix [完整解锁]")
	case "partially_unlocked":
		list = append(list, "Netflix [仅自制剧]")
	default:
		list = append(list, "Netflix [未解锁]")
	}

	if p.YouTube.Status == "unlocked" {
		list = append(list, "YouTube [原生]")
	}
	if p.Google.Status == "unlocked" {
		list = append(list, "Google [无验证码]")
	}
	return strings.Join(list, " | ")
}

func checkWebTerminalItems(_ context.Context, cfg *config.Config, deps Deps) []DoctorItem {
	if cfg == nil || !cfg.Server.WebTerminal.Enabled {
		return nil
	}

	rawCA := strings.TrimSpace(cfg.Server.WebTerminal.MtlsCA)
	caPath := deploy.NormalizeMtlsCAPath(rawCA)
	caOK := deps.FileNonEmpty(caPath)
	legacyCfg := rawCA != "" && deploy.IsLegacyCaddyMtlsCAPath(rawCA)

	items := make([]DoctorItem, 0, 2)
	switch {
	case caOK && !legacyCfg:
		items = append(items, DoctorItem{
			Category: "security",
			Name:     "Web 终端 mTLS 证书",
			Status:   "ok",
			Summary:  fmt.Sprintf("CA 信任池正常 (%s)", caPath),
		})
	case caOK && legacyCfg:
		items = append(items, DoctorItem{
			Category: "security",
			Name:     "Web 终端 mTLS 证书",
			Status:   "warn",
			Summary:  fmt.Sprintf("CA 证书已在 %s 就绪，但配置仍指向旧路径 %s", caPath, rawCA),
			Detail:   "运行 'singctl sr sync' 可自动收敛配置并清理废弃的 /etc/caddy/mtls 目录",
		})
	default:
		items = append(items, DoctorItem{
			Category: "security",
			Name:     "Web 终端 mTLS 证书",
			Status:   "fail",
			Summary:  fmt.Sprintf("Web 终端已启用，但 mTLS CA 证书缺失 (%s)", caPath),
			Detail:   "请运行 'singctl sr term install' 重新生成 mTLS 证书并恢复 Caddy 网关",
		})
	}

	gottyActive := deps.IsServiceActive("gotty")
	wstunnelActive := deps.IsServiceActive("wstunnel")
	if gottyActive && wstunnelActive {
		items = append(items, DoctorItem{
			Category: "services",
			Name:     "Web 终端后台服务 (gotty/wstunnel)",
			Status:   "ok",
			Summary:  "gotty 与 wstunnel 均运行中",
		})
	} else {
		items = append(items, DoctorItem{
			Category: "services",
			Name:     "Web 终端后台服务 (gotty/wstunnel)",
			Status:   "warn",
			Summary:  fmt.Sprintf("gotty=%v, wstunnel=%v", gottyActive, wstunnelActive),
			Detail:   "运行 'singctl sr term status' 或 'singctl sr term install' 检查/启动 Web 终端服务",
		})
	}
	return items
}
