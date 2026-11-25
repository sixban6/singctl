// 文件职责：负责客户端本地 DNS（AdGuard Home/SmartDNS vs 安全公网运营商 UDP 兜底）热切换、状态巡检与 RFC 6303 私网 PTR NXDOMAIN 防环注入。
package singbox

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"singctl/internal/common/netx"
	"singctl/internal/constant"
	log "singctl/internal/logger"
	"singctl/internal/singbox/sboption"
)

const (
	DefaultFallbackPlainUDPDNS = "114.114.114.114"
	// DNSSDBrowseKeyword 是 Bonjour / mDNS 服务发现反查特征串，用于在 sing-box 侧就地返回 NXDOMAIN 防回环。
	DNSSDBrowseKeyword = "_dns-sd._udp."
)

var defaultResolvPaths = []string{
	"/tmp/resolv.conf.d/resolv.conf.auto",
	"/tmp/resolv.conf.auto",
	"/etc/resolv.conf",
}

// IsPublicISPUnicastIPv4 委托给 netx.IsPublicISPUnicastIPv4，校验合法公网单播 IPv4 DNS 地址（排除私网/回环/CGNAT/FakeIP/本机 IP）。
func IsPublicISPUnicastIPv4(ip net.IP, localIPSet map[string]struct{}) bool {
	return netx.IsPublicISPUnicastIPv4(ip, localIPSet)
}

// ProbeSafeWANFallbackDNS 按优先级扫描宿主机 WAN 口/运营商 resolv 文件中的公网 DNS IPv4（严格过滤全部局域网/回环/CGNAT/FakeIP/本机 IP 防止停用防劫持 DNS 后陷入 53 自环）；
// 未探测到任何安全公网 ISP DNS 时回退至 DefaultFallbackPlainUDPDNS ("114.114.114.114")。
func ProbeSafeWANFallbackDNS(resolvPaths []string, localIPs []string) string {
	if len(resolvPaths) == 0 {
		resolvPaths = defaultResolvPaths
	}
	localIPSet := make(map[string]struct{})
	if localIPs != nil {
		for _, raw := range localIPs {
			if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil && ip.To4() != nil {
				localIPSet[ip.To4().String()] = struct{}{}
			}
		}
	} else if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP != nil {
				if v4 := ipNet.IP.To4(); v4 != nil {
					localIPSet[v4.String()] = struct{}{}
				}
			}
		}
	}

	for _, p := range resolvPaths {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(raw), "\n") {
			if idx := strings.IndexAny(line, "#;"); idx >= 0 {
				line = line[:idx]
			}
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
				continue
			}
			cand := strings.TrimSpace(fields[1])
			if host, _, splitErr := net.SplitHostPort(cand); splitErr == nil {
				cand = host
			}
			if ip := net.ParseIP(cand); IsPublicISPUnicastIPv4(ip, localIPSet) {
				return ip.To4().String()
			}
		}
	}
	return DefaultFallbackPlainUDPDNS
}

// privateReverseDNSSuffixes 覆盖 RFC 6303 标准私网/链路本地反查域，配合 _dns-sd._udp. 在 sing-box 侧就地返回 NXDOMAIN，
// 既防止与 AdGuard/dnsmasq 形成回环放大，也杜绝内网 IP 段拓扑外泄到公网 DoH 或运营商 DNS。
var privateReverseDNSSuffixes = []string{
	"0.in-addr.arpa",
	"10.in-addr.arpa",
	"127.in-addr.arpa",
	"168.192.in-addr.arpa",
	"254.169.in-addr.arpa",
	"16.172.in-addr.arpa",
	"17.172.in-addr.arpa",
	"18.172.in-addr.arpa",
	"19.172.in-addr.arpa",
	"20.172.in-addr.arpa",
	"21.172.in-addr.arpa",
	"22.172.in-addr.arpa",
	"23.172.in-addr.arpa",
	"24.172.in-addr.arpa",
	"25.172.in-addr.arpa",
	"26.172.in-addr.arpa",
	"27.172.in-addr.arpa",
	"28.172.in-addr.arpa",
	"29.172.in-addr.arpa",
	"30.172.in-addr.arpa",
	"31.172.in-addr.arpa",
	"c.f.ip6.arpa",
	"d.f.ip6.arpa",
	"8.e.f.ip6.arpa",
	"9.e.f.ip6.arpa",
	"a.e.f.ip6.arpa",
	"b.e.f.ip6.arpa",
}

// PrivateReverseDNSSuffixes 返回 RFC 6303 私网与链路本地反查域名后缀副本。
func PrivateReverseDNSSuffixes() []string { return slices.Clone(privateReverseDNSSuffixes) }

// PatchDNSLocalJSON 在现有 sing-box 配置 JSON 上无损切换 dns_local 解析器：
//   - useAdGuard=true : 指向本地外部防劫持 DNS (udp://127.0.0.1:<dnsPort>) 并强制关闭 sing-box 缓存与乐观解析；
//   - useAdGuard=false: 统一切回安全公网运营商 DNS / 114.114.114.114 (udp://<ip>:53)，
//     同样强制 disable_cache=true、optimistic=false、store_dns=false，杜绝双层缓存、私网乒乓环路与陈旧乐观记录。
func PatchDNSLocalJSON(rawJSON string, useAdGuard bool, dnsPort int) (string, bool, error) {
	return PatchDNSLocalJSONWithFallback(rawJSON, useAdGuard, dnsPort, "")
}

// PatchDNSLocalJSONWithFallback 在 PatchDNSLocalJSON 基础上支持显式传入备选公网单播 DNS IPv4；
// 若传入为空、私网或回环地址，则自动忽略并回退至 ProbeSafeWANFallbackDNS，杜绝旁路由死循环。
func PatchDNSLocalJSONWithFallback(rawJSON string, useAdGuard bool, dnsPort int, fallbackPublicIP string) (string, bool, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, false, nil
	}
	if dnsPort <= 0 || dnsPort > 65535 {
		dnsPort = 5353
	}

	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", false, err
	}
	if !patchDNSLocalInDoc(doc, useAdGuard, dnsPort, fallbackPublicIP) {
		return rawJSON, false, nil
	}

	formatted, err := doc.MarshalPretty()
	if err != nil {
		return "", false, err
	}
	return formatted + "\n", true, nil
}

func resolveSafeFallbackPublicIP(fallbackPublicIP string) string {
	trimmed := strings.TrimSpace(fallbackPublicIP)
	if ip := net.ParseIP(trimmed); IsPublicISPUnicastIPv4(ip, nil) {
		return ip.To4().String()
	}
	return ProbeSafeWANFallbackDNS(nil, nil)
}

func patchDNSLocalInDoc(doc *sboption.Document, useExternal bool, dnsPort int, fallbackPublicIP string) bool {
	if doc == nil || doc.DNS == nil || len(doc.DNS.Servers) == 0 {
		return false
	}

	targetIdx := -1
	for i := range doc.DNS.Servers {
		if doc.DNS.Servers[i].Tag == "dns_local" {
			targetIdx = i
			break
		}
	}
	if targetIdx < 0 {
		return false
	}

	var desiredSrv sboption.DNSServer
	if useExternal {
		desiredSrv = sboption.DNSServer{
			Tag:        "dns_local",
			Type:       "udp",
			Server:     "127.0.0.1",
			ServerPort: dnsPort,
		}
	} else {
		fbIP := resolveSafeFallbackPublicIP(fallbackPublicIP)
		desiredSrv = sboption.DNSServer{
			Tag:        "dns_local",
			Type:       "udp",
			Server:     fbIP,
			ServerPort: 53,
		}
	}

	existingSrv := doc.DNS.Servers[targetIdx]
	alreadyMatch := dnsServerStructEqual(existingSrv, desiredSrv)

	curDisableCache := doc.DNS.DisableCache != nil && *doc.DNS.DisableCache
	curOptimistic := doc.DNS.Optimistic != nil && *doc.DNS.Optimistic
	cacheMatch := doc.DNS.DisableCache != nil && doc.DNS.Optimistic != nil &&
		curDisableCache && !curOptimistic
	if doc.Experimental != nil && doc.Experimental.CacheFile != nil {
		cf := doc.Experimental.CacheFile
		if cf.StoreDNS == nil || *cf.StoreDNS {
			cacheMatch = false
		}
		if useExternal && (cf.StoreFakeIP == nil || *cf.StoreFakeIP) {
			cacheMatch = false
		}
	}

	ptrChanged := ensurePrivatePTRBlockRulesInDoc(doc)
	if alreadyMatch && cacheMatch && !ptrChanged {
		return false
	}

	if !alreadyMatch || !cacheMatch {
		doc.DNS.Servers[targetIdx] = desiredSrv
		doc.DNS.DisableCache = new(true)
		doc.DNS.Optimistic = new(false)

		if doc.Experimental != nil && doc.Experimental.CacheFile != nil {
			doc.Experimental.CacheFile.StoreDNS = new(false)
			if useExternal {
				doc.Experimental.CacheFile.StoreFakeIP = new(false)
			}
		}
	}
	return true
}

// InjectPrivatePTRBlockRules 在非 iOS 客户端 sing-box 配置中幂等前置 RFC 6303 私网反查与 DNS-SD 浏览域的本地 NXDOMAIN 规则。
func InjectPrivatePTRBlockRules(rawJSON string) (string, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, nil
	}
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", err
	}
	if !ensurePrivatePTRBlockRulesInDoc(doc) {
		return rawJSON, nil
	}
	return doc.MarshalCompact()
}

func ensurePrivatePTRBlockRulesInDoc(doc *sboption.Document) bool {
	if doc == nil || doc.DNS == nil {
		return false
	}
	hasSuffixRule := false
	hasKeywordRule := false
	for _, r := range doc.DNS.Rules {
		isSfx, isKw := sboption.IsManagedPrivatePTRDNSRule(r, privateReverseDNSSuffixes, DNSSDBrowseKeyword)
		if isSfx {
			hasSuffixRule = true
		}
		if isKw {
			hasKeywordRule = true
		}
	}
	if hasSuffixRule && hasKeywordRule {
		return false
	}

	prepend := make([]sboption.DNSRule, 0, 2)
	if !hasSuffixRule {
		prepend = append(prepend, sboption.DNSRule{
			Action:       "predefined",
			DomainSuffix: sboption.ListOf(privateReverseDNSSuffixes...),
			Rcode:        "NXDOMAIN",
		})
	}
	if !hasKeywordRule {
		prepend = append(prepend, sboption.DNSRule{
			Action:        "predefined",
			DomainKeyword: sboption.ListOf(DNSSDBrowseKeyword),
			Rcode:         "NXDOMAIN",
		})
	}
	merged := make([]sboption.DNSRule, 0, len(prepend)+len(doc.DNS.Rules))
	merged = append(merged, prepend...)
	merged = append(merged, doc.DNS.Rules...)
	doc.DNS.Rules = merged
	return true
}

func dnsServerStructEqual(a, b sboption.DNSServer) bool {
	return len(a.Extra) == 0 && len(b.Extra) == 0 &&
		a.Tag == b.Tag &&
		a.Type == b.Type &&
		a.Server == b.Server &&
		a.ServerPort == b.ServerPort &&
		a.Path == b.Path &&
		a.Address == b.Address &&
		a.Detour == b.Detour
}

// InspectSingBoxDNSLocal 检查磁盘上的 sing-box config.json 当前是否已将 dns_local 指向本地 127.0.0.1:<port>。
func InspectSingBoxDNSLocal(sbConfigPath string) (linked bool, port int) {
	path := cmp.Or(strings.TrimSpace(sbConfigPath), constant.SingBoxConfigFile)
	if path == "" {
		return false, 0
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, 0
	}
	doc, err := sboption.ParseDocument(raw)
	if err != nil || doc.DNS == nil {
		return false, 0
	}
	for _, s := range doc.DNS.Servers {
		if s.Tag == "dns_local" {
			if strings.TrimSpace(s.Server) == "127.0.0.1" {
				p := s.ServerPort
				if p <= 0 {
					p = 53
				}
				return true, p
			}
			return false, 0
		}
	}
	return false, 0
}

// InspectSingBoxDNSLocalTarget 返回磁盘上 sing-box dns_local 的可读目标地址（如 "udp://127.0.0.1:5353"、"udp://114.114.114.114:53"）。
func InspectSingBoxDNSLocalTarget(sbConfigPath string) string {
	path := cmp.Or(strings.TrimSpace(sbConfigPath), constant.SingBoxConfigFile)
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	doc, err := sboption.ParseDocument(raw)
	if err != nil || doc.DNS == nil {
		return ""
	}
	for _, s := range doc.DNS.Servers {
		if s.Tag != "dns_local" {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(s.Type))
		host := strings.TrimSpace(s.Server)
		if typ != "" {
			if typ == "udp" {
				p := s.ServerPort
				if p <= 0 {
					p = 53
				}
				return fmt.Sprintf("udp://%s:%d", host, p)
			}
			if s.ServerPort > 0 {
				return fmt.Sprintf("%s://%s:%d%s", typ, host, s.ServerPort, s.Path)
			}
			return fmt.Sprintf("%s://%s%s", typ, host, s.Path)
		}
		return strings.TrimSpace(s.Address)
	}
	return ""
}

// SyncLiveSingBoxDNSLocal 遵循规则 02 两阶段原子切换准则，离线修改现有 sing-box 配置中的 dns_local，
// 通过 `sing-box check` 语法校验后原子覆盖并发送 SIGHUP 无感热重载。
func SyncLiveSingBoxDNSLocal(ctx context.Context, sbConfigPath, sbWorkConfigPath string, useAdGuard bool, dnsPort int) (bool, error) {
	return SyncLiveSingBoxDNSLocalWithFallback(ctx, sbConfigPath, sbWorkConfigPath, useAdGuard, dnsPort, "")
}

// SyncLiveSingBoxDNSLocalWithFallback 在 SyncLiveSingBoxDNSLocal 基础上支持显式传入备选公网单播 DNS IPv4（无效/私网地址自动回退 ProbeSafeWANFallbackDNS）。
func SyncLiveSingBoxDNSLocalWithFallback(ctx context.Context, sbConfigPath, sbWorkConfigPath string, useAdGuard bool, dnsPort int, fallbackPublicIP string) (bool, error) {
	cfgPath := cmp.Or(strings.TrimSpace(sbConfigPath), constant.SingBoxConfigFile)
	workPath := cmp.Or(strings.TrimSpace(sbWorkConfigPath), constant.SingBoxWorkConfigFile)
	if cfgPath == "" {
		return false, nil
	}
	rawBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	resolvedFB := ""
	if !useAdGuard {
		resolvedFB = resolveSafeFallbackPublicIP(fallbackPublicIP)
	}
	updatedJSON, changed, err := PatchDNSLocalJSONWithFallback(string(rawBytes), useAdGuard, dnsPort, resolvedFB)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}

	if err := ApplyLiveSingBoxConfig(ctx, cfgPath, workPath, updatedJSON, "dnslocal"); err != nil {
		return false, err
	}
	if useAdGuard {
		log.Success("已平滑热重载 sing-box：dns_local -> 本地防劫持 DNS (127.0.0.1:%d)", dnsPort)
	} else {
		log.Success("已平滑热重载 sing-box：dns_local -> 运营商/基础公网 DNS (udp://%s:53)", resolvedFB)
	}
	return true, nil
}
