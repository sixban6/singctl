package singbox

import (
	"cmp"
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"

	"singctl/internal/constant"
	log "singctl/internal/logger"
)

const (
	defaultFallbackDoHServer = "223.5.5.5"
	defaultFallbackDoHPath   = "/dns-query"
	dnsSDBrowseKeyword       = "_dns-sd._udp."
)

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

// PatchDNSLocalJSON 在现有 sing-box 配置 JSON 上无损切换 dns_local 解析器：
//   - useAdGuard=true : 指向本地 AdGuard Home (udp://127.0.0.1:<dnsPort>) 并关闭 sing-box 重复缓存；
//   - useAdGuard=false: 恢复为纯 IP 加密 DoH (https://223.5.5.5/dns-query，已获 TProxy output 链豁免)，
//     确保停用或卸载 AdGuard Home 时全屋网关零断网、无需依赖外部网络重新拉取订阅。
func PatchDNSLocalJSON(rawJSON string, useAdGuard bool, dnsPort int) (string, bool, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, false, nil
	}
	if dnsPort <= 0 || dnsPort > 65535 {
		dnsPort = 5353
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", false, err
	}
	dnsMap, ok := root["dns"].(map[string]any)
	if !ok {
		return rawJSON, false, nil
	}
	servers, ok := dnsMap["servers"].([]any)
	if !ok {
		return rawJSON, false, nil
	}

	targetIdx := -1
	var existingSrv map[string]any
	for i, item := range servers {
		srvMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if tag, _ := srvMap["tag"].(string); tag == "dns_local" {
			targetIdx = i
			existingSrv = srvMap
			break
		}
	}
	if targetIdx < 0 {
		return rawJSON, false, nil
	}

	var desiredSrv map[string]any
	if useAdGuard {
		desiredSrv = map[string]any{
			"tag":         "dns_local",
			"type":        "udp",
			"server":      "127.0.0.1",
			"server_port": dnsPort,
		}
	} else {
		desiredSrv = map[string]any{
			"tag":         "dns_local",
			"type":        "https",
			"server":      defaultFallbackDoHServer,
			"server_port": 443,
			"path":        defaultFallbackDoHPath,
		}
	}

	alreadyMatch := dnsServerEqual(existingSrv, desiredSrv)
	wantDisableCache := useAdGuard
	wantOptimistic := !useAdGuard

	curDisableCache, _ := dnsMap["disable_cache"].(bool)
	curOptimistic, _ := dnsMap["optimistic"].(bool)
	cacheMatch := curDisableCache == wantDisableCache && curOptimistic == wantOptimistic
	ptrChanged := ensurePrivatePTRBlockRules(dnsMap)

	if alreadyMatch && cacheMatch && !ptrChanged {
		return rawJSON, false, nil
	}

	if !alreadyMatch || !cacheMatch {
		servers[targetIdx] = desiredSrv
		dnsMap["servers"] = servers
		dnsMap["disable_cache"] = wantDisableCache
		dnsMap["optimistic"] = wantOptimistic

		if expMap, ok := root["experimental"].(map[string]any); ok {
			if cfMap, ok := expMap["cache_file"].(map[string]any); ok {
				if useAdGuard {
					cfMap["store_dns"] = false
					cfMap["store_fakeip"] = false
				} else {
					cfMap["store_dns"] = true
				}
			}
		}
	}

	formatted, err := PrettyJSONFromValue(root)
	if err != nil {
		return "", false, err
	}
	return formatted, true, nil
}

// InjectPrivatePTRBlockRules 在非 iOS 客户端 sing-box 配置中幂等前置 RFC 6303 私网反查与 DNS-SD 浏览域的本地 NXDOMAIN 规则。
func InjectPrivatePTRBlockRules(rawJSON string) (string, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, nil
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", err
	}
	dnsMap, ok := root["dns"].(map[string]any)
	if !ok {
		return rawJSON, nil
	}
	if !ensurePrivatePTRBlockRules(dnsMap) {
		return rawJSON, nil
	}
	out, err := json.Marshal(root)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func ensurePrivatePTRBlockRules(dnsMap map[string]any) bool {
	if dnsMap == nil {
		return false
	}
	existing, _ := dnsMap["rules"].([]any)
	hasSuffixRule := false
	hasKeywordRule := false
	for _, item := range existing {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		act, _ := m["action"].(string)
		rcode, _ := m["rcode"].(string)
		if act != "predefined" || !strings.EqualFold(rcode, "NXDOMAIN") {
			continue
		}
		if matchesStringSliceField(m["domain_suffix"], privateReverseDNSSuffixes) {
			hasSuffixRule = true
		}
		if matchesStringSliceField(m["domain_keyword"], []string{dnsSDBrowseKeyword}) {
			hasKeywordRule = true
		}
	}
	if hasSuffixRule && hasKeywordRule {
		return false
	}

	prepend := make([]any, 0, 2)
	if !hasSuffixRule {
		prepend = append(prepend, map[string]any{
			"action":        "predefined",
			"domain_suffix": slices.Clone(privateReverseDNSSuffixes),
			"rcode":         "NXDOMAIN",
		})
	}
	if !hasKeywordRule {
		prepend = append(prepend, map[string]any{
			"action":         "predefined",
			"domain_keyword": []string{dnsSDBrowseKeyword},
			"rcode":          "NXDOMAIN",
		})
	}
	merged := make([]any, 0, len(prepend)+len(existing))
	merged = append(merged, prepend...)
	merged = append(merged, existing...)
	dnsMap["rules"] = merged
	return true
}

func matchesStringSliceField(raw any, want []string) bool {
	items, ok := raw.([]any)
	if !ok {
		if strItems, okStr := raw.([]string); okStr {
			return slices.Equal(strItems, want)
		}
		return false
	}
	if len(items) != len(want) {
		return false
	}
	for i, item := range items {
		s, ok := item.(string)
		if !ok || s != want[i] {
			return false
		}
	}
	return true
}

func dnsServerEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ab) == string(bb)
}

// PrettyJSONFromValue 将任意对象序列化为 2 空格缩进的 JSON。
func PrettyJSONFromValue(v any) (string, error) {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
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
	var parsed struct {
		DNS struct {
			Servers []struct {
				Tag        string `json:"tag"`
				Type       string `json:"type"`
				Server     string `json:"server"`
				ServerPort int    `json:"server_port"`
			} `json:"servers"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false, 0
	}
	for _, s := range parsed.DNS.Servers {
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

// SyncLiveSingBoxDNSLocal 遵循规则 02 两阶段原子切换准则，离线修改现有 sing-box 配置中的 dns_local，
// 通过 `sing-box check` 语法校验后原子覆盖并发送 SIGHUP 无感热重载（不中断存量连接，不依赖外部网络拉订阅）。
func SyncLiveSingBoxDNSLocal(ctx context.Context, sbConfigPath, sbWorkConfigPath string, useAdGuard bool, dnsPort int) (bool, error) {
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

	updatedJSON, changed, err := PatchDNSLocalJSON(string(rawBytes), useAdGuard, dnsPort)
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
		log.Success("已平滑热重载 sing-box：dns_local -> 本地 AdGuard Home (127.0.0.1:%d)", dnsPort)
	} else {
		log.Success("已平滑热重载 sing-box：dns_local -> 内置纯 IP 加密 DoH (https://%s/dns-query)", defaultFallbackDoHServer)
	}
	return true, nil
}
