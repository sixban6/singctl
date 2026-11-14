package singbox

import (
	"cmp"
	"context"
	"encoding/json"
	"os"
	"strings"

	"singctl/internal/constant"
	log "singctl/internal/logger"
)

const (
	defaultFallbackDoHServer = "223.5.5.5"
	defaultFallbackDoHPath   = "/dns-query"
)

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

	if alreadyMatch && cacheMatch {
		return rawJSON, false, nil
	}

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

	formatted, err := PrettyJSONFromValue(root)
	if err != nil {
		return "", false, err
	}
	return formatted, true, nil
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
