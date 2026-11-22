// 文件职责：覆盖三路配置无损合并（MergeManualConfig）跨订阅刷新保留用户手改项与 0600 权限测试。
package singbox_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/singbox"
)

func extractTaggedSetForTest(raw any) map[string]bool {
	set := make(map[string]bool)
	slice, ok := raw.([]any)
	if !ok {
		return set
	}
	for _, item := range slice {
		if m, ok := item.(map[string]any); ok {
			if tag := strFieldForTest(m, "tag"); tag != "" {
				set[tag] = true
			}
		}
	}
	return set
}

func strFieldForTest(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}

func sliceStringsForTest(raw any) []string {
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func TestMergeManualConfig_PreservesUserEditsAcrossSubRefresh(t *testing.T) {
	baseJSON := `{
  "log": { "level": "warn" },
  "dns": {
    "servers": [
      { "tag": "dns_proxy", "type": "https", "server": "1.1.1.1" },
      { "tag": "dns_local", "type": "udp", "server": "223.5.5.5" }
    ],
    "rules": [
      { "clash_mode": "Direct", "server": "dns_local" }
    ],
    "final": "dns_proxy"
  },
  "inbounds": [
    { "tag": "tproxy-in", "type": "tproxy", "listen": "::", "listen_port": 7893 }
  ],
  "outbounds": [
    { "tag": "Proxy", "type": "selector", "outbounds": ["#Auto", "HK-01", "JP-01"] },
    { "tag": "#Auto", "type": "urltest", "outbounds": ["HK-01", "JP-01"], "interval": "3m" },
    { "tag": "HK-01", "type": "vless", "server": "198.51.100.10", "server_port": 443, "uuid": "11111111-1111-1111-1111-111111111111" },
    { "tag": "JP-01", "type": "vless", "server": "198.51.100.11", "server_port": 443, "uuid": "11111111-1111-1111-1111-111111111111" },
    { "tag": "#DC", "type": "direct" }
  ],
  "route": {
    "rules": [
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "ip_is_private": true, "outbound": "#DC" }
    ],
    "final": "Proxy"
  },
  "experimental": {
    "clash_api": { "external_controller": "127.0.0.1:9090", "secret": "keep-this-secret" }
  }
}`

	currentJSON := `{
  "log": { "level": "info" },
  "dns": {
    "servers": [
      { "tag": "dns_proxy", "type": "https", "server": "1.1.1.1" },
      { "tag": "dns_local", "type": "udp", "server": "223.5.5.5" },
      { "tag": "dns_corp", "type": "udp", "server": "192.168.1.2" }
    ],
    "rules": [
      { "clash_mode": "Direct", "server": "dns_local" },
      { "domain_suffix": ["corp.example.com"], "server": "dns_corp" }
    ],
    "final": "dns_proxy"
  },
  "inbounds": [
    { "tag": "tproxy-in", "type": "tproxy", "listen": "::", "listen_port": 7893 },
    { "tag": "mixed-lan", "type": "mixed", "listen": "0.0.0.0", "listen_port": 7890 }
  ],
  "outbounds": [
    { "tag": "Proxy", "type": "selector", "outbounds": ["#Auto", "HK-01", "JP-01", "home-socks"] },
    { "tag": "#Auto", "type": "urltest", "outbounds": ["HK-01", "JP-01"], "interval": "5m" },
    { "tag": "HK-01", "type": "vless", "server": "198.51.100.10", "server_port": 443, "uuid": "11111111-1111-1111-1111-111111111111" },
    { "tag": "JP-01", "type": "vless", "server": "198.51.100.11", "server_port": 443, "uuid": "11111111-1111-1111-1111-111111111111" },
    { "tag": "home-socks", "type": "socks", "server": "203.0.113.55", "server_port": 1080 },
    { "tag": "#DC", "type": "direct" }
  ],
  "route": {
    "rules": [
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "domain_suffix": ["corp.example.com"], "outbound": "#DC" },
      { "domain_suffix": ["old-jp.example.com"], "outbound": "JP-01" },
      { "ip_is_private": true, "outbound": "#DC" }
    ],
    "final": "Proxy"
  },
  "experimental": {
    "clash_api": { "external_controller": "127.0.0.1:9090", "secret": "keep-this-secret" }
  }
}`

	freshJSON := `{
  "log": { "level": "warn" },
  "dns": {
    "servers": [
      { "tag": "dns_proxy", "type": "https", "server": "1.1.1.1" },
      { "tag": "dns_local", "type": "udp", "server": "223.5.5.5" }
    ],
    "rules": [
      { "clash_mode": "Direct", "server": "dns_local" }
    ],
    "final": "dns_proxy"
  },
  "inbounds": [
    { "tag": "tproxy-in", "type": "tproxy", "listen": "::", "listen_port": 7893 }
  ],
  "outbounds": [
    { "tag": "Proxy", "type": "selector", "outbounds": ["#Auto", "HK-01", "SG-01"] },
    { "tag": "#Auto", "type": "urltest", "outbounds": ["HK-01", "SG-01"], "interval": "3m" },
    { "tag": "HK-01", "type": "vless", "server": "198.51.100.10", "server_port": 443, "uuid": "22222222-2222-2222-2222-222222222222" },
    { "tag": "SG-01", "type": "vless", "server": "198.51.100.99", "server_port": 443, "uuid": "22222222-2222-2222-2222-222222222222" },
    { "tag": "#DC", "type": "direct" }
  ],
  "route": {
    "rules": [
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "ip_is_private": true, "outbound": "#DC" }
    ],
    "final": "Proxy"
  },
  "experimental": {
    "clash_api": { "external_controller": "127.0.0.1:9090", "secret": "new-random-secret" }
  }
}`

	merged, changes, err := singbox.MergeManualConfig(baseJSON, currentJSON, freshJSON)
	if err != nil {
		t.Fatalf("MergeManualConfig failed: %v", err)
	}
	if changes == 0 {
		t.Fatalf("expected non-zero preserved manual changes")
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(merged), &root); err != nil {
		t.Fatalf("unmarshal merged JSON: %v", err)
	}

	logMap, _ := root["log"].(map[string]any)
	if logMap["level"] != "info" {
		t.Fatalf("expected log.level='info' preserved, got %v", logMap["level"])
	}

	expMap, _ := root["experimental"].(map[string]any)
	clashMap, _ := expMap["clash_api"].(map[string]any)
	if clashMap["secret"] != "keep-this-secret" {
		t.Fatalf("expected clash_api.secret='keep-this-secret' preserved, got %v", clashMap["secret"])
	}

	inTags := extractTaggedSetForTest(root["inbounds"])
	if !inTags["mixed-lan"] || !inTags["tproxy-in"] {
		t.Fatalf("expected both tproxy-in and user-added mixed-lan inbounds, got %v", inTags)
	}

	outSlice, _ := root["outbounds"].([]any)
	outByTag := make(map[string]map[string]any)
	for _, it := range outSlice {
		if m, ok := it.(map[string]any); ok {
			outByTag[strFieldForTest(m, "tag")] = m
		}
	}
	if _, hasJP := outByTag["JP-01"]; hasJP {
		t.Fatalf("expected retired subscription node JP-01 to be removed")
	}
	if _, hasSG := outByTag["SG-01"]; !hasSG {
		t.Fatalf("expected new subscription node SG-01 to be present")
	}
	if hk := outByTag["HK-01"]; hk["uuid"] != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("expected HK-01 rotated uuid from fresh subscription to win, got %v", hk["uuid"])
	}
	if _, hasCustom := outByTag["home-socks"]; !hasCustom {
		t.Fatalf("expected user-added custom outbound home-socks to be preserved")
	}
	proxyMembers := sliceStringsForTest(outByTag["Proxy"]["outbounds"])
	if !slices.Contains(proxyMembers, "home-socks") || !slices.Contains(proxyMembers, "SG-01") || slices.Contains(proxyMembers, "JP-01") {
		t.Fatalf("unexpected Proxy selector members after merge: %v", proxyMembers)
	}
	if outByTag["#Auto"]["interval"] != "5m" {
		t.Fatalf("expected user-modified #Auto interval '5m' to be preserved, got %v", outByTag["#Auto"]["interval"])
	}

	if !strings.Contains(merged, `"corp.example.com"`) || !strings.Contains(merged, `"dns_corp"`) {
		t.Fatalf("expected user-added corp.example.com DNS & route rules preserved, got:\n%s", merged)
	}
	if strings.Contains(merged, `"old-jp.example.com"`) {
		t.Fatalf("expected route rule referencing retired node JP-01 to be pruned cleanly, got:\n%s", merged)
	}

	mergedAgain, _, err := singbox.MergeManualConfig(freshJSON, merged, freshJSON)
	if err != nil {
		t.Fatalf("second MergeManualConfig failed: %v", err)
	}
	h1, c1, err := singbox.ProxyOutboundsFingerprint(merged)
	if err != nil {
		t.Fatal(err)
	}
	h2, c2, err := singbox.ProxyOutboundsFingerprint(mergedAgain)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 || c1 != c2 {
		t.Fatalf("expected stable fingerprint across unchanged ticks, got (%s,%d) vs (%s,%d)", h1, c1, h2, c2)
	}
}

func TestPrepareRegeneratedConfig_ToggleOnAndOff_Permissions0600(t *testing.T) {
	tmpDir := t.TempDir()
	sbPath := filepath.Join(tmpDir, "config.json")

	base := `{"log":{"level":"warn"},"inbounds":[{"tag":"tun-in","type":"tun"}],"outbounds":[{"tag":"#DC","type":"direct"}],"route":{"rules":[{"action":"sniff"}]}}`
	if err := singbox.SaveBaseSnapshot(sbPath, base); err != nil {
		t.Fatalf("SaveBaseSnapshot failed: %v", err)
	}
	baseInfo, err := os.Stat(singbox.BaseSnapshotPath(sbPath))
	if err != nil || baseInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected base snapshot mode 0600, got %v (err=%v)", baseInfo, err)
	}

	edited := `{"log":{"level":"debug"},"inbounds":[{"tag":"tun-in","type":"tun"},{"tag":"socks-in","type":"socks","listen_port":1080}],"outbounds":[{"tag":"#DC","type":"direct"}],"route":{"rules":[{"action":"sniff"}]}}`
	if err := os.WriteFile(sbPath, []byte(edited), 0600); err != nil {
		t.Fatal(err)
	}

	fresh := `{"log":{"level":"warn"},"inbounds":[{"tag":"tun-in","type":"tun"}],"outbounds":[{"tag":"US-01","type":"vless","server":"198.51.100.20","server_port":443},{"tag":"#DC","type":"direct"}],"route":{"rules":[{"action":"sniff"}]}}`

	outOn, cntOn := singbox.PrepareRegeneratedConfig(t.Context(), sbPath, fresh, true)
	if cntOn == 0 || !strings.Contains(outOn, `"socks-in"`) || !strings.Contains(outOn, `"debug"`) || !strings.Contains(outOn, `"US-01"`) {
		t.Fatalf("expected preserveManual=true to keep manual edits + new node, cnt=%d out=%s", cntOn, outOn)
	}

	outOff, cntOff := singbox.PrepareRegeneratedConfig(t.Context(), sbPath, fresh, false)
	if cntOff != 0 || strings.Contains(outOff, `"socks-in"`) || strings.Contains(outOff, `"debug"`) {
		t.Fatalf("expected preserveManual=false to produce clean template without manual edits, cnt=%d out=%s", cntOff, outOff)
	}
}
