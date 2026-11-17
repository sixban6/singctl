package singbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

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

	// 用户手动修改了 config.json：
	// 1. log.level 改为 info
	// 2. 新增局域网 mixed-in :7890 入站
	// 3. 新增自建住宅落地 home-socks 出站，并将其挂入 Proxy 选择器
	// 4. 新增内网 DNS 服务器 dns_corp 与企业域名路由规则 corp.example.com -> #DC
	// 5. 新增一条引用即将下线节点 JP-01 的临时规则（验证下线后自动安全清理，不炸 sing-box check）
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

	// 新一轮订阅刷新：HK-01 轮换了新 UUID，JP-01 下线，新增 SG-01，且重新生成了新的随机 secret
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

	merged, changes, err := MergeManualConfig(baseJSON, currentJSON, freshJSON)
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

	// 1. 验证 log.level 保留了用户手改的 info
	logMap, _ := root["log"].(map[string]any)
	if logMap["level"] != "info" {
		t.Fatalf("expected log.level='info' preserved, got %v", logMap["level"])
	}

	// 2. 验证 clash_api.secret 复用了当前运行态 secret
	expMap, _ := root["experimental"].(map[string]any)
	clashMap, _ := expMap["clash_api"].(map[string]any)
	if clashMap["secret"] != "keep-this-secret" {
		t.Fatalf("expected clash_api.secret='keep-this-secret' preserved, got %v", clashMap["secret"])
	}

	// 3. 验证新增的 mixed-lan 入站保留
	inTags := extractTaggedSet(root["inbounds"])
	if !inTags["mixed-lan"] || !inTags["tproxy-in"] {
		t.Fatalf("expected both tproxy-in and user-added mixed-lan inbounds, got %v", inTags)
	}

	// 4. 验证订阅节点已更新 (SG-01 上线、JP-01 下线、HK-01 更新了新 UUID)，且用户自建 home-socks 与 Proxy 挂载保留
	outSlice, _ := root["outbounds"].([]any)
	outByTag := make(map[string]map[string]any)
	for _, it := range outSlice {
		if m, ok := it.(map[string]any); ok {
			outByTag[strField(m, "tag")] = m
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
	proxyMembers := sliceStrings(outByTag["Proxy"]["outbounds"])
	if !slices.Contains(proxyMembers, "home-socks") || !slices.Contains(proxyMembers, "SG-01") || slices.Contains(proxyMembers, "JP-01") {
		t.Fatalf("unexpected Proxy selector members after merge: %v", proxyMembers)
	}
	if outByTag["#Auto"]["interval"] != "5m" {
		t.Fatalf("expected user-modified #Auto interval '5m' to be preserved, got %v", outByTag["#Auto"]["interval"])
	}

	// 5. 验证自定义路由与自定义 DNS 规则保留，且指向已下线节点 JP-01 的失效规则已被自动剥离防崩
	if !strings.Contains(merged, `"corp.example.com"`) || !strings.Contains(merged, `"dns_corp"`) {
		t.Fatalf("expected user-added corp.example.com DNS & route rules preserved, got:\n%s", merged)
	}
	if strings.Contains(merged, `"old-jp.example.com"`) {
		t.Fatalf("expected route rule referencing retired node JP-01 to be pruned cleanly, got:\n%s", merged)
	}

	// 6. 验证当上游订阅未再变化时，再次合并后的代理指纹与当前完全一致（不会触发死循环重载）
	mergedAgain, _, err := MergeManualConfig(freshJSON, merged, freshJSON)
	if err != nil {
		t.Fatalf("second MergeManualConfig failed: %v", err)
	}
	h1, c1, err := ProxyOutboundsFingerprint(merged)
	if err != nil {
		t.Fatal(err)
	}
	h2, c2, err := ProxyOutboundsFingerprint(mergedAgain)
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
	if err := SaveBaseSnapshot(sbPath, base); err != nil {
		t.Fatalf("SaveBaseSnapshot failed: %v", err)
	}
	baseInfo, err := os.Stat(BaseSnapshotPath(sbPath))
	if err != nil || baseInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected base snapshot mode 0600, got %v (err=%v)", baseInfo, err)
	}

	edited := `{"log":{"level":"debug"},"inbounds":[{"tag":"tun-in","type":"tun"},{"tag":"socks-in","type":"socks","listen_port":1080}],"outbounds":[{"tag":"#DC","type":"direct"}],"route":{"rules":[{"action":"sniff"}]}}`
	if err := os.WriteFile(sbPath, []byte(edited), 0600); err != nil {
		t.Fatal(err)
	}

	fresh := `{"log":{"level":"warn"},"inbounds":[{"tag":"tun-in","type":"tun"}],"outbounds":[{"tag":"US-01","type":"vless","server":"198.51.100.20","server_port":443},{"tag":"#DC","type":"direct"}],"route":{"rules":[{"action":"sniff"}]}}`

	// 开关开启 (preserveManual = true)：保留 socks-in 与 log.level=debug，同时拥有新节点 US-01
	outOn, cntOn := PrepareRegeneratedConfig(t.Context(), sbPath, fresh, true)
	if cntOn == 0 || !strings.Contains(outOn, `"socks-in"`) || !strings.Contains(outOn, `"debug"`) || !strings.Contains(outOn, `"US-01"`) {
		t.Fatalf("expected preserveManual=true to keep manual edits + new node, cnt=%d out=%s", cntOn, outOn)
	}

	// 开关关闭 (preserveManual = false)：全新覆盖，不保留 socks-in 与 debug
	outOff, cntOff := PrepareRegeneratedConfig(t.Context(), sbPath, fresh, false)
	if cntOff != 0 || strings.Contains(outOff, `"socks-in"`) || strings.Contains(outOff, `"debug"`) {
		t.Fatalf("expected preserveManual=false to produce clean template without manual edits, cnt=%d out=%s", cntOff, outOff)
	}
}
