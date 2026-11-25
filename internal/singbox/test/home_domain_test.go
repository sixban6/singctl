// 文件职责：测试 sing-box 配置编译流水线与热补丁对本地域名（.home）置顶 dns_local 解析与 direct 路由规则的幂等注入。
package singbox_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"singctl/internal/singbox"
)

func TestSingBox_HomeDomainDNSAndRouteRule(t *testing.T) {
	baseJSON := `{
  "dns": {
    "servers": [
      {"tag": "dns_proxy", "type": "https", "server": "1.1.1.1"},
      {"tag": "dns_local", "type": "udp", "server": "127.0.0.1", "server_port": 5353}
    ],
    "rules": [
      {"domain_suffix": ["openai.com"], "server": "dns_proxy"}
    ],
    "final": "dns_proxy"
  },
  "route": {
    "rules": [
      {"protocol": "dns", "action": "hijack-dns"},
      {"domain_suffix": ["openai.com"], "outbound": "#VPS"}
    ],
    "final": "#VPS"
  }
}`

	patched, changed, err := singbox.PatchHomeDomainDNSJSON(baseJSON, "home", "")
	if err != nil || !changed {
		t.Fatalf("PatchHomeDomainDNSJSON(home) = (changed=%v, err=%v), want (true, nil)", changed, err)
	}

	var doc struct {
		DNS struct {
			Rules []map[string]any `json:"rules"`
		} `json:"dns"`
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(patched), &doc); err != nil {
		t.Fatalf("unmarshal patched JSON: %v", err)
	}
	if len(doc.DNS.Rules) < 2 || doc.DNS.Rules[0]["server"] != "dns_local" {
		t.Fatalf("expected top dns rule pointing to dns_local, got %+v", doc.DNS.Rules)
	}
	if len(doc.Route.Rules) < 3 {
		t.Fatalf("expected direct route rule injected after hijack-dns, got %+v", doc.Route.Rules)
	}

	// Strictly idempotent
	patched2, changed2, err := singbox.PatchHomeDomainDNSJSON(patched, "home", "")
	if err != nil || changed2 || patched2 != patched {
		t.Fatalf("repeat PatchHomeDomainDNSJSON must be idempotent, changed=%v err=%v", changed2, err)
	}

	// Switching suffix home -> home.arpa replaces old rule cleanly
	patched3, changed3, err := singbox.PatchHomeDomainDNSJSON(patched, "home.arpa", "home")
	if err != nil || !changed3 {
		t.Fatalf("suffix switch failed: changed=%v err=%v", changed3, err)
	}
	if err := json.Unmarshal([]byte(patched3), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.DNS.Rules) != 2 {
		t.Fatalf("old home rule should be replaced, got %d dns rules: %+v", len(doc.DNS.Rules), doc.DNS.Rules)
	}
}

func TestSingBox_HomeDomainUsesActualDirectOutboundTagAndHealsLegacyDirect(t *testing.T) {
	// Real SingCtl config uses tag "#DC" for type "direct" (no tag named "direct"!)
	rawJSON := `{
  "outbounds": [
    {"type": "selector", "tag": "#VPS", "outbounds": ["#DC"]},
    {"type": "direct", "tag": "#DC"}
  ],
  "dns": {
    "servers": [
      {"tag": "dns_local", "type": "udp", "server": "127.0.0.1", "server_port": 5353}
    ],
    "rules": []
  },
  "route": {
    "rules": [
      {"domain_suffix": ["home"], "outbound": "direct"},
      {"protocol": "dns", "action": "hijack-dns"}
    ],
    "final": "#VPS"
  }
}`
	patched, changed, err := singbox.PatchHomeDomainDNSJSON(rawJSON, "home", "")
	if err != nil || !changed {
		t.Fatalf("expected #DC auto-heal patch, changed=%v err=%v", changed, err)
	}
	var doc struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(patched), &doc); err != nil {
		t.Fatal(err)
	}
	foundDC := false
	for _, r := range doc.Route.Rules {
		if r["outbound"] == "direct" {
			t.Fatalf("stale outbound=direct must be healed to #DC, got %+v", doc.Route.Rules)
		}
		if r["outbound"] == "#DC" {
			foundDC = true
		}
	}
	if !foundDC {
		t.Fatalf("expected direct route rule targeting #DC, got %+v", doc.Route.Rules)
	}
}

func TestFindSingBoxRunPIDs_ExcludesUjailEnvAndCheck(t *testing.T) {
	procRoot := t.TempDir()
	writeCmd := func(pid, cmdline string) {
		pDir := filepath.Join(procRoot, pid)
		if err := os.MkdirAll(pDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pDir, "cmdline"), []byte(cmdline), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeCmd("20289", "ujail\x00-n\x00sing-box\x00--\x00/usr/bin/sing-box\x00run\x00-c\x00/tmp/sing-box-work/config.json\x00")
	writeCmd("20290", "/usr/bin/env\x00GOMEMLIMIT=20MiB\x00/usr/bin/sing-box\x00run\x00-c\x00/tmp/sing-box-work/config.json\x00")
	writeCmd("20291", "/usr/bin/sing-box\x00run\x00-c\x00/tmp/sing-box-work/config.json\x00")
	writeCmd("20292", "/usr/bin/sing-box\x00check\x00-c\x00/etc/sing-box/config.json\x00")
	writeCmd("20293", "/usr/bin/singctl\x00dm\x00start\x00")

	got := singbox.FindSingBoxRunPIDs(procRoot)
	if !slices.Equal(got, []int{20291}) {
		t.Fatalf("FindSingBoxRunPIDs = %v, want [20291] (must exclude ujail/env/check)", got)
	}
}
