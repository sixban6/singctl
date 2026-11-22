// 文件职责：覆盖本地 AdGuard DNS 与加密 DoH 兜底热切换及 RFC 6303 私网 PTR NXDOMAIN 防环注入测试。
package singbox_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
)

func TestPatchDNSLocalJSON_RoundTripAndSingBoxCheck(t *testing.T) {
	base := `{
  "dns": {
    "servers": [
      {"tag": "dns_proxy", "type": "udp", "server": "8.8.8.8"},
      {"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}
    ],
    "final": "dns_proxy"
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "store_dns": true,
      "store_fakeip": true
    }
  }
}`

	toAGH, changed, err := singbox.PatchDNSLocalJSON(base, true, 5353)
	if err != nil {
		t.Fatalf("PatchDNSLocalJSON(useAdGuard=true) failed: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true when switching to AdGuard Home")
	}

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(toAGH), 0600); err != nil {
		t.Fatal(err)
	}
	linked, port := singbox.InspectSingBoxDNSLocal(cfgPath)
	if !linked || port != 5353 {
		t.Fatalf("expected linked=true port=5353, got linked=%v port=%d", linked, port)
	}

	_, changedAgain, err := singbox.PatchDNSLocalJSON(toAGH, true, 5353)
	if err != nil {
		t.Fatal(err)
	}
	if changedAgain {
		t.Fatal("expected changed=false on idempotent call")
	}

	toFallback, changedFB, err := singbox.PatchDNSLocalJSON(toAGH, false, 5353)
	if err != nil {
		t.Fatalf("PatchDNSLocalJSON(useAdGuard=false) failed: %v", err)
	}
	if !changedFB {
		t.Fatal("expected changed=true when switching back to encrypted DoH fallback")
	}
	if err := os.WriteFile(cfgPath, []byte(toFallback), 0600); err != nil {
		t.Fatal(err)
	}
	linkedFB, _ := singbox.InspectSingBoxDNSLocal(cfgPath)
	if linkedFB {
		t.Fatal("expected linked=false after fallback to pure-IP DoH")
	}

	if sbBin, err := exec.LookPath("sing-box"); err == nil && sbBin != "" {
		for name, content := range map[string]string{"adguard": toAGH, "fallback_doh": toFallback} {
			checkFile := filepath.Join(tmpDir, name+".json")
			if err := os.WriteFile(checkFile, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.CommandContext(t.Context(), sbBin, "check", "-c", checkFile).CombinedOutput(); err != nil {
				t.Fatalf("sing-box check failed for %s: %v\n%s", name, err, string(out))
			}
		}
	}
}

func TestInjectPrivatePTRBlockRules_PrecedesClashAndNoWildcardARPA(t *testing.T) {
	base := `{
  "dns": {
    "servers": [
      {"tag": "dns_local", "type": "udp", "server": "127.0.0.1", "server_port": 5353},
      {"tag": "dns_proxy", "type": "udp", "server": "8.8.8.8"}
    ],
    "rules": [
      {"clash_mode": "Direct", "server": "dns_local"},
      {"rule_set": "geosite-private", "server": "dns_local"}
    ],
    "final": "dns_proxy"
  }
}`

	injected, err := singbox.InjectPrivatePTRBlockRules(base)
	if err != nil {
		t.Fatalf("InjectPrivatePTRBlockRules failed: %v", err)
	}

	parsed, err := sboption.ParseDocument([]byte(injected))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNS.Rules) != 4 {
		t.Fatalf("expected 4 rules (2 prepended + 2 existing), got %d: %+v", len(parsed.DNS.Rules), parsed.DNS.Rules)
	}
	r0 := parsed.DNS.Rules[0]
	r1 := parsed.DNS.Rules[1]
	if r0.Action != "predefined" || r0.Rcode != "NXDOMAIN" || !slices.Equal(r0.DomainSuffix.Slice(), singbox.PrivateReverseDNSSuffixes()) {
		t.Fatalf("expected rule[0] to be private PTR predefined NXDOMAIN, got %+v", r0)
	}
	if r1.Action != "predefined" || r1.Rcode != "NXDOMAIN" || !slices.Equal(r1.DomainKeyword.Slice(), []string{singbox.DNSSDBrowseKeyword}) {
		t.Fatalf("expected rule[1] to be DNS-SD keyword predefined NXDOMAIN, got %+v", r1)
	}
	if parsed.DNS.Rules[2].ClashMode != "Direct" {
		t.Fatalf("expected clash_mode=Direct rule preserved after prepended rules, got %+v", parsed.DNS.Rules[2])
	}
	if strings.Contains(injected, `"in-addr.arpa"`) || strings.Contains(injected, `"ip6.arpa"`) {
		t.Fatalf("must not contain bare wildcard in-addr.arpa/ip6.arpa that blocks public rDNS:\n%s", injected)
	}

	again, err := singbox.InjectPrivatePTRBlockRules(injected)
	if err != nil {
		t.Fatalf("second InjectPrivatePTRBlockRules failed: %v", err)
	}
	if again != injected {
		t.Fatalf("expected identical output on idempotent InjectPrivatePTRBlockRules")
	}
}
