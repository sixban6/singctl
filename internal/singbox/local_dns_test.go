package singbox

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

	// 1. Switch to AdGuard Home (127.0.0.1:5353)
	toAGH, changed, err := PatchDNSLocalJSON(base, true, 5353)
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
	linked, port := InspectSingBoxDNSLocal(cfgPath)
	if !linked || port != 5353 {
		t.Fatalf("expected linked=true port=5353, got linked=%v port=%d", linked, port)
	}

	// Idempotent second call
	_, changedAgain, err := PatchDNSLocalJSON(toAGH, true, 5353)
	if err != nil {
		t.Fatal(err)
	}
	if changedAgain {
		t.Fatal("expected changed=false on idempotent call")
	}

	// 2. Fallback to built-in pure-IP encrypted DoH (zero-downtime stop/uninstall)
	toFallback, changedFB, err := PatchDNSLocalJSON(toAGH, false, 5353)
	if err != nil {
		t.Fatalf("PatchDNSLocalJSON(useAdGuard=false) failed: %v", err)
	}
	if !changedFB {
		t.Fatal("expected changed=true when switching back to encrypted DoH fallback")
	}
	if err := os.WriteFile(cfgPath, []byte(toFallback), 0600); err != nil {
		t.Fatal(err)
	}
	linkedFB, _ := InspectSingBoxDNSLocal(cfgPath)
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

	injected, err := InjectPrivatePTRBlockRules(base)
	if err != nil {
		t.Fatalf("InjectPrivatePTRBlockRules failed: %v", err)
	}

	var parsed struct {
		DNS struct {
			Rules []map[string]any `json:"rules"`
		} `json:"dns"`
	}
	if err := json.Unmarshal([]byte(injected), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNS.Rules) != 4 {
		t.Fatalf("expected 4 rules (2 prepended + 2 existing), got %d: %+v", len(parsed.DNS.Rules), parsed.DNS.Rules)
	}
	r0 := parsed.DNS.Rules[0]
	r1 := parsed.DNS.Rules[1]
	if r0["action"] != "predefined" || r0["rcode"] != "NXDOMAIN" || !matchesStringSliceField(r0["domain_suffix"], privateReverseDNSSuffixes) {
		t.Fatalf("expected rule[0] to be private PTR predefined NXDOMAIN, got %+v", r0)
	}
	if r1["action"] != "predefined" || r1["rcode"] != "NXDOMAIN" || !matchesStringSliceField(r1["domain_keyword"], []string{dnsSDBrowseKeyword}) {
		t.Fatalf("expected rule[1] to be DNS-SD keyword predefined NXDOMAIN, got %+v", r1)
	}
	if parsed.DNS.Rules[2]["clash_mode"] != "Direct" {
		t.Fatalf("expected clash_mode=Direct rule preserved after prepended rules, got %+v", parsed.DNS.Rules[2])
	}
	if strings.Contains(injected, `"in-addr.arpa"`) || strings.Contains(injected, `"ip6.arpa"`) {
		t.Fatalf("must not contain bare wildcard in-addr.arpa/ip6.arpa that blocks public rDNS:\n%s", injected)
	}

	// Idempotent re-injection makes no modification.
	again, err := InjectPrivatePTRBlockRules(injected)
	if err != nil {
		t.Fatalf("second InjectPrivatePTRBlockRules failed: %v", err)
	}
	if again != injected {
		t.Fatalf("expected identical output on idempotent InjectPrivatePTRBlockRules")
	}
}
