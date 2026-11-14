package singbox

import (
	"os"
	"os/exec"
	"path/filepath"
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
