// 文件职责：验证 SmartDNS 域名/重写校验防注入、托管规则 0600 落盘、去广告预设与 4 MiB 体积硬上限。
package smartdns_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/smartdns"
)

func TestValidateDomainAndRewriteAnswer(t *testing.T) {
	goodDomains := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com"},
		{"SUB.Example.COM.", "sub.example.com"},
		{"nas.lan", "nas.lan"},
		{"_svc.home.example.com", "_svc.home.example.com"},
	}
	for _, tc := range goodDomains {
		got, err := smartdns.ValidateDomain(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ValidateDomain(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
		}
	}

	badDomains := []string{
		"",
		"   ",
		".example.com",
		"a..example.com",
		"example.com\naddress /evil.com/192.0.2.1",
		"example.com\rserver 192.0.2.1",
		"example.com /#",
		"example.com;rm -rf /",
		"*.example.com",
		"bad/slash.example.com",
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("a.", 130) + "com",
	}
	for _, bad := range badDomains {
		if got, err := smartdns.ValidateDomain(bad); err == nil {
			t.Errorf("ValidateDomain(%q) expected error, got %q", bad, got)
		}
	}

	goodAnswers := []struct {
		in   string
		want string
	}{
		{"192.0.2.10", "192.0.2.10"},
		{"192.168.1.10", "192.168.1.10"},
		{"2001:db8::10", "2001:db8::10"},
		{"#", "#"},
	}
	for _, tc := range goodAnswers {
		got, err := smartdns.ValidateRewriteAnswer(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ValidateRewriteAnswer(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
		}
	}

	badAnswers := []string{
		"",
		"   ",
		"not-an-ip",
		"example.com",
		"192.0.2.10\nbind 0.0.0.0:53",
		"#\nserver 192.0.2.1",
		"192.0.2.10 # comment",
	}
	for _, bad := range badAnswers {
		if got, err := smartdns.ValidateRewriteAnswer(bad); err == nil {
			t.Errorf("ValidateRewriteAnswer(%q) expected error, got %q", bad, got)
		}
	}
}

func TestValidateFilterURLAndCuratedPresets(t *testing.T) {
	presets := smartdns.CuratedFilterPresets()
	if len(presets) < 2 {
		t.Fatalf("expected at least 2 curated presets, got %d", len(presets))
	}
	wantIDs := map[string]string{
		"anti-ad-smartdns":      "https://anti-ad.net/anti-ad-for-smartdns.conf",
		"hagezi-light-smartdns": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt",
	}
	for _, p := range presets {
		if expectedURL, ok := wantIDs[p.ID]; ok {
			if p.URL != expectedURL {
				t.Errorf("preset %s URL = %q, want %q", p.ID, p.URL, expectedURL)
			}
			delete(wantIDs, p.ID)
		}
		if _, err := smartdns.ValidateFilterURL(p.URL); err != nil {
			t.Errorf("preset %s has invalid URL %q: %v", p.ID, p.URL, err)
		}
	}
	if len(wantIDs) != 0 {
		t.Fatalf("missing expected presets: %v", wantIDs)
	}

	for _, badURL := range []string{"", "file:///etc/passwd", "ftp://example.com/a.txt", "https://example.com/a\nb", "https:///nohost"} {
		if _, err := smartdns.ValidateFilterURL(badURL); err == nil {
			t.Errorf("ValidateFilterURL(%q) expected error", badURL)
		}
	}
}

func TestWriteManagedRules_Atomic0600AndValidation(t *testing.T) {
	rulesDir := filepath.Join(t.TempDir(), "smartdns-rules.d")

	err := smartdns.WriteManagedRules(rulesDir, smartdns.RuleSetInput{
		Whitelist: []string{"api.example.com", "API.EXAMPLE.COM", "sub.example.com"},
		Rewrites: []smartdns.RewriteEntry{
			{Domain: "nas.example.com", Answer: "192.0.2.10"},
			{Domain: "v6.example.com", Answer: "2001:db8::10"},
			{Domain: "block.example.com", Answer: "#"},
		},
		AuditBlockedDomains: []string{"tracker.example.com", "ads.example.com"},
	})
	if err != nil {
		t.Fatalf("WriteManagedRules failed: %v", err)
	}

	dirInfo, err := os.Stat(rulesDir)
	if err != nil || dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("rulesDir perm = %v err = %v, want 0700", dirInfo.Mode().Perm(), err)
	}

	checkFile := func(name string, wantLines []string) {
		t.Helper()
		p := filepath.Join(rulesDir, name)
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Errorf("%s perm = %04o, want 0600", name, fi.Mode().Perm())
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, want := range wantLines {
			if !strings.Contains(text, want) {
				t.Errorf("%s missing %q\ncontent:\n%s", name, want, text)
			}
		}
	}

	checkFile("whitelist.conf", []string{
		"domain-rules /api.example.com/ -address -",
		"domain-rules /sub.example.com/ -address -",
	})
	checkFile("rewrites.conf", []string{
		"address /nas.example.com/192.0.2.10",
		"address /v6.example.com/2001:db8::10",
		"address /block.example.com/#",
	})
	checkFile("audit_block.conf", []string{
		"address /tracker.example.com/#",
		"address /ads.example.com/#",
	})

	// Ensure placeholders creates adblock.conf without clobbering existing files
	if err := smartdns.EnsureRulePlaceholders(rulesDir); err != nil {
		t.Fatalf("EnsureRulePlaceholders failed: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(rulesDir, "adblock.conf")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected adblock.conf placeholder with 0600, fi=%v err=%v", fi, err)
	}

	// Reject injection payload without corrupting existing files
	if err := smartdns.WriteManagedRules(rulesDir, smartdns.RuleSetInput{
		Whitelist: []string{"ok.example.com\nserver 192.0.2.1"},
	}); err == nil {
		t.Fatal("expected injection payload rejected")
	}
	rawWL, _ := os.ReadFile(filepath.Join(rulesDir, "whitelist.conf"))
	if !strings.Contains(string(rawWL), "api.example.com") {
		t.Fatalf("existing whitelist.conf should remain intact after rejected write")
	}
}

func TestNormalizeAdblockLine(t *testing.T) {
	cases := []struct {
		line   string
		want   string
		wantOK bool
	}{
		{"", "", false},
		{"# comment", "", false},
		{"! adblock header", "", false},
		{"address /ads.example.com/#", "address /ads.example.com/#", true},
		{"address /ADS.EXAMPLE.COM/#4", "address /ads.example.com/#", true},
		{"address /track.example.com/0.0.0.0", "address /track.example.com/#", true},
		{"0.0.0.0 banner.example.com", "address /banner.example.com/#", true},
		{"127.0.0.1 pop.example.com # inline", "address /pop.example.com/#", true},
		{"127.0.0.1 localhost", "", false},
		{"||abp.example.com^", "address /abp.example.com/#", true},
		{"plain.example.com", "address /plain.example.com/#", true},
		// Injection / unsafe SmartDNS directives must be stripped!
		{"bind 0.0.0.0:53", "", false},
		{"server 192.0.2.1", "", false},
		{"conf-file /etc/shadow", "", false},
		{"address /evil.example.com/# -group bad", "", false},
		{"address /evil.example.com/192.0.2.99", "", false},
		{"singleword", "", false},
	}

	for _, tc := range cases {
		got, ok := smartdns.NormalizeAdblockLine(tc.line)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("NormalizeAdblockLine(%q) = (%q, %v), want (%q, %v)", tc.line, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestSyncAdblockFilters_DownloadNormalizeDedupPauseAndSizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/smartdns.conf":
			_, _ = w.Write([]byte(`# anti-ad sample
address /ad1.example.com/#
address /dup.example.com/#
bind 0.0.0.0:53
server 192.0.2.1
`))
		case "/domains.txt":
			_, _ = w.Write([]byte(`# hagezi light sample
dup.example.com
0.0.0.0 ad2.example.com
||ad3.example.com^
conf-file /etc/passwd
`))
		case "/oversized.txt":
			// Exceeds 4 MiB hard cap
			chunk := strings.Repeat("a.example.com\n", 1024)
			for range 400 {
				_, _ = w.Write([]byte(chunk))
			}
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	rulesDir := filepath.Join(t.TempDir(), "rules.d")

	// Normal sync merges + deduplicates + strips malicious directives
	count, err := smartdns.SyncAdblockFilters(t.Context(), rulesDir, []string{
		srv.URL + "/smartdns.conf",
		srv.URL + "/domains.txt",
	}, false)
	if err != nil {
		t.Fatalf("SyncAdblockFilters failed: %v", err)
	}
	if count != 4 {
		t.Fatalf("rule count = %d, want 4", count)
	}
	raw, err := os.ReadFile(filepath.Join(rulesDir, "adblock.conf"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"address /ad1.example.com/#",
		"address /dup.example.com/#",
		"address /ad2.example.com/#",
		"address /ad3.example.com/#",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("adblock.conf missing %q\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"bind 0.0.0.0:53", "server 192.0.2.1", "conf-file /etc/passwd"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("adblock.conf must NOT contain injected directive %q", forbidden)
		}
	}

	// Oversized file (> 4 MiB) is rejected and does NOT overwrite valid adblock.conf
	if _, err := smartdns.SyncAdblockFilters(t.Context(), rulesDir, []string{srv.URL + "/oversized.txt"}, false); err == nil {
		t.Fatal("expected oversized filter file (> 4 MiB) to be rejected")
	}
	rawAfterFail, _ := os.ReadFile(filepath.Join(rulesDir, "adblock.conf"))
	if !strings.Contains(string(rawAfterFail), "ad1.example.com") {
		t.Fatalf("existing adblock.conf was clobbered on oversized error")
	}

	// Paused writes empty placeholder and returns 0
	pausedCount, err := smartdns.SyncAdblockFilters(t.Context(), rulesDir, []string{srv.URL + "/smartdns.conf"}, true)
	if err != nil || pausedCount != 0 {
		t.Fatalf("paused SyncAdblockFilters = (%d, %v), want (0, nil)", pausedCount, err)
	}
	rawPaused, _ := os.ReadFile(filepath.Join(rulesDir, "adblock.conf"))
	if strings.Contains(string(rawPaused), "address /") {
		t.Fatalf("paused adblock.conf should not contain active block rules:\n%s", string(rawPaused))
	}
}
