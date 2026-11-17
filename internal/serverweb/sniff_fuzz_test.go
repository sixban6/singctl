package serverweb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeIPString_LinuxSSAndZoneFormats(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"198.51.100.42:54321", "198.51.100.42"},
		{"[::ffff:198.51.100.42]:54321", "198.51.100.42"},
		{"::ffff:198.51.100.42:54321", "198.51.100.42"},
		{"[::FFFF:203.0.113.9]:443", "203.0.113.9"},
		{"::FFFF:203.0.113.9:443", "203.0.113.9"},
		{"198.51.100.42%eth0:54321", "198.51.100.42"},
		{"[2001:db8::1%eth0]:54321", "2001:db8::1"},
		{"not-an-ip:443", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := normalizeIPString(tc.raw); got != tc.want {
			t.Errorf("normalizeIPString(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestParseNFTDuration_OverflowAndNegativeGuard(t *testing.T) {
	if got := parseNFTDuration("-5h"); got != 0 {
		t.Fatalf("expected negative duration to clamp to 0, got %v", got)
	}
	if got := parseNFTDuration("999999999999d"); got < 0 {
		t.Fatalf("expected huge day count not to overflow negative, got %v", got)
	}
	if got := parseNFTDuration("2d3h"); got != 51*time.Hour {
		t.Fatalf("expected 51h, got %v", got)
	}
}

func TestReadTailBytes_DiscardsTornFirstLine(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "kern.log")
	line1 := "2026-05-01T10:00:00Z host kernel: [NFT] DROP IN=eth0 SRC=198.51.100.123 DST=203.0.113.1 PROTO=TCP DPT=23\n"
	line2 := "2026-05-01T10:00:01Z host kernel: [NFT] DROP IN=eth0 SRC=203.0.113.88 DST=203.0.113.1 PROTO=TCP DPT=3389\n"
	if err := os.WriteFile(logFile, []byte(line1+line2), 0600); err != nil {
		t.Fatal(err)
	}

	// Cut right after "SRC=1" in line1 so naive tail read would start with "98.51.100.123..."
	idx := strings.Index(line1, "198.51.100.123")
	maxBytes := int64(len(line1)+len(line2)) - int64(idx+1)

	tail, err := readTailBytes(logFile, maxBytes)
	if err != nil {
		t.Fatalf("readTailBytes failed: %v", err)
	}
	if strings.Contains(string(tail), "98.51.100.123") {
		t.Fatalf("readTailBytes kept torn first line (risk of corrupted IP): %q", string(tail))
	}
	if !strings.Contains(string(tail), "203.0.113.88") {
		t.Fatalf("expected intact second line in tail, got %q", string(tail))
	}
}

func FuzzSniffParsers(f *testing.F) {
	f.Add("elements = { 198.51.100.5 timeout 7d expires 6d23h59m, 198.51.100.0/24 }")
	f.Add("2026-05-01 12:30:45,123 fail2ban.actions [123]: NOTICE [sshd] Ban 203.0.113.45")
	f.Add("SYN-RECV 0 0 [::ffff:203.0.113.1]:443 ::ffff:198.51.100.77:51234")
	f.Add("Mar  7 03:15:22 vps kernel: [NFT] SRC=198.51.100.9 DST=203.0.113.1 DPT=445")
	f.Add("   `- Banned IP list:\t198.51.100.11 2001:db8::2 invalid_tok")

	refNow := time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, raw string) {
		_ = normalizeIPString(raw)
		_ = ComputeSubnetCIDR(raw)
		_ = MatchScannerTag(raw, raw)
		_ = parseNFTDuration(raw)
		_ = parseNFTSetEntries(raw, refNow)
		_ = parseFail2banLogTimestamps(raw, refNow)
		_ = parseFail2banBannedIPs(raw)
		_ = parseSSExternalProbes(raw)
		_ = parseLogLineTimestamp(raw, refNow)
	})
}
