package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
)

func TestDetectSSHPorts_OpenWrtDropbearAndSSHD(t *testing.T) {
	dir := t.TempDir()
	sshdCfg := filepath.Join(dir, "sshd_config")
	dropbearCfg := filepath.Join(dir, "dropbear")

	if err := os.WriteFile(sshdCfg, []byte("# comment\nPort 2200\nPort 22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropbearCfg, []byte("config dropbear\n\toption PasswordAuth 'off'\n\toption Port '2222'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ports := detectSSHPortsFrom("192.0.2.10 54321 192.0.2.1 2222", []string{sshdCfg}, dropbearCfg)
	for _, want := range []int{2222, 2200, 22} {
		if !slices.Contains(ports, want) {
			t.Fatalf("expected detected ports %v to contain %d", ports, want)
		}
	}

	// Fallback to 22 when no files/env specify an explicit port
	fallback := detectSSHPortsFrom("", []string{filepath.Join(dir, "missing")}, filepath.Join(dir, "missing-db"))
	if !slices.Equal(fallback, []int{22}) {
		t.Fatalf("expected fallback [22], got %v", fallback)
	}
}

func TestBuildSecurityNFTWithOptions_ModesAndSelfLockProtection(t *testing.T) {
	if len(DefaultProtectedPorts()) == 0 {
		t.Fatal("DefaultProtectedPorts should not be empty")
	}
	if !slices.Contains(DefaultWhitelistV4(), "100.64.0.0/10") {
		t.Fatal("DefaultWhitelistV4 should protect Tailscale CGNAT 100.64.0.0/10")
	}
	if !slices.Contains(DefaultForeverBlocklistV4(), "167.94.145.0/24") {
		t.Fatal("DefaultForeverBlocklistV4 should contain builtin scanner range")
	}

	opts := BuildOptions{
		SSHConnection:        "192.0.2.55 51234 192.0.2.1 2222",
		CallerIP:             "198.51.100.77",
		ActiveSSHPorts:       []int{2222},
		Mode:                 "standard",
		BanTimeoutDays:       14,
		PingLimitPerSec:      25,
		CustomWhitelist:      []string{"203.0.113.10", "2001:db8:cafe::/48"},
		ExtraForeverBan:      []string{"198.51.100.0/24"},
		CustomProtectedPorts: []int{23, 2222, 443, 8090, 5900},
	}

	nft := BuildSecurityNFTWithOptions(opts)
	for _, mustContain := range []string{
		"table inet security",
		"timeout 14d",
		"limit rate 25/second counter accept",
		"192.0.2.55",
		"198.51.100.77",
		"203.0.113.10",
		"2001:db8:cafe::/48",
		"198.51.100.0/24",
		"set whitelist_ip6",
		"set protected_ports",
		"5900",
	} {
		if !strings.Contains(nft, mustContain) {
			t.Fatalf("standard ruleset missing %q", mustContain)
		}
	}

	// Ensure active SSH port 2222 and critical service ports (443, 8090) are excluded from protected_ports
	idx := strings.Index(nft, "set protected_ports")
	if idx < 0 {
		t.Fatal("protected_ports block missing")
	}
	endIdx := strings.Index(nft[idx:], "\n    }")
	if endIdx < 0 {
		t.Fatal("protected_ports block unclosed")
	}
	portBlock := nft[idx : idx+endIdx]
	for _, forbidden := range []string{"2222", "443", "8090"} {
		if strings.Contains(portBlock, forbidden) {
			t.Fatalf("protected_ports must never contain critical/SSH port %s; got:\n%s", forbidden, portBlock)
		}
	}

	// Minimal mode omits protected_ports set while preserving whitelist + dynamic + forever sets
	minOpts := opts
	minOpts.Mode = "minimal"
	minNFT := BuildSecurityNFTWithOptions(minOpts)
	if strings.Contains(minNFT, "set protected_ports") {
		t.Fatal("minimal mode must not declare set protected_ports")
	}
	if !strings.Contains(minNFT, "set blocklist_ip4_forever") || !strings.Contains(minNFT, "set whitelist_ip6") {
		t.Fatal("minimal mode must retain forever blocklist and IPv6 whitelist")
	}
}

func TestParseSecurityTableJSON_CountersSetsAndRanges(t *testing.T) {
	fixture := `{
  "nftables": [
    {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
    {"table": {"family": "inet", "name": "security", "handle": 10}},
    {"set": {"family": "inet", "name": "whitelist_ip", "table": "security", "type": "ipv4_addr", "elem": [
      {"prefix": {"addr": "10.0.0.0", "len": 8}},
      {"prefix": {"addr": "100.64.0.0", "len": 10}},
      "203.0.113.10"
    ]}},
    {"set": {"family": "inet", "name": "whitelist_ip6", "table": "security", "type": "ipv6_addr", "elem": [
      {"prefix": {"addr": "fd00::", "len": 8}}
    ]}},
    {"set": {"family": "inet", "name": "blocklist_ip4_forever", "table": "security", "type": "ipv4_addr", "elem": [
      {"range": ["167.94.145.0", "167.94.146.255"]},
      {"prefix": {"addr": "198.51.100.0", "len": 24}}
    ]}},
    {"set": {"family": "inet", "name": "blocklist_ip4", "table": "security", "type": "ipv4_addr", "timeout": 604800, "elem": [
      {"elem": {"val": "203.0.113.99", "timeout": 604800, "expires": 518400}}
    ]}},
    {"set": {"family": "inet", "name": "blocklist_ip6", "table": "security", "type": "ipv6_addr", "timeout": 604800, "elem": [
      {"elem": {"val": "2001:db8::99", "timeout": 604800, "expires": 3600}}
    ]}},
    {"set": {"family": "inet", "name": "protected_ports", "table": "security", "type": "inet_service", "elem": [
      {"range": [20, 23]},
      3389
    ]}},
    {"rule": {"family": "inet", "table": "security", "chain": "input", "handle": 20, "expr": [
      {"limit": {"rate": 15, "per": "second"}},
      {"counter": {"packets": 4, "bytes": 336}},
      {"accept": null}
    ]}},
    {"rule": {"family": "inet", "table": "security", "chain": "input", "handle": 21, "expr": [
      {"log": {"prefix": "[NFT] Ban Forever IPv4: "}},
      {"counter": {"packets": 120, "bytes": 7200}},
      {"drop": null}
    ]}},
    {"rule": {"family": "inet", "table": "security", "chain": "input", "handle": 22, "expr": [
      {"log": {"prefix": "[NFT] Blocked IPv4 (listed): "}},
      {"counter": {"packets": 80, "bytes": 4800}},
      {"drop": null}
    ]}},
    {"rule": {"family": "inet", "table": "security", "chain": "input", "handle": 23, "expr": [
      {"log": {"prefix": "[NFT] Blocked IPv4 TCP: "}},
      {"counter": {"packets": 35, "bytes": 2100}},
      {"drop": null}
    ]}}
  ]
}`

	snap, err := ParseSecurityTableJSON([]byte(fixture))
	if err != nil {
		t.Fatalf("ParseSecurityTableJSON error: %v", err)
	}
	if !snap.Active || snap.Mode != "standard" {
		t.Fatalf("expected active standard snapshot, got active=%v mode=%s", snap.Active, snap.Mode)
	}
	if snap.BanTimeoutDays != 7 || snap.PingLimitPerSec != 15 {
		t.Fatalf("unexpected params: timeout=%d ping=%d", snap.BanTimeoutDays, snap.PingLimitPerSec)
	}
	if !slices.Contains(snap.ForeverV4, "167.94.145.0-167.94.146.255") || !slices.Contains(snap.ForeverV4, "198.51.100.0/24") {
		t.Fatalf("expected auto-merged range + CIDR in ForeverV4, got %v", snap.ForeverV4)
	}
	if len(snap.DynamicV4) != 1 || snap.DynamicV4[0].Target != "203.0.113.99" || snap.DynamicV4[0].ExpiresSec != 518400 {
		t.Fatalf("unexpected DynamicV4: %+v", snap.DynamicV4)
	}
	if len(snap.DynamicV6) != 1 || snap.DynamicV6[0].Target != "2001:db8::99" {
		t.Fatalf("unexpected DynamicV6: %+v", snap.DynamicV6)
	}
	if !slices.Equal(snap.ProtectedPorts, []int{20, 21, 22, 23, 3389}) {
		t.Fatalf("unexpected ProtectedPorts: %v", snap.ProtectedPorts)
	}
	if snap.Stats.TotalBlockedPackets != 235 || snap.Stats.TotalBlockedBytes != 14100 {
		t.Fatalf("unexpected total counters: %+v", snap.Stats)
	}

	// Verify CollapseLargeSetsInNFTText collapses >12 entries
	manySnap := &KernelSnapshot{DynamicV4: make([]BanItem, 15)}
	var elems []string
	for i := 1; i <= 15; i++ {
		elems = append(elems, fmt.Sprintf("203.0.113.%d", i))
	}
	rawNFT := "table inet security {\n    set blocklist_ip4 {\n        type ipv4_addr\n        elements = { " + strings.Join(elems, ", ") + " }\n    }\n}"
	collapsed := CollapseLargeSetsInNFTText(rawNFT, manySnap)
	if !strings.Contains(collapsed, "共 15 条动态封禁 IP") || strings.Contains(collapsed, "203.0.113.15") {
		t.Fatalf("expected dynamic set collapse, got:\n%s", collapsed)
	}
}

func TestValidateBanAndWhitelistTargets_SelfLockGuard(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{ServerIP: "198.51.100.200"},
	}

	rejectCases := []struct {
		target string
		scope  string
	}{
		{"", "dynamic"},
		{"192.168.1.50", "dynamic"},
		{"10.0.0.5", "dynamic"},
		{"100.64.1.2", "dynamic"},
		{"127.0.0.1", "dynamic"},
		{"8.8.8.8", "dynamic"},
		{"1.1.1.1", "forever"},
		{"203.0.113.88", "dynamic"},   // matches callerIP below
		{"198.51.100.200", "dynamic"}, // matches ServerIP above
		{"203.0.0.0/8", "forever"},    // too broad (< /16)
		{"203.0.113.0/24", "dynamic"}, // CIDR not allowed in dynamic scope
		{"2001:db8::/48", "forever"},  // IPv6 not allowed in forever scope
		{"not-an-ip", "dynamic"},
	}
	for _, tc := range rejectCases {
		if norm, _, err := ValidateBanTarget(tc.target, tc.scope, "203.0.113.88", cfg); err == nil {
			t.Fatalf("expected ValidateBanTarget(%q, %q) to fail, got normalized=%q", tc.target, tc.scope, norm)
		}
	}

	norm, isV6, err := ValidateBanTarget("203.0.113.42", "dynamic", "203.0.113.88", cfg)
	if err != nil || isV6 || norm != "203.0.113.42" {
		t.Fatalf("unexpected result for valid IPv4 dynamic ban: norm=%q isV6=%v err=%v", norm, isV6, err)
	}

	norm6, isV6, err := ValidateBanTarget("2001:db8::42", "dynamic", "203.0.113.88", cfg)
	if err != nil || !isV6 || norm6 != "2001:db8::42" {
		t.Fatalf("unexpected result for valid IPv6 dynamic ban: norm=%q isV6=%v err=%v", norm6, isV6, err)
	}

	normNet, isV6, err := ValidateBanTarget("203.0.113.0/24", "forever", "198.51.100.1", cfg)
	if err != nil || isV6 || normNet != "203.0.113.0/24" {
		t.Fatalf("unexpected result for valid forever CIDR: norm=%q isV6=%v err=%v", normNet, isV6, err)
	}

	wNorm, wV6, err := ValidateWhitelistTarget("2001:db8:1::/48")
	if err != nil || !wV6 || wNorm != "2001:db8:1::/48" {
		t.Fatalf("unexpected whitelist normalization: norm=%q isV6=%v err=%v", wNorm, wV6, err)
	}
	if !IsBuiltinWhitelist("10.0.0.0/8") || !IsBuiltinWhitelist("100.64.0.0/10") || IsBuiltinWhitelist("203.0.113.10") {
		t.Fatal("IsBuiltinWhitelist mismatch")
	}
}

func TestParseNFTLogLines_SanitizesWAN(t *testing.T) {
	rawLogs := strings.Join([]string{
		"[12345.678901] [NFT] Blocked IPv4 TCP: IN=pppoe-wan OUT= MAC=00:00:00:00:00:00 SRC=203.0.113.99 DST=198.51.100.1 LEN=44 PROTO=TCP SPT=54321 DPT=3389 SYN",
		"[12346.100000] [NFT] Ban Forever IPv4: IN=eth1 OUT= SRC=198.51.100.55 DST=192.0.2.1 PROTO=UDP DPT=1434",
		"[12347.000000] unrelated kernel line",
	}, "\n")

	events := ParseNFTLogLines(rawLogs, 10)
	if len(events) != 2 {
		t.Fatalf("expected 2 parsed events, got %d", len(events))
	}
	// Latest first
	if events[0].SrcIP != "198.51.100.55" || events[0].Category != "永久黑段拦截" || events[0].DstPort != 1434 {
		t.Fatalf("unexpected first event: %+v", events[0])
	}
	if events[1].SrcIP != "203.0.113.99" || events[1].Category != "IPv4 高危 TCP 诱捕" || events[1].Iface != "pppoe-wan" || events[1].Proto != "TCP" || events[1].DstPort != 3389 {
		t.Fatalf("unexpected second event: %+v", events[1])
	}

	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	// Router WAN DST IPs must never appear anywhere in serialized log events
	for _, wanIP := range []string{"198.51.100.1", "192.0.2.1"} {
		if strings.Contains(string(encoded), wanIP) {
			t.Fatalf("serialized NFTLogEvent leaked router WAN IP %s: %s", wanIP, string(encoded))
		}
	}
}

func TestParseSecurityTableJSON_TerseMode(t *testing.T) {
	terseStandard := `{
  "nftables": [
    {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
    {"table": {"family": "inet", "name": "security", "handle": 10}},
    {"set": {"family": "inet", "name": "blocklist_ip4_forever", "table": "security", "type": "ipv4_addr"}},
    {"set": {"family": "inet", "name": "blocklist_ip4", "table": "security", "type": "ipv4_addr", "timeout": 604800}},
    {"set": {"family": "inet", "name": "blocklist_ip6", "table": "security", "type": "ipv6_addr", "timeout": 604800}},
    {"set": {"family": "inet", "name": "whitelist_ip", "table": "security", "type": "ipv4_addr"}},
    {"set": {"family": "inet", "name": "protected_ports", "table": "security", "type": "inet_service"}}
  ]
}`
	snapStd, err := ParseSecurityTableJSON([]byte(terseStandard))
	if err != nil {
		t.Fatalf("ParseSecurityTableJSON terse standard error: %v", err)
	}
	if !snapStd.Active || snapStd.Mode != "standard" {
		t.Fatalf("expected active=true mode=standard for terse output with protected_ports, got active=%v mode=%s", snapStd.Active, snapStd.Mode)
	}

	terseMinimal := `{
  "nftables": [
    {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
    {"table": {"family": "inet", "name": "security", "handle": 10}},
    {"set": {"family": "inet", "name": "blocklist_ip4_forever", "table": "security", "type": "ipv4_addr"}},
    {"set": {"family": "inet", "name": "blocklist_ip4", "table": "security", "type": "ipv4_addr", "timeout": 604800}},
    {"set": {"family": "inet", "name": "blocklist_ip6", "table": "security", "type": "ipv6_addr", "timeout": 604800}},
    {"set": {"family": "inet", "name": "whitelist_ip", "table": "security", "type": "ipv4_addr"}}
  ]
}`
	snapMin, err := ParseSecurityTableJSON([]byte(terseMinimal))
	if err != nil {
		t.Fatalf("ParseSecurityTableJSON terse minimal error: %v", err)
	}
	if !snapMin.Active || snapMin.Mode != "minimal" {
		t.Fatalf("expected active=true mode=minimal for terse output without protected_ports, got active=%v mode=%s", snapMin.Active, snapMin.Mode)
	}
}
