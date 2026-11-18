package serverweb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSniffTracker_AntiLockoutGuardsAndConcurrentPersistence(t *testing.T) {
	dir := t.TempDir()
	sniffPath := filepath.Join(dir, "sniff.json")
	banPath := filepath.Join(dir, "bans.json")

	lim := NewIPLimiter(3, time.Minute, time.Hour, banPath)
	defer lim.Close()

	tr := NewSniffTracker(nil, lim, sniffPath)
	ctx := t.Context()

	operatorIP := "198.51.100.10"
	proxyClientIP := "203.0.113.25"
	tr.MarkTrustedClientIPs(proxyClientIP)

	// 1. Must block self-lockout on operator IP, operator /24 CIDR, trusted proxy client IP, private LAN, and overly wide /8 CIDR
	for _, blockedCase := range []string{
		"",
		"not-an-ip",
		"127.0.0.1",
		"192.168.1.1",
		"10.0.0.0/24",
		"198.51.0.0/8",
		operatorIP,
		"198.51.100.0/24", // contains operatorIP!
		proxyClientIP,
		"203.0.113.0/24", // contains active trusted proxyClientIP!
	} {
		if _, _, err := tr.BlockTargetForNode(ctx, blockedCase, "local", operatorIP); err == nil {
			t.Errorf("expected anti-lockout guard to reject target %q, got nil", blockedCase)
		}
	}

	// 2. Concurrent ObserveNodeAt + IngestRemoteSniffOutput + Snapshot under -race
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := fmt.Sprintf("198.51.100.%d", 100+id)
			tr.Observe(ip, "TLS/443 握手探测", "masqueraded", 3)
			tr.ObserveNode("edge-1", "Edge-US", ip, "SSH/:2222 端口试探", "observing", 2)
			tr.IngestRemoteSniffOutput("edge-1", "Edge-US",
				"===NFT_V4===\nelements = { 203.0.113.99 timeout 7d expires 6d23h }\n===F2B===\n`- Banned IP list: 203.0.113.98\n===SS===\nSYN-RECV 0 0 [::ffff:203.0.113.1]:443 ::ffff:198.51.100.200:54321\n")
		}(g)
	}
	wg.Wait()

	tr.Flush()
	st, err := os.Stat(sniffPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 sniff.json, got %v (err=%v)", st, err)
	}

	// Reload into fresh SniffTracker and verify persisted records + remote NFT scripts
	tr2 := NewSniffTracker(nil, lim, sniffPath)
	snap := tr2.buildSnapshot(ctx, "all", false, true)
	if snap.TotalSniffIPs == 0 {
		t.Fatal("expected reloaded SniffTracker to retain persisted unique IPs")
	}

	if s := buildRemoteNFTBlockScript("203.0.113.88", false, true); !strings.Contains(s, "203.0.113.88") {
		t.Fatalf("unexpected remote NFT block script: %s", s)
	}
	if s := buildRemoteNFTUnblockScript("203.0.113.0/24", true, true); !strings.Contains(s, "203.0.113.0/24") {
		t.Fatalf("unexpected remote NFT unblock script: %s", s)
	}
	if s := buildRemoteNFTFlushScript(); s == "" {
		t.Fatal("expected non-empty remote NFT flush script")
	}
}

func TestSniffTracker_NFTTableAutoBootstrapOnMissingSecurityTable(t *testing.T) {
	// 1. Remote script must self-heal missing `table inet security` and preload nf_tables
	remoteIPScript := buildRemoteNFTBlockScript("203.0.113.88", false, true)
	for _, want := range []string{
		"nft list table inet security",
		"modprobe nf_tables",
		"table inet security",
		"blocklist_ip4",
		"203.0.113.88",
	} {
		if !strings.Contains(remoteIPScript, want) {
			t.Fatalf("remote block script missing %q:\n%s", want, remoteIPScript)
		}
	}

	// 2. Local applyNFTBlockIP: simulate missing `table inet security` via fake nft binary in PATH
	binDir := t.TempDir()
	stateFile := filepath.Join(binDir, "table_loaded")
	logFile := filepath.Join(binDir, "nft_calls.log")
	fakeNFT := filepath.Join(binDir, "nft")
	script := fmt.Sprintf(`#!/bin/sh
echo "$@" >> %q
if [ "$1" = "list" ] && [ "$2" = "table" ] && [ "$3" = "inet" ] && [ "$4" = "security" ]; then
  [ -f %q ] && exit 0 || exit 1
fi
if [ "$1" = "-f" ]; then
  touch %q
  exit 0
fi
if [ "$1" = "add" ] && [ "$2" = "element" ]; then
  [ -f %q ] && exit 0 || exit 1
fi
exit 0
`, logFile, stateFile, stateFile, stateFile)
	if err := os.WriteFile(fakeNFT, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	if err := applyNFTBlockIP("203.0.113.77", true); err != nil {
		t.Fatalf("expected applyNFTBlockIP to auto-bootstrap missing security table and succeed, got: %v", err)
	}
	callsBytes, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(callsBytes)
	if !strings.Contains(calls, "list table inet security") || !strings.Contains(calls, "-f") || !strings.Contains(calls, "add element inet security blocklist_ip4") {
		t.Fatalf("expected list -> -f bootstrap -> add element sequence, got:\n%s", calls)
	}
}
