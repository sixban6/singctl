package sniff_test

import (
	"strings"
	"testing"
	"time"

	"singctl/internal/sniff"
)

func TestBuildNFTBlockBatchScript_SingleTransactionAndValidation(t *testing.T) {
	ops := []sniff.NFTBlockOp{
		{Action: sniff.NFTActionBlockIP, Target: "203.0.113.10", IsIPv4: true, Timeout: 7 * 24 * time.Hour},
		{Action: sniff.NFTActionBlockIP, Target: "2001:db8::99", IsIPv4: false, Timeout: 7 * 24 * time.Hour},
		{Action: sniff.NFTActionBlockCIDR, Target: "198.51.100.0/24", IsIPv4: true},
		{Action: sniff.NFTActionUnblock, Target: "192.0.2.55", IsIPv4: true},
		{Action: sniff.NFTActionUnblockCIDR, Target: "203.0.113.0/24", IsIPv4: true},
	}

	script, err := sniff.BuildNFTBlockBatchScript(ops)
	if err != nil {
		t.Fatalf("BuildNFTBlockBatchScript failed: %v", err)
	}
	for _, want := range []string{
		"add element inet security blocklist_ip4 { 203.0.113.10 timeout 604800s }",
		"add element inet security blocklist_ip6 { 2001:db8::99 timeout 604800s }",
		"add element inet security blocklist_ip4_forever { 198.51.100.0/24 }",
		"delete element inet security blocklist_ip4 { 192.0.2.55 }",
		"delete element inet security blocklist_ip4_forever { 203.0.113.0/24 }",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("batch script missing %q:\n%s", want, script)
		}
	}

	flushScript, err := sniff.BuildNFTBlockBatchScript([]sniff.NFTBlockOp{{Action: sniff.NFTActionFlushAll}})
	if err != nil {
		t.Fatalf("flush batch failed: %v", err)
	}
	for _, want := range []string{
		"flush set inet security blocklist_ip4",
		"flush set inet security blocklist_ip6",
		"flush set inet security blocklist_ip4_forever",
	} {
		if !strings.Contains(flushScript, want) {
			t.Fatalf("flush batch missing %q:\n%s", want, flushScript)
		}
	}

	// Reject shell/nft injection payloads
	for _, badTarget := range []string{"", "203.0.113.1; flush ruleset", "203.0.113.1\ndrop", "not-an-ip"} {
		if _, err := sniff.BuildNFTBlockBatchScript([]sniff.NFTBlockOp{
			{Action: sniff.NFTActionBlockIP, Target: badTarget, IsIPv4: true},
		}); err == nil {
			t.Fatalf("expected invalid/injection target %q to be rejected", badTarget)
		}
	}
}
