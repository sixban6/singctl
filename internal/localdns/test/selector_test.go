// 文件职责：验证双引擎防劫持 DNS（SmartDNS / AdGuard Home）硬件准入评估、自动选型策略与运行态活跃引擎解析边界契约。
package localdns_test

import (
	"errors"
	"strings"
	"testing"

	"singctl/internal/common/sysinfo"
	"singctl/internal/constant"
	"singctl/internal/localdns"
)

func TestRecommendEngine_DualEngineHardwareMatrix(t *testing.T) {
	const mib = 1024 * 1024

	cases := []struct {
		name               string
		hw                 localdns.HardwareProfile
		installed          map[string]bool
		wantRecommended    string
		wantActive         string
		wantAGHEligible    bool
		wantAGHDiskBlock   bool
		wantAGHMemBlock    bool
		wantSmartEligible  bool
		wantSmartDiskBlock bool
		wantSmartMemBlock  bool
	}{
		{
			name:              "high_spec_fresh_recommends_adguard",
			hw:                localdns.HardwareProfile{TotalRAMBytes: 2048 * mib, AvailRAMBytes: 1400 * mib, AvailDiskMB: 512},
			installed:         map[string]bool{},
			wantRecommended:   constant.DNSEngineAdGuard,
			wantActive:        constant.DNSEngineAdGuard,
			wantAGHEligible:   true,
			wantSmartEligible: true,
		},
		{
			name:              "n60pro_480m_total_205m_avail_50mb_disk_recommends_smartdns",
			hw:                localdns.HardwareProfile{TotalRAMBytes: 491040 * 1024, AvailRAMBytes: 210260 * 1024, AvailDiskMB: 50},
			installed:         map[string]bool{},
			wantRecommended:   constant.DNSEngineSmartDNS,
			wantActive:        constant.DNSEngineSmartDNS,
			wantAGHEligible:   false,
			wantAGHDiskBlock:  true,
			wantAGHMemBlock:   true,
			wantSmartEligible: true,
		},
		{
			name:              "ax3000t_256m_recommends_smartdns_eligible",
			hw:                localdns.HardwareProfile{TotalRAMBytes: 224 * mib, AvailRAMBytes: 72 * mib, AvailDiskMB: 25},
			installed:         map[string]bool{},
			wantRecommended:   constant.DNSEngineSmartDNS,
			wantActive:        constant.DNSEngineSmartDNS,
			wantAGHEligible:   false,
			wantAGHDiskBlock:  true,
			wantAGHMemBlock:   true,
			wantSmartEligible: true,
		},
		{
			name:              "tiny_flash_8mb_blocks_both_recommends_smartdns_ineligible",
			hw:                localdns.HardwareProfile{TotalRAMBytes: 2048 * mib, AvailRAMBytes: 1500 * mib, AvailDiskMB: 8},
			installed:         map[string]bool{},
			wantRecommended:   constant.DNSEngineSmartDNS,
			wantActive:        constant.DNSEngineSmartDNS,
			wantAGHEligible:   false,
			wantAGHDiskBlock:  true,
			wantSmartEligible: false,
			wantSmartDiskBlock: true,
		},
		{
			name:              "exact_adguard_boundary_512m_not_gt_falls_to_smartdns",
			hw:                localdns.HardwareProfile{TotalRAMBytes: 512 * mib, AvailRAMBytes: 256 * mib, AvailDiskMB: 80},
			installed:         map[string]bool{},
			wantRecommended:   constant.DNSEngineSmartDNS,
			wantActive:        constant.DNSEngineSmartDNS,
			wantAGHEligible:   false,
			wantAGHMemBlock:   true,
			wantSmartEligible: true,
		},
		{
			name:              "legacy_128m_router_111m_total_marks_smartdns_ineligible",
			hw:                localdns.HardwareProfile{TotalRAMBytes: 111 * mib, AvailRAMBytes: 64 * mib, AvailDiskMB: 20},
			installed:         map[string]bool{},
			wantRecommended:   constant.DNSEngineSmartDNS,
			wantActive:        constant.DNSEngineSmartDNS,
			wantAGHEligible:   false,
			wantAGHDiskBlock:  true,
			wantAGHMemBlock:   true,
			wantSmartEligible: false,
			wantSmartMemBlock: true,
		},
		{
			name:              "exhausted_avail_31m_marks_smartdns_ineligible",
			hw:                localdns.HardwareProfile{TotalRAMBytes: 224 * mib, AvailRAMBytes: 31 * mib, AvailDiskMB: 25},
			installed:         map[string]bool{},
			wantRecommended:   constant.DNSEngineSmartDNS,
			wantActive:        constant.DNSEngineSmartDNS,
			wantAGHEligible:   false,
			wantAGHDiskBlock:  true,
			wantAGHMemBlock:   true,
			wantSmartEligible: false,
			wantSmartMemBlock: true,
		},
		{
			name:              "exact_smartdns_pass_112m_32m_10mb",
			hw:                localdns.HardwareProfile{TotalRAMBytes: 112 * mib, AvailRAMBytes: 32 * mib, AvailDiskMB: 10},
			installed:         map[string]bool{},
			wantRecommended:   constant.DNSEngineSmartDNS,
			wantActive:        constant.DNSEngineSmartDNS,
			wantAGHEligible:   false,
			wantAGHDiskBlock:  true,
			wantAGHMemBlock:   true,
			wantSmartEligible: true,
		},
		{
			name:              "legacy_installed_adguard_preserved",
			hw:                localdns.HardwareProfile{TotalRAMBytes: 1024 * mib, AvailRAMBytes: 600 * mib, AvailDiskMB: 200},
			installed:         map[string]bool{constant.DNSEngineAdGuard: true, constant.DNSEngineSmartDNS: true},
			wantRecommended:   constant.DNSEngineAdGuard,
			wantActive:        constant.DNSEngineAdGuard,
			wantAGHEligible:   true,
			wantSmartEligible: true,
		},
		{
			name:              "legacy_installed_smartdns_preserved_on_n60pro",
			hw:                localdns.HardwareProfile{TotalRAMBytes: 491040 * 1024, AvailRAMBytes: 210260 * 1024, AvailDiskMB: 45},
			installed:         map[string]bool{constant.DNSEngineSmartDNS: true},
			wantRecommended:   constant.DNSEngineSmartDNS,
			wantActive:        constant.DNSEngineSmartDNS,
			wantAGHEligible:   false,
			wantAGHDiskBlock:  true,
			wantAGHMemBlock:   true,
			wantSmartEligible: true,
		},
		{
			name:              "unknown_nonlinux_ram_and_disk_recommends_adguard",
			hw:                localdns.HardwareProfile{DiskUnknown: true},
			installed:         map[string]bool{},
			wantRecommended:   constant.DNSEngineAdGuard,
			wantActive:        constant.DNSEngineAdGuard,
			wantAGHEligible:   true,
			wantSmartEligible: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := localdns.RecommendEngine(tc.hw, tc.installed)
			if res.RecommendedEngine != tc.wantRecommended {
				t.Fatalf("RecommendedEngine = %q, want %q (reason=%q)", res.RecommendedEngine, tc.wantRecommended, res.RecommendedReason)
			}
			if res.ActiveEngine != tc.wantActive {
				t.Fatalf("ActiveEngine = %q, want %q", res.ActiveEngine, tc.wantActive)
			}
			if strings.TrimSpace(res.RecommendedReason) == "" {
				t.Fatal("RecommendedReason must not be empty")
			}

			if len(res.Eligibility) != 2 {
				t.Fatalf("expected exactly 2 eligibility entries (smartdns + adguard), got %d: %+v", len(res.Eligibility), res.Eligibility)
			}
			if _, hasSB := res.Eligibility["singbox"]; hasSB {
				t.Fatal("eligibility map must NOT contain removed singbox engine")
			}

			aghElig := res.Eligibility[constant.DNSEngineAdGuard]
			if aghElig.Eligible != tc.wantAGHEligible || aghElig.DiskBlocked != tc.wantAGHDiskBlock || aghElig.MemoryBlocked != tc.wantAGHMemBlock {
				t.Fatalf("adguard eligibility = %+v, want eligible=%v disk=%v mem=%v", aghElig, tc.wantAGHEligible, tc.wantAGHDiskBlock, tc.wantAGHMemBlock)
			}
			if !aghElig.Eligible && aghElig.BlockedReason == "" {
				t.Fatal("blocked adguard must include non-empty BlockedReason")
			}

			smElig := res.Eligibility[constant.DNSEngineSmartDNS]
			if smElig.Eligible != tc.wantSmartEligible || smElig.DiskBlocked != tc.wantSmartDiskBlock || smElig.MemoryBlocked != tc.wantSmartMemBlock {
				t.Fatalf("smartdns eligibility = %+v, want eligible=%v disk=%v mem=%v", smElig, tc.wantSmartEligible, tc.wantSmartDiskBlock, tc.wantSmartMemBlock)
			}
			if !smElig.Eligible && smElig.BlockedReason == "" {
				t.Fatal("blocked smartdns must include non-empty BlockedReason")
			}
		})
	}
}

func TestResolveActiveEngine_DualEnginePreferencesAndLegacyCompat(t *testing.T) {
	const mib = 1024 * 1024
	highHW := localdns.HardwareProfile{TotalRAMBytes: 2048 * mib, AvailRAMBytes: 1200 * mib, AvailDiskMB: 500}

	cases := []struct {
		name       string
		configured string
		dnsEnabled bool
		installed  map[string]bool
		wantActive string
	}{
		{
			name:       "legacy_singbox_normalizes_to_auto_preserving_installed_adguard",
			configured: "singbox",
			dnsEnabled: true,
			installed:  map[string]bool{constant.DNSEngineAdGuard: true},
			wantActive: constant.DNSEngineAdGuard,
		},
		{
			name:       "legacy_singbox_uninstalled_high_hw_uses_recommended_adguard",
			configured: "singbox",
			dnsEnabled: true,
			installed:  map[string]bool{},
			wantActive: constant.DNSEngineAdGuard,
		},
		{
			name:       "disabled_dns_keeps_configured_dual_engine_id",
			configured: constant.DNSEngineAdGuard,
			dnsEnabled: false,
			installed:  map[string]bool{constant.DNSEngineAdGuard: true},
			wantActive: constant.DNSEngineAdGuard,
		},
		{
			name:       "configured_smartdns_not_installed_keeps_smartdns_for_uninstalled_view",
			configured: constant.DNSEngineSmartDNS,
			dnsEnabled: true,
			installed:  map[string]bool{},
			wantActive: constant.DNSEngineSmartDNS,
		},
		{
			name:       "configured_adguard_not_installed_keeps_adguard_for_uninstalled_view",
			configured: constant.DNSEngineAdGuard,
			dnsEnabled: true,
			installed:  map[string]bool{constant.DNSEngineSmartDNS: true},
			wantActive: constant.DNSEngineAdGuard,
		},
		{
			name:       "configured_smartdns_installed_activates_smartdns",
			configured: constant.DNSEngineSmartDNS,
			dnsEnabled: true,
			installed:  map[string]bool{constant.DNSEngineSmartDNS: true, constant.DNSEngineAdGuard: true},
			wantActive: constant.DNSEngineSmartDNS,
		},
		{
			name:       "unknown_configured_falls_back_to_auto",
			configured: "invalid-engine",
			dnsEnabled: true,
			installed:  map[string]bool{constant.DNSEngineAdGuard: true},
			wantActive: constant.DNSEngineAdGuard,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := localdns.ResolveActiveEngine(tc.configured, tc.dnsEnabled, highHW, tc.installed)
			if res.ActiveEngine != tc.wantActive {
				t.Fatalf("ResolveActiveEngine(%q, enabled=%v) ActiveEngine=%q, want %q",
					tc.configured, tc.dnsEnabled, res.ActiveEngine, tc.wantActive)
			}
		})
	}
}

func TestProbeHardwareProfile_HandlesUnsupportedAndErrors(t *testing.T) {
	const mib = 1024 * 1024
	hp := localdns.ProbeHardwareProfile(
		"/usr/bin",
		func() (sysinfo.MemInfo, error) {
			return sysinfo.MemInfo{TotalBytes: 512 * mib, AvailableBytes: 205 * mib}, nil
		},
		func(string) (sysinfo.DiskSpace, error) {
			return sysinfo.DiskSpace{AvailBytes: 50 * mib}, nil
		},
	)
	if hp.TotalRAMBytes != 512*mib || hp.AvailRAMBytes != 205*mib || hp.AvailDiskMB != 50 || hp.DiskUnknown {
		t.Fatalf("unexpected probed hardware profile: %+v", hp)
	}

	hpUnsupported := localdns.ProbeHardwareProfile(
		"/usr/bin",
		func() (sysinfo.MemInfo, error) { return sysinfo.MemInfo{}, errors.ErrUnsupported },
		func(string) (sysinfo.DiskSpace, error) { return sysinfo.DiskSpace{}, errors.ErrUnsupported },
	)
	if !hpUnsupported.DiskUnknown || hpUnsupported.TotalRAMBytes != 0 {
		t.Fatalf("expected DiskUnknown=true on unsupported statfs, got %+v", hpUnsupported)
	}
}
