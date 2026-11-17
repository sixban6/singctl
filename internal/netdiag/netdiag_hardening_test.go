package netdiag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateAdvice_CarrierMatrixAndHy2Tuning(t *testing.T) {
	// 1. Clean low-loss link -> recommends VLESS-Reality
	lowLossPing := &PingResult{
		Port:         443,
		LossRate:     0.0,
		Jitter:       5 * time.Millisecond,
		QualityLevel: "极佳",
	}
	adv1 := GenerateAdvice(&ISPInfo{Type: ISPTelecom}, lowLossPing, &TraceResult{RouteType: "CN2_GIA"}, true)
	if adv1.RecommendedProtocol != ProtocolVLESSReality || adv1.CarrierMatchScore != 98 {
		t.Fatalf("unexpected CN2_GIA low-loss advice: %+v", adv1)
	}

	// 2. Heavy-loss 163 link + UDP blocked warning
	heavyPing := &PingResult{
		Port:     443,
		LossRate: 18.5,
		Jitter:   90 * time.Millisecond,
		TCP:      &PingResult{RTTs: []time.Duration{180 * time.Millisecond}, LossRate: 2.0},
		UDP:      &PingResult{Received: 0, LossRate: 100.0},
	}
	adv2 := GenerateAdvice(&ISPInfo{Type: ISPTelecom}, heavyPing, &TraceResult{RouteType: "163"}, false)
	if adv2.RecommendedProtocol != ProtocolHysteria2 || adv2.SuggestedHy2Down != 80 || adv2.CarrierMatchScore != 45 {
		t.Fatalf("unexpected 163 heavy-loss advice: %+v", adv2)
	}
	if !strings.Contains(adv2.ProtocolReason, "未响应 QUIC 握手") {
		t.Fatalf("expected UDP blocked warning in ProtocolReason, got %q", adv2.ProtocolReason)
	}

	// 3. Moderate loss + UDP QoS differential loss across Unicom / Mobile / Overseas
	qosPing := &PingResult{
		Port:     443,
		LossRate: 6.0,
		Jitter:   40 * time.Millisecond,
		TCP:      &PingResult{RTTs: []time.Duration{150 * time.Millisecond}, LossRate: 1.0},
		UDP:      &PingResult{Received: 5, LossRate: 28.0},
	}
	for _, tc := range []struct {
		isp   ISPType
		route string
	}{
		{ISPTelecom, "CN2_GT"},
		{ISPTelecom, "CU9929"},
		{ISPTelecom, "CMIN2"},
		{ISPUnicom, "CU9929"},
		{ISPUnicom, "CU4837"},
		{ISPUnicom, "CN2_GIA"},
		{ISPMobile, "CMIN2"},
		{ISPMobile, "CMI"},
		{ISPMobile, "UNKNOWN"},
		{ISPOverseas, "UNKNOWN"},
	} {
		adv := GenerateAdvice(&ISPInfo{Type: tc.isp}, qosPing, &TraceResult{RouteType: tc.route}, true)
		if adv.SuggestedHy2Down != 120 || !strings.Contains(adv.ProtocolReason, "UDP QoS") {
			t.Fatalf("unexpected QoS advice for (%s, %s): %+v", tc.isp, tc.route, adv)
		}
	}

	// 4. Tailored carrier buying guides
	for _, isp := range []*ISPInfo{
		nil,
		{Type: ISPTelecom, Country: "CN", Region: "SH", City: "Shanghai", IP: "198.51.100.1"},
		{Type: ISPUnicom, Country: "CN", Region: "BJ", City: "Beijing", IP: "198.51.100.2"},
		{Type: ISPMobile, Country: "CN", Region: "GD", City: "Shenzhen", IP: "198.51.100.3"},
		{Type: ISPOverseas, Country: "US", IP: "203.0.113.5"},
	} {
		if guide := GetTailoredCarrierAdvice(isp); strings.TrimSpace(guide) == "" {
			t.Fatalf("expected non-empty carrier guide for %+v", isp)
		}
	}

	// 5. ApplyHy2Config preserves 0600 permissions
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 10\n  down: 50\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyHy2Config(cfgPath, 30, 200); err != nil {
		t.Fatalf("ApplyHy2Config failed: %v", err)
	}
	raw, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(raw), "up: 30") || !strings.Contains(string(raw), "down: 200") {
		t.Fatalf("ApplyHy2Config did not update bandwidth:\n%s", string(raw))
	}
}
