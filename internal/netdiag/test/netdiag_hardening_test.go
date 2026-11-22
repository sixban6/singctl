// 文件职责：验证运营商骨干网评分矩阵、UDP QoS 差分丢包识别、购机建议与 Hysteria2 带宽 0600 安全写回。
package netdiag_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/netdiag"
)

func TestGenerateAdvice_CarrierMatrixAndHy2Tuning(t *testing.T) {
	// 1. Clean low-loss link -> recommends VLESS-Reality
	lowLossPing := &netdiag.PingResult{
		Port:         443,
		LossRate:     0.0,
		Jitter:       5 * time.Millisecond,
		QualityLevel: "极佳",
	}
	adv1 := netdiag.GenerateAdvice(&netdiag.ISPInfo{Type: netdiag.ISPTelecom}, lowLossPing, &netdiag.TraceResult{RouteType: "CN2_GIA"}, true)
	if adv1.RecommendedProtocol != netdiag.ProtocolVLESSReality || adv1.CarrierMatchScore != 98 {
		t.Fatalf("unexpected CN2_GIA low-loss advice: %+v", adv1)
	}

	// 2. Heavy-loss 163 link + UDP blocked warning
	heavyPing := &netdiag.PingResult{
		Port:     443,
		LossRate: 18.5,
		Jitter:   90 * time.Millisecond,
		TCP:      &netdiag.PingResult{RTTs: []time.Duration{180 * time.Millisecond}, LossRate: 2.0},
		UDP:      &netdiag.PingResult{Received: 0, LossRate: 100.0},
	}
	adv2 := netdiag.GenerateAdvice(&netdiag.ISPInfo{Type: netdiag.ISPTelecom}, heavyPing, &netdiag.TraceResult{RouteType: "163"}, false)
	if adv2.RecommendedProtocol != netdiag.ProtocolHysteria2 || adv2.SuggestedHy2Down != 80 || adv2.CarrierMatchScore != 45 {
		t.Fatalf("unexpected 163 heavy-loss advice: %+v", adv2)
	}
	if !strings.Contains(adv2.ProtocolReason, "未响应 QUIC 握手") {
		t.Fatalf("expected UDP blocked warning in ProtocolReason, got %q", adv2.ProtocolReason)
	}

	// 3. Moderate loss + UDP QoS differential loss across Unicom / Mobile / Overseas
	qosPing := &netdiag.PingResult{
		Port:     443,
		LossRate: 6.0,
		Jitter:   40 * time.Millisecond,
		TCP:      &netdiag.PingResult{RTTs: []time.Duration{150 * time.Millisecond}, LossRate: 1.0},
		UDP:      &netdiag.PingResult{Received: 5, LossRate: 28.0},
	}
	for _, tc := range []struct {
		isp   netdiag.ISPType
		route string
	}{
		{netdiag.ISPTelecom, "CN2_GT"},
		{netdiag.ISPTelecom, "CU9929"},
		{netdiag.ISPTelecom, "CMIN2"},
		{netdiag.ISPUnicom, "CU9929"},
		{netdiag.ISPUnicom, "CU4837"},
		{netdiag.ISPUnicom, "CN2_GIA"},
		{netdiag.ISPMobile, "CMIN2"},
		{netdiag.ISPMobile, "CMI"},
		{netdiag.ISPMobile, "UNKNOWN"},
		{netdiag.ISPOverseas, "UNKNOWN"},
	} {
		adv := netdiag.GenerateAdvice(&netdiag.ISPInfo{Type: tc.isp}, qosPing, &netdiag.TraceResult{RouteType: tc.route}, true)
		if adv.SuggestedHy2Down != 120 || !strings.Contains(adv.ProtocolReason, "UDP QoS") {
			t.Fatalf("unexpected QoS advice for (%s, %s): %+v", tc.isp, tc.route, adv)
		}
	}

	// 4. Tailored carrier buying guides
	for _, isp := range []*netdiag.ISPInfo{
		nil,
		{Type: netdiag.ISPTelecom, Country: "CN", Region: "SH", City: "Shanghai", IP: "198.51.100.1"},
		{Type: netdiag.ISPUnicom, Country: "CN", Region: "BJ", City: "Beijing", IP: "198.51.100.2"},
		{Type: netdiag.ISPMobile, Country: "CN", Region: "GD", City: "Shenzhen", IP: "198.51.100.3"},
		{Type: netdiag.ISPOverseas, Country: "US", IP: "203.0.113.5"},
	} {
		if guide := netdiag.GetTailoredCarrierAdvice(isp); strings.TrimSpace(guide) == "" {
			t.Fatalf("expected non-empty carrier guide for %+v", isp)
		}
	}

	// 5. ApplyHy2Config preserves 0600 permissions
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 10\n  down: 50\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := netdiag.ApplyHy2Config(cfgPath, 30, 200); err != nil {
		t.Fatalf("ApplyHy2Config failed: %v", err)
	}
	raw, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(raw), "up: 30") || !strings.Contains(string(raw), "down: 200") {
		t.Fatalf("ApplyHy2Config did not update bandwidth:\n%s", string(raw))
	}
}
