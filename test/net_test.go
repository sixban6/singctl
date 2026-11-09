package test

import (
	"bytes"
	"context"
	"net"
	"os"
	"singctl/internal/cmd"
	"singctl/internal/config"
	"singctl/internal/netdiag"
	"strings"
	"testing"
	"time"
)

func TestNetCommand_Subcommands(t *testing.T) {
	netCmd := cmd.NewNetCmd("/tmp/singctl.yaml")
	if netCmd.Use != "net" {
		t.Errorf("expected use 'net', got %s", netCmd.Use)
	}

	expectedSubcmds := map[string]bool{
		"diag":   false,
		"ping":   false,
		"trace":  false,
		"return": false,
		"advice": false,
	}

	for _, sub := range netCmd.Commands() {
		useName := strings.Fields(sub.Use)[0]
		if _, ok := expectedSubcmds[useName]; ok {
			expectedSubcmds[useName] = true
		}
	}

	for name, found := range expectedSubcmds {
		if !found {
			t.Errorf("missing subcommand %s in singctl net", name)
		}
	}
}

func TestNetAdviceCommand_Execution(t *testing.T) {
	netCmd := cmd.NewNetCmd("/tmp/singctl.yaml")
	buf := new(bytes.Buffer)
	netCmd.SetOut(buf)
	netCmd.SetErr(buf)
	netCmd.SetArgs([]string{"advice", "--carrier", "cu"})

	if err := netCmd.Execute(); err != nil {
		t.Fatalf("singctl net advice execution failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "中国联通") {
		t.Errorf("expected output to contain '中国联通', got:\n%s", out)
	}

	// Test --all
	buf.Reset()
	netCmd.SetArgs([]string{"advice", "--all"})
	if err := netCmd.Execute(); err != nil {
		t.Fatalf("singctl net advice --all execution failed: %v", err)
	}
	if !strings.Contains(buf.String(), "全量百科") {
		t.Errorf("expected output to contain '全量百科', got:\n%s", buf.String())
	}
}

func TestGenerateAdvice_Protocol(t *testing.T) {
	// 0% loss, low jitter -> VLESS-Reality
	cleanPing := &netdiag.PingResult{
		LossRate:     0.0,
		Jitter:       5 * time.Millisecond,
		QualityLevel: netdiag.QualityExcellent,
	}
	adv := netdiag.GenerateAdvice(nil, cleanPing, nil, false)
	if adv.RecommendedProtocol != netdiag.ProtocolVLESSReality {
		t.Errorf("expected VLESS-Reality for clean route, got %s", adv.RecommendedProtocol)
	}

	// 15% loss -> Hysteria 2
	lossyPing := &netdiag.PingResult{
		LossRate:     15.0,
		Jitter:       60 * time.Millisecond,
		QualityLevel: netdiag.QualitySevere,
	}
	adv = netdiag.GenerateAdvice(nil, lossyPing, nil, false)
	if adv.RecommendedProtocol != netdiag.ProtocolHysteria2 {
		t.Errorf("expected Hysteria 2 for lossy route, got %s", adv.RecommendedProtocol)
	}
	if adv.SuggestedHy2Down > 100 {
		t.Errorf("expected conservative hy2.down for severe loss, got %d", adv.SuggestedHy2Down)
	}
}

func TestApplyHy2Config_PreservesComments(t *testing.T) {
	rawYaml := `# Main configuration
subs:
  - name: "main" # primary sub
    url: "https://example.com"

# Bandwidth settings for Hysteria 2
hy2:
  up: 10 # upload speed
  down: 100 # download speed
`
	tmpFile, err := os.CreateTemp("", "singctl_test_hy2_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if err := os.WriteFile(tmpFile.Name(), []byte(rawYaml), 0600); err != nil {
		t.Fatal(err)
	}

	// Apply updated bandwidth
	if err := netdiag.ApplyHy2Config(tmpFile.Name(), 35, 250); err != nil {
		t.Fatalf("ApplyHy2Config failed: %v", err)
	}

	// Read updated file
	updatedData, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	content := string(updatedData)
	if !strings.Contains(content, "up: 35") {
		t.Errorf("expected up: 35 in updated file, got:\n%s", content)
	}
	if !strings.Contains(content, "down: 250") {
		t.Errorf("expected down: 250 in updated file, got:\n%s", content)
	}
	// Verify comments preserved
	if !strings.Contains(content, "# Bandwidth settings for Hysteria 2") {
		t.Errorf("expected comment preserved, got:\n%s", content)
	}

	// Load via config.Load to ensure valid parsing
	cfg, err := config.Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if cfg.Hy2.Up != 35 || cfg.Hy2.Down != 250 {
		t.Errorf("expected Hy2 {35, 250}, got %+v", cfg.Hy2)
	}
}

func TestGetCarrierBuyingGuide(t *testing.T) {
	guide := netdiag.GetCarrierBuyingGuide()
	if !strings.Contains(guide, "中国电信") || !strings.Contains(guide, "CN2 GIA") {
		t.Errorf("guide missing key elements: %s", guide)
	}
}

func TestInspectHop(t *testing.T) {
	tests := []struct {
		ip          string
		host        string
		wantTag     string
		wantCarrier string
		wantRoute   string
		wantASN     string
	}{
		{"59.43.18.1", "", "CN2 (59.43)", "中国电信", "CN2", "AS4809"},
		{"202.97.22.1", "", "163 (202.97)", "中国电信", "163", "AS4134"},
		{"218.105.10.1", "", "9929 (CU-Premium)", "中国联通", "9929", "AS9929"},
		{"210.51.10.1", "", "9929 (CU-Premium)", "中国联通", "9929", "AS9929"},
		{"219.158.113.1", "", "4837 (CU-169)", "中国联通", "4837", "AS4837"},
		{"223.120.22.1", "", "CMIN2 (223.120)", "中国移动", "CMIN2", "AS58807"},
		{"221.183.55.1", "", "CMI (AS9808)", "中国移动", "CMI", "AS9808"},
		{"183.91.1.1", "", "CMI (AS9808)", "中国移动", "CMI", "AS9808"},
		{"129.250.0.1", "ae-0.gin.ntt.net", "NTT", "国际中转", "NTT", "AS2914"},
		{"154.54.0.1", "be210.ccr41.lax05.atlas.cogentco.com", "Cogent", "国际中转", "Cogent", "AS174"},
		{"210.130.0.1", "iij.net", "IIJ", "日本直连", "IIJ", "AS2497"},
	}

	for _, tt := range tests {
		tag, carrier, route, asn := netdiag.InspectHop(tt.ip, tt.host)
		if tag != tt.wantTag || carrier != tt.wantCarrier || route != tt.wantRoute || asn != tt.wantASN {
			t.Errorf("InspectHop(%q, %q) = (%q, %q, %q, %q), want (%q, %q, %q, %q)",
				tt.ip, tt.host, tag, carrier, route, asn, tt.wantTag, tt.wantCarrier, tt.wantRoute, tt.wantASN)
		}
	}
}

func TestClassifyRoute(t *testing.T) {
	// 1. Pure CN2 GIA (59.43 only, no 202.97)
	giaHops := []netdiag.HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "59.43.18.1"},
		{Hop: 3, IP: "59.43.247.1"},
		{Hop: 4, IP: "154.22.1.1"},
	}
	name, rType, _ := netdiag.ClassifyRoute(giaHops)
	if rType != "CN2_GIA" {
		t.Errorf("expected CN2_GIA, got %s (%s)", rType, name)
	}

	// 2. CN2 GT (202.97 + 59.43)
	gtHops := []netdiag.HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "202.97.22.1"},
		{Hop: 3, IP: "59.43.247.1"},
		{Hop: 4, IP: "154.22.1.1"},
	}
	name, rType, _ = netdiag.ClassifyRoute(gtHops)
	if rType != "CN2_GT" {
		t.Errorf("expected CN2_GT, got %s (%s)", rType, name)
	}

	// 3. 163 (202.97 only)
	hops163 := []netdiag.HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "202.97.22.1"},
		{Hop: 3, IP: "202.97.55.1"},
		{Hop: 4, IP: "154.22.1.1"},
	}
	name, rType, _ = netdiag.ClassifyRoute(hops163)
	if rType != "163" {
		t.Errorf("expected 163, got %s (%s)", rType, name)
	}

	// 4. CU4837
	hops4837 := []netdiag.HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "219.158.113.1"},
		{Hop: 3, IP: "154.22.1.1"},
	}
	name, rType, _ = netdiag.ClassifyRoute(hops4837)
	if rType != "CU4837" {
		t.Errorf("expected CU4837, got %s (%s)", rType, name)
	}

	// 5. CU9929
	hops9929 := []netdiag.HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "218.105.10.1"},
		{Hop: 3, IP: "154.22.1.1"},
	}
	name, rType, _ = netdiag.ClassifyRoute(hops9929)
	if rType != "CU9929" {
		t.Errorf("expected CU9929, got %s (%s)", rType, name)
	}

	// 6. CMIN2
	hopsCMIN2 := []netdiag.HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "223.120.22.1"},
		{Hop: 3, IP: "154.22.1.1"},
	}
	name, rType, _ = netdiag.ClassifyRoute(hopsCMIN2)
	if rType != "CMIN2" {
		t.Errorf("expected CMIN2, got %s (%s)", rType, name)
	}

	// 7. CMI
	hopsCMI := []netdiag.HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "221.183.55.1"},
		{Hop: 3, IP: "154.22.1.1"},
	}
	name, rType, _ = netdiag.ClassifyRoute(hopsCMI)
	if rType != "CMI" {
		t.Errorf("expected CMI, got %s (%s)", rType, name)
	}
}

func TestGetPublicISP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	isp, err := netdiag.GetPublicISP(ctx)
	if err != nil {
		t.Skipf("skipping live network detection test: %v", err)
		return
	}
	if isp.IP == "" {
		t.Errorf("expected non-empty IP")
	}
}

func TestParseCipCCOutput(t *testing.T) {
	mock := `IP	: 1.2.3.4
地址	: 中国 浙江 杭州
运营商	: 电信
`
	info, err := netdiag.ParseCipCCOutput(mock)
	if err != nil {
		t.Fatalf("parseCipCCOutput failed: %v", err)
	}
	if info.IP != "1.2.3.4" || info.City != "杭州" || info.Type != netdiag.ISPTelecom {
		t.Errorf("unexpected parsed info: %+v", info)
	}
}

func TestCategorizeISP(t *testing.T) {
	if cat := netdiag.CategorizeISP("中国电信", "", "", "CN"); cat != netdiag.ISPTelecom {
		t.Errorf("expected ISPTelecom, got %s", cat)
	}
	if cat := netdiag.CategorizeISP("中国联通", "", "", "CN"); cat != netdiag.ISPUnicom {
		t.Errorf("expected ISPUnicom, got %s", cat)
	}
	if cat := netdiag.CategorizeISP("中国移动", "", "", "CN"); cat != netdiag.ISPMobile {
		t.Errorf("expected ISPMobile, got %s", cat)
	}
	if cat := netdiag.CategorizeISP("CERNET", "", "", "CN"); cat != netdiag.ISPBroadnet {
		t.Errorf("expected ISPBroadnet, got %s", cat)
	}
	if cat := netdiag.CategorizeISP("Comcast", "", "", "US"); cat != netdiag.ISPOverseas {
		t.Errorf("expected ISPOverseas, got %s", cat)
	}
}

func TestEvaluateQuality(t *testing.T) {
	if q := netdiag.EvaluateQuality(0.0, 5*time.Millisecond); q != netdiag.QualityExcellent {
		t.Errorf("expected QualityExcellent, got %s", q)
	}
	if q := netdiag.EvaluateQuality(1.5, 30*time.Millisecond); q != netdiag.QualityGood {
		t.Errorf("expected QualityGood, got %s", q)
	}
	if q := netdiag.EvaluateQuality(8.0, 50*time.Millisecond); q != netdiag.QualityCongested {
		t.Errorf("expected QualityCongested, got %s", q)
	}
	if q := netdiag.EvaluateQuality(25.0, 100*time.Millisecond); q != netdiag.QualitySevere {
		t.Errorf("expected QualitySevere, got %s", q)
	}
}

func TestParseSystemPingOutput(t *testing.T) {
	darwinOutput := `PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=145.201 ms
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=148.112 ms

--- 1.1.1.1 ping statistics ---
2 packets transmitted, 2 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 145.201/146.656/148.112/1.455 ms`

	res := &netdiag.PingResult{Sent: 2}
	netdiag.ParseSystemPingOutput(darwinOutput, res)

	if res.LossRate != 0.0 {
		t.Errorf("expected 0.0%% loss, got %.1f%%", res.LossRate)
	}
	if res.Received != 2 {
		t.Errorf("expected 2 received, got %d", res.Received)
	}
	if res.AvgRTT < 140*time.Millisecond || res.AvgRTT > 150*time.Millisecond {
		t.Errorf("expected AvgRTT around 146ms, got %v", res.AvgRTT)
	}
	if res.Jitter <= 0 {
		t.Errorf("expected non-zero jitter, got %v", res.Jitter)
	}
}

func TestComputeRTTStats_DetectsSYNRetransmission(t *testing.T) {
	// 复现 OpenWrt 真实场景：9 轮正常 ~150ms，1 轮因丢包触发内核 1.0s SYN 重传达到 1154ms
	rtts := []time.Duration{
		144 * time.Millisecond,
		150 * time.Millisecond,
		148 * time.Millisecond,
		152 * time.Millisecond,
		1154 * time.Millisecond, // 内核 TCP SYN 重传
		149 * time.Millisecond,
		151 * time.Millisecond,
		147 * time.Millisecond,
		153 * time.Millisecond,
		150 * time.Millisecond,
	}

	res := &netdiag.PingResult{Sent: 10, IsTCP: true, Protocol: "TCP"}
	netdiag.ComputeRTTStats(res, rtts, true)

	if res.RetransCount != 1 {
		t.Fatalf("expected RetransCount=1, got %d", res.RetransCount)
	}
	if res.LossCount != 1 || res.LossRate != 10.0 {
		t.Fatalf("expected LossCount=1 and LossRate=10.0%%, got LossCount=%d, LossRate=%.1f%%", res.LossCount, res.LossRate)
	}
}

func TestRunUDPPing_LocalQUICMock(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}
	defer pc.Close()

	udpAddr := pc.LocalAddr().(*net.UDPAddr)

	// 模拟 QUIC 服务端：仅回复偶数序号包，模拟 50% UDP 丢包
	go func() {
		buf := make([]byte, 1500)
		count := 0
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n >= 1200 && buf[0] == 0xc0 {
				count++
				if count%2 == 1 {
					// 回复 RFC 9000 Version Negotiation
					resp := []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8}
					_, _ = pc.WriteTo(resp, addr)
				}
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := netdiag.RunUDPPing(ctx, netdiag.PingOptions{
		Host:     "127.0.0.1",
		Port:     udpAddr.Port,
		Count:    4,
		Timeout:  150 * time.Millisecond,
		Interval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RunUDPPing failed: %v", err)
	}

	if res.Sent != 4 || res.Received != 2 || res.LossCount != 2 || res.LossRate != 50.0 {
		t.Errorf("expected 50%% UDP loss (2/4), got Sent=%d, Received=%d, Loss=%.1f%%", res.Sent, res.Received, res.LossRate)
	}
}

func TestMergeMultiPingResults_TakesWorstLossAndDetectsLocalTUN(t *testing.T) {
	tcp := &netdiag.PingResult{
		Sent:     10,
		Received: 10,
		LossRate: 0.0,
		MinRTT:   5 * time.Millisecond,
		AvgRTT:   10 * time.Millisecond,
		MaxRTT:   15 * time.Millisecond,
		RTTs:     []time.Duration{5 * time.Millisecond, 10 * time.Millisecond},
	}
	udp := &netdiag.PingResult{
		Sent:      10,
		Received:  5,
		LossCount: 5,
		LossRate:  50.0,
		MinRTT:    185 * time.Millisecond,
		AvgRTT:    195 * time.Millisecond,
		MaxRTT:    205 * time.Millisecond,
		Jitter:    8 * time.Millisecond,
		RTTs:      []time.Duration{185 * time.Millisecond, 195 * time.Millisecond},
	}
	icmp := &netdiag.PingResult{
		Sent:      10,
		Received:  8,
		LossCount: 2,
		LossRate:  20.0,
		MinRTT:    170 * time.Millisecond,
		AvgRTT:    175 * time.Millisecond,
		MaxRTT:    180 * time.Millisecond,
		Jitter:    4 * time.Millisecond,
		RTTs:      []time.Duration{170 * time.Millisecond, 175 * time.Millisecond},
	}

	merged := netdiag.MergeMultiPingResults(netdiag.PingOptions{Host: "198.51.100.10", Port: 443, Count: 10}, tcp, udp, icmp)
	if !tcp.LocalProxied {
		t.Errorf("expected tcp.LocalProxied=true when TCP MinRTT=5ms vs UDP MinRTT=185ms")
	}
	if merged.LossRate != 50.0 {
		t.Errorf("expected merged.LossRate=50.0%% (worst active protocol), got %.1f%%", merged.LossRate)
	}
	if merged.MinRTT != 185*time.Millisecond {
		t.Errorf("expected merged.MinRTT to use physical UDP/ICMP RTT (185ms) instead of TUN 5ms, got %v", merged.MinRTT)
	}
}

func TestEvaluateBestISPs(t *testing.T) {
	mockResults := []netdiag.ReturnHopResult{
		{
			Carrier:   netdiag.ISPTelecom,
			Name:      "上海电信 (CN2 节点)",
			RouteName: "电信 CN2 GIA (AS4809 精品骨干网)",
			AvgRTT:    140 * time.Millisecond,
			LossRate:  0.0,
		},
		{
			Carrier:   netdiag.ISPUnicom,
			Name:      "北京联通 (4837 骨干)",
			RouteName: "联通 169 普通骨干网 (AS4837)",
			AvgRTT:    160 * time.Millisecond,
			LossRate:  1.0,
		},
		{
			Carrier:   netdiag.ISPMobile,
			Name:      "广州移动 (CMI 出口)",
			RouteName: "移动 CMI (AS9808 国际骨干网)",
			AvgRTT:    180 * time.Millisecond,
			LossRate:  2.0,
		},
	}

	best := netdiag.EvaluateBestISPs(mockResults)
	if len(best) != 3 {
		t.Errorf("expected all 3 carriers to be recommended, got %d", len(best))
	}

	summary := netdiag.BuildReturnSummaryText(mockResults, best)
	if !strings.Contains(summary, "全网优化线路") && !strings.Contains(summary, "电信") {
		t.Errorf("expected positive summary, got %s", summary)
	}
}
