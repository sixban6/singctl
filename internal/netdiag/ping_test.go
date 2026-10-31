package netdiag

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestEvaluateQuality(t *testing.T) {
	if q := EvaluateQuality(0.0, 5*time.Millisecond); q != QualityExcellent {
		t.Errorf("expected QualityExcellent, got %s", q)
	}
	if q := EvaluateQuality(1.5, 30*time.Millisecond); q != QualityGood {
		t.Errorf("expected QualityGood, got %s", q)
	}
	if q := EvaluateQuality(8.0, 50*time.Millisecond); q != QualityCongested {
		t.Errorf("expected QualityCongested, got %s", q)
	}
	if q := EvaluateQuality(25.0, 100*time.Millisecond); q != QualitySevere {
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

	res := &PingResult{Sent: 2}
	parseSystemPingOutput(darwinOutput, res)

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

	res := &PingResult{Sent: 10, IsTCP: true, Protocol: "TCP"}
	computeRTTStats(res, rtts, true)

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

	res, err := RunUDPPing(ctx, PingOptions{
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
	tcp := &PingResult{
		Sent:     10,
		Received: 10,
		LossRate: 0.0,
		MinRTT:   5 * time.Millisecond,
		AvgRTT:   10 * time.Millisecond,
		MaxRTT:   15 * time.Millisecond,
		RTTs:     []time.Duration{5 * time.Millisecond, 10 * time.Millisecond},
	}
	udp := &PingResult{
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
	icmp := &PingResult{
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

	merged := mergeMultiPingResults(PingOptions{Host: "198.51.100.10", Port: 443, Count: 10}, tcp, udp, icmp)
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
