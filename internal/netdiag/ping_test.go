package netdiag

import (
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
