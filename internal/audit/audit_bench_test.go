package audit

import (
	"fmt"
	"testing"

	"singctl/internal/config"
)

func BenchmarkNonlinearEngine_EvaluateFlow_And_IsBlocked(b *testing.B) {
	cfg := &config.Config{
		Audit: config.AuditConfig{
			Whitelist: []string{"corp.example.com", "cdn.example.com"},
		},
		CustomRules: config.CustomRulesConfig{
			Block: []config.BlockRule{
				{Target: "ads.example.com"},
				{Target: "tracker.example.com"},
				{Target: "198.51.100.99", SourceIP: "192.168.1.50"},
				{Target: "pcdn.example.net"},
			},
		},
	}
	eng := NewNonlinearEngine(cfg)

	flows := make([]FlowRecord, 64)
	for i := range flows {
		flows[i] = FlowRecord{
			DeviceIP:      fmt.Sprintf("192.168.1.%d", 10+(i%20)),
			DeviceName:    "iPhone-15",
			Target:        fmt.Sprintf("sub-%d.api.service.example.org", i),
			DestPort:      443,
			UploadBytes:   512 * 1024,
			DownloadBytes: 2 * 1024 * 1024,
			ConnCount:     8,
			ActiveSpanSec: 600,
			IntervalCV:    0.45,
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for idx := range flows {
			f := flows[idx]
			_ = eng.IsBlocked(f.DeviceIP, f.Target)
			eng.EvaluateFlow(&f)
		}
	}
}
