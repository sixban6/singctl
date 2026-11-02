package doctor

import (
	"testing"

	"singctl/internal/config"
)

func TestDoctor_BasicRun(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Sni: "www.apple.com",
		},
	}

	report := RunDoctor(cfg)
	if report == nil {
		t.Fatalf("expected non-nil report")
	}
	if report.Score < 0 || report.Score > 100 {
		t.Fatalf("score out of bounds: %d", report.Score)
	}
	if len(report.Items) == 0 {
		t.Fatalf("expected at least 1 check item")
	}
}

func TestCheckMediaUnlock(t *testing.T) {
	report := CheckMediaUnlock()
	if report == nil {
		t.Fatalf("expected non-nil media unlock report")
	}
	if report.TestedAt == "" {
		t.Fatalf("expected testedAt to be populated")
	}
}
