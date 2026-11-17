package audit

import (
	"slices"
	"testing"

	"singctl/internal/config"
)

type customPortDetector struct{}

func (customPortDetector) Name() string { return "custom_port_probe" }

func (customPortDetector) Evaluate(flow *FlowRecord) (float64, string) {
	if flow.DestPort == 4444 {
		return 6.5, "自定义算子: 命中高危端口 4444"
	}
	return 0, ""
}

func TestNonlinearEngine_RegisterDetector_OCP(t *testing.T) {
	eng := NewNonlinearEngine(&config.Config{})
	eng.RegisterDetector(customPortDetector{})

	flow := &FlowRecord{
		Target:     "probe.example.com",
		DestPort:   4444,
		IsDirectIP: false,
	}
	eng.EvaluateFlow(flow)

	if got := flow.NonlinearFactors["custom_port_probe"]; got != 6.5 {
		t.Fatalf("expected custom detector factor 6.5, got %v", got)
	}
	if !slices.Contains(flow.Reasons, "自定义算子: 命中高危端口 4444") {
		t.Fatalf("expected custom detector reason in %v", flow.Reasons)
	}
	if flow.RiskScore <= 0 {
		t.Fatalf("expected positive risk score after custom detector trigger, got %d", flow.RiskScore)
	}
}
