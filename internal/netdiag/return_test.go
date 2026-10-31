package netdiag

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateBestISPs(t *testing.T) {
	mockResults := []ReturnHopResult{
		{
			Carrier:   ISPTelecom,
			Name:      "上海电信 (CN2 节点)",
			RouteName: "电信 CN2 GIA (AS4809 精品骨干网)",
			AvgRTT:    140 * time.Millisecond,
			LossRate:  0.0,
		},
		{
			Carrier:   ISPUnicom,
			Name:      "北京联通 (4837 骨干)",
			RouteName: "联通 169 普通骨干网 (AS4837)",
			AvgRTT:    160 * time.Millisecond,
			LossRate:  1.0,
		},
		{
			Carrier:   ISPMobile,
			Name:      "广州移动 (CMI 出口)",
			RouteName: "移动 CMI (AS9808 国际骨干网)",
			AvgRTT:    180 * time.Millisecond,
			LossRate:  2.0,
		},
	}

	best := evaluateBestISPs(mockResults)
	if len(best) != 3 {
		t.Errorf("expected all 3 carriers to be recommended, got %d", len(best))
	}

	summary := buildReturnSummaryText(mockResults, best)
	if !strings.Contains(summary, "全网优化线路") && !strings.Contains(summary, "电信") {
		t.Errorf("expected positive summary, got %s", summary)
	}
}
