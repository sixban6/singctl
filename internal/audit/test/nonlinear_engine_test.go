// 文件职责：覆盖可插拔异常检测算子（Detector / AxisProjector）注册扩展与安全/隐私双轴正交投射测试。
package audit_test

import (
	"slices"
	"testing"

	"singctl/internal/audit"
	"singctl/internal/config"
)

type customPortDetector struct{}

func (customPortDetector) Name() string { return "custom_port_probe" }

func (customPortDetector) Evaluate(flow *audit.FlowRecord) (float64, string) {
	if flow.DestPort == 4444 {
		return 6.5, "自定义算子: 命中高危端口 4444"
	}
	return 0, ""
}

func TestNonlinearEngine_RegisterDetector_OCP(t *testing.T) {
	eng := audit.NewNonlinearEngine(&config.Config{})
	eng.RegisterDetector(customPortDetector{})

	flow := &audit.FlowRecord{
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

type customPrivacyDetector struct{}

func (customPrivacyDetector) Name() string { return "custom_privacy_probe" }

func (customPrivacyDetector) Evaluate(flow *audit.FlowRecord) (float64, string) {
	if flow != nil && flow.Target == "tracker.example.com" {
		return 28.0, "自定义算子: 隐私行为上报"
	}
	return 0, ""
}

func (customPrivacyDetector) ProjectAxes(*audit.FlowRecord) audit.AxisWeights {
	return audit.AxisWeights{Privacy: 1.0}
}

func TestNonlinearEngine_AxisProjector_OCPAndBuiltinAxes(t *testing.T) {
	t.Run("custom_privacy_detector_projects_only_to_privacy_axis", func(t *testing.T) {
		eng := audit.NewNonlinearEngine(&config.Config{})
		eng.RegisterDetector(customPrivacyDetector{})

		flow := &audit.FlowRecord{
			Target:     "tracker.example.com",
			DestPort:   443,
			IsDirectIP: false,
		}
		eng.EvaluateFlow(flow)

		if flow.PrivacyScore == 0 {
			t.Fatalf("expected positive PrivacyScore, got %d", flow.PrivacyScore)
		}
		if flow.SecurityScore != 0 {
			t.Fatalf("expected zero SecurityScore for privacy-only detector, got %d", flow.SecurityScore)
		}
		if flow.DominantAxis != "privacy" {
			t.Fatalf("expected DominantAxis=privacy, got %q", flow.DominantAxis)
		}
	})

	t.Run("builtin_detectors_axis_weights", func(t *testing.T) {
		eng := audit.NewNonlinearEngine(&config.Config{})

		pcdnFlow := &audit.FlowRecord{
			Target:        "pcdn.example.com",
			DestPort:      443,
			UploadBytes:   512 * 1024,
			DownloadBytes: 64 * 1024,
		}
		eng.EvaluateFlow(pcdnFlow)
		if pcdnFlow.PCDNKind == "" || pcdnFlow.SecurityScore == 0 || pcdnFlow.PrivacyScore != 0 {
			t.Fatalf("expected PCDN flow to project onto security axis only, got sec=%d priv=%d kind=%q",
				pcdnFlow.SecurityScore, pcdnFlow.PrivacyScore, pcdnFlow.PCDNKind)
		}

		trackerFlow := &audit.FlowRecord{
			Target:        "telemetry.example.com",
			DestPort:      443,
			UploadBytes:   16 * 1024,
			DownloadBytes: 64 * 1024,
		}
		eng.EvaluateFlow(trackerFlow)
		if trackerFlow.PCDNKind != "" || trackerFlow.PrivacyScore == 0 || trackerFlow.SecurityScore != 0 {
			t.Fatalf("expected tracker flow to project onto privacy axis only, got sec=%d priv=%d kind=%q",
				trackerFlow.SecurityScore, trackerFlow.PrivacyScore, trackerFlow.PCDNKind)
		}

		beaconFlow := &audit.FlowRecord{
			Target:      "heartbeat.example.com",
			DestPort:    443,
			ConnCount:   20,
			IntervalCV:  0.05,
			UploadBytes: 16 * 1024,
		}
		eng.EvaluateFlow(beaconFlow)
		if beaconFlow.SecurityScore == 0 || beaconFlow.PrivacyScore == 0 {
			t.Fatalf("expected beacon flow to project onto both axes, got sec=%d priv=%d",
				beaconFlow.SecurityScore, beaconFlow.PrivacyScore)
		}

		eng.EvaluateFlow(nil)
	})
}

func TestNonlinearEngine_WeChatCoreShortLinksTrusted_TelemetryStillFlagged(t *testing.T) {
	eng := audit.NewNonlinearEngine(&config.Config{})

	for _, coreDomain := range []string{
		"sgminorshort.wechat.com",
		"sgshort.wechat.com",
		"sglong.wechat.com",
		"c2c.cdn.wechat.com",
		"szminorshort.weixin.qq.com",
		"wyw-pics.wxqcloud.qq.com.cn",
		"emoji.qpic.cn",
	} {
		if !eng.IsTrusted(coreDomain) {
			t.Errorf("expected WeChat core domain %q to be in trusted baseline", coreDomain)
		}
		flow := &audit.FlowRecord{
			Target:        coreDomain,
			DestPort:      80,
			Network:       "tcp",
			UploadBytes:   512 * 1024,
			DownloadBytes: 64 * 1024,
			UploadRatio:   8.0,
			ConnCount:     150,
			NightHits:     12,
		}
		eng.EvaluateFlow(flow)
		if flow.Threat == audit.ThreatHighRisk || flow.Threat == audit.ThreatSuspicious {
			t.Errorf("WeChat core domain %q must not be flagged suspicious/high_risk, got threat=%s score=%d reasons=%v",
				coreDomain, flow.Threat, flow.RiskScore, flow.Reasons)
		}
	}

	for _, telemetryDomain := range []string{
		"wetelemetry.weixin.qq.com",
		"report.trade.weixin.qq.com",
		"report-online.sh.wxgateway.com",
	} {
		if eng.IsTrusted(telemetryDomain) {
			t.Errorf("WeChat telemetry domain %q must NOT be in trusted baseline", telemetryDomain)
		}
		flow := &audit.FlowRecord{
			Target:        telemetryDomain,
			DestPort:      443,
			Network:       "tcp",
			UploadBytes:   64 * 1024,
			DownloadBytes: 8 * 1024,
			UploadRatio:   8.0,
			ConnCount:     30,
		}
		eng.EvaluateFlow(flow)
		if flow.PrivacyScore == 0 {
			t.Errorf("expected WeChat telemetry domain %q to retain non-zero PrivacyScore", telemetryDomain)
		}
	}
}
