package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
)

func TestDecompiledSRS_SingleStringAndArray_AndYouTubeAppID(t *testing.T) {
	raw := `{
		"version": 2,
		"rules": [
			{
				"domain": "yt3.googleusercontent.com",
				"domain_suffix": ["googlevideo.com", "youtube.com"],
				"domain_keyword": "youtube",
				"ip_cidr": "203.0.113.0/24"
			}
		]
	}`
	var parsed decompiledSRS
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("unmarshal single+array decompiledSRS failed: %v", err)
	}
	if len(parsed.Rules) != 1 || len(parsed.Rules[0].Domain) != 1 || parsed.Rules[0].Domain[0] != "yt3.googleusercontent.com" {
		t.Fatalf("unexpected single string domain decode: %+v", parsed.Rules)
	}
	if len(parsed.Rules[0].DomainSuffix) != 2 || len(parsed.Rules[0].IPCIDR) != 1 {
		t.Fatalf("unexpected array/single field counts: %+v", parsed.Rules[0])
	}

	if got := IdentifyApp("www.youtube.com", "", ""); got != "YouTube" {
		t.Fatalf("expected www.youtube.com -> YouTube, got %q", got)
	}
	if got := IdentifyApp("rr3---sn-test.googlevideo.com", "", ""); got != "YouTube" {
		t.Fatalf("expected googlevideo.com -> YouTube, got %q", got)
	}
}

func TestNonlinearEngine_SlowLongSpanIoTHeartbeat_Vs_FastBurst(t *testing.T) {
	eng := NewNonlinearEngine(nil)

	// 1. 10 天累计 306MB（均速约 371 B/s）的 IoT 云端长连接心跳 -> 应显著降低安全轴误报
	slowFlow := FlowRecord{
		DeviceIP:      "192.168.1.60",
		DeviceName:    "SmartAirPurifier",
		DeviceRole:    "iot",
		Target:        "erv-cloud.example.com",
		AppName:       "智能家居云",
		DestIP:        "203.0.113.69",
		DestPort:      443,
		Network:       "tcp",
		Outbound:      "#DC",
		UploadBytes:   306 * 1024 * 1024,
		DownloadBytes: 96 * 1024 * 1024,
		ConnCount:     55,
		ActiveConns:   1,
		ActiveSpanSec: 10 * 24 * 3600,
		NightHits:     5,
	}
	eng.EvaluateFlow(&slowFlow)
	if slowFlow.AvgUploadBps <= 300 || slowFlow.AvgUploadBps >= 500 {
		t.Fatalf("unexpected AvgUploadBps for 10-day slow heartbeat: %.2f", slowFlow.AvgUploadBps)
	}
	if slowFlow.SecurityScore >= 45 {
		t.Fatalf("expected damped SecurityScore < 45 for slow 10-day IoT heartbeat, got %d (reasons=%v)", slowFlow.SecurityScore, slowFlow.Reasons)
	}
	if !strings.Contains(strings.Join(slowFlow.Reasons, " | "), "均速") {
		t.Fatalf("expected rate-annotated reason, got %v", slowFlow.Reasons)
	}

	// 2. 同等 306MB 若集中在 10 分钟内突发送出（约 522 KB/s）-> 仍应触发高危告警
	burstFlow := slowFlow
	burstFlow.ActiveSpanSec = 600
	burstFlow.Reasons = nil
	burstFlow.NonlinearFactors = nil
	eng.EvaluateFlow(&burstFlow)
	if burstFlow.SecurityScore < 75 || burstFlow.RiskScore < 80 || burstFlow.Threat != ThreatHighRisk {
		t.Fatalf("expected high_risk burst score for 10-min 306MB upload, got sec=%d risk=%d threat=%s",
			burstFlow.SecurityScore, burstFlow.RiskScore, burstFlow.Threat)
	}
}

func TestCollector_SampleActiveConnections(t *testing.T) {
	var stage atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if stage.Load() == 0 {
			_, _ = w.Write([]byte(`{
				"connections": [
					{
						"id": "yt-burst-1",
						"upload": 524288,
						"download": 67108864,
						"start": "2026-11-20T20:00:00Z",
						"chains": ["sec_node", "#VPS", "Proxy"],
						"rule": "rule_set=geosite-youtube",
						"metadata": {
							"network": "tcp",
							"sourceIP": "192.168.1.50",
							"destinationIP": "203.0.113.88",
							"destinationPort": "443",
							"host": "rr1---sn-test.googlevideo.com"
						}
					}
				]
			}`))
			return
		}
		_, _ = w.Write([]byte(`{"connections": []}`))
	}))
	defer srv.Close()

	statePath := filepath.Join(t.TempDir(), "audit-state.json")
	c := NewCollector(nil)
	c.SetEndpointsForTest([]string{srv.URL}, "", statePath)

	// Stage 0: 后台轻量采样捕获高速短连接
	if ok := c.SampleActiveConnections(t.Context()); !ok {
		t.Fatal("expected SampleActiveConnections to return reachable=true")
	}

	// Stage 1: 短连接已关闭后再运行 Collect()，验证先前采样流量与 YouTube 识别完整保留
	stage.Store(1)
	rep := c.Collect(t.Context(), CollectOptions{Limit: -1})
	if !rep.Reachable || len(rep.Flows) != 1 {
		t.Fatalf("expected 1 persisted flow after connection closed, got reachable=%v len=%d", rep.Reachable, len(rep.Flows))
	}
	f := rep.Flows[0]
	if f.Target != "rr1---sn-test.googlevideo.com" || f.DownloadBytes != 67108864 || f.AppName != "YouTube" {
		t.Fatalf("unexpected sampled flow record: %+v", f)
	}
}

func TestThrottler_BuildNFTScript_SelfLock_And_Teardown(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{ServerIP: "198.51.100.250"},
		Audit: config.AuditConfig{
			Throttles: []config.AuditThrottleRule{
				{Target: "iot-cloud.example.com", Port: 443, RateKBps: 5},
			},
		},
	}

	// 安全防自锁校验
	for _, blocked := range []string{"8.8.8.8", "192.168.1.1", "198.51.100.250", "ruleset:block-builtin-pcdn", "*.example.com"} {
		if _, _, err := NormalizeThrottleTarget(cfg, blocked, 443); err == nil {
			t.Fatalf("expected NormalizeThrottleTarget to reject unsafe target %q", blocked)
		}
	}

	var appliedScript string
	var deletedCalled bool
	th := &Throttler{
		lookupIPs: func(_ context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("192.168.1.50"),   // 私网必须过滤
				netip.MustParseAddr("198.51.100.250"), // 代理节点 IP 必须过滤
				netip.MustParseAddr("203.0.113.69"),   // 仅保留合法公网目标
			}, nil
		},
		runNFT: func(_ context.Context, script string) error {
			appliedScript = script
			return nil
		},
		deleteNFT: func(_ context.Context) error {
			deletedCalled = true
			return nil
		},
	}

	res := th.Apply(t.Context(), cfg)
	if !res.Applied || res.ActiveRules != 1 || res.ActiveIPs != 1 {
		t.Fatalf("unexpected apply result: %+v", res)
	}
	for _, want := range []string{
		"table inet " + ThrottleNFTTable,
		"priority -160",
		`iifname "lo" return`,
		"ip daddr 203.0.113.69 meta l4proto { tcp, udp } th dport 443 limit rate over 5 kbytes/second burst 16 kbytes drop",
	} {
		if !strings.Contains(appliedScript, want) {
			t.Fatalf("expected nft script to contain %q, got:\n%s", want, appliedScript)
		}
	}
	for _, forbidden := range []string{"192.168.1.50", "198.51.100.250"} {
		if strings.Contains(appliedScript, forbidden) {
			t.Fatalf("nft script leaked protected IP %s:\n%s", forbidden, appliedScript)
		}
	}

	// 清空规则后自动触发 deleteNFT 清理表
	if !RemoveThrottleRule(cfg, "iot-cloud.example.com", 443) {
		t.Fatal("expected RemoveThrottleRule to return true")
	}
	resClean := th.Apply(t.Context(), cfg)
	if !resClean.Applied || !deletedCalled {
		t.Fatalf("expected Apply on empty throttles to delete nft table, got res=%+v deleted=%v", resClean, deletedCalled)
	}
	_ = time.Second
}
