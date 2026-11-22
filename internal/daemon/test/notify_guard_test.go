// 文件职责：覆盖守护进程 P0 告警闭环（lifecycle 托管通知调度器、配置热更新、tailscaled OOM 守护、资源预警与恢复、看门狗自愈、策略组切换失败及审计新设备/高危告警）。
package daemon_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"singctl/internal/audit"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/notify"
	"singctl/internal/safecommit"
)

type capturedWebhookEvent struct {
	EventType string `json:"eventType"`
	Severity  string `json:"severity"`
	DedupKey  string `json:"dedupKey"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Resolved  bool   `json:"resolved"`
}

func startWebhookCollector(t *testing.T) (*httptest.Server, func() []capturedWebhookEvent) {
	t.Helper()
	var mu sync.Mutex
	var events []capturedWebhookEvent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var ev capturedWebhookEvent
		if json.Unmarshal(raw, &ev) == nil && ev.EventType != "" {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []capturedWebhookEvent {
		mu.Lock()
		defer mu.Unlock()
		out := make([]capturedWebhookEvent, len(events))
		copy(out, events)
		return out
	}
}

func waitForEvents(t *testing.T, get func() []capturedWebhookEvent, want int) []capturedWebhookEvent {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		evs := get()
		if len(evs) >= want {
			return evs
		}
		time.Sleep(15 * time.Millisecond)
	}
	return get()
}

func TestDaemon_LifecycleNotifier_OOMGuard_ResourceGuardAndRecovery(t *testing.T) {
	hookSrv, getEvents := startWebhookCollector(t)

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	logPath := filepath.Join(tmpDir, "daemon.log")
	procRoot := filepath.Join(tmpDir, "proc")
	pidDir := filepath.Join(procRoot, "7788")
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("tailscaled\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "oom_score_adj"), []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Notify: config.NotifyConfig{
			Enabled:         true,
			CooldownMinutes: 15,
			DailyLimit:      50,
			Channels: config.NotifyChannelsConfig{
				Webhook: config.GenericWebhookConfig{
					Enabled: true,
					URL:     hookSrv.URL,
				},
			},
		},
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	diskUsedPct := 90
	diskAvail := uint64(6 * 1024 * 1024)
	memAvail := uint64(32 * 1024 * 1024)

	d := daemon.NewDaemonWithOptions(cfg, daemon.DaemonOptions{
		ConfigPath:      cfgPath,
		Version:         "v1.0.0-test",
		Paths:           daemon.Paths{LogFile: logPath, StateFile: filepath.Join(tmpDir, "state.json")},
		SkipSignalSetup: true,
		PidWriter:       func() error { return nil },
		PidRemover:      func() error { return nil },
		OOMProcRoot:     procRoot,
		NotifyDeps: notify.DispatcherDeps{
			HTTPClient: hookSrv.Client(),
			Hostname:   "router-test",
		},
		TelemetryDeps: &sysinfo.TelemetryDeps{
			IsOpenWrt: func() bool { return true },
			Statfs: func(path string) (sysinfo.DiskSpace, error) {
				mu.Lock()
				defer mu.Unlock()
				if path == "/overlay" {
					return sysinfo.DiskSpace{
						TotalBytes:  64 * 1024 * 1024,
						UsedBytes:   uint64(64*1024*1024) - diskAvail,
						AvailBytes:  diskAvail,
						UsedPercent: diskUsedPct,
					}, nil
				}
				return sysinfo.DiskSpace{TotalBytes: 64 << 20, AvailBytes: 40 << 20, UsedPercent: 37}, nil
			},
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				mu.Lock()
				defer mu.Unlock()
				return sysinfo.MemInfo{
					TotalBytes:     256 * 1024 * 1024,
					AvailableBytes: memAvail,
				}, nil
			},
		},
	})

	if d.Notifier() == nil {
		t.Fatal("expected daemon to initialize Notifier")
	}
	lc := d.BuildForegroundLifecycle()
	if err := lc.Start(t.Context()); err != nil {
		t.Fatalf("lifecycle Start failed: %v", err)
	}
	defer func() { _ = lc.Close() }()

	// 1. OOM 免疫守护将 fake tailscaled 保护为 -1000
	if !d.GuardTailscaleOOMOnce() {
		t.Fatal("expected GuardTailscaleOOMOnce to protect tailscaled")
	}
	if st := safecommit.InspectTailscaledOOM(procRoot); !st.Protected || st.ScoreAdj != -1000 {
		t.Fatalf("expected oom_score_adj=-1000, got %+v", st)
	}

	// 缺失 tailscaled 时必须静默跳过不返回报错
	dNoTS := daemon.NewDaemonWithOptions(cfg, daemon.DaemonOptions{
		ConfigPath:      cfgPath,
		SkipSignalSetup: true,
		OOMProcRoot:     filepath.Join(tmpDir, "empty-proc"),
	})
	if dNoTS.GuardTailscaleOOMOnce() {
		t.Fatal("expected GuardTailscaleOOMOnce false when tailscaled absent")
	}

	// 2. 资源预警触发磁盘与内存双告警，缓解后发 Resolved:true 恢复通知
	d.CheckHostResourcesOnce()
	evs := waitForEvents(t, getEvents, 2)
	if len(evs) < 2 {
		t.Fatalf("expected 2 resource_guard alerts (disk+mem), got %d: %+v", len(evs), evs)
	}
	for _, ev := range evs[:2] {
		if ev.EventType != string(notify.EventResourceGuard) || ev.Resolved {
			t.Fatalf("expected unresolved resource_guard event, got %+v", ev)
		}
	}

	// 恢复资源后应配对发送两条 Resolved:true 通知
	mu.Lock()
	diskUsedPct = 45
	diskAvail = 35 * 1024 * 1024
	memAvail = 128 * 1024 * 1024
	mu.Unlock()

	d.CheckHostResourcesOnce()
	evs = waitForEvents(t, getEvents, 4)
	if len(evs) < 4 {
		t.Fatalf("expected 2 resolved resource_guard events, total=%d: %+v", len(evs), evs)
	}
	resolvedCount := 0
	for _, ev := range evs {
		if ev.EventType == string(notify.EventResourceGuard) && ev.Resolved {
			resolvedCount++
		}
	}
	if resolvedCount != 2 {
		t.Fatalf("expected 2 resolved resource_guard events, got %d (%+v)", resolvedCount, evs)
	}

	// 3. 看门狗自愈告警与恢复通知
	d.RecordWatchdogHealEvent(false, "process_down", "sing-box 已退出并触发重启")
	d.RecordWatchdogHealEvent(true, "recovered", "sing-box 已恢复健康")
	evs = waitForEvents(t, getEvents, 6)
	healAlert, healRecovered := false, false
	for _, ev := range evs {
		if ev.EventType == string(notify.EventWatchdogHeal) {
			if ev.Resolved {
				healRecovered = true
			} else {
				healAlert = true
			}
		}
	}
	if !healAlert || !healRecovered {
		t.Fatalf("expected both watchdog_heal alert and recovery, got %+v", evs)
	}

	// 4. 审计新设备（首轮建立基线不刷屏，第二轮新 MAC 触发）与高危流告警
	d.ObserveAuditReport(&audit.Report{
		Reachable: true,
		Devices: []audit.DeviceSummary{
			{DeviceIP: "192.168.1.10", DeviceName: "nas", DeviceMAC: "AA:BB:CC:00:00:01"},
		},
	})
	d.ObserveAuditReport(&audit.Report{
		Reachable: true,
		Devices: []audit.DeviceSummary{
			{DeviceIP: "192.168.1.10", DeviceName: "nas", DeviceMAC: "AA:BB:CC:00:00:01"},
			{DeviceIP: "192.168.1.25", DeviceName: "guest-phone", DeviceMAC: "AA:BB:CC:00:00:02"},
		},
		Flows: []audit.FlowRecord{
			{
				DeviceIP:   "192.168.1.25",
				DeviceName: "guest-phone",
				Target:     "bad.example.com",
				Threat:     audit.ThreatHighRisk,
				State:      audit.EnforcementObserved,
				RiskScore:  92,
				Reasons:    []string{"异常大额夜间上传"},
			},
		},
	})
	evs = waitForEvents(t, getEvents, 8)
	sawNewDev, sawHighRisk := false, false
	for _, ev := range evs {
		if ev.EventType == string(notify.EventNewDevice) {
			sawNewDev = true
		}
		if ev.EventType == string(notify.EventAuditHighRisk) {
			sawHighRisk = true
		}
	}
	if !sawNewDev || !sawHighRisk {
		t.Fatalf("expected new_device and audit_high_risk events, got %+v", evs)
	}
}

func TestGroupFailover_EmitsSubOrNodeFailNotification(t *testing.T) {
	// Mock Clash API: 主选 node-a 超时，备选 node-b 也超时 -> 触发故障切换失败告警
	clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/proxies":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"proxies": map[string]any{
					"Proxy": map[string]any{
						"type": "Selector",
						"now":  "node-a",
						"all":  []string{"node-a", "node-b"},
					},
					"node-a": map[string]any{"type": "Shadowsocks"},
					"node-b": map[string]any{"type": "Shadowsocks"},
				},
			})
		default:
			w.WriteHeader(http.StatusGatewayTimeout)
		}
	}))
	defer clashSrv.Close()

	var mu sync.Mutex
	var emitted []notify.Event
	fo := daemon.NewGroupFailoverState()
	fo.WatchedGroups = []string{"Proxy"}
	fo.ProbeURLs = []string{"http://example.com/generate_204"}
	fo.ProbeTimeout = 100 * time.Millisecond
	fo.ConfirmRetries = 0
	fo.EnableWANGate = false
	fo.CheckWANFn = func(context.Context) bool { return true }
	fo.OnNotify = func(ev notify.Event) {
		mu.Lock()
		emitted = append(emitted, ev)
		mu.Unlock()
	}

	fo.Patrol(t.Context(), []string{clashSrv.URL}, "")

	mu.Lock()
	defer mu.Unlock()
	if len(emitted) == 0 {
		t.Fatal("expected EventSubOrNodeFail emitted when all candidates dead")
	}
	if emitted[0].Type != notify.EventSubOrNodeFail || emitted[0].Severity != notify.SeverityCritical {
		t.Fatalf("unexpected failover notification: %+v", emitted[0])
	}
}
