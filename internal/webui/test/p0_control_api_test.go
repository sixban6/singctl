// 文件职责：端到端黑盒覆盖客户端 WebUI P0 控制面 API（实时遥测、Safe Commit 回滚与高危联动、多渠道通知配置与测试、8 项深度体检与快捷修复）。
package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/doctor"
	"singctl/internal/gateway"
	"singctl/internal/notify"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/safecommit"
	"singctl/internal/singbox"
	"singctl/internal/webui"
)

func createFakeProcWithTailscaled(t *testing.T, pid string, initialScore string) string {
	t.Helper()
	procRoot := filepath.Join(t.TempDir(), "proc")
	pidDir := filepath.Join(procRoot, pid)
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("tailscaled\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "oom_score_adj"), []byte(initialScore+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return procRoot
}

func doJSONReq(t *testing.T, srv *webui.Server, method, path string, payload any, authToken string) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "SingCtlWebUI")
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	return rec
}

func TestWebUI_StatusIncludesHostTelemetryAndSafeCommit(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var statCalls atomic.Int32
	sampler := sysinfo.NewCPUSamplerWithReader(func() (string, error) {
		n := statCalls.Add(1)
		if n == 1 {
			return "cpu  100 0 100 800 0 0 0 0\n", nil
		}
		return "cpu  150 0 150 1100 0 0 0 0\n", nil
	})
	procRoot := createFakeProcWithTailscaled(t, "4242", "-1000")

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		SkipAdGuardProbeForTest: true,
		CPUSampler:              sampler,
		TelemetryDeps: &sysinfo.TelemetryDeps{
			ReadUptimeSec: func() int64 { return 86400 },
			ReadLoadAvg:   func() [3]float64 { return [3]float64{0.25, 0.30, 0.28} },
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{
					TotalBytes:     512 * 1024 * 1024,
					AvailableBytes: 256 * 1024 * 1024,
				}, nil
			},
			Statfs: func(path string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{
					TotalBytes:  100 * 1024 * 1024,
					UsedBytes:   40 * 1024 * 1024,
					AvailBytes:  60 * 1024 * 1024,
					UsedPercent: 40,
				}, nil
			},
			IsOpenWrt: func() bool { return true },
			NumCPU:    func() int { return 4 },
			Now:       func() time.Time { return time.Unix(1700000000, 0) },
		},
		SafeCommitStateDir: filepath.Join(dir, "sc-state"),
		SafeCommitProcRoot: procRoot,
	})

	// New() 必须已调用 Prime()，因此首次 GET /api/status 即可返回 cpuReady=true 和有效 cpuPercent（零 sleep）
	rec := doJSONReq(t, srv, http.MethodGet, "/api/status", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/status status=%d body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Host struct {
			Hostname  string                `json:"hostname"`
			OS        string                `json:"os"`
			Arch      string                `json:"arch"`
			Telemetry sysinfo.HostTelemetry `json:"telemetry"`
		} `json:"host"`
		SafeCommit safecommit.StatusReport `json:"safeCommit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal /api/status: %v", err)
	}
	if resp.Host.OS == "" || resp.Host.Arch == "" {
		t.Fatalf("legacy host fields missing: %+v", resp.Host)
	}
	if !resp.Host.Telemetry.CPUReady || resp.Host.Telemetry.CPUPercent != 25.0 {
		t.Fatalf("expected primed first-call CPU telemetry ready=true pct=25.0, got %+v", resp.Host.Telemetry)
	}
	if resp.Host.Telemetry.UptimeSec != 86400 || resp.Host.Telemetry.CPUCores != 4 || resp.Host.Telemetry.Mem.UsedPercent != 50 {
		t.Fatalf("unexpected telemetry values: %+v", resp.Host.Telemetry)
	}
	if resp.Host.Telemetry.Disk.MountPath != "/overlay" || resp.Host.Telemetry.TmpDisk == nil {
		t.Fatalf("expected OpenWrt /overlay + /tmp disk telemetry, got %+v", resp.Host.Telemetry)
	}
	if resp.SafeCommit.Active || !resp.SafeCommit.TailscaleOOM.Found || !resp.SafeCommit.TailscaleOOM.Protected || resp.SafeCommit.TailscaleOOM.PID != 4242 {
		t.Fatalf("unexpected safeCommit status: %+v", resp.SafeCommit)
	}
}

func TestWebUI_SafeCommitAPI_FullLifecycleOOMAndConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "sing-box.json")
	sdPath := filepath.Join(dir, "smartdns.conf")
	scDir := filepath.Join(dir, "safecommit")
	procRoot := createFakeProcWithTailscaled(t, "5150", "0")

	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbPath, []byte(`{"dns":{"disable_cache":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sdPath, []byte("bind 127.0.0.1:5353\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var webhookHits atomic.Int32
	var lastEventType atomic.Value
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var ev struct {
			EventType string `json:"eventType"`
		}
		if json.Unmarshal(raw, &ev) == nil {
			lastEventType.Store(ev.EventType)
		}
		webhookHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer hookSrv.Close()

	// 配置通知渠道以便回滚触发 EventSafeCommitRollback
	initCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	initCfg.Notify = config.NotifyConfig{
		Enabled: true,
		Channels: config.NotifyChannelsConfig{
			Webhook: config.GenericWebhookConfig{
				Enabled: true,
				URL:     hookSrv.URL,
			},
		},
	}
	if err := config.Save(cfgPath, initCfg); err != nil {
		t.Fatal(err)
	}

	var sbReloaded, fwDisabled, dnsReloaded atomic.Bool
	notifier := notify.NewDispatcher(notify.OptionsFromConfig(initCfg.Notify), notify.DispatcherDeps{
		HTTPClient: hookSrv.Client(),
	})
	notifier.Start(t.Context())
	defer notifier.Close()

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		SingBoxConfigPath:       sbPath,
		SmartDNSConfigPath:      sdPath,
		Password:                "secret-pass",
		SkipAdGuardProbeForTest: true,
		SafeCommitStateDir:      scDir,
		SafeCommitProcRoot:      procRoot,
		SafeCommitSpawnWatcher:  func(token string) (int, error) { return 0, nil },
		SafeCommitKillWatcher:   func(pid int) error { return nil },
		SafeCommitBaselineForTest: func() (bool, bool) {
			return true, false
		},
		SafeCommitRollbackOps: &safecommit.RollbackOps{
			StartOrReloadSingBox: func(context.Context) error { sbReloaded.Store(true); return nil },
			DisableFirewall:      func(context.Context) error { fwDisabled.Store(true); return nil },
			ReloadDNS:            func(context.Context, string) error { dnsReloaded.Store(true); return nil },
		},
		NotifyDispatcher: notifier,
	})
	tok := srv.SessionToken()

	// 0. 未鉴权访问必须 401
	unauth := doJSONReq(t, srv, http.MethodGet, "/api/safe-commit/status", nil, "")
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized, got %d", unauth.Code)
	}

	// 1. GET /api/safe-commit/status
	rec := doJSONReq(t, srv, http.MethodGet, "/api/safe-commit/status", nil, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/safe-commit/status failed: %d %s", rec.Code, rec.Body.String())
	}
	var stResp struct {
		Active       bool                       `json:"active"`
		RemainingSec int64                      `json:"remainingSec"`
		TailscaleOOM safecommit.OOMShieldStatus `json:"tailscaleOom"`
		Config       struct {
			DefaultTTLSec       int  `json:"defaultTtlSec"`
			ProtectTailscaleOOM bool `json:"protectTailscaleOom"`
		} `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &stResp); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if stResp.Active || stResp.Config.DefaultTTLSec != 180 || !stResp.Config.ProtectTailscaleOOM {
		t.Fatalf("unexpected initial status: %+v", stResp)
	}
	if !stResp.TailscaleOOM.Found || stResp.TailscaleOOM.Protected {
		t.Fatalf("expected tailscaled found=true protected=false, got %+v", stResp.TailscaleOOM)
	}

	// 2. PUT /api/safe-commit/config 越界 TTL 返回 400
	badCfg := doJSONReq(t, srv, http.MethodPut, "/api/safe-commit/config", map[string]any{
		"defaultTtlSec":       30,
		"protectTailscaleOom": true,
	}, tok)
	if badCfg.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for TTL=30, got %d: %s", badCfg.Code, badCfg.Body.String())
	}

	// 3. PUT /api/safe-commit/config 合法保存（0600 落盘 + 立刻应用 OOM 免疫）
	okCfg := doJSONReq(t, srv, http.MethodPut, "/api/safe-commit/config", map[string]any{
		"defaultTtlSec":       240,
		"protectTailscaleOom": true,
	}, tok)
	if okCfg.Code != http.StatusOK {
		t.Fatalf("PUT /api/safe-commit/config failed: %d %s", okCfg.Code, okCfg.Body.String())
	}
	fi, err := os.Stat(cfgPath)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected config perm 0600, got %v err=%v", fi, err)
	}
	var cfgResp struct {
		OK           bool                       `json:"ok"`
		TailscaleOOM safecommit.OOMShieldStatus `json:"tailscaleOom"`
		Config       struct {
			DefaultTTLSec       int  `json:"defaultTtlSec"`
			ProtectTailscaleOOM bool `json:"protectTailscaleOom"`
		} `json:"config"`
	}
	_ = json.Unmarshal(okCfg.Body.Bytes(), &cfgResp)
	if !cfgResp.OK || cfgResp.Config.DefaultTTLSec != 240 || !cfgResp.TailscaleOOM.Protected {
		t.Fatalf("unexpected PUT config resp: %+v", cfgResp)
	}

	// 4. POST /api/safe-commit/oom-protect 幂等返回 ok:true
	oomRec := doJSONReq(t, srv, http.MethodPost, "/api/safe-commit/oom-protect", map[string]any{}, tok)
	if oomRec.Code != http.StatusOK || !strings.Contains(oomRec.Body.String(), `"ok":true`) {
		t.Fatalf("POST oom-protect failed: %d %s", oomRec.Code, oomRec.Body.String())
	}

	// 5. POST /api/safe-commit/arm 非法 TTL 返回 400
	badArm := doJSONReq(t, srv, http.MethodPost, "/api/safe-commit/arm", map[string]any{"ttlSec": 999}, tok)
	if badArm.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid arm TTL, got %d", badArm.Code)
	}

	// 6. POST /api/safe-commit/arm（ttlSec<=0 使用配置默认 240）
	armRec := doJSONReq(t, srv, http.MethodPost, "/api/safe-commit/arm", map[string]any{"reason": "测试高危修改"}, tok)
	if armRec.Code != http.StatusOK {
		t.Fatalf("POST arm failed: %d %s", armRec.Code, armRec.Body.String())
	}
	var armResp struct {
		OK     bool `json:"ok"`
		Status struct {
			Active bool              `json:"active"`
			State  *safecommit.State `json:"state"`
		} `json:"status"`
	}
	_ = json.Unmarshal(armRec.Body.Bytes(), &armResp)
	if !armResp.OK || !armResp.Status.Active || armResp.Status.State == nil || armResp.Status.State.TTLSec != 240 {
		t.Fatalf("unexpected arm resp: %+v", armResp)
	}

	// 7. POST /api/safe-commit/confirm 错误 token 返回 400
	badConfirm := doJSONReq(t, srv, http.MethodPost, "/api/safe-commit/confirm", map[string]any{"token": "wrong-token"}, tok)
	if badConfirm.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on wrong token, got %d: %s", badConfirm.Code, badConfirm.Body.String())
	}

	// 8. POST /api/safe-commit/confirm 空 token 确认激活态
	okConfirm := doJSONReq(t, srv, http.MethodPost, "/api/safe-commit/confirm", map[string]any{}, tok)
	if okConfirm.Code != http.StatusOK {
		t.Fatalf("confirm failed: %d %s", okConfirm.Code, okConfirm.Body.String())
	}
	var confResp struct {
		OK        bool `json:"ok"`
		Confirmed bool `json:"confirmed"`
		Status    struct {
			Active bool `json:"active"`
		} `json:"status"`
	}
	_ = json.Unmarshal(okConfirm.Body.Bytes(), &confResp)
	if !confResp.OK || !confResp.Confirmed || confResp.Status.Active {
		t.Fatalf("unexpected confirm resp: %+v", confResp)
	}

	// 9. 重新 Arm，篡改 sing-box.json 后执行 POST /api/safe-commit/rollback 验证原子还原 + 回调 + 告警推送
	arm2 := doJSONReq(t, srv, http.MethodPost, "/api/safe-commit/arm", map[string]any{"ttlSec": 120, "reason": "准备回滚验证"}, tok)
	if arm2.Code != http.StatusOK {
		t.Fatalf("arm2 failed: %d", arm2.Code)
	}
	if err := os.WriteFile(sbPath, []byte(`{"broken":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	rbRec := doJSONReq(t, srv, http.MethodPost, "/api/safe-commit/rollback", map[string]any{"trigger": "manual"}, tok)
	if rbRec.Code != http.StatusOK {
		t.Fatalf("rollback failed: %d %s", rbRec.Code, rbRec.Body.String())
	}
	restored, err := os.ReadFile(sbPath)
	if err != nil || !strings.Contains(string(restored), `"disable_cache":true`) {
		t.Fatalf("expected sing-box.json restored, got %q err=%v", string(restored), err)
	}
	if !sbReloaded.Load() || !fwDisabled.Load() || !dnsReloaded.Load() {
		t.Fatalf("expected rollback ops invoked: sb=%v fw=%v dns=%v", sbReloaded.Load(), fwDisabled.Load(), dnsReloaded.Load())
	}

	deadline := time.Now().Add(2 * time.Second)
	for webhookHits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if webhookHits.Load() == 0 || lastEventType.Load() != string(notify.EventSafeCommitRollback) {
		t.Fatalf("expected EventSafeCommitRollback notification, hits=%d last=%v", webhookHits.Load(), lastEventType.Load())
	}

	// 10. OOM 找不到 tailscaled 进程时返回 200 ok:false
	emptyProc := filepath.Join(t.TempDir(), "empty-proc")
	_ = os.MkdirAll(emptyProc, 0755)
	srvNoTS := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		SkipAdGuardProbeForTest: true,
		SafeCommitStateDir:      filepath.Join(dir, "sc2"),
		SafeCommitProcRoot:      emptyProc,
	})
	noTSRec := doJSONReq(t, srvNoTS, http.MethodPost, "/api/safe-commit/oom-protect", map[string]any{}, "")
	if noTSRec.Code != http.StatusOK || !strings.Contains(noTSRec.Body.String(), `"ok":false`) {
		t.Fatalf("expected 200 ok:false when tailscaled absent, got %d %s", noTSRec.Code, noTSRec.Body.String())
	}
}

func TestWebUI_SafeCommitHighRiskOperationLinkage(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "sing-box.json")
	smartBin := filepath.Join(dir, "smartdns")
	if err := os.WriteFile(cfgPath, []byte("subs:\n  - name: main\n    url: https://example.com/sub\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbPath, []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"https","server":"223.5.5.5","server_port":443,"path":"/dns-query"}],"disable_cache":true,"optimistic":false}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(smartBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	fakeBin := ""
	if runtime.GOOS != "windows" {
		fakeBin = writeFakeSingctlScript(t, 0, "ok")
	}

	scDir := filepath.Join(dir, "sc-link")
	srv := webui.New(webui.Options{
		ConfigPath:                cfgPath,
		SingBoxConfigPath:         sbPath,
		SmartDNSBinPath:           smartBin,
		SmartDNSConfigPath:        filepath.Join(dir, "smartdns.conf"),
		SmartDNSRulesDir:          filepath.Join(dir, "smartdns-rules.d"),
		SmartDNSAuditLogPath:      filepath.Join(dir, "smartdns-audit.log"),
		LocalDNSServiceMgr:        servicemgr.NewMock(),
		ExecutablePath:            fakeBin,
		SkipAdGuardProbeForTest:   true,
		SafeCommitStateDir:        scDir,
		SafeCommitSpawnWatcher:    func(token string) (int, error) { return 0, nil },
		SafeCommitKillWatcher:     func(pid int) error { return nil },
		SafeCommitBaselineForTest: func() (bool, bool) { return true, false },
		AdGuardMemInfoForTest: func() sysinfo.MemInfo {
			return sysinfo.MemInfo{TotalBytes: 1024 * 1024 * 1024, AvailableBytes: 512 * 1024 * 1024}
		},
		DiskSpaceForTest: func(string) (sysinfo.DiskSpace, error) {
			return sysinfo.DiskSpace{AvailBytes: 100 * 1024 * 1024}, nil
		},
		LocalDNSProbeDNSForTest: func(string, time.Duration) error { return nil },
		LocalDNSProbeResForTest: func(string, string, time.Duration) ([]string, time.Duration, error) {
			return []string{"192.0.2.1"}, 5 * time.Millisecond, nil
		},
		LocalDNSSyncSingBoxDNSLocalForTest: func(_ context.Context, p, _ string, useExternal bool, port int) (bool, error) {
			raw, _ := os.ReadFile(p)
			out, changed, err := singbox.PatchDNSLocalJSON(string(raw), useExternal, port)
			if err == nil && changed {
				_ = os.WriteFile(p, []byte(out), 0600)
			}
			return changed, err
		},
		GatewayProberForTest: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{
				LANIP:                 "192.168.100.2",
				LANCIDR:               "192.168.100.0/24",
				LANIface:              "eth0",
				CurrentGatewayIP:      "192.168.100.1",
				SuggestedMainRouterIP: "192.168.100.1",
			}
		},
	})

	// 1. POST /api/gateway 带 safeCommit:true 自动 Arm
	gwRec := doJSONReq(t, srv, http.MethodPost, "/api/gateway", map[string]any{
		"mode":             "side",
		"mainRouterIP":     "192.168.100.1",
		"safeCommit":       true,
		"safeCommitTtlSec": 150,
	}, "")
	if gwRec.Code != http.StatusOK {
		t.Fatalf("POST /api/gateway with safeCommit failed: %d %s", gwRec.Code, gwRec.Body.String())
	}
	stRec := doJSONReq(t, srv, http.MethodGet, "/api/safe-commit/status", nil, "")
	if !strings.Contains(stRec.Body.String(), `"active":true`) || !strings.Contains(stRec.Body.String(), `"ttlSec":150`) {
		t.Fatalf("expected active safeCommit with ttlSec=150 after gateway change, got %s", stRec.Body.String())
	}
	_ = doJSONReq(t, srv, http.MethodPost, "/api/safe-commit/confirm", map[string]any{}, "")

	// 2. POST /api/dns/switch-engine 别名路由带 safeCommit:true 自动 Arm
	dnsRec := doJSONReq(t, srv, http.MethodPost, "/api/dns/switch-engine", map[string]any{
		"engine":           "smartdns",
		"safeCommit":       true,
		"safeCommitTtlSec": 180,
	}, "")
	if dnsRec.Code != http.StatusOK {
		t.Fatalf("POST /api/dns/switch-engine failed: %d %s", dnsRec.Code, dnsRec.Body.String())
	}
	stRec = doJSONReq(t, srv, http.MethodGet, "/api/safe-commit/status", nil, "")
	if !strings.Contains(stRec.Body.String(), `"active":true`) {
		t.Fatalf("expected active safeCommit after dns switch-engine, got %s", stRec.Body.String())
	}
	_ = doJSONReq(t, srv, http.MethodPost, "/api/safe-commit/confirm", map[string]any{}, "")

	// 3. POST /api/action 带 safeCommit:true 自动 Arm
	if runtime.GOOS != "windows" {
		actRec := doJSONReq(t, srv, http.MethodPost, "/api/action", map[string]any{
			"name":             "sb-restart",
			"safeCommit":       true,
			"safeCommitTtlSec": 120,
		}, "")
		if actRec.Code != http.StatusOK {
			t.Fatalf("POST /api/action with safeCommit failed: %d %s", actRec.Code, actRec.Body.String())
		}
		stRec = doJSONReq(t, srv, http.MethodGet, "/api/safe-commit/status", nil, "")
		if !strings.Contains(stRec.Body.String(), `"active":true`) || !strings.Contains(stRec.Body.String(), `"ttlSec":120`) {
			t.Fatalf("expected active safeCommit after action, got %s", stRec.Body.String())
		}
	}
}

func TestWebUI_NotifyAPI_RedactionMergeValidationAndTestDelivery(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var receivedHeader atomic.Value
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader.Store(r.Header.Get("X-Test-Auth"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer hookSrv.Close()

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		SkipAdGuardProbeForTest: true,
		NotifyHTTPClient:        hookSrv.Client(),
	})

	// 1. GET /api/notify/config 默认填充有效值与空 recentHistory
	getRec := doJSONReq(t, srv, http.MethodGet, "/api/notify/config", nil, "")
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /api/notify/config failed: %d %s", getRec.Code, getRec.Body.String())
	}
	var getResp struct {
		Config        config.NotifyConfig       `json:"config"`
		SecretStatus  config.NotifySecretStatus `json:"secretStatus"`
		RecentHistory []notify.HistoryRecord    `json:"recentHistory"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("unmarshal GET notify config: %v", err)
	}
	if getResp.Config.CooldownMinutes != 15 || getResp.Config.DailyLimit != 50 || !getResp.Config.Events.WatchdogHeal {
		t.Fatalf("expected effective defaults in GET notify config, got %+v", getResp.Config)
	}
	if getResp.RecentHistory == nil {
		t.Fatal("expected recentHistory to be non-nil JSON array []")
	}

	// 2. PUT /api/notify/config 使用 { "config": ... } 包装格式保存，校验脱敏响应不泄漏明文密钥
	secretToken := "123456789:ABCDEF_VERY_SECRET_TOKEN_XYZ"
	headerSecret := "super-secret-webhook-header-value"
	putRec := doJSONReq(t, srv, http.MethodPut, "/api/notify/config", map[string]any{
		"config": map[string]any{
			"enabled":         true,
			"cooldownMinutes": 10,
			"dailyLimit":      80,
			"quietHours":      "23:00-07:00",
			"channels": map[string]any{
				"telegram": map[string]any{
					"enabled":  true,
					"botToken": secretToken,
					"chatId":   "10001",
				},
				"webhook": map[string]any{
					"enabled":     true,
					"url":         hookSrv.URL,
					"headerName":  "X-Test-Auth",
					"headerValue": headerSecret,
				},
			},
		},
	}, "")
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT /api/notify/config failed: %d %s", putRec.Code, putRec.Body.String())
	}
	if strings.Contains(putRec.Body.String(), secretToken) || strings.Contains(putRec.Body.String(), headerSecret) {
		t.Fatalf("plaintext secret leaked in PUT response: %s", putRec.Body.String())
	}
	fi, err := os.Stat(cfgPath)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 config mode, got %v err=%v", fi, err)
	}

	// 3. 平铺 PUT 回传掩码值时必须保留原明文密钥
	putFlat := doJSONReq(t, srv, http.MethodPut, "/api/notify/config", map[string]any{
		"enabled":         true,
		"cooldownMinutes": 20,
		"dailyLimit":      60,
		"quietHours":      "22:30-06:30",
		"channels": map[string]any{
			"telegram": map[string]any{
				"enabled":  true,
				"botToken": "********",
				"chatId":   "10001",
			},
			"webhook": map[string]any{
				"enabled":     true,
				"url":         hookSrv.URL,
				"headerName":  "X-Test-Auth",
				"headerValue": "",
			},
		},
	}, "")
	if putFlat.Code != http.StatusOK {
		t.Fatalf("flat PUT /api/notify/config failed: %d %s", putFlat.Code, putFlat.Body.String())
	}
	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Notify.Channels.Telegram.BotToken != secretToken || saved.Notify.Channels.Webhook.HeaderValue != headerSecret {
		t.Fatalf("expected masked/empty secrets preserved, got tg=%q wh=%q",
			saved.Notify.Channels.Telegram.BotToken, saved.Notify.Channels.Webhook.HeaderValue)
	}

	// 4. 非法 QuietHours / URL / CRLF Header 必须返回 400
	badQH := doJSONReq(t, srv, http.MethodPut, "/api/notify/config", map[string]any{
		"quietHours": "bad-range",
	}, "")
	if badQH.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid quietHours, got %d", badQH.Code)
	}
	badURL := doJSONReq(t, srv, http.MethodPut, "/api/notify/config", map[string]any{
		"channels": map[string]any{
			"webhook": map[string]any{
				"enabled": true,
				"url":     "file:///etc/shadow",
			},
		},
	}, "")
	if badURL.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid webhook URL, got %d", badURL.Code)
	}

	// 5. POST /api/notify/test 测试指定渠道（验证合并保留密钥生效并记录历史）
	testRec := doJSONReq(t, srv, http.MethodPost, "/api/notify/test", map[string]any{
		"channel": "webhook",
	}, "")
	if testRec.Code != http.StatusOK {
		t.Fatalf("POST /api/notify/test failed: %d %s", testRec.Code, testRec.Body.String())
	}
	var testResp struct {
		OK            bool                    `json:"ok"`
		Results       []notify.DeliveryResult `json:"results"`
		RecentHistory []notify.HistoryRecord  `json:"recentHistory"`
	}
	if err := json.Unmarshal(testRec.Body.Bytes(), &testResp); err != nil {
		t.Fatalf("unmarshal test resp: %v", err)
	}
	if !testResp.OK || len(testResp.Results) != 1 || !testResp.Results[0].OK {
		t.Fatalf("expected webhook test ok=true, got %+v", testResp)
	}
	if receivedHeader.Load() != headerSecret {
		t.Fatalf("expected preserved header secret sent, got %v", receivedHeader.Load())
	}
	if len(testResp.RecentHistory) == 0 {
		t.Fatal("expected recentHistory populated after SendTest")
	}

	// 6. POST /api/notify/test 带草稿 config（保存前调试）
	draftRec := doJSONReq(t, srv, http.MethodPost, "/api/notify/test", map[string]any{
		"channel": "webhook",
		"config": map[string]any{
			"channels": map[string]any{
				"webhook": map[string]any{
					"enabled":     true,
					"url":         hookSrv.URL,
					"headerName":  "X-Test-Auth",
					"headerValue": "********",
				},
			},
		},
	}, "")
	if draftRec.Code != http.StatusOK || !strings.Contains(draftRec.Body.String(), `"ok":true`) {
		t.Fatalf("draft test failed: %d %s", draftRec.Code, draftRec.Body.String())
	}
}

func TestWebUI_DoctorAPI_RunAndQuickFixes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "sing-box.json")
	smartBin := filepath.Join(dir, "smartdns")
	smartConf := filepath.Join(dir, "smartdns.conf")
	procRoot := createFakeProcWithTailscaled(t, "6060", "0")

	if err := os.WriteFile(cfgPath, []byte("gateway:\n  ipv6_mode: off\ndns:\n  engine: smartdns\n  dns_port: 5353\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// 故意放一个明文 UDP 53 dns_local 让 sync-dns-local 修复
	if err := os.WriteFile(sbPath, []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"223.5.5.5","server_port":53}],"disable_cache":false,"optimistic":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(smartBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(smartConf, []byte("bind 127.0.0.1:5353\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var dnsSyncCalled atomic.Bool
	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		SingBoxConfigPath:       sbPath,
		SmartDNSBinPath:         smartBin,
		SmartDNSConfigPath:      smartConf,
		SmartDNSRulesDir:        filepath.Join(dir, "smartdns-rules.d"),
		SmartDNSAuditLogPath:    filepath.Join(dir, "smartdns-audit.log"),
		LocalDNSServiceMgr:      servicemgr.NewMock(),
		SkipAdGuardProbeForTest: true,
		SafeCommitProcRoot:      procRoot,
		LocalDNSProbeDNSForTest: func(string, time.Duration) error { return nil },
		LocalDNSSyncSingBoxDNSLocalForTest: func(_ context.Context, p, _ string, useExternal bool, port int) (bool, error) {
			dnsSyncCalled.Store(true)
			raw, _ := os.ReadFile(p)
			out, changed, err := singbox.PatchDNSLocalJSON(string(raw), useExternal, port)
			if err == nil && changed {
				_ = os.WriteFile(p, []byte(out), 0600)
			}
			return changed, err
		},
		DoctorEnvForTest: func(cfg *config.Config) *doctor.Env {
			return &doctor.Env{
				Config:            cfg,
				ConfigPath:        cfgPath,
				SingBoxConfigPath: sbPath,
				SmartDNSConfPath:  smartConf,
				ProcRoot:          procRoot,
				IsOpenWrt:         func() bool { return false },
				LookPath:          func(string) (string, error) { return "", os.ErrNotExist },
				DialTCP:           func(context.Context, string) error { return nil },
				HTTPProbe:         func(context.Context, string) (int, int64, error) { return 204, 15, nil },
				Statfs: func(string) (sysinfo.DiskSpace, error) {
					return sysinfo.DiskSpace{TotalBytes: 200 << 20, AvailBytes: 150 << 20, UsedPercent: 25}, nil
				},
				ReadMemInfo: func() (sysinfo.MemInfo, error) {
					return sysinfo.MemInfo{TotalBytes: 512 << 20, AvailableBytes: 300 << 20}, nil
				},
			}
		},
	})

	// 1. GET & POST /api/doctor/run 均返回 8 项检查报告
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec := doJSONReq(t, srv, method, "/api/doctor/run", map[string]any{}, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s /api/doctor/run failed: %d %s", method, rec.Code, rec.Body.String())
		}
		var rep doctor.Report
		if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
			t.Fatalf("unmarshal doctor report: %v", err)
		}
		if len(rep.Checks) != 8 {
			t.Fatalf("expected 8 doctor checks, got %d", len(rep.Checks))
		}
	}

	// 2. POST /api/doctor/fix 非法 action 返回 400
	badFix := doJSONReq(t, srv, http.MethodPost, "/api/doctor/fix", map[string]any{"action": "rm-rf-root"}, "")
	if badFix.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown fix action, got %d", badFix.Code)
	}

	// 3. POST /api/doctor/fix protect-tailscale-oom
	oomFix := doJSONReq(t, srv, http.MethodPost, "/api/doctor/fix", map[string]any{"action": "protect-tailscale-oom"}, "")
	if oomFix.Code != http.StatusOK || !strings.Contains(oomFix.Body.String(), `"ok":true`) {
		t.Fatalf("protect-tailscale-oom fix failed: %d %s", oomFix.Code, oomFix.Body.String())
	}
	if st := safecommit.InspectTailscaledOOM(procRoot); !st.Protected {
		t.Fatalf("expected tailscaled protected after fix, got %+v", st)
	}

	// 4. POST /api/doctor/fix sync-dns-local
	dnsFix := doJSONReq(t, srv, http.MethodPost, "/api/doctor/fix", map[string]any{"action": "sync-dns-local"}, "")
	if dnsFix.Code != http.StatusOK || !dnsSyncCalled.Load() {
		t.Fatalf("sync-dns-local fix failed: code=%d called=%v body=%s", dnsFix.Code, dnsSyncCalled.Load(), dnsFix.Body.String())
	}
	updatedSB, _ := os.ReadFile(sbPath)
	if !strings.Contains(string(updatedSB), `"disable_cache": true`) {
		t.Fatalf("expected sing-box.json patched with disable_cache:true, got %s", string(updatedSB))
	}

	// 5. POST /api/doctor/fix sync-smartdns-ipv6
	sdFix := doJSONReq(t, srv, http.MethodPost, "/api/doctor/fix", map[string]any{"action": "sync-smartdns-ipv6"}, "")
	if sdFix.Code != http.StatusOK {
		t.Fatalf("sync-smartdns-ipv6 fix failed: %d %s", sdFix.Code, sdFix.Body.String())
	}
	sdRaw, _ := os.ReadFile(smartConf)
	if !strings.Contains(string(sdRaw), "force-AAAA-SOA yes") {
		t.Fatalf("expected smartdns.conf updated with force-AAAA-SOA yes, got:\n%s", string(sdRaw))
	}

	// 6. 并发安全校验 (-race)
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			r := doJSONReq(t, srv, http.MethodGet, "/api/doctor/run", nil, "")
			if r.Code != http.StatusOK {
				t.Errorf("concurrent doctor run failed: %d", r.Code)
			}
		})
	}
	wg.Wait()
}
