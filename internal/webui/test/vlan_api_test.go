// 文件职责：覆盖客户端 WebUI VLAN 自动化 API 契约（概览、Dry-Run 预览、Safe Commit 自动武装应用、安全删除与错误码）。
package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/safecommit"
	"singctl/internal/vlan"
	"singctl/internal/webui"
)

func TestVLANAPI_OverviewPreviewApplyAndDeleteWithSafeCommit(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(cfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}
	bypassFile := filepath.Join(tmpDir, "vlan-proxy-bypass.list")

	var appliedCmds []string
	var networkReloaded bool
	vlanSvc := vlan.NewService(vlan.Env{
		IsOpenWrt: func() bool { return true },
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			if len(args) == 2 && args[0] == "show" && args[1] == "network" {
				return `network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].type='bridge'
network.@device[0].ports='lan1' 'lan2' 'lan3' 'lan4'
network.lan=interface
network.lan.device='br-lan'
network.lan.proto='static'
network.lan.ipaddr='192.168.29.1'
network.lan.netmask='255.255.255.0'
network.wan=interface
network.wan.device='eth1'
network.wan.proto='dhcp'
`, nil
			}
			return "", nil
		},
		BatchUCI: func(_ context.Context, cmds []string) error {
			appliedCmds = append(appliedCmds, cmds...)
			return nil
		},
		ReloadNetwork: func(_ context.Context) error {
			networkReloaded = true
			return nil
		},
		SyncProxyBypass: func(_ context.Context, cidrs []string) error {
			return vlan.WriteProxyBypassList(bypassFile, cidrs)
		},
		ReadFile: func(p string) ([]byte, error) { return os.ReadFile(p) },
		ListNetDevs: func() ([]string, error) {
			return []string{"lo", "eth1", "lan1", "lan2", "lan3", "lan4", "br-lan"}, nil
		},
		ReadIPv4Addrs: func() (map[string]string, error) {
			return map[string]string{"eth1": "192.168.1.151/24", "br-lan": "192.168.29.1/24"}, nil
		},
		ProxyBypassFile: bypassFile,
	})

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		SafeCommitStateDir:      filepath.Join(tmpDir, "sc-state"),
		SafeCommitSpawnWatcher:  func(string) (int, error) { return 4242, nil },
		SafeCommitKillWatcher:   func(int) error { return nil },
		SafeCommitRollbackOps:   &safecommit.RollbackOps{},
		SafeCommitBaselineForTest: func() (bool, bool) { return false, false },
		VLANServiceForTest:      vlanSvc,
	})

	doJSON := func(method, path string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.RemoteAddr = "192.168.29.50:54321"
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. GET /api/vlan/overview
	rec := doJSON(http.MethodGet, "/api/vlan/overview", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"driver":"dsa"`) {
		t.Fatalf("GET /api/vlan/overview failed: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 2. POST /api/vlan/preview (valid IoT VLAN)
	iotPayload := vlan.SaveSegmentRequest{
		ID:          "iot",
		DisplayName: "智能家居隔离网",
		Preset:      vlan.PresetIoT,
		VLANID:      28,
		IPAddr:      "192.168.20.1",
		ProxyMode:   vlan.ProxyModeDirect,
		Ports:       map[string]string{"lan3": vlan.PortModeAccess},
		Policy: vlan.SecurityPolicy{
			AllowWAN:         true,
			BlockRouterMgmt:  true,
			BlockUpstreamLAN: true,
		},
	}
	rec = doJSON(http.MethodPost, "/api/vlan/preview", iotPayload)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"valid":true`) {
		t.Fatalf("POST /api/vlan/preview failed: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 3. POST /api/vlan/apply arms Safe Commit automatically and applies UCI
	rec = doJSON(http.MethodPost, "/api/vlan/apply", iotPayload)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"safeCommitToken"`) {
		t.Fatalf("POST /api/vlan/apply failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !networkReloaded || len(appliedCmds) == 0 {
		t.Fatalf("expected network reloaded and UCI applied: reloaded=%v cmds=%d", networkReloaded, len(appliedCmds))
	}

	// 4. DELETE caller's own management segment ("lan") must return 400
	rec = doJSON(http.MethodDelete, "/api/vlan/segment/lan", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 deleting caller mgmt segment 'lan', got code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestVLANAPI_DelayedAsyncReload_Returns200BeforeReloadWithDetachedContext(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(cfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}
	bypassFile := filepath.Join(tmpDir, "vlan-proxy-bypass.list")

	var reloaded atomic.Bool
	reloadDone := make(chan error, 1)

	vlanSvc := vlan.NewService(vlan.Env{
		IsOpenWrt: func() bool { return true },
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			if len(args) == 2 && args[0] == "show" && args[1] == "network" {
				return `network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].type='bridge'
network.@device[0].ports='lan1' 'lan2' 'lan3' 'lan4'
network.lan=interface
network.lan.device='br-lan'
network.lan.proto='static'
network.lan.ipaddr='192.168.29.1'
network.lan.netmask='255.255.255.0'
network.wan=interface
network.wan.device='eth1'
network.wan.proto='dhcp'
`, nil
			}
			return "", nil
		},
		BatchUCI: func(_ context.Context, _ []string) error { return nil },
		ReloadNetworkWithOpts: func(ctx context.Context, _ vlan.ReloadOptions) error {
			reloaded.Store(true)
			reloadDone <- ctx.Err()
			return nil
		},
		SyncProxyBypass: func(_ context.Context, cidrs []string) error {
			return vlan.WriteProxyBypassList(bypassFile, cidrs)
		},
		ReadFile: func(p string) ([]byte, error) { return os.ReadFile(p) },
		ListNetDevs: func() ([]string, error) {
			return []string{"lo", "eth1", "lan1", "lan2", "lan3", "lan4", "br-lan"}, nil
		},
		ReadIPv4Addrs: func() (map[string]string, error) {
			return map[string]string{"eth1": "192.168.1.151/24", "br-lan": "192.168.29.1/24"}, nil
		},
		ProxyBypassFile: bypassFile,
	})

	delay := 40 * time.Millisecond
	srv := webui.New(webui.Options{
		ConfigPath:                  cfgPath,
		SafeCommitStateDir:          filepath.Join(tmpDir, "sc-state"),
		SafeCommitSpawnWatcher:      func(string) (int, error) { return 4243, nil },
		SafeCommitKillWatcher:       func(int) error { return nil },
		SafeCommitRollbackOps:       &safecommit.RollbackOps{},
		SafeCommitBaselineForTest:   func() (bool, bool) { return false, false },
		VLANServiceForTest:          vlanSvc,
		VLANAsyncReloadDelayForTest: &delay,
	})

	iotPayload := vlan.SaveSegmentRequest{
		ID:          "iot",
		DisplayName: "智能家居隔离网",
		Preset:      vlan.PresetIoT,
		VLANID:      28,
		IPAddr:      "192.168.20.1",
		ProxyMode:   vlan.ProxyModeDirect,
		Ports:       map[string]string{"lan3": vlan.PortModeAccess},
		Policy:      vlan.SecurityPolicy{AllowWAN: true, BlockRouterMgmt: true},
	}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(iotPayload)

	reqCtx, cancelReq := context.WithCancel(t.Context())
	req := httptest.NewRequest(http.MethodPost, "/api/vlan/apply", &buf).WithContext(reqCtx)
	req.RemoteAddr = "192.168.29.50:54321"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"active":true`) {
		t.Fatalf("POST /api/vlan/apply failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	// Response MUST return BEFORE delayed reload fires so mobile browsers receive safeCommit before Wi-Fi resets!
	if reloaded.Load() {
		t.Fatal("expected HTTP 200 response flushed BEFORE delayed reload executes")
	}
	// Simulate HTTP client disconnect / request context cancel immediately after receiving 200
	cancelReq()

	select {
	case ctxErr := <-reloadDone:
		if ctxErr != nil {
			t.Fatalf("expected delayed reload context detached via WithoutCancel, got err=%v", ctxErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for delayed async reload")
	}
}

func TestVLANAPI_WifiSecretAndCustomDHCPDNS(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(cfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}
	bypassFile := filepath.Join(tmpDir, "vlan-proxy-bypass.list")
	dnsBypassFile := filepath.Join(tmpDir, "vlan-dns-bypass.list")

	vlanSvc := vlan.NewService(vlan.Env{
		IsOpenWrt: func() bool { return true },
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			if len(args) == 2 && args[0] == "show" {
				switch args[1] {
				case "network":
					return `network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].type='bridge'
network.@device[0].ports='lan1' 'lan2' 'lan3' 'lan4'
network.lan=interface
network.lan.device='br-lan'
network.lan.proto='static'
network.lan.ipaddr='192.168.29.1'
network.lan.netmask='255.255.255.0'
network.wan=interface
network.wan.device='eth1'
network.wan.proto='dhcp'
network.@bridge-vlan[0]=bridge-vlan
network.@bridge-vlan[0].device='br-lan'
network.@bridge-vlan[0].vlan='28'
network.@bridge-vlan[0].ports='lan3:u*'
network.iot=interface
network.iot.device='br-lan.28'
network.iot.proto='static'
network.iot.ipaddr='192.168.20.1'
network.iot.netmask='255.255.255.0'
`, nil
				case "wireless":
					return `wireless.radio0=wifi-device
wireless.radio0.type='mac80211'
wireless.radio0.band='2g'
wireless.singctl_vlan_iot=wifi-iface
wireless.singctl_vlan_iot.device='radio0'
wireless.singctl_vlan_iot.mode='ap'
wireless.singctl_vlan_iot.network='iot'
wireless.singctl_vlan_iot.ssid='IoT-Test'
wireless.singctl_vlan_iot.key='SecretWifi-2026'
`, nil
				}
			}
			return "", nil
		},
		BatchUCI:      func(_ context.Context, _ []string) error { return nil },
		ReloadNetwork: func(_ context.Context) error { return nil },
		ReadFile:      func(p string) ([]byte, error) { return os.ReadFile(p) },
		ListNetDevs: func() ([]string, error) {
			return []string{"lo", "eth1", "lan1", "lan2", "lan3", "lan4", "br-lan", "br-lan.28"}, nil
		},
		ReadIPv4Addrs: func() (map[string]string, error) {
			return map[string]string{"eth1": "192.168.1.151/24", "br-lan": "192.168.29.1/24", "br-lan.28": "192.168.20.1/24"}, nil
		},
		ProxyBypassFile: bypassFile,
		DNSBypassFile:   dnsBypassFile,
	})

	srv := webui.New(webui.Options{
		ConfigPath:                cfgPath,
		SafeCommitStateDir:        filepath.Join(tmpDir, "sc-state"),
		SafeCommitSpawnWatcher:    func(string) (int, error) { return 4244, nil },
		SafeCommitKillWatcher:     func(int) error { return nil },
		SafeCommitRollbackOps:     &safecommit.RollbackOps{},
		SafeCommitBaselineForTest: func() (bool, bool) { return false, false },
		VLANServiceForTest:        vlanSvc,
	})

	doReq := func(method, path string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.RemoteAddr = "192.168.29.50:54321"
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Fetch Wi-Fi secret on demand
	rec := doReq(http.MethodGet, "/api/vlan/segment/iot/wifi-secret", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET wifi-secret failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("expected Cache-Control: no-store, got %q", cc)
	}
	if !strings.Contains(rec.Body.String(), `"password":"SecretWifi-2026"`) {
		t.Fatalf("expected revealed wifi password in body, got %s", rec.Body.String())
	}

	// 2. Invalid ID returns 400; missing segment returns 404
	if badRec := doReq(http.MethodGet, "/api/vlan/segment/iot;bad/wifi-secret", nil); badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad segment id, got %d body=%s", badRec.Code, badRec.Body.String())
	}
	if missRec := doReq(http.MethodGet, "/api/vlan/segment/nonexistent/wifi-secret", nil); missRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown segment, got %d body=%s", missRec.Code, missRec.Body.String())
	}

	// 3. Apply custom DHCPDNS -> persists dns bypass file with 0600 and arms Safe Commit
	recApply := doReq(http.MethodPost, "/api/vlan/apply", vlan.SaveSegmentRequest{
		ID:        "iot",
		VLANID:    28,
		IPAddr:    "192.168.20.1",
		ProxyMode: vlan.ProxyModeDirect,
		DHCPDNS:   []string{"192.168.29.88", "223.5.5.5"},
		Ports:     map[string]string{"lan3": vlan.PortModeAccess},
		Policy:    vlan.SecurityPolicy{AllowWAN: true, BlockRouterMgmt: true},
	})
	if recApply.Code != http.StatusOK || !strings.Contains(recApply.Body.String(), `"safeCommitToken"`) {
		t.Fatalf("POST /api/vlan/apply with dhcpDns failed: code=%d body=%s", recApply.Code, recApply.Body.String())
	}
	rawBypass, err := os.ReadFile(dnsBypassFile)
	if err != nil || !strings.Contains(string(rawBypass), "192.168.20.0/24 192.168.29.88,223.5.5.5") {
		t.Fatalf("expected dns bypass file updated, err=%v content=%q", err, string(rawBypass))
	}
}
