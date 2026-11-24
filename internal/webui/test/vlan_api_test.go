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
	"testing"

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
