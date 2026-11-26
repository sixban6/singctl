// 文件职责：验证网关流量卸载状态探测、热开关 API (PUT /api/gateway/flow-offload) 与深度体检联动修复接口。
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

	"singctl/internal/gateway"
	"singctl/internal/webui"
)

func TestGatewayFlowOffloadAPI_GetPutAndDoctorUnification(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("gateway:\n  mode: main\n  side_router_ip: 192.0.2.88\n"), 0600); err != nil {
		t.Fatal(err)
	}

	currentEnabled := true
	applyCalls := []bool{}

	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		Version:    "v1.14.201-test",
		GatewayProberForTest: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{
				LANIP:    "192.0.2.1",
				LANCIDR:  "192.0.2.0/24",
				LANIface: "br-lan",
			}
		},
		FlowOffloadProberForTest: func(context.Context) gateway.FlowOffloadStatus {
			return gateway.FlowOffloadStatus{
				Supported:         true,
				IsOpenWrt:         true,
				Enabled:           currentEnabled,
				TurboACCPresent:   true,
				TurboACCFastpath:  "mediatek_hnat",
				HNATSupported:     true,
				HNATActive:        currentEnabled,
				PreservedFeatures: []string{"TCP BBR 拥塞控制", "FullCone NAT"},
			}
		},
		FlowOffloadApplyForTest: func(_ context.Context, enable bool) (gateway.FlowOffloadApplyResult, error) {
			applyCalls = append(applyCalls, enable)
			currentEnabled = enable
			if enable {
				return gateway.FlowOffloadApplyResult{
					Enabled:        true,
					AppliedLive:    false,
					RebootRequired: true,
					RestoredBackup: true,
					Message:        "配置已保存并写入，需重启路由器生效",
					Status: gateway.FlowOffloadStatus{
						Supported:       true,
						IsOpenWrt:       true,
						Enabled:         false,
						TurboACCPresent: true,
						HNATSupported:   true,
					},
				}, nil
			}
			return gateway.FlowOffloadApplyResult{
				Enabled:        false,
				AppliedLive:    true,
				RebootRequired: false,
				Message:        "已关闭软/硬件流量卸载并在线热生效",
				Status: gateway.FlowOffloadStatus{
					Supported:       true,
					IsOpenWrt:       true,
					Enabled:         false,
					TurboACCPresent: true,
					HNATSupported:   true,
				},
			}, nil
		},
	})

	// 1. GET /api/gateway exposes flowOffloadStatus
	getRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/api/gateway", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /api/gateway status=%d body=%s", getRec.Code, getRec.Body.String())
	}
	if !strings.Contains(getRec.Body.String(), `"flowOffloadStatus"`) || !strings.Contains(getRec.Body.String(), `"hnatActive":true`) {
		t.Fatalf("expected flowOffloadStatus in GET /api/gateway: %s", getRec.Body.String())
	}

	// 2. PUT /api/gateway/flow-offload rejects missing enabled field & invalid JSON
	for _, badBody := range []string{"{broken", `{}`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/gateway/flow-offload", bytes.NewBufferString(badBody))
		req.Header.Set("Content-Type", "application/json")
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for body %s, got %d (%s)", badBody, rec.Code, rec.Body.String())
		}
	}

	// 3. PUT /api/gateway/flow-offload {enabled:false} succeeds live
	putOffRec := httptest.NewRecorder()
	putOffReq := httptest.NewRequest(http.MethodPut, "/api/gateway/flow-offload", bytes.NewBufferString(`{"enabled":false}`))
	putOffReq.Header.Set("Content-Type", "application/json")
	srv.Mux.ServeHTTP(putOffRec, putOffReq)
	if putOffRec.Code != http.StatusOK {
		t.Fatalf("PUT disable failed status=%d body=%s", putOffRec.Code, putOffRec.Body.String())
	}
	var offResp struct {
		OK                bool                      `json:"ok"`
		Enabled           bool                      `json:"enabled"`
		AppliedLive       bool                      `json:"appliedLive"`
		RebootRequired    bool                      `json:"rebootRequired"`
		FlowOffloadStatus gateway.FlowOffloadStatus `json:"flowOffloadStatus"`
	}
	if err := json.Unmarshal(putOffRec.Body.Bytes(), &offResp); err != nil {
		t.Fatalf("unmarshal disable response: %v", err)
	}
	if !offResp.OK || offResp.Enabled || !offResp.AppliedLive || offResp.RebootRequired || offResp.FlowOffloadStatus.Enabled {
		t.Fatalf("unexpected disable response: %+v", offResp)
	}

	// 4. PUT /api/gateway/flow-offload {enabled:true} propagates rebootRequired & restoredBackup
	putOnRec := httptest.NewRecorder()
	putOnReq := httptest.NewRequest(http.MethodPut, "/api/gateway/flow-offload", bytes.NewBufferString(`{"enabled":true}`))
	putOnReq.Header.Set("Content-Type", "application/json")
	srv.Mux.ServeHTTP(putOnRec, putOnReq)
	if putOnRec.Code != http.StatusOK {
		t.Fatalf("PUT enable failed status=%d body=%s", putOnRec.Code, putOnRec.Body.String())
	}
	if !strings.Contains(putOnRec.Body.String(), `"rebootRequired":true`) || !strings.Contains(putOnRec.Body.String(), `"restoredBackup":true`) {
		t.Fatalf("expected rebootRequired & restoredBackup in enable response: %s", putOnRec.Body.String())
	}

	// 5. POST /api/doctor/fix {"action":"disable-flow-offload"} routes through unified handler
	docRec := httptest.NewRecorder()
	docReq := httptest.NewRequest(http.MethodPost, "/api/doctor/fix", bytes.NewBufferString(`{"action":"disable-flow-offload"}`))
	docReq.Header.Set("Content-Type", "application/json")
	srv.Mux.ServeHTTP(docRec, docReq)
	if docRec.Code != http.StatusOK {
		t.Fatalf("POST /api/doctor/fix disable-flow-offload failed: %d %s", docRec.Code, docRec.Body.String())
	}
	if len(applyCalls) != 3 || applyCalls[2] != false {
		t.Fatalf("expected doctor fix to invoke unified flow offload apply(false), calls=%v", applyCalls)
	}
}
