// 文件职责：覆盖 WebUI 统一 Tailscale 拓扑聚合 (/api/tailscale/mesh) 云端 ACL 放行自动检测与零误报契约测试。
package webui_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"singctl/internal/tailscale"
	"singctl/internal/webui"
)

func buildCloudACLTestServer(t *testing.T, pfSnap *tailscale.PacketFilterSnapshot) *webui.Server {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(`subs:
  - name: "main"
    url: "https://example.com/sub"
gateway:
  mode: "main"
tailscale:
  auth_key: "tskey-auth-test-0001-abcdef"
  subnets: "192.168.27.0/24,192.168.28.0/24,192.168.31.0/24"
  use_build: false
  p2p_assist:
    role_mode: "router"
`), 0600); err != nil {
		t.Fatalf("write singctl.yaml: %v", err)
	}

	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	apiStub := &stubTSLocalAPI{
		statusFn: func(call int) (*tailscale.StatusSnapshot, error) {
			return &tailscale.StatusSnapshot{
				BackendState: "Running",
				Self: tailscale.PeerStatus{
					ID:           "nSelf",
					HostName:     "n60pro",
					ShortName:    "n60pro",
					TailscaleIPs: []string{"100.64.0.10"},
				},
			}, nil
		},
		netMap: &tailscale.NetMapSnapshot{
			SelfEndpoints: []string{"203.0.113.1:41641"},
			PeerEndpoints: map[string][]string{},
			PacketFilter:  pfSnap,
		},
	}

	ctrl := &tailscale.P2PAssistController{
		LocalAPI:    apiStub,
		FW4:         &tailscale.FW4Manager{BaseDir: t.TempDir()},
		Now:         func() time.Time { return now },
		Sleep:       func(ctx context.Context, d time.Duration) error { return nil },
		HostSelfIPs: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.1")} },
	}

	return webui.New(webui.Options{
		ConfigPath: cfgPath,
		Version:    "v1.14.212-test",
		TailscaleP2PForTest: &webui.TailscaleP2PTestHooks{
			Controller:     ctrl,
			FW4Available:   false,
			UjailAvailable: false,
			Now:            func() time.Time { return now },
			DefaultLANCIDR: "192.168.31.0/24",
			LiveSubnets:    "192.168.27.0/24, 192.168.28.0/24, 192.168.31.0/24",
			RouteOutput: strings.Join([]string{
				"192.168.27.0/24 via 192.168.31.151 dev br-lan",
				"192.168.28.0/24 via 192.168.31.151 dev br-lan",
				"192.168.31.0/24 dev br-lan scope link src 192.168.31.1",
			}, "\n"),
		},
	})
}

func TestTailscaleMeshAPI_CloudACL_BlockedAndAllowed(t *testing.T) {
	pfSnap := tailscale.ParseNetmapPacketFilter([]byte(`{
		"PacketFilter": [{
			"Caps": [],
			"Srcs": ["100.64.0.99/32"],
			"Dsts": [
				{"Net": "192.168.31.0/24", "Ports": {"First": 0, "Last": 65535}},
				{"Net": "192.168.28.10/32", "Ports": {"First": 22, "Last": 22}}
			]
		}]
	}`))
	srv := buildCloudACLTestServer(t, pfSnap)

	req := httptest.NewRequest(http.MethodGet, "/api/tailscale/mesh", nil)
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tailscale/mesh status=%d body=%s", rec.Code, rec.Body.String())
	}

	rawBody := rec.Body.String()
	// 规则 01 脱敏校验：绝不向前端暴露原始 PacketFilter / Srcs 明细。
	if strings.Contains(rawBody, "PacketFilter") || strings.Contains(rawBody, `"Srcs"`) || strings.Contains(rawBody, "100.64.0.99") {
		t.Fatalf("raw PacketFilter details leaked in API response: %s", rawBody)
	}

	var payload struct {
		LocalNetworks []struct {
			CIDR             string   `json:"cidr"`
			Selected         bool     `json:"selected"`
			Approved         bool     `json:"approved"`
			ACLStatus        string   `json:"aclStatus"`
			ACLMatchedRanges []string `json:"aclMatchedRanges"`
		} `json:"localNetworks"`
		CloudACL tailscale.CloudACLSummary `json:"cloudAcl"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode /api/tailscale/mesh response: %v", err)
	}

	byCIDR := make(map[string]struct {
		approved         bool
		aclStatus        string
		aclMatchedRanges []string
	})
	for _, netItem := range payload.LocalNetworks {
		byCIDR[netItem.CIDR] = struct {
			approved         bool
			aclStatus        string
			aclMatchedRanges []string
		}{
			approved:         netItem.Approved,
			aclStatus:        netItem.ACLStatus,
			aclMatchedRanges: netItem.ACLMatchedRanges,
		}
	}

	if got := byCIDR["192.168.27.0/24"]; !got.approved || got.aclStatus != tailscale.ACLStatusBlocked {
		t.Fatalf("192.168.27.0/24 = %+v, want approved=true, aclStatus=blocked", got)
	}
	if got := byCIDR["192.168.28.0/24"]; !got.approved || got.aclStatus != tailscale.ACLStatusPartial || !reflect.DeepEqual(got.aclMatchedRanges, []string{"192.168.28.10/32:22"}) {
		t.Fatalf("192.168.28.0/24 = %+v, want approved=true, aclStatus=partial, matched=[192.168.28.10/32:22]", got)
	}
	if got := byCIDR["192.168.31.0/24"]; !got.approved || got.aclStatus != tailscale.ACLStatusAllowed {
		t.Fatalf("192.168.31.0/24 = %+v, want approved=true, aclStatus=allowed", got)
	}

	if !payload.CloudACL.Checked {
		t.Fatalf("expected cloudAcl.checked=true, got %+v", payload.CloudACL)
	}
	if !reflect.DeepEqual(payload.CloudACL.BlockedSubnets, []string{"192.168.27.0/24"}) {
		t.Fatalf("cloudAcl.blockedSubnets = %v, want [192.168.27.0/24]", payload.CloudACL.BlockedSubnets)
	}
	if !reflect.DeepEqual(payload.CloudACL.PartialSubnets, []string{"192.168.28.0/24"}) {
		t.Fatalf("cloudAcl.partialSubnets = %v, want [192.168.28.0/24]", payload.CloudACL.PartialSubnets)
	}
}

func TestTailscaleMeshAPI_CloudACL_UnavailableNoFalseAlarm(t *testing.T) {
	srv := buildCloudACLTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/tailscale/mesh", nil)
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tailscale/mesh status=%d body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		LocalNetworks []struct {
			CIDR      string `json:"cidr"`
			ACLStatus string `json:"aclStatus"`
		} `json:"localNetworks"`
		CloudACL tailscale.CloudACLSummary `json:"cloudAcl"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode /api/tailscale/mesh response: %v", err)
	}
	if payload.CloudACL.Checked || len(payload.CloudACL.BlockedSubnets) != 0 || len(payload.CloudACL.PartialSubnets) != 0 {
		t.Fatalf("expected unchecked empty cloudAcl when PacketFilter is nil, got %+v", payload.CloudACL)
	}
	for _, netItem := range payload.LocalNetworks {
		if netItem.ACLStatus != "" {
			t.Fatalf("expected empty aclStatus when PacketFilter unavailable, got %+v", netItem)
		}
	}
}
