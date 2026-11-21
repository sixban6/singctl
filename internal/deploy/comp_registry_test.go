package deploy

import (
	"testing"

	"singctl/internal/component"
)

func TestServerRegistry_AdaptersAndCapabilities(t *testing.T) {
	reg := ServerRegistry()
	all := reg.All()
	if len(all) != 4 {
		t.Fatalf("expected 4 registered server components, got %d", len(all))
	}

	cases := []struct {
		query    string
		wantID   string
		wantUnit string
		wantCfg  bool
		wantUp   bool
	}{
		{query: "singbox", wantID: "singbox", wantUnit: "sing-box", wantCfg: true, wantUp: true},
		{query: "sb", wantID: "singbox", wantUnit: "sing-box", wantCfg: true, wantUp: true},
		{query: "caddy", wantID: "caddy", wantUnit: "caddy", wantCfg: true, wantUp: true},
		{query: "subhub", wantID: "subhub", wantUnit: "singctl-sub", wantCfg: false, wantUp: false},
		{query: "substore", wantID: "subhub", wantUnit: "singctl-sub", wantCfg: false, wantUp: false},
		{query: "warp", wantID: "warp", wantUnit: "wireproxy", wantCfg: true, wantUp: true},
		{query: "wireproxy", wantID: "warp", wantUnit: "wireproxy", wantCfg: true, wantUp: true},
	}

	for _, tc := range cases {
		c, err := reg.Resolve(tc.query)
		if err != nil {
			t.Fatalf("ServerRegistry().Resolve(%q) unexpected error: %v", tc.query, err)
		}
		if c.ID() != tc.wantID || c.UnitName() != tc.wantUnit {
			t.Fatalf("Resolve(%q) = (%s, %s), want (%s, %s)", tc.query, c.ID(), c.UnitName(), tc.wantID, tc.wantUnit)
		}
		_, isCfg := c.(component.Configurable)
		_, isUp := c.(component.Upgradable)
		if isCfg != tc.wantCfg || isUp != tc.wantUp {
			t.Fatalf("Resolve(%q) capabilities cfg=%v (want %v) up=%v (want %v)", tc.query, isCfg, tc.wantCfg, isUp, tc.wantUp)
		}
	}
}
