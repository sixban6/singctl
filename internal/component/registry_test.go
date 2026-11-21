package component

import (
	"context"
	"os"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/platform/servicemgr"
)

type stubComp struct {
	id      string
	aliases []string
	display string
	unit    string
}

func (s *stubComp) ID() string          { return s.id }
func (s *stubComp) Aliases() []string   { return s.aliases }
func (s *stubComp) DisplayName() string { return s.display }
func (s *stubComp) UnitName() string    { return s.unit }
func (s *stubComp) ExecuteServiceAction(_ context.Context, _ string, _ servicemgr.Manager, _ servicemgr.CmdRunner, _ string) error {
	return nil
}

type stubFullComp struct {
	stubComp
}

func (s *stubFullComp) ResolveConfigTarget(overridePath string) (ConfigTarget, error) {
	p := overridePath
	if p == "" {
		p = "/etc/example/conf.json"
	}
	return ConfigTarget{PrimaryPath: p, FileMode: os.FileMode(0600)}, nil
}

func (s *stubFullComp) ValidateConfig(_ context.Context, _ string, _ servicemgr.CmdRunner, _ string) error {
	return nil
}
func (s *stubFullComp) ApplyOwnership(string) {}
func (s *stubFullComp) ReloadAfterSave(_ context.Context, _ string, _ servicemgr.Manager, _ servicemgr.CmdRunner, _ bool) error {
	return nil
}

func (s *stubFullComp) CheckUpdate(*config.Config) (*CheckUpdateInfo, error) {
	return &CheckUpdateInfo{Component: s.id}, nil
}
func (s *stubFullComp) Upgrade(*config.Config) (*UpgradeInfo, error) {
	return &UpgradeInfo{Component: s.id, Updated: true}, nil
}
func (s *stubFullComp) DeployServer(*config.Config) error    { return nil }
func (s *stubFullComp) ReinstallServer(*config.Config) error { return nil }
func (s *stubFullComp) UninstallServer() error               { return nil }

func TestRegistry_RegisterResolveOrderAndCapabilities(t *testing.T) {
	reg := NewRegistry()

	c1 := &stubFullComp{stubComp{id: "singbox", aliases: []string{"sb", "sing-box"}, display: "sing-box 代理核心", unit: "sing-box"}}
	c2 := &stubComp{id: "subhub", aliases: []string{"substore", "sub-store"}, display: "SubHub 订阅引擎", unit: "singctl-sub"}

	if err := reg.Register(nil); err == nil {
		t.Fatalf("expected error registering nil component")
	}
	if err := reg.Register(&stubComp{id: "  "}); err == nil {
		t.Fatalf("expected error registering blank component id")
	}
	if err := reg.Register(c1); err != nil {
		t.Fatalf("register singbox: %v", err)
	}
	if err := reg.Register(c2); err != nil {
		t.Fatalf("register subhub: %v", err)
	}
	// Duplicate ID or alias must be rejected
	if err := reg.Register(&stubComp{id: "singbox"}); err == nil {
		t.Fatalf("expected error registering duplicate id")
	}
	if err := reg.Register(&stubComp{id: "other", aliases: []string{"SB"}}); err == nil {
		t.Fatalf("expected error registering colliding alias")
	}

	tests := []struct {
		query    string
		wantID   string
		wantUnit string
		wantCfg  bool
		wantUp   bool
		wantErr  bool
	}{
		{query: "singbox", wantID: "singbox", wantUnit: "sing-box", wantCfg: true, wantUp: true},
		{query: "SB", wantID: "singbox", wantUnit: "sing-box", wantCfg: true, wantUp: true},
		{query: "sing-box", wantID: "singbox", wantUnit: "sing-box", wantCfg: true, wantUp: true},
		{query: " subhub ", wantID: "subhub", wantUnit: "singctl-sub", wantCfg: false, wantUp: false},
		{query: "SubStore", wantID: "subhub", wantUnit: "singctl-sub", wantCfg: false, wantUp: false},
		{query: "unknown", wantErr: true},
		{query: "", wantErr: true},
	}

	for _, tc := range tests {
		got, err := reg.Resolve(tc.query)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("Resolve(%q) expected error, got nil", tc.query)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Resolve(%q) unexpected error: %v", tc.query, err)
		}
		if got.ID() != tc.wantID || got.UnitName() != tc.wantUnit {
			t.Fatalf("Resolve(%q) = (%s, %s), want (%s, %s)", tc.query, got.ID(), got.UnitName(), tc.wantID, tc.wantUnit)
		}
		_, isCfg := got.(Configurable)
		_, isUp := got.(Upgradable)
		_, isLife := got.(ServerLifecycle)
		if isCfg != tc.wantCfg || isUp != tc.wantUp || isLife != tc.wantUp {
			t.Fatalf("Resolve(%q) capabilities cfg=%v up=%v life=%v", tc.query, isCfg, isUp, isLife)
		}
	}

	all := reg.All()
	if len(all) != 2 || all[0].ID() != "singbox" || all[1].ID() != "subhub" {
		t.Fatalf("All() did not preserve registration order: %+v", all)
	}

	// Concurrent Resolve must be -race safe
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if c, err := reg.Resolve("sb"); err != nil || c.ID() != "singbox" {
				t.Errorf("concurrent Resolve failed: c=%v err=%v", c, err)
			}
		})
	}
	wg.Wait()
}
