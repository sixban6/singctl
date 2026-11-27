// 文件职责：验证 Tailscale P2P 直连辅助配置的默认值钳位、限时双向过期降级、缺失空格修复、清空保存及版本迁移保真。
package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/configs"
	"singctl/internal/config"
)

func TestTailscaleP2PAssistConfig_DefaultsAndClamping(t *testing.T) {
	var def config.TailscaleP2PAssistConfig
	if def.EffectiveJITWindowSec() != 5 {
		t.Fatalf("expected default EffectiveJITWindowSec=5, got %d", def.EffectiveJITWindowSec())
	}
	if def.EffectiveCooldownSec() != 300 {
		t.Fatalf("expected default EffectiveCooldownSec=300, got %d", def.EffectiveCooldownSec())
	}
	if !def.EffectivePayloadFilter() {
		t.Fatal("expected default EffectivePayloadFilter=true when nil")
	}
	if def.EffectiveListenPort() != 41641 {
		t.Fatalf("expected default EffectiveListenPort=41641, got %d", def.EffectiveListenPort())
	}

	low := config.TailscaleP2PAssistConfig{JITWindowSec: 1, CooldownSec: 5}
	if low.EffectiveJITWindowSec() != 3 {
		t.Fatalf("expected clamped min JITWindowSec=3, got %d", low.EffectiveJITWindowSec())
	}
	if low.EffectiveCooldownSec() != 30 {
		t.Fatalf("expected clamped min CooldownSec=30, got %d", low.EffectiveCooldownSec())
	}

	high := config.TailscaleP2PAssistConfig{JITWindowSec: 99, CooldownSec: 9999, ListenPort: 51820}
	if high.EffectiveJITWindowSec() != 10 {
		t.Fatalf("expected clamped max JITWindowSec=10, got %d", high.EffectiveJITWindowSec())
	}
	if high.EffectiveCooldownSec() != 3600 {
		t.Fatalf("expected clamped max CooldownSec=3600, got %d", high.EffectiveCooldownSec())
	}
	if high.EffectiveListenPort() != 51820 {
		t.Fatalf("expected custom ListenPort=51820, got %d", high.EffectiveListenPort())
	}

	pfFalse := false
	high.PayloadFilter = &pfFalse
	if high.EffectivePayloadFilter() {
		t.Fatal("expected explicit PayloadFilter=false to be honored")
	}
}

func TestTailscaleP2PPeerConfig_AccessModeAndExpiry(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	if mode, ok := config.NormalizeTailscaleAccessMode("outbound_only"); !ok || mode != config.TailscaleAccessOutboundOnly {
		t.Fatalf("unexpected normalize result: %q %v", mode, ok)
	}
	if mode, ok := config.NormalizeTailscaleAccessMode("BIDIRECTIONAL_TIMED"); !ok || mode != config.TailscaleAccessBidirectionalTimed {
		t.Fatalf("unexpected normalize result: %q %v", mode, ok)
	}
	if mode, ok := config.NormalizeTailscaleAccessMode("bidirectional"); !ok || mode != config.TailscaleAccessBidirectional {
		t.Fatalf("unexpected normalize result: %q %v", mode, ok)
	}
	if mode, ok := config.NormalizeTailscaleAccessMode(""); !ok || mode != config.TailscaleAccessOutboundOnly {
		t.Fatalf("expected empty access mode to default outbound_only, got %q %v", mode, ok)
	}
	if _, ok := config.NormalizeTailscaleAccessMode("invalid-mode"); ok {
		t.Fatal("expected invalid access mode to return ok=false")
	}

	activeTimed := config.TailscaleP2PPeerConfig{
		Name:               "router-remote",
		AccessMode:         config.TailscaleAccessBidirectionalTimed,
		BidirectionalUntil: now.Add(48 * time.Hour).Format(time.RFC3339),
	}
	if got := activeTimed.EffectiveAccessMode(now); got != config.TailscaleAccessBidirectionalTimed {
		t.Fatalf("expected active bidirectional_timed, got %q", got)
	}
	if rem := activeTimed.RemainingBidirectional(now); rem != 48*time.Hour {
		t.Fatalf("expected remaining 48h, got %v", rem)
	}

	expiredTimed := config.TailscaleP2PPeerConfig{
		Name:               "router-remote",
		AccessMode:         config.TailscaleAccessBidirectionalTimed,
		BidirectionalUntil: now.Add(-1 * time.Second).Format(time.RFC3339),
	}
	if got := expiredTimed.EffectiveAccessMode(now); got != config.TailscaleAccessOutboundOnly {
		t.Fatalf("expected expired bidirectional_timed to degrade to outbound_only, got %q", got)
	}
	if rem := expiredTimed.RemainingBidirectional(now); rem != 0 {
		t.Fatalf("expected expired remaining=0, got %v", rem)
	}

	invalidTimed := config.TailscaleP2PPeerConfig{
		Name:               "router-remote",
		AccessMode:         config.TailscaleAccessBidirectionalTimed,
		BidirectionalUntil: "not-a-timestamp",
	}
	if got := invalidTimed.EffectiveAccessMode(now); got != config.TailscaleAccessOutboundOnly {
		t.Fatalf("expected invalid timestamp to degrade to outbound_only, got %q", got)
	}

	permBidir := config.TailscaleP2PPeerConfig{
		Name:       "router-remote",
		AccessMode: config.TailscaleAccessBidirectional,
	}
	if got := permBidir.EffectiveAccessMode(now); got != config.TailscaleAccessBidirectional {
		t.Fatalf("expected bidirectional, got %q", got)
	}
}

func TestTailscaleP2PAssistConfig_LoadSaveColonFixAndUpdate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	raw := `subs:
  - name: "main"
    url: "https://example.com/sub"
tailscale:
  p2p_assist:
    enabled:true
    jit_window_sec:6
    cooldown_sec:180
    payload_filter:false
    sandbox_ujail:true
    listen_port:41641
    peers:
      - id:"nPeer111CNTRL"
        name:"router-remote"
        tailscale_ip:"100.64.200.2"
        jit_enabled:true
        access_mode:"bidirectional_timed"
        bidirectional_until:"2026-11-30T00:00:00Z"
        allowed_lan_targets:
          - "192.168.180.10:8445"
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0600); err != nil {
		t.Fatalf("write raw config: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	p2p := cfg.Tailscale.P2PAssist
	if !p2p.Enabled || p2p.EffectiveJITWindowSec() != 6 || p2p.EffectiveCooldownSec() != 180 {
		t.Fatalf("unexpected p2p scalar values: %+v", p2p)
	}
	if p2p.EffectivePayloadFilter() {
		t.Fatal("expected PayloadFilter=false after load")
	}
	if !p2p.SandboxUjail || len(p2p.Peers) != 1 {
		t.Fatalf("unexpected sandbox/peers: %+v", p2p)
	}
	if p2p.Peers[0].ID != "nPeer111CNTRL" || p2p.Peers[0].TailscaleIP != "100.64.200.2" || len(p2p.Peers[0].AllowedLANTargets) != 1 {
		t.Fatalf("unexpected peer[0]: %+v", p2p.Peers[0])
	}

	// Save back, confirm 0600 permissions, then clear peers and save again to ensure stale peers are removed
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	st, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %04o", st.Mode().Perm())
	}

	cfg.Tailscale.P2PAssist.Enabled = false
	cfg.Tailscale.P2PAssist.Peers = nil
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("second Save failed: %v", err)
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if reloaded.Tailscale.P2PAssist.Enabled || len(reloaded.Tailscale.P2PAssist.Peers) != 0 {
		t.Fatalf("expected cleared peers after Save, got %+v", reloaded.Tailscale.P2PAssist)
	}
}

func TestMigrateConfig_PreservesTailscaleP2PAssist(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	oldYAML := `subs:
  - name: "main"
    url: "https://example.com/sub"
tailscale:
  auth_key: ""
  subnets: "192.168.180.0/24"
  use_build: false
  p2p_assist:
    enabled: true
    jit_window_sec: 5
    cooldown_sec: 300
    payload_filter: true
    peers:
      - id: "nPeer111CNTRL"
        name: "router-remote"
        jit_enabled: true
        access_mode: "outbound_only"
        allowed_lan_targets:
          - "192.168.180.0/24"
`
	if err := os.WriteFile(cfgPath, []byte(oldYAML), 0600); err != nil {
		t.Fatalf("write old config: %v", err)
	}

	if err := config.MigrateConfig(cfgPath, configs.DefaultConfigYAML); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	migrated, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load migrated failed: %v", err)
	}
	p2p := migrated.Tailscale.P2PAssist
	if !p2p.Enabled || len(p2p.Peers) != 1 || p2p.Peers[0].Name != "router-remote" || p2p.Peers[0].ID != "nPeer111CNTRL" {
		t.Fatalf("expected MigrateConfig to preserve tailscale.p2p_assist, got %+v", p2p)
	}
	raw, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(raw), "p2p_assist") {
		t.Fatalf("expected raw migrated YAML to contain p2p_assist:\n%s", string(raw))
	}
}

func TestTailscaleLocalSubnetRule_ScopeNormalizationAndClone(t *testing.T) {
	if s, ok := config.NormalizeTailscaleSubnetScope(""); !ok || s != config.TailscaleScopeAll {
		t.Fatalf("empty scope got (%q, %v), want (%q, true)", s, ok, config.TailscaleScopeAll)
	}
	if s, ok := config.NormalizeTailscaleSubnetScope("ALLOWLIST"); !ok || s != config.TailscaleScopeAllowlist {
		t.Fatalf("allowlist got (%q, %v)", s, ok)
	}
	if s, ok := config.NormalizeTailscaleSubnetScope("denylist"); !ok || s != config.TailscaleScopeDenylist {
		t.Fatalf("denylist got (%q, %v)", s, ok)
	}
	if _, ok := config.NormalizeTailscaleSubnetScope("bogus"); ok {
		t.Fatal("expected invalid scope to return ok=false")
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	raw := `subs:
  - name: "main"
    url: "https://example.com/sub"
tailscale:
  subnets: "192.168.31.0/24"
  p2p_assist:
    enabled: true
    role_mode:"gateway"
    local_rules:
      - cidr:"192.168.31.0/24"
        scope:"allowlist"
        devices:
          - "192.168.31.88"
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Tailscale.P2PAssist.RoleMode != "gateway" || len(loaded.Tailscale.P2PAssist.LocalRules) != 1 {
		t.Fatalf("unexpected RoleMode/LocalRules after load: %+v", loaded.Tailscale.P2PAssist)
	}
	cloned := loaded.Clone()
	cloned.Tailscale.P2PAssist.LocalRules[0].Devices[0] = "192.168.31.99"
	if loaded.Tailscale.P2PAssist.LocalRules[0].Devices[0] != "192.168.31.88" {
		t.Fatal("Clone did not isolate LocalRules.Devices slice")
	}
}

func TestTailscaleP2PAssistConfig_DownstreamAssistDefaultsAndClone(t *testing.T) {
	var zero config.TailscaleP2PAssistConfig
	if !zero.EffectiveDownstreamAssist() {
		t.Fatal("expected nil DownstreamAssist to default to true")
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	raw := `subs:
  - name: "main"
    url: "https://example.com/sub"
tailscale:
  p2p_assist:
    enabled: true
    downstream_assist:false
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Tailscale.P2PAssist.EffectiveDownstreamAssist() {
		t.Fatal("expected explicit downstream_assist:false to evaluate false")
	}
	cloned := loaded.Clone()
	*cloned.Tailscale.P2PAssist.DownstreamAssist = true
	if loaded.Tailscale.P2PAssist.EffectiveDownstreamAssist() {
		t.Fatal("Clone did not isolate DownstreamAssist pointer")
	}
}
