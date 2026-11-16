package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseWireproxyConfFromUnitAndResolvePaths(t *testing.T) {
	tmp := t.TempDir()
	primary := filepath.Join(tmp, "wireproxy", "wireproxy.conf")
	compat := filepath.Join(tmp, "wireguard", "proxy.conf")
	custom := filepath.Join(tmp, "custom", "my-warp.conf")
	unitFile := filepath.Join(tmp, "wireproxy.service")

	// 1. 未安装任何配置文件时 exists == false
	active, mirrors, exists := ResolveWireproxyConfigPathsWithEnv(WireproxyPathEnv{
		PrimaryConf: primary,
		CompatConf:  compat,
		UnitFiles:   []string{unitFile},
	})
	if exists || active != primary || len(mirrors) != 0 {
		t.Fatalf("unexpected empty resolve: active=%q mirrors=%v exists=%v", active, mirrors, exists)
	}

	// 2. 老版本 fscarmen/warp（仅有 /etc/wireguard/proxy.conf）：应被忽略并返回 exists=false，从而触发纯 Go 部署迁移
	if err := os.MkdirAll(filepath.Dir(compat), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(compat, []byte("[Interface]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitFile, []byte("[Service]\nExecStart=/usr/bin/wireproxy -c "+compat+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	active, mirrors, exists = ResolveWireproxyConfigPathsWithEnv(WireproxyPathEnv{
		PrimaryConf: primary,
		CompatConf:  compat,
		UnitFiles:   []string{unitFile},
	})
	if exists || active != primary || len(mirrors) != 0 {
		t.Fatalf("expected legacy compat %q to be ignored in pure-Go mode, got active=%q mirrors=%v exists=%v", compat, active, mirrors, exists)
	}

	// 3. 标准纯 Go 配置 /etc/wireproxy/wireproxy.conf 存在时，精准识别为唯一有效配置
	if err := os.MkdirAll(filepath.Dir(primary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(primary, []byte("[Interface]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	active, mirrors, exists = ResolveWireproxyConfigPathsWithEnv(WireproxyPathEnv{
		PrimaryConf: primary,
		CompatConf:  compat,
		UnitFiles:   []string{unitFile},
	})
	if !exists || active != primary || len(mirrors) != 0 {
		t.Fatalf("expected pure-Go active=%q exists=true mirrors=nil, got active=%q mirrors=%v exists=%v", primary, active, mirrors, exists)
	}

	// 4. systemd ExecStart=--config= 自定义路径解析
	if err := os.MkdirAll(filepath.Dir(custom), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(custom, []byte("[Interface]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := ParseWireproxyConfFromUnit("ExecStart=\"/usr/local/bin/wireproxy\" --config=\"" + custom + "\"\n"); got != custom {
		t.Fatalf("expected ParseWireproxyConfFromUnit=%q, got %q", custom, got)
	}
}

func TestRotateWarpIdentity_SuccessAnd0600Hardening(t *testing.T) {
	tmp := t.TempDir()
	primary := filepath.Join(tmp, "wireproxy", "wireproxy.conf")
	compat := filepath.Join(tmp, "wireguard", "proxy.conf")
	unitFile := filepath.Join(tmp, "wireproxy.service")

	if err := os.MkdirAll(filepath.Dir(primary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(primary, []byte("ORIG-PURE-GO-CONF"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitFile, []byte("[Service]\nExecStart=/usr/local/bin/wireproxy -c "+primary+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	restarts := 0
	newIP, newLoc, err := RotateWarpIdentityWithDeps(&WarpRotateDeps{
		PathEnv: WireproxyPathEnv{
			PrimaryConf: primary,
			CompatConf:  compat,
			UnitFiles:   []string{unitFile},
		},
		GenerateKeypair: func() (string, string, error) {
			return "DUMMY_TEST_PRIVKEY_BASE64=", "DUMMY_TEST_PUBKEY_BASE64=", nil
		},
		RegisterWarp: func(string) (*warpRegResponse, error) {
			var resp warpRegResponse
			resp.Config.Interface.Addresses.V4 = "172.16.0.2"
			resp.Config.Interface.Addresses.V6 = "2606:4700:110::2"
			return &resp, nil
		},
		HasIPv6: func() bool { return false },
		RestartService: func() error {
			restarts++
			return nil
		},
		FetchExitInfo: func(time.Duration) (string, string, string, bool) {
			return "198.51.100.88", "SJC", "on", true
		},
		PollAttempts: 2,
		PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RotateWarpIdentityWithDeps failed: %v", err)
	}
	if newIP != "198.51.100.88" || newLoc != "SJC" || restarts != 1 {
		t.Fatalf("unexpected rotation result: ip=%q loc=%q restarts=%d", newIP, newLoc, restarts)
	}

	st, statErr := os.Stat(primary)
	if statErr != nil {
		t.Fatalf("expected %s to exist after rotation: %v", primary, statErr)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on %s, got %04o", primary, st.Mode().Perm())
	}
	raw, _ := os.ReadFile(primary)
	if !strings.Contains(string(raw), "DUMMY_TEST_PRIVKEY_BASE64=") || !strings.Contains(string(raw), "MTU = 1280") {
		t.Fatalf("expected updated private key and MTU = 1280 in %s, got:\n%s", primary, string(raw))
	}

	baks, _ := filepath.Glob(primary + ".*.bak")
	if len(baks) != 1 {
		t.Fatalf("expected 1 backup file for %s, got %v", primary, baks)
	}
	if st, _ := os.Stat(baks[0]); st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 backup file, got %04o", st.Mode().Perm())
	}
}

func TestRotateWarpIdentity_HandshakeTimeoutRollsBackCleanly(t *testing.T) {
	tmp := t.TempDir()
	primary := filepath.Join(tmp, "wireproxy", "wireproxy.conf")
	compat := filepath.Join(tmp, "wireguard", "proxy.conf")
	unitFile := filepath.Join(tmp, "wireproxy.service")

	if err := os.MkdirAll(filepath.Dir(primary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(primary, []byte("ORIG-CONF"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitFile, []byte("[Service]\nExecStart=/usr/local/bin/wireproxy -c "+primary+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	restarts := 0
	_, _, err := RotateWarpIdentityWithDeps(&WarpRotateDeps{
		PathEnv: WireproxyPathEnv{
			PrimaryConf: primary,
			CompatConf:  compat,
			UnitFiles:   []string{unitFile},
		},
		GenerateKeypair: func() (string, string, error) {
			return "NEW_PRIV=", "NEW_PUB=", nil
		},
		RegisterWarp: func(string) (*warpRegResponse, error) {
			var resp warpRegResponse
			resp.Config.Interface.Addresses.V4 = "172.16.0.2"
			return &resp, nil
		},
		HasIPv6: func() bool { return false },
		RestartService: func() error {
			restarts++
			return nil
		},
		FetchExitInfo: func(time.Duration) (string, string, string, bool) {
			return "", "", "", false
		},
		PollAttempts: 2,
		PollInterval: time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "自动回滚") {
		t.Fatalf("expected rollback error, got %v", err)
	}
	if restarts != 2 {
		t.Fatalf("expected 2 restarts (apply + rollback), got %d", restarts)
	}

	restored, rErr := os.ReadFile(primary)
	if rErr != nil || string(restored) != "ORIG-CONF" {
		t.Fatalf("expected %s to roll back to ORIG-CONF, got %q (err=%v)", primary, string(restored), rErr)
	}
	if st, _ := os.Stat(primary); st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 on rolled-back %s, got %04o", primary, st.Mode().Perm())
	}
}

func TestRotateWarpIdentity_MultiEndpointFallback(t *testing.T) {
	tmp := t.TempDir()
	primary := filepath.Join(tmp, "wireproxy", "wireproxy.conf")
	unitFile := filepath.Join(tmp, "wireproxy.service")

	if err := os.MkdirAll(filepath.Dir(primary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(primary, []byte("ORIG-CONF"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitFile, []byte("[Service]\nExecStart=/usr/local/bin/wireproxy -c "+primary+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	restarts := 0
	newIP, newLoc, err := RotateWarpIdentityWithDeps(&WarpRotateDeps{
		PathEnv: WireproxyPathEnv{
			PrimaryConf: primary,
			UnitFiles:   []string{unitFile},
		},
		CandidateEndpoints: []string{"162.159.192.1:2408", "162.159.193.10:1701"},
		GenerateKeypair:    func() (string, string, error) { return "NEW_PRIV=", "NEW_PUB=", nil },
		RegisterWarp: func(string) (*warpRegResponse, error) {
			var resp warpRegResponse
			resp.Config.Interface.Addresses.V4 = "172.16.0.2"
			return &resp, nil
		},
		HasIPv6:        func() bool { return false },
		RestartService: func() error { restarts++; return nil },
		FetchExitInfo: func(time.Duration) (string, string, string, bool) {
			raw, _ := os.ReadFile(primary)
			if strings.Contains(string(raw), "162.159.193.10:1701") {
				return "203.0.113.77", "LAX", "on", true
			}
			return "", "", "", false
		},
		PollAttempts: 1,
		PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("expected multi-endpoint fallback to succeed, got %v", err)
	}
	if newIP != "203.0.113.77" || newLoc != "LAX" || restarts != 2 {
		t.Fatalf("unexpected fallback result: ip=%q loc=%q restarts=%d", newIP, newLoc, restarts)
	}
	raw, _ := os.ReadFile(primary)
	if !strings.Contains(string(raw), "Endpoint = 162.159.193.10:1701") {
		t.Fatalf("expected persisted fallback endpoint, got:\n%s", string(raw))
	}
}

func TestSwitchWarpEndpoint_CyclesCandidatesAndRecovers(t *testing.T) {
	tmp := t.TempDir()
	confPath := filepath.Join(tmp, "wireproxy.conf")
	orig := BuildWireproxyConfig("172.16.0.2/32", "DUMMY_PRIV=", "DUMMY_PUB=", false)
	if err := os.WriteFile(confPath, []byte(orig), 0600); err != nil {
		t.Fatal(err)
	}

	tried := []string{}
	ep, ip, loc, err := SwitchWarpEndpointWithDeps(&WarpEndpointSwitchDeps{
		ConfPath:           confPath,
		CandidateEndpoints: []string{"162.159.192.1:2408", "162.159.193.10:1701", "162.159.195.1:500"},
		RestartService: func() error {
			raw, _ := os.ReadFile(confPath)
			tried = append(tried, ExtractWireproxyEndpoint(string(raw)))
			return nil
		},
		ProbeTargets: func(time.Duration) (string, string, error) {
			raw, _ := os.ReadFile(confPath)
			if ExtractWireproxyEndpoint(string(raw)) == "162.159.195.1:500" {
				return "198.51.100.44", "NRT", nil
			}
			return "", "", errors.New("udp blocked")
		},
		PollAttempts: 1,
		PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("SwitchWarpEndpointWithDeps failed: %v", err)
	}
	if ep != "162.159.195.1:500" || ip != "198.51.100.44" || loc != "NRT" {
		t.Fatalf("unexpected switch result: ep=%q ip=%q loc=%q", ep, ip, loc)
	}
	// Starts right after current endpoint 162.159.192.1:2408
	if !slices.Equal(tried, []string{"162.159.193.10:1701", "162.159.195.1:500"}) {
		t.Fatalf("expected endpoint rotation order after current, got %v", tried)
	}
}

func TestPurgeLegacyFscarmenWarp(t *testing.T) {
	tmp := t.TempDir()
	warpScript := filepath.Join(tmp, "usr-bin-warp")
	oldBin := filepath.Join(tmp, "usr-bin-wireproxy")
	legacyConf := filepath.Join(tmp, "wireguard", "proxy.conf")
	legacyBak := filepath.Join(tmp, "wireguard", "proxy.conf.bak")
	legacyDir := filepath.Join(tmp, "opt-warp-go")
	unitFile := filepath.Join(tmp, "wireproxy.service")
	primaryBin := filepath.Join(tmp, "usr-local-bin-wireproxy")
	primaryConf := filepath.Join(tmp, "wireproxy", "wireproxy.conf")

	_ = os.MkdirAll(filepath.Dir(legacyConf), 0755)
	_ = os.MkdirAll(legacyDir, 0755)
	_ = os.WriteFile(warpScript, []byte("#!/bin/bash\n"), 0755)
	_ = os.WriteFile(oldBin, []byte("upstream-wireproxy-no-resolve"), 0755)
	_ = os.WriteFile(primaryBin, []byte("non-windtf-wireproxy"), 0755)
	_ = os.WriteFile(legacyConf, []byte("[Interface]\n"), 0644)
	_ = os.WriteFile(legacyBak, []byte("[Interface]\n"), 0644)
	_ = os.WriteFile(unitFile, []byte("[Service]\nExecStart=/usr/bin/wireproxy -c "+legacyConf+"\n"), 0644)

	env := &LegacyWarpPurgeEnv{
		LegacyFiles:      []string{warpScript, oldBin, legacyConf, legacyBak},
		LegacyDirs:       []string{legacyDir},
		UnitFiles:        []string{unitFile},
		StopServices:     []string{"warp-go"},
		StandardUnitPath: unitFile,
		PrimaryBin:       primaryBin,
		PrimaryConf:      primaryConf,
		RunSystemctl:     func(...string) error { return nil },
	}

	if !HasLegacyFscarmenWarpWithEnv(env) {
		t.Fatal("expected HasLegacyFscarmenWarpWithEnv to return true")
	}

	purged, err := PurgeLegacyFscarmenWarpWithEnv(env)
	if err != nil || !purged {
		t.Fatalf("PurgeLegacyFscarmenWarpWithEnv failed: purged=%v err=%v", purged, err)
	}

	for _, gone := range []string{warpScript, oldBin, primaryBin, legacyConf, legacyBak, legacyDir} {
		if _, stErr := os.Stat(gone); !errors.Is(stErr, os.ErrNotExist) {
			t.Fatalf("expected legacy artifact %q to be deleted, got err=%v", gone, stErr)
		}
	}

	unitRaw, uErr := os.ReadFile(unitFile)
	if uErr != nil {
		t.Fatalf("expected rewritten unit file: %v", uErr)
	}
	if !strings.Contains(string(unitRaw), "ExecStart="+primaryBin+" -s -c "+primaryConf) {
		t.Fatalf("expected unit rewritten to pure-Go ExecStart, got:\n%s", string(unitRaw))
	}

	// Simulate pure-Go windtf/wireproxy binary installed
	_ = os.WriteFile(primaryBin, []byte("...ResolveStrategy..."), 0755)
	if HasLegacyFscarmenWarpWithEnv(env) {
		t.Fatal("expected HasLegacyFscarmenWarpWithEnv to return false once purged and windtf binary present")
	}
}

func TestRotateWarpIdentity_NoConfigBootstrapsViaDeployFallback(t *testing.T) {
	tmp := t.TempDir()
	primary := filepath.Join(tmp, "wireproxy", "wireproxy.conf")
	compat := filepath.Join(tmp, "wireguard", "proxy.conf")

	deployCalls := 0
	newIP, newLoc, err := RotateWarpIdentityWithDeps(&WarpRotateDeps{
		PathEnv: WireproxyPathEnv{
			PrimaryConf: primary,
			CompatConf:  compat,
			UnitFiles:   []string{filepath.Join(tmp, "missing.service")},
		},
		DeployFallback: func() error {
			deployCalls++
			return nil
		},
		FetchExitInfo: func(time.Duration) (string, string, string, bool) {
			return "203.0.113.55", "LAX", "on", true
		},
		PollAttempts: 2,
		PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("expected bootstrap fallback to succeed, got %v", err)
	}
	if deployCalls != 1 || newIP != "203.0.113.55" || newLoc != "LAX" {
		t.Fatalf("unexpected fallback result: deployCalls=%d ip=%q loc=%q", deployCalls, newIP, newLoc)
	}
}

func TestRotateWarpIdentity_PrioritizesCurrentEndpoint(t *testing.T) {
	tmp := t.TempDir()
	primary := filepath.Join(tmp, "wireproxy", "wireproxy.conf")
	unitFile := filepath.Join(tmp, "wireproxy.service")

	if err := os.MkdirAll(filepath.Dir(primary), 0700); err != nil {
		t.Fatal(err)
	}
	orig := BuildWireproxyConfigWithEndpoint("172.16.0.2/32, 2606:4700:110::2/128", "OLD_PRIV=", "OLD_PUB=", "162.159.195.1:500", false)
	if err := os.WriteFile(primary, []byte(orig), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitFile, []byte("[Service]\nExecStart=/usr/local/bin/wireproxy -s -c "+primary+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var tried []string
	restarts := 0
	newIP, newLoc, err := RotateWarpIdentityWithDeps(&WarpRotateDeps{
		PathEnv: WireproxyPathEnv{
			PrimaryConf: primary,
			UnitFiles:   []string{unitFile},
		},
		CandidateEndpoints: []string{"162.159.192.1:2408", "162.159.195.1:500", "162.159.193.10:1701"},
		GenerateKeypair:    func() (string, string, error) { return "NEW_PRIV=", "NEW_PUB=", nil },
		RegisterWarp: func(string) (*warpRegResponse, error) {
			var resp warpRegResponse
			resp.Config.Interface.Addresses.V4 = "172.16.0.2"
			resp.Config.Interface.Addresses.V6 = "2606:4700:110::3"
			return &resp, nil
		},
		HasIPv6: func() bool { return false },
		RestartService: func() error {
			restarts++
			raw, _ := os.ReadFile(primary)
			tried = append(tried, ExtractWireproxyEndpoint(string(raw)))
			return nil
		},
		FetchExitInfo: func(time.Duration) (string, string, string, bool) {
			raw, _ := os.ReadFile(primary)
			if ExtractWireproxyEndpoint(string(raw)) == "162.159.195.1:500" {
				return "2001:db8::9", "LAX", "on", true
			}
			return "", "", "", false
		},
		PollAttempts: 1,
		PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("expected prioritized current endpoint to succeed, got %v", err)
	}
	if restarts != 1 || !slices.Equal(tried, []string{"162.159.195.1:500"}) {
		t.Fatalf("expected 162.159.195.1:500 tried first with 1 restart, got restarts=%d tried=%v", restarts, tried)
	}
	if newIP != "2001:db8::9" || newLoc != "LAX" {
		t.Fatalf("unexpected rotation result: ip=%q loc=%q", newIP, newLoc)
	}
}

func TestRotateWarpIdentity_StageProbeParallelFallbackAndDistinctIP(t *testing.T) {
	tmp := t.TempDir()
	primary := filepath.Join(tmp, "wireproxy", "wireproxy.conf")
	unitFile := filepath.Join(tmp, "wireproxy.service")

	if err := os.MkdirAll(filepath.Dir(primary), 0700); err != nil {
		t.Fatal(err)
	}
	orig := BuildWireproxyConfigWithEndpoint("172.16.0.2/32, 2606:4700:110::1/128", "OLD_PRIV=", "OLD_PUB=", "162.159.192.1:2408", false)
	if err := os.WriteFile(primary, []byte(orig), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitFile, []byte("[Service]\nExecStart=/usr/local/bin/wireproxy -s -c "+primary+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var (
		mu       sync.Mutex
		regRound int
		restarts int
		probed   []string
	)

	newIP, newLoc, err := RotateWarpIdentityWithDeps(&WarpRotateDeps{
		PathEnv: WireproxyPathEnv{
			PrimaryConf: primary,
			UnitFiles:   []string{unitFile},
		},
		CandidateEndpoints: []string{"162.159.192.1:2408", "162.159.195.1:500", "188.114.96.1:4500"},
		PreviousIP:         "2001:db8::1",
		GenerateKeypair: func() (string, string, error) {
			return "NEW_PRIV=", "NEW_PUB=", nil
		},
		RegisterWarp: func(string) (*warpRegResponse, error) {
			mu.Lock()
			regRound++
			curRound := regRound
			mu.Unlock()
			var resp warpRegResponse
			resp.Config.Interface.Addresses.V4 = "172.16.0.2"
			resp.Config.Interface.Addresses.V6 = "2606:4700:110::" + string(rune('1'+curRound))
			return &resp, nil
		},
		HasIPv6: func() bool { return false },
		StageProbe: func(endpoint, confContent string) (string, string, bool) {
			if !strings.Contains(confContent, "ResolveStrategy = ipv6") {
				t.Errorf("expected dual-stack staging config to use ResolveStrategy = ipv6, got:\n%s", confContent)
			}
			mu.Lock()
			probed = append(probed, endpoint)
			round := regRound
			mu.Unlock()
			if endpoint != "162.159.195.1:500" {
				return "", "", false
			}
			if round == 1 {
				return "2001:db8::1", "LAX", true
			}
			return "2001:db8::2", "LAX", true
		},
		RestartService: func() error {
			mu.Lock()
			restarts++
			mu.Unlock()
			return nil
		},
	})
	if err != nil {
		t.Fatalf("RotateWarpIdentityWithDeps staging failed: %v", err)
	}
	if restarts != 1 {
		t.Fatalf("expected live RestartService called exactly once after staging, got %d", restarts)
	}
	if newIP != "2001:db8::2" || newLoc != "LAX" {
		t.Fatalf("expected distinct second-round IP 2001:db8::2, got ip=%q loc=%q", newIP, newLoc)
	}
	if len(probed) < 2 {
		t.Fatalf("expected parallel endpoint probes when first failed, probed=%v", probed)
	}
	raw, _ := os.ReadFile(primary)
	if !strings.Contains(string(raw), "Endpoint = 162.159.195.1:500") || !strings.Contains(string(raw), "ResolveStrategy = ipv6") {
		t.Fatalf("expected persisted working endpoint & ResolveStrategy = ipv6, got:\n%s", string(raw))
	}
}
