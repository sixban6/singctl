package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

	// 2. 老版本 fscarmen/warp：仅有 /etc/wireguard/proxy.conf，无 wireproxy.conf，且 systemd ExecStart -c 指向 proxy.conf
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
	if !exists || active != compat {
		t.Fatalf("expected active=%q exists=true, got active=%q exists=%v", compat, active, exists)
	}
	if !slices.Contains(mirrors, primary) {
		t.Fatalf("expected mirrorPaths to include primary %q, got %v", primary, mirrors)
	}

	// 3. 无 unit 文件时也应回退发现 legacy proxy.conf
	active, _, exists = ResolveWireproxyConfigPathsWithEnv(WireproxyPathEnv{
		PrimaryConf: primary,
		CompatConf:  compat,
		UnitFiles:   []string{filepath.Join(tmp, "missing.service")},
	})
	if !exists || active != compat {
		t.Fatalf("expected legacy fallback to compat %q, got %q (exists=%v)", compat, active, exists)
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

func TestRotateWarpIdentity_LegacyProxyConfSuccessAnd0600Hardening(t *testing.T) {
	tmp := t.TempDir()
	primary := filepath.Join(tmp, "wireproxy", "wireproxy.conf")
	compat := filepath.Join(tmp, "wireguard", "proxy.conf")
	unitFile := filepath.Join(tmp, "wireproxy.service")

	if err := os.MkdirAll(filepath.Dir(compat), 0755); err != nil {
		t.Fatal(err)
	}
	// 故意使用过宽权限 0644 模拟老脚本产物，且不创建 primary 目录
	if err := os.WriteFile(compat, []byte("ORIG-LEGACY-CONF"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitFile, []byte("[Service]\nExecStart=/usr/bin/wireproxy -c "+compat+"\n"), 0644); err != nil {
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

	for _, p := range []string{compat, primary} {
		st, statErr := os.Stat(p)
		if statErr != nil {
			t.Fatalf("expected %s to exist after rotation: %v", p, statErr)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 permissions on %s, got %04o", p, st.Mode().Perm())
		}
		raw, _ := os.ReadFile(p)
		if !strings.Contains(string(raw), "DUMMY_TEST_PRIVKEY_BASE64=") {
			t.Fatalf("expected updated private key in %s, got:\n%s", p, string(raw))
		}
	}

	baks, _ := filepath.Glob(compat + ".*.bak")
	if len(baks) != 1 {
		t.Fatalf("expected 1 backup file for %s, got %v", compat, baks)
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

	if err := os.MkdirAll(filepath.Dir(compat), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(compat, []byte("ORIG-CONF"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitFile, []byte("[Service]\nExecStart=/usr/bin/wireproxy -c "+compat+"\n"), 0644); err != nil {
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

	restored, rErr := os.ReadFile(compat)
	if rErr != nil || string(restored) != "ORIG-CONF" {
		t.Fatalf("expected %s to roll back to ORIG-CONF, got %q (err=%v)", compat, string(restored), rErr)
	}
	if st, _ := os.Stat(compat); st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 on rolled-back %s, got %04o", compat, st.Mode().Perm())
	}
	if _, statErr := os.Stat(primary); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected newly created mirror %s to be removed on rollback, got err=%v", primary, statErr)
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
