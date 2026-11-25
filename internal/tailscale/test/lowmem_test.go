// 文件职责：测试 Tailscale 小内存路由器自适应 GOMEMLIMIT/GOGC 护栏生成、既有 procd/systemd 无损幂等注入与重复启动软链清理。
package tailscale_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/tailscale"
)

func TestTailscale_LowMemServiceEnvAndDuplicateRcCleanup(t *testing.T) {
	const mib = 1024 * 1024

	// 1. Full-range tiered memory env table
	if env := tailscale.ComputeMemoryEnv(224 * mib); env["GOMEMLIMIT"] != "14MiB" || env["GOGC"] != "25" || env["TS_NO_LOGS_NO_SUPPORT"] != "true" {
		t.Fatalf("unexpected 224MiB tailscale env: %v", env)
	}
	if env := tailscale.ComputeMemoryEnv(479 * mib); env["GOMEMLIMIT"] != "22MiB" || env["GOGC"] != "40" || env["TS_NO_LOGS_NO_SUPPORT"] != "true" {
		t.Fatalf("unexpected 479MiB tailscale env: %v", env)
	}
	if env := tailscale.ComputeMemoryEnv(1024 * mib); env["GOMEMLIMIT"] != "48MiB" || env["GOGC"] != "" {
		t.Fatalf("unexpected 1GiB tailscale env: %v", env)
	}
	if env := tailscale.ComputeMemoryEnv(2048 * mib); env["GOMEMLIMIT"] != "64MiB" || env["GOGC"] != "" {
		t.Fatalf("unexpected 2GiB tailscale env: %v", env)
	}
	if env := tailscale.ComputeMemoryEnv(4096 * mib); env["GOMEMLIMIT"] != "128MiB" || env["GOGC"] != "" {
		t.Fatalf("unexpected 4GiB tailscale env: %v", env)
	}
	if env := tailscale.ComputeMemoryEnv(0); len(env) != 0 {
		t.Fatalf("expected no memory env limit on unknown RAM, got %v", env)
	}

	// 2. RenderInitScriptWithMem injects full-range procd_set_param env (ultra-low includes GOGC, 2GiB keeps default GOGC)
	ultraScript := tailscale.RenderInitScriptWithMem(true, 224*mib)
	if !strings.Contains(ultraScript, "procd_set_param env GOGC=25 GOMEMLIMIT=14MiB TS_NO_LOGS_NO_SUPPORT=true") {
		t.Fatalf("expected ultra-low procd env in rendered init script:\n%s", ultraScript)
	}
	bigScript := tailscale.RenderInitScriptWithMem(true, 2048*mib)
	if !strings.Contains(bigScript, "procd_set_param env GOMEMLIMIT=64MiB") || strings.Contains(bigScript, "GOGC=") {
		t.Fatalf("2GiB RAM init script must set GOMEMLIMIT=64MiB without overriding GOGC:\n%s", bigScript)
	}

	// 3. EnsureLowMemServiceEnv idempotently patches existing OpenWrt procd script + cleans duplicate S80tailscale
	dir := t.TempDir()
	initd := filepath.Join(dir, "tailscale")
	rcd := filepath.Join(dir, "rc.d")
	if err := os.MkdirAll(rcd, 0755); err != nil {
		t.Fatal(err)
	}
	origProcd := `#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
STOP=10

start_service() {
    procd_open_instance
    procd_set_param command /usr/sbin/tailscaled
    procd_append_param command --state=/etc/tailscale/tailscaled.state
    procd_set_param respawn
    procd_close_instance
}
`
	if err := os.WriteFile(initd, []byte(origProcd), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../init.d/tailscale", filepath.Join(rcd, "S80tailscale")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../init.d/tailscale", filepath.Join(rcd, "S99tailscale")); err != nil {
		t.Fatal(err)
	}

	changed, svcType, err := tailscale.EnsureLowMemServiceEnv(initd, filepath.Join(dir, "missing.service"), rcd, 224*mib)
	if err != nil || !changed || svcType != "procd" {
		t.Fatalf("EnsureLowMemServiceEnv first run = (%v, %q, %v), want (true, procd, nil)", changed, svcType, err)
	}
	afterBytes, err := os.ReadFile(initd)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(afterBytes), "procd_set_param env GOGC=25 GOMEMLIMIT=14MiB TS_NO_LOGS_NO_SUPPORT=true") {
		t.Fatalf("patched procd script missing env:\n%s", string(afterBytes))
	}
	if _, err := os.Lstat(filepath.Join(rcd, "S80tailscale")); !os.IsNotExist(err) {
		t.Fatalf("expected duplicate S80tailscale symlink removed when S99tailscale exists")
	}
	if _, err := os.Lstat(filepath.Join(rcd, "S99tailscale")); err != nil {
		t.Fatalf("expected S99tailscale preserved: %v", err)
	}

	// Second run must be strictly idempotent (changed=false)
	changed2, _, err := tailscale.EnsureLowMemServiceEnv(initd, filepath.Join(dir, "missing.service"), rcd, 224*mib)
	if err != nil || changed2 {
		t.Fatalf("second EnsureLowMemServiceEnv should be idempotent, got changed=%v err=%v", changed2, err)
	}
}
