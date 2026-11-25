// 文件职责：测试 AdGuard Home 全内存段自适应 GOMEMLIMIT 阶梯计算与 procd/systemd 服务脚本幂等无损注入。
package adguard_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/adguard"
)

func TestAdGuard_FullRangeMemoryEnvAndServiceReconcile(t *testing.T) {
	const mib = 1024 * 1024

	cases := []struct {
		ram       uint64
		wantLimit string
		wantGOGC  string
	}{
		{0, "", ""},
		{224 * mib, "96MiB", "30"},
		{479 * mib, "128MiB", "50"},
		{1024 * mib, "160MiB", ""},
		{2048 * mib, "256MiB", ""},
		{4096 * mib, "384MiB", ""},
	}
	for _, tc := range cases {
		env := adguard.ComputeMemoryEnv(tc.ram)
		if tc.wantLimit == "" {
			if len(env) != 0 {
				t.Fatalf("ram=%d expected empty env, got %v", tc.ram, env)
			}
			continue
		}
		if env["GOMEMLIMIT"] != tc.wantLimit || env["GOGC"] != tc.wantGOGC {
			t.Fatalf("ComputeMemoryEnv(%d) = %v, want limit=%q gogc=%q", tc.ram, env, tc.wantLimit, tc.wantGOGC)
		}
	}

	dir := t.TempDir()
	initd := filepath.Join(dir, "AdGuardHome")
	rawProcd := adguard.BuildOpenWrtInitScript("/usr/bin/AdGuardHome", "/etc/AdGuardHome/AdGuardHome.yaml", "/etc/AdGuardHome")
	if err := os.WriteFile(initd, []byte(rawProcd), 0755); err != nil {
		t.Fatal(err)
	}

	// 2GiB host injects GOMEMLIMIT=256MiB without lowering GOGC
	changed, svcType, err := adguard.EnsureMemoryLimitServiceEnv(initd, filepath.Join(dir, "missing.service"), 2048*mib)
	if err != nil || !changed || svcType != "procd" {
		t.Fatalf("first EnsureMemoryLimitServiceEnv = (%v, %q, %v), want (true, procd, nil)", changed, svcType, err)
	}
	body, err := os.ReadFile(initd)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "procd_set_param env GOMEMLIMIT=256MiB") || strings.Contains(string(body), "GOGC=") {
		t.Fatalf("unexpected patched AdGuardHome procd:\n%s", string(body))
	}

	// Strictly idempotent on repeat
	changed2, _, err := adguard.EnsureMemoryLimitServiceEnv(initd, filepath.Join(dir, "missing.service"), 2048*mib)
	if err != nil || changed2 {
		t.Fatalf("repeat EnsureMemoryLimitServiceEnv must be idempotent, got changed=%v err=%v", changed2, err)
	}

	// Systemd unit reconciliation
	sysUnit := filepath.Join(dir, "AdGuardHome.service")
	rawSys := adguard.BuildSystemdUnit("/usr/bin/AdGuardHome", "/etc/AdGuardHome/AdGuardHome.yaml", "/etc/AdGuardHome")
	if err := os.WriteFile(sysUnit, []byte(rawSys), 0644); err != nil {
		t.Fatal(err)
	}
	changedSys, svcSys, err := adguard.EnsureMemoryLimitServiceEnv(filepath.Join(dir, "missing-init"), sysUnit, 4096*mib)
	if err != nil || !changedSys || svcSys != "systemd" {
		t.Fatalf("systemd EnsureMemoryLimitServiceEnv = (%v, %q, %v), want (true, systemd, nil)", changedSys, svcSys, err)
	}
	sysBody, _ := os.ReadFile(sysUnit)
	if !strings.Contains(string(sysBody), `Environment="GOMEMLIMIT=384MiB"`) {
		t.Fatalf("unexpected patched systemd unit:\n%s", string(sysBody))
	}
}
