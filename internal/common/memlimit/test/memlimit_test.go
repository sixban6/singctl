// 文件职责：验证 memlimit 守护角色零分配识别、超小内存自适应 GOMEMLIMIT 软上限与 GOGC 阶梯及显式环境变量优先级。
package memlimit_test

import (
	"math"
	"sync"
	"testing"

	"singctl/internal/common/memlimit"
)

func TestDetectDaemonRole_And_ComputeMemoryAndGCTiers(t *testing.T) {
	const mib = 1024 * 1024
	roleTests := []struct {
		args []string
		want memlimit.Role
	}{
		{nil, memlimit.RoleNone},
		{[]string{"singctl"}, memlimit.RoleNone},
		{[]string{"singctl", "version"}, memlimit.RoleNone},
		{[]string{"singctl", "dm", "status"}, memlimit.RoleNone},
		{[]string{"singctl", "web", "stop"}, memlimit.RoleNone},
		{[]string{"singctl", "-c", "/etc/singctl/singctl.yaml", "dm", "start"}, memlimit.RoleDaemonOrWeb},
		{[]string{"singctl", "web", "start", "-l", ":8090"}, memlimit.RoleDaemonOrWeb},
		{[]string{"singctl", "sr", "ui"}, memlimit.RoleDaemonOrWeb},
		{[]string{"singctl", "sr", "sub"}, memlimit.RoleSubHub},
	}
	for _, tc := range roleTests {
		if got := memlimit.DetectDaemonRole(tc.args); got != tc.want {
			t.Fatalf("DetectDaemonRole(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}

	if got := memlimit.ParseMeminfoTotalBytes("MemTotal:         491040 kB\n"); got != 491040*1024 {
		t.Fatalf("ParseMeminfoTotalBytes = %d", got)
	}

	tierTests := []struct {
		name       string
		totalRAM   uint64
		wantSubMiB int64
		wantWebMiB int64
		wantGC     int
	}{
		{"unknown_zero_ram_keeps_safe_default", 0, 48, 64, 100},
		{"ultra_low_128MiB", 128 * mib, 18, 22, 50},
		{"ultra_low_224MiB_router", 224 * mib, 18, 22, 50},
		{"ultra_low_256MiB_router", 256 * mib, 18, 22, 50},
		{"ultra_low_288MiB_boundary", 288 * mib, 18, 22, 50},
		{"low_289MiB", 289 * mib, 24, 28, 50},
		{"low_384MiB_router", 384 * mib, 24, 28, 50},
		{"low_n60pro_479MiB_router", 491040 * 1024, 24, 28, 50},
		{"low_512MiB_boundary", 512 * mib, 24, 28, 50},
		{"mid_513MiB", 513 * mib, 32, 48, 100},
		{"mid_1024MiB_boundary", 1024 * mib, 32, 48, 100},
		{"standard_2048MiB_boundary", 2048 * mib, 48, 64, 100},
		{"large_4096MiB", 4096 * mib, 64, 96, 100},
		{"extreme_max_uint64", math.MaxUint64, 64, 96, 100},
	}

	for _, tc := range tierTests {
		t.Run(tc.name, func(t *testing.T) {
			if got := memlimit.ComputeSoftMemoryLimit(memlimit.RoleNone, tc.totalRAM); got != 0 {
				t.Fatalf("RoleNone limit = %d, want 0", got)
			}
			if got := memlimit.ComputeGCPercent(memlimit.RoleNone, tc.totalRAM); got != 0 {
				t.Fatalf("RoleNone GOGC = %d, want 0", got)
			}
			if got := memlimit.ComputeSoftMemoryLimit(memlimit.RoleSubHub, tc.totalRAM); got != tc.wantSubMiB*mib {
				t.Fatalf("RoleSubHub(%d) limit = %d MiB, want %d MiB", tc.totalRAM/mib, got/mib, tc.wantSubMiB)
			}
			if got := memlimit.ComputeSoftMemoryLimit(memlimit.RoleDaemonOrWeb, tc.totalRAM); got != tc.wantWebMiB*mib {
				t.Fatalf("RoleDaemonOrWeb(%d) limit = %d MiB, want %d MiB", tc.totalRAM/mib, got/mib, tc.wantWebMiB)
			}
			if got := memlimit.ComputeGCPercent(memlimit.RoleSubHub, tc.totalRAM); got != tc.wantGC {
				t.Fatalf("RoleSubHub(%d) GOGC = %d, want %d", tc.totalRAM/mib, got, tc.wantGC)
			}
			if got := memlimit.ComputeGCPercent(memlimit.RoleDaemonOrWeb, tc.totalRAM); got != tc.wantGC {
				t.Fatalf("RoleDaemonOrWeb(%d) GOGC = %d, want %d", tc.totalRAM/mib, got, tc.wantGC)
			}
		})
	}
}

func TestApplyRuntimeLimits_RespectsExplicitEnvAndConcurrency(t *testing.T) {
	const mib = 1024 * 1024

	// 1. 224MB router sets both GOMEMLIMIT=22MiB and GOGC=50 when env vars are unset
	var setMem int64
	var setGC int
	lim, gc := memlimit.ApplyRuntimeLimits(
		[]string{"singctl", "dm", "start"},
		func(string) string { return "" },
		func() uint64 { return 224 * mib },
		func(v int64) int64 { setMem = v; return -1 },
		func(v int) int { setGC = v; return 100 },
	)
	if lim != 22*mib || setMem != 22*mib || gc != 50 || setGC != 50 {
		t.Fatalf("224MB ApplyRuntimeLimits = (%d, %d), set=(%d, %d), want (22MiB, 50)", lim, gc, setMem, setGC)
	}

	// 2. n60pro (~479.5 MiB) sets GOMEMLIMIT=28MiB and GOGC=50
	setMem, setGC = 0, 0
	lim, gc = memlimit.ApplyRuntimeLimits(
		[]string{"singctl", "dm", "start"},
		func(string) string { return "" },
		func() uint64 { return 491040 * 1024 },
		func(v int64) int64 { setMem = v; return -1 },
		func(v int) int { setGC = v; return 100 },
	)
	if lim != 28*mib || setMem != 28*mib || gc != 50 || setGC != 50 {
		t.Fatalf("n60pro ApplyRuntimeLimits = (%d, %d), set=(%d, %d), want (28MiB, 50)", lim, gc, setMem, setGC)
	}

	// 3. Explicit GOMEMLIMIT respected while GOGC is still auto-tuned
	setMem, setGC = 0, 0
	lim, gc = memlimit.ApplyRuntimeLimits(
		[]string{"singctl", "dm", "start"},
		func(k string) string {
			if k == "GOMEMLIMIT" {
				return "128MiB"
			}
			return ""
		},
		func() uint64 { return 224 * mib },
		func(v int64) int64 { setMem = v; return -1 },
		func(v int) int { setGC = v; return 100 },
	)
	if lim != 0 || setMem != 0 || gc != 50 || setGC != 50 {
		t.Fatalf("explicit GOMEMLIMIT should skip setLimit but apply GOGC=50, got lim=%d gc=%d", lim, gc)
	}

	// 4. Explicit GOGC respected while GOMEMLIMIT is still auto-tuned
	setMem, setGC = 0, 0
	lim, gc = memlimit.ApplyRuntimeLimits(
		[]string{"singctl", "sr", "sub"},
		func(k string) string {
			if k == "GOGC" {
				return "off"
			}
			return ""
		},
		func() uint64 { return 512 * mib },
		func(v int64) int64 { setMem = v; return -1 },
		func(v int) int { setGC = v; return 100 },
	)
	if lim != 24*mib || setMem != 24*mib || gc != 0 || setGC != 0 {
		t.Fatalf("explicit GOGC should skip setGCPercent but apply GOMEMLIMIT=24MiB, got lim=%d gc=%d", lim, gc)
	}

	// 5. Backward-compatible ApplyForArgs and nil safety + concurrent race safety
	if got := memlimit.ApplyForArgs([]string{"singctl", "dm", "start"}, nil, nil, nil); got != 0 {
		t.Fatalf("expected 0 on nil callbacks, got %d", got)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			var localApplied int64
			got := memlimit.ApplyForArgs(
				[]string{"singctl", "dm", "start"},
				func(string) string { return "" },
				func() uint64 { return 512 * mib },
				func(v int64) int64 { localApplied = v; return -1 },
			)
			if got != 28*mib || localApplied != 28*mib {
				t.Errorf("ApplyForArgs(512MB) = (%d, %d), want 28MiB", got, localApplied)
			}
		})
	}
	wg.Wait()
	_ = memlimit.ApplyDefault([]string{"singctl", "version"})
}
