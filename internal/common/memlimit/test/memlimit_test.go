// 文件职责：验证 memlimit 守护角色零分配识别、宿主机内存解析与自适应 GOMEMLIMIT 软上限计算。
package memlimit_test

import (
	"testing"

	"singctl/internal/common/memlimit"
)

func TestDetectDaemonRole_And_ComputeSoftMemoryLimit(t *testing.T) {
	const mib = 1024 * 1024
	roleTests := []struct {
		args []string
		want memlimit.Role
	}{
		{nil, memlimit.RoleNone},
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

	if got := memlimit.ParseMeminfoTotalBytes("MemTotal:         983724 kB\n"); got != 983724*1024 {
		t.Fatalf("ParseMeminfoTotalBytes = %d", got)
	}
	if memlimit.ComputeSoftMemoryLimit(memlimit.RoleSubHub, 512*mib) != 32*mib {
		t.Fatal("512MB RoleSubHub mismatch")
	}
	if memlimit.ComputeSoftMemoryLimit(memlimit.RoleDaemonOrWeb, 4096*mib) != 96*mib {
		t.Fatal("4096MB RoleDaemonOrWeb mismatch")
	}

	var applied int64
	got := memlimit.ApplyForArgs(
		[]string{"singctl", "dm", "start"},
		func(string) string { return "" },
		func() uint64 { return 512 * mib },
		func(v int64) int64 { applied = v; return -1 },
	)
	if got != 48*mib || applied != 48*mib {
		t.Fatalf("ApplyForArgs = (%d, %d)", got, applied)
	}
	_ = memlimit.ApplyDefault([]string{"singctl", "version"})
}
