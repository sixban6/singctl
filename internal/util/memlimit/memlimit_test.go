package memlimit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectDaemonRole(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
		want Role
	}{
		{name: "nil args", args: nil, want: RoleNone},
		{name: "empty args", args: []string{}, want: RoleNone},
		{name: "single binary arg", args: []string{"singctl"}, want: RoleNone},
		{name: "short CLI version", args: []string{"singctl", "version"}, want: RoleNone},
		{name: "short CLI status", args: []string{"singctl", "status"}, want: RoleNone},
		{name: "short CLI sb gen", args: []string{"singctl", "sb", "gen"}, want: RoleNone},
		{name: "short CLI doctor", args: []string{"singctl", "doctor"}, want: RoleNone},
		{name: "short CLI fl update", args: []string{"singctl", "fl", "update"}, want: RoleNone},
		{name: "daemon status", args: []string{"singctl", "dm", "status"}, want: RoleNone},
		{name: "web stop", args: []string{"singctl", "web", "stop"}, want: RoleNone},
		{name: "sr ui status", args: []string{"singctl", "sr", "ui", "status"}, want: RoleNone},
		{name: "sr sub status", args: []string{"singctl", "sr", "sub", "status"}, want: RoleNone},
		{name: "dm start", args: []string{"singctl", "dm", "start"}, want: RoleDaemonOrWeb},
		{name: "daemon start with global config flag", args: []string{"singctl", "-c", "/etc/singctl/singctl.yaml", "daemon", "start"}, want: RoleDaemonOrWeb},
		{name: "dm start with inline config flag", args: []string{"singctl", "--config=/etc/singctl/singctl.yaml", "dm", "start"}, want: RoleDaemonOrWeb},
		{name: "web start", args: []string{"singctl", "--config", "/etc/singctl/singctl.yaml", "web", "start", "-l", ":8090"}, want: RoleDaemonOrWeb},
		{name: "short alias w start", args: []string{"singctl", "w", "start"}, want: RoleDaemonOrWeb},
		{name: "foreground web with listen flag", args: []string{"singctl", "web", "--listen", "127.0.0.1:8090"}, want: RoleDaemonOrWeb},
		{name: "foreground web with short -l flag", args: []string{"singctl", "w", "-l=:8090"}, want: RoleDaemonOrWeb},
		{name: "sr ui systemd exec", args: []string{"singctl", "-c", "/etc/singctl/singctl.yaml", "sr", "ui"}, want: RoleDaemonOrWeb},
		{name: "server ui", args: []string{"singctl", "server", "ui"}, want: RoleDaemonOrWeb},
		{name: "sr web", args: []string{"singctl", "sr", "web"}, want: RoleDaemonOrWeb},
		{name: "server web", args: []string{"singctl", "server", "web", "--listen", "127.0.0.1:8092"}, want: RoleDaemonOrWeb},
		{name: "sr sub systemd exec", args: []string{"singctl", "-c", "/etc/singctl/singctl.yaml", "sr", "sub", "--listen", "127.0.0.1:3001"}, want: RoleSubHub},
		{name: "server sub", args: []string{"singctl", "server", "sub"}, want: RoleSubHub},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectDaemonRole(tc.args); got != tc.want {
				t.Fatalf("DetectDaemonRole(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestParseMeminfoTotalBytes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want uint64
	}{
		{
			name: "typical 1GB VPS meminfo",
			raw:  "MemTotal:         983724 kB\nMemFree:          158500 kB\nMemAvailable:     407816 kB\n",
			want: 983724 * 1024,
		},
		{
			name: "whitespace tabs and lowercase unit",
			raw:  "Buffers: 100 kB\nMemTotal:\t2039840 kb\n",
			want: 2039840 * 1024,
		},
		{
			name: "missing MemTotal",
			raw:  "MemFree: 158500 kB\n",
			want: 0,
		},
		{
			name: "empty input",
			raw:  "",
			want: 0,
		},
		{
			name: "malformed non-numeric",
			raw:  "MemTotal: abc kB\n",
			want: 0,
		},
		{
			name: "zero MemTotal",
			raw:  "MemTotal: 0 kB\n",
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseMeminfoTotalBytes(tc.raw); got != tc.want {
				t.Fatalf("ParseMeminfoTotalBytes(%q) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

func TestComputeSoftMemoryLimit(t *testing.T) {
	const mib = 1024 * 1024
	tests := []struct {
		name  string
		role  Role
		total uint64
		want  int64
	}{
		{name: "role none ignores RAM", role: RoleNone, total: 1024 * mib, want: 0},
		{name: "unknown RAM subhub", role: RoleSubHub, total: 0, want: 48 * mib},
		{name: "unknown RAM daemon/web", role: RoleDaemonOrWeb, total: 0, want: 64 * mib},
		{name: "512MB VPS subhub", role: RoleSubHub, total: 512 * mib, want: 32 * mib},
		{name: "1024MB VPS subhub", role: RoleSubHub, total: 1024 * mib, want: 32 * mib},
		{name: "512MB VPS daemon/web", role: RoleDaemonOrWeb, total: 512 * mib, want: 48 * mib},
		{name: "1024MB VPS daemon/web", role: RoleDaemonOrWeb, total: 1024 * mib, want: 48 * mib},
		{name: "2048MB OpenWrt subhub", role: RoleSubHub, total: 2048 * mib, want: 48 * mib},
		{name: "2048MB OpenWrt daemon/web", role: RoleDaemonOrWeb, total: 2048 * mib, want: 64 * mib},
		{name: "4096MB host subhub", role: RoleSubHub, total: 4096 * mib, want: 64 * mib},
		{name: "4096MB host daemon/web", role: RoleDaemonOrWeb, total: 4096 * mib, want: 96 * mib},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ComputeSoftMemoryLimit(tc.role, tc.total); got != tc.want {
				t.Fatalf("ComputeSoftMemoryLimit(%v, %d) = %d, want %d", tc.role, tc.total, got, tc.want)
			}
		})
	}
}

func TestApplyForArgs(t *testing.T) {
	t.Run("explicit GOMEMLIMIT env overrides auto limit", func(t *testing.T) {
		called := false
		got := ApplyForArgs(
			[]string{"singctl", "dm", "start"},
			func(k string) string {
				if k == "GOMEMLIMIT" {
					return "128MiB"
				}
				return ""
			},
			func() uint64 { return 512 << 20 },
			func(v int64) int64 {
				called = true
				return v
			},
		)
		if got != 0 || called {
			t.Fatalf("expected explicit GOMEMLIMIT to bypass auto limit, got=%d called=%v", got, called)
		}
	})

	t.Run("daemon applies computed limit when env empty", func(t *testing.T) {
		var applied int64
		got := ApplyForArgs(
			[]string{"singctl", "-c", "/etc/singctl/singctl.yaml", "web", "start"},
			func(string) string { return "" },
			func() uint64 { return 983724 * 1024 }, // ~960 MiB
			func(v int64) int64 {
				applied = v
				return -1
			},
		)
		want := int64(48 << 20)
		if got != want || applied != want {
			t.Fatalf("got=%d applied=%d, want %d", got, applied, want)
		}
	})

	t.Run("SINGCTL_WEB_BACKGROUND triggers web role even without start arg", func(t *testing.T) {
		var applied int64
		got := ApplyForArgs(
			[]string{"singctl", "web"},
			func(k string) string {
				if k == "SINGCTL_WEB_BACKGROUND" {
					return "1"
				}
				return ""
			},
			func() uint64 { return 2048 << 20 },
			func(v int64) int64 {
				applied = v
				return -1
			},
		)
		want := int64(64 << 20)
		if got != want || applied != want {
			t.Fatalf("got=%d applied=%d, want %d", got, applied, want)
		}
	})

	t.Run("short CLI does not call setLimit", func(t *testing.T) {
		called := false
		got := ApplyForArgs(
			[]string{"singctl", "version"},
			func(string) string { return "" },
			func() uint64 { return 512 << 20 },
			func(v int64) int64 {
				called = true
				return v
			},
		)
		if got != 0 || called {
			t.Fatalf("expected RoleNone to skip setLimit, got=%d called=%v", got, called)
		}
	})

	t.Run("reads real meminfo file parser cleanly", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "meminfo")
		if err := os.WriteFile(p, []byte("MemTotal:         983724 kB\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if got := readMeminfoTotalBytesFromFile(p); got != 983724*1024 {
			t.Fatalf("got %d, want %d", got, 983724*1024)
		}
	})
}

func BenchmarkDetectDaemonRole(b *testing.B) {
	args := []string{"singctl", "-c", "/etc/singctl/singctl.yaml", "web", "start", "-l", ":8090"}
	b.ReportAllocs()
	for b.Loop() {
		if DetectDaemonRole(args) != RoleDaemonOrWeb {
			b.Fatal("unexpected role")
		}
	}
}
