package heal

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseAptSimulateSecurityUpdates(t *testing.T) {
	simOutput := `NOTE: This is only a simulation!
Reading package lists...
Building dependency tree...
Inst htop [3.2.2-1] (3.2.2-2 Debian:12.8/stable [amd64])
Inst libssl3 [3.0.11-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
Inst openssh-server [1:9.2p1-2+deb12u3] (1:9.2p1-2+deb12u4 Ubuntu:22.04/jammy-security [amd64])
Inst vim-common [2:9.0.1378-2] (2:9.0.1499-1 Debian:12.8/stable [all])
Inst ca-certificates [20230311] (20240203 CustomMirror:stable [all])
Conf libssl3 (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
`
	got := ParseAptSimulateSecurityUpdates(simOutput)
	want := []string{"ca-certificates", "libssl3", "openssh-server"}
	if !slices.Equal(got, want) {
		t.Fatalf("ParseAptSimulateSecurityUpdates = %v, want %v", got, want)
	}
}

func TestHasDeletedSharedLibInMaps(t *testing.T) {
	cleanMaps := `55f1a2000000-55f1a2450000 r-xp 00000000 08:01 262149 /usr/bin/caddy
7f8912000000-7f8912320000 r-xp 00020000 08:01 131099 /usr/lib/x86_64-linux-gnu/libssl.so.3
7f8911000000-7f8911004000 rw-s 00000000 00:01 999999 /tmp/caddy-shm (deleted)
`
	if HasDeletedSharedLibInMaps(cleanMaps) {
		t.Fatal("expected cleanMaps (only non-.so /tmp deleted file) to be false")
	}

	staleMaps := cleanMaps + "7f8913000000-7f8913190000 r-xp 00018000 08:01 131200 /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)\n"
	if !HasDeletedSharedLibInMaps(staleMaps) {
		t.Fatal("expected staleMaps with deleted libcrypto.so.3 to return true")
	}
}

func TestCompareKernelVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.1.0-9-amd64", "6.1.0-10-amd64", -1},
		{"6.1.0-27-amd64", "6.1.0-44-amd64", -1},
		{"6.1.0-44-amd64", "6.1.0-44-amd64", 0},
		{"6.8.0-51-generic", "5.15.0-125-generic", 1},
	}
	for _, tc := range cases {
		if got := CompareKernelVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareKernelVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestValidateScheduleInjectionDefense(t *testing.T) {
	if err := ValidateSchedule("*-*-* 04:00:00"); err != nil {
		t.Fatalf("expected standard OnCalendar to be valid, got %v", err)
	}
	if err := ValidateSchedule("Sun *-*-* 03:30:00"); err != nil {
		t.Fatalf("expected weekly OnCalendar to be valid, got %v", err)
	}
	if err := ValidateSchedule("*-*-* 04:00:00\nExecStart=/bin/evil"); err == nil {
		t.Fatal("expected newline injection in schedule to be rejected")
	}
	if err := ValidateSchedule("$(reboot)"); err == nil {
		t.Fatal("expected shell metacharacters in schedule to be rejected")
	}
}

func TestStatePersistence0600AndHistoryCap(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")

	p := HealPolicy{AutoHealEnabled: true, Schedule: "*-*-* 04:00:00", AutoReboot: true}
	if err := SavePolicy(cfgPath, p); err != nil {
		t.Fatalf("SavePolicy failed: %v", err)
	}

	statePath := ResolveStateFilePath(cfgPath)
	fi, err := os.Stat(statePath)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected security_heal.json perm 0600, got %v (err=%v)", fi.Mode().Perm(), err)
	}

	for i := range 35 {
		if err := RecordExecution(cfgPath, HealHistoryItem{
			Trigger: "timer",
			Success: true,
			Summary: fmt.Sprintf("run-%d", i),
		}, nil); err != nil {
			t.Fatalf("RecordExecution #%d failed: %v", i, err)
		}
	}

	loaded := loadPersistedState(statePath)
	if len(loaded.History) != 30 {
		t.Fatalf("expected history capped at 30 items, got %d", len(loaded.History))
	}
	if loaded.History[0].Summary != "run-34" {
		t.Fatalf("expected newest entry first (run-34), got %q", loaded.History[0].Summary)
	}
}
