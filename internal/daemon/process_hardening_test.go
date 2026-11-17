package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizeProcName_LinuxSelfUpdateSuffixes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/usr/bin/singctl", "singctl"},
		{"/usr/bin/singctl (deleted)", "singctl"},
		{"/usr/local/bin/singctl.backup", "singctl"},
		{"/usr/local/bin/singctl.backup.backup", "singctl"},
		{"/usr/bin/singctl.backup (deleted)", "singctl"},
		{"/tmp/singctl.exe", "singctl"},
		{"/tmp/singctl.exe.backup", "singctl"},
		{"", "singctl"},
	}

	for _, tc := range cases {
		if got := sanitizeProcName(tc.in); got != tc.want {
			t.Errorf("sanitizeProcName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCmdlineClassification_PreventsKillingWebOrServerUI(t *testing.T) {
	dmArgs := []string{"/usr/bin/singctl", "--config", "/etc/singctl/singctl.yaml", "dm", "start"}
	if !isDaemonStartCmdline(dmArgs) {
		t.Fatalf("expected dm start args to be recognized as daemon start cmdline")
	}
	if isConflictingSingctlSubcommand(dmArgs) {
		t.Fatalf("expected dm start args not to be flagged as conflicting subcommand")
	}

	daemonFullArgs := []string{"singctl", "-c", "/etc/singctl/singctl.yaml", "daemon", "start"}
	if !isDaemonStartCmdline(daemonFullArgs) {
		t.Fatalf("expected daemon start args to be recognized as daemon start cmdline")
	}

	webArgs := []string{"/usr/bin/singctl", "--config", "/etc/singctl/singctl.yaml", "web", "start", "-l", ":8090"}
	if isDaemonStartCmdline(webArgs) {
		t.Fatalf("expected web start args NOT to match daemon start")
	}
	if !isConflictingSingctlSubcommand(webArgs) {
		t.Fatalf("expected web start args to be flagged as conflicting singctl subcommand")
	}

	srArgs := []string{"/usr/local/bin/singctl", "-c", "/etc/singctl/singctl.yaml", "sr", "ui"}
	if !isConflictingSingctlSubcommand(srArgs) {
		t.Fatalf("expected sr ui args to be flagged as conflicting singctl subcommand")
	}
}

func TestWritePidFile_Permissions0600(t *testing.T) {
	dir := t.TempDir()
	prev := PidFilePathOverride
	PidFilePathOverride = filepath.Join(dir, PidFileName)
	t.Cleanup(func() { PidFilePathOverride = prev })

	if err := WritePidFile(); err != nil {
		t.Fatalf("WritePidFile failed: %v", err)
	}
	fi, err := os.Stat(PidFilePathOverride)
	if err != nil {
		t.Fatalf("stat pid file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected pid file perm 0600, got %04o", perm)
	}
	pid, err := ReadDaemonPid()
	if err != nil || pid != os.Getpid() {
		t.Fatalf("ReadDaemonPid = (%d, %v), want (%d, nil)", pid, err, os.Getpid())
	}
}
