// 文件职责：覆盖守护进程名后缀归一化、同二进制子命令冲突识别与隔离路径 PID 0600 落盘测试。
package daemon_test

import (
	"os"
	"path/filepath"
	"testing"

	"singctl/internal/daemon"
)

func TestSanitizeProcName_CmdlineClassification_And_PidFile0600(t *testing.T) {
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
		if got := daemon.SanitizeProcName(tc.in); got != tc.want {
			t.Errorf("SanitizeProcName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	dmArgs := []string{"/usr/bin/singctl", "--config", "/etc/singctl/singctl.yaml", "dm", "start"}
	if !daemon.IsDaemonStartCmdline(dmArgs) || daemon.IsConflictingSingctlSubcommand(dmArgs) {
		t.Fatal("unexpected classification for dm start args")
	}
	if !daemon.IsDaemonStartCmdline([]string{"singctl", "-c", "/etc/singctl/singctl.yaml", "daemon", "start"}) {
		t.Fatal("expected daemon start args to match")
	}

	webArgs := []string{"/usr/bin/singctl", "--config", "/etc/singctl/singctl.yaml", "web", "start", "-l", ":8090"}
	if daemon.IsDaemonStartCmdline(webArgs) || !daemon.IsConflictingSingctlSubcommand(webArgs) {
		t.Fatal("expected web start args to be flagged as conflicting subcommand")
	}
	if !daemon.IsConflictingSingctlSubcommand([]string{"/usr/local/bin/singctl", "-c", "/etc/singctl/singctl.yaml", "sr", "ui"}) {
		t.Fatal("expected sr ui args to be flagged as conflicting subcommand")
	}

	pidPath := filepath.Join(t.TempDir(), daemon.PidFileName)
	if err := daemon.WritePidFileAt(pidPath); err != nil {
		t.Fatalf("WritePidFileAt failed: %v", err)
	}
	fi, err := os.Stat(pidPath)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected pid file perm 0600, got %v err=%v", fi, err)
	}
	pid, err := daemon.ReadDaemonPidAt(pidPath)
	if err != nil || pid != os.Getpid() {
		t.Fatalf("ReadDaemonPidAt = (%d, %v), want (%d, nil)", pid, err, os.Getpid())
	}
}
