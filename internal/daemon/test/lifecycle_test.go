// 文件职责：覆盖守护进程三阶段前台生命周期启停、0600 日志句柄管理及 PID 锁失败逆序回滚测试。
package daemon_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"singctl/internal/config"
	"singctl/internal/daemon"
)

func TestDaemonForegroundLifecycle_StartCloseAndRollback(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "daemon.log")

	pidWritten := false
	pidRemoved := false

	d := daemon.NewDaemonWithOptions(&config.Config{}, daemon.DaemonOptions{
		Version:         "v1.0.0-test",
		Paths:           daemon.Paths{LogFile: logPath},
		SkipSignalSetup: true,
		PidWriter: func() error {
			pidWritten = true
			return nil
		},
		PidRemover: func() error {
			pidRemoved = true
			return nil
		},
	})

	lc := d.BuildForegroundLifecycle()
	if err := lc.Start(t.Context()); err != nil {
		t.Fatalf("lifecycle Start failed: %v", err)
	}
	if !pidWritten || !d.HasOpenLogFile() {
		t.Fatal("expected pidWriter invoked and log file opened")
	}

	fi, err := os.Stat(logPath)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected daemon log permission 0600, got %v err=%v", fi, err)
	}

	if err := lc.Close(); err != nil {
		t.Fatalf("lifecycle Close failed: %v", err)
	}
	if !pidRemoved || d.HasOpenLogFile() {
		t.Fatal("expected pidRemover invoked and log file closed on Close")
	}

	logPath2 := filepath.Join(tmpDir, "daemon-rollback.log")
	sentinel := errors.New("pid lock busy")
	d2 := daemon.NewDaemonWithOptions(&config.Config{}, daemon.DaemonOptions{
		Version:         "v1.0.0-test",
		Paths:           daemon.Paths{LogFile: logPath2},
		SkipSignalSetup: true,
		PidWriter:       func() error { return sentinel },
		PidRemover: func() error {
			t.Fatal("pidRemover should not be called when pidWriter itself failed")
			return nil
		},
	})
	if err := d2.BuildForegroundLifecycle().Start(t.Context()); !errors.Is(err, sentinel) {
		t.Fatalf("expected pid sentinel error, got %v", err)
	}
	if d2.HasOpenLogFile() {
		t.Fatal("expected daemon-log resource to be rolled back on pid lock failure")
	}
}
