package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"singctl/internal/config"
)

func TestDaemonForegroundLifecycle_StartAndClose(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "daemon.log")

	pidWritten := false
	pidRemoved := false

	d := NewDaemonWithMeta(&config.Config{}, "", "v1.0.0-test")
	d.logPathOverride = logPath
	d.skipSignalSetup = true
	d.pidWriter = func() error {
		pidWritten = true
		return nil
	}
	d.pidRemover = func() error {
		pidRemoved = true
		return nil
	}

	lc := d.buildForegroundLifecycle()
	if err := lc.Start(t.Context()); err != nil {
		t.Fatalf("lifecycle Start failed: %v", err)
	}

	if !pidWritten {
		t.Fatal("expected pidWriter to be invoked")
	}
	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat daemon log failed: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected daemon log permission 0600, got %04o", perm)
	}

	if err := lc.Close(); err != nil {
		t.Fatalf("lifecycle Close failed: %v", err)
	}
	if !pidRemoved {
		t.Fatal("expected pidRemover to be invoked on Close")
	}

	d.logMu.Lock()
	openFile := d.logFile
	d.logMu.Unlock()
	if openFile != nil {
		t.Fatal("expected daemon log file handle to be closed and cleared")
	}
}

func TestDaemonForegroundLifecycle_PidErrorRollsBackLogFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "daemon.log")
	sentinel := errors.New("pid lock busy")

	d := NewDaemonWithMeta(&config.Config{}, "", "v1.0.0-test")
	d.logPathOverride = logPath
	d.skipSignalSetup = true
	d.pidWriter = func() error {
		return sentinel
	}
	d.pidRemover = func() error {
		t.Fatal("pidRemover should not be called when pidWriter itself failed")
		return nil
	}

	lc := d.buildForegroundLifecycle()
	err := lc.Start(t.Context())
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected pid sentinel error, got %v", err)
	}

	d.logMu.Lock()
	openFile := d.logFile
	d.logMu.Unlock()
	if openFile != nil {
		t.Fatal("expected daemon-log resource to be rolled back on pid lock failure")
	}
}
