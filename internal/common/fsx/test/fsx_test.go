// 文件职责：验证 fsx 随机临时文件 0600 原子写入、CommitVerified 事务回滚、SafeReplace、异步快照及定长日志截断保护。
package fsx_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/common/fsx"
)

func TestWriteAtomic_ConcurrentSafetyAndPermissions(t *testing.T) {
	if err := fsx.WriteAtomic("", []byte("x"), 0600); err == nil {
		t.Fatal("expected error for empty target path")
	}

	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "nested", "secret.json")

	var wg sync.WaitGroup
	payloads := make([][]byte, 16)
	for i := range 16 {
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 512)
		p := payloads[i]
		wg.Go(func() {
			if err := fsx.WriteAtomic0600(secretPath, p); err != nil {
				t.Errorf("concurrent WriteAtomic0600 failed: %v", err)
			}
		})
	}
	wg.Wait()

	got, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read final file: %v", err)
	}
	matched := false
	for _, p := range payloads {
		if bytes.Equal(got, p) {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("final file content corrupted under concurrent writes")
	}
	st, err := os.Stat(secretPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 mode, got %v (err=%v)", st, err)
	}
}

func TestCommitVerified_PreVerifyAndPostApplyAutoRollback(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	// 1. Initial commit succeeds with 0600 permissions
	err := fsx.CommitVerified(fsx.CommitOptions{
		TargetPath: cfgPath,
		Data:       []byte(`{"version":1}`),
		Verify: func(staged string) error {
			st, sErr := os.Stat(staged)
			if sErr != nil || st.Mode().Perm() != 0600 {
				t.Fatalf("staged file must be 0600 before Verify, got %v (%v)", st, sErr)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("initial CommitVerified failed: %v", err)
	}

	// 2. Verify failure MUST abort before touching live file
	err = fsx.CommitVerified(fsx.CommitOptions{
		TargetPath: cfgPath,
		Data:       []byte(`{broken-json`),
		Verify: func(string) error {
			return errors.New("sing-box check failed")
		},
	})
	if err == nil {
		t.Fatal("expected Verify failure to return error")
	}
	gotAfterVerifyFail, _ := os.ReadFile(cfgPath)
	if string(gotAfterVerifyFail) != `{"version":1}` {
		t.Fatalf("Verify failure polluted live config: %q", string(gotAfterVerifyFail))
	}

	// 3. PostApply failure MUST automatically rollback to previous config!
	err = fsx.CommitVerified(fsx.CommitOptions{
		TargetPath: cfgPath,
		Data:       []byte(`{"version":2}`),
		KeepBackup: 2,
		Verify:     func(string) error { return nil },
		PostApply: func() error {
			// At this moment live file has version 2, simulate reload/probe failure
			liveNow, _ := os.ReadFile(cfgPath)
			if string(liveNow) != `{"version":2}` {
				t.Errorf("expected live file to hold candidate during PostApply, got %q", string(liveNow))
			}
			return errors.New("outbound health probe failed")
		},
	})
	if err == nil {
		t.Fatal("expected PostApply failure to return error")
	}
	gotAfterRollback, _ := os.ReadFile(cfgPath)
	if string(gotAfterRollback) != `{"version":1}` {
		t.Fatalf("PostApply failure did NOT auto-rollback live config: got %q", string(gotAfterRollback))
	}

	// 4. Successful upgrade to v3 + BackupAndPrune rotation
	for v := range 4 {
		if err := fsx.CommitVerified(fsx.CommitOptions{
			TargetPath: cfgPath,
			Data:       []byte(`{"version":` + string(rune('3'+v)) + `}`),
			KeepBackup: 2,
		}); err != nil {
			t.Fatalf("commit v%d failed: %v", v, err)
		}
	}
	if _, err := fsx.BackupAndPrune(cfgPath, 2); err != nil {
		t.Fatalf("BackupAndPrune failed: %v", err)
	}
}

func TestSafeReplace_CopyDir_FindExecutable_And_AsyncSnapshotWriter(t *testing.T) {
	dir := t.TempDir()
	targetBin := filepath.Join(dir, "bin", "singctl")
	srcV1 := filepath.Join(dir, "v1")
	srcV2 := filepath.Join(dir, "v2")
	_ = os.WriteFile(srcV1, []byte("v1"), 0644)
	_ = os.WriteFile(srcV2, []byte("v2"), 0644)

	if err := fsx.InstallOrReplace(srcV1, targetBin); err != nil {
		t.Fatal(err)
	}
	if err := fsx.SafeReplace(targetBin, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected SafeReplace with missing source to fail")
	}
	if err := fsx.InstallOrReplace(srcV2, targetBin); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(targetBin); string(b) != "v2" {
		t.Fatalf("expected v2, got %q", string(b))
	}

	nested := filepath.Join(dir, "ext", "a", "b")
	_ = os.MkdirAll(nested, 0755)
	_ = os.WriteFile(filepath.Join(nested, "singctl-linux"), []byte("exe"), 0644)
	if found, err := fsx.FindExecutable(filepath.Join(dir, "ext"), "singctl"); err != nil || !strings.HasSuffix(found, "singctl-linux") {
		t.Fatalf("FindExecutable = (%q, %v)", found, err)
	}

	cfgSrc := filepath.Join(dir, "csrc")
	cfgDst := filepath.Join(dir, "cdst")
	_ = os.MkdirAll(cfgSrc, 0755)
	_ = os.WriteFile(filepath.Join(cfgSrc, "skip.go"), []byte("package x"), 0644)
	_ = os.WriteFile(filepath.Join(cfgSrc, "a.yaml"), []byte("a: 1\n"), 0644)
	if err := fsx.CopyDir(cfgSrc, cfgDst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfgDst, "skip.go")); !os.IsNotExist(err) {
		t.Fatal("CopyDir must skip .go files")
	}

	// AsyncSnapshotWriter coalescing & TrySingleFlight
	snapPath := filepath.Join(dir, "snap.json")
	w := fsx.NewAsyncSnapshotWriter(snapPath, nil)
	w.SetWriteFunc(fsx.WriteAtomic0600)
	for seq := uint64(1); seq <= 5; seq++ {
		w.Submit([]byte(`{"seq":`+string(rune('0'+seq))+`}`), seq, 50*time.Millisecond)
	}
	w.Close(time.Second)
	snapRaw, err := os.ReadFile(snapPath)
	if err != nil || string(snapRaw) != `{"seq":5}` {
		t.Fatalf("AsyncSnapshotWriter final = (%q, %v), want seq 5", string(snapRaw), err)
	}

	var flag atomic.Bool
	done := make(chan struct{}, 1)
	fsx.TrySingleFlight(&flag, time.Second, func(context.Context) {
		done <- struct{}{}
	})
	<-done
}

func TestCapFileTail_And_OpenCappedAppendFile(t *testing.T) {
	dir := t.TempDir()

	// 1. Edge cases: empty path, missing file, directory target, non-positive maxBytes
	if err := fsx.CapFileTail("", 1024); err == nil {
		t.Fatal("expected error on empty path")
	}
	if _, err := fsx.OpenCappedAppendFile("   ", 1024, 0600); err == nil {
		t.Fatal("expected error on empty path in OpenCappedAppendFile")
	}
	missingLog := filepath.Join(dir, "nonexistent.log")
	if err := fsx.CapFileTail(missingLog, 256*1024); err != nil {
		t.Fatalf("missing log file should be a clean no-op, got %v", err)
	}
	if err := fsx.CapFileTail(dir, 1024); err == nil {
		t.Fatal("expected error when CapFileTail targets a directory")
	}

	// 2. Under-limit and exact-limit files remain untouched; non-positive maxBytes is no-op
	logPath := filepath.Join(dir, "logs", "daemon.log")
	f, err := fsx.OpenCappedAppendFile(logPath, 256, 0)
	if err != nil {
		t.Fatalf("OpenCappedAppendFile new file failed: %v", err)
	}
	if _, err := f.WriteString("boot-line-1\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	st, err := os.Stat(logPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected default 0600 permission on capped log, got %v (%v)", st, err)
	}
	if err := fsx.CapFileTail(logPath, 0); err != nil {
		t.Fatalf("maxBytes=0 should be no-op, got %v", err)
	}
	if err := fsx.CapFileTail(logPath, -1); err != nil {
		t.Fatalf("maxBytes=-1 should be no-op, got %v", err)
	}
	if err := fsx.CapFileTail(logPath, 256); err != nil {
		t.Fatalf("under-limit CapFileTail failed: %v", err)
	}
	if got, _ := os.ReadFile(logPath); string(got) != "boot-line-1\n" {
		t.Fatalf("under-limit file should remain intact, got %q", string(got))
	}

	// 3. Oversized file (> 256 KiB) is atomically truncated to latest half (~128 KiB), preserving tail & permissions
	const maxLogBytes = 256 * 1024
	var buf bytes.Buffer
	for i := range 10000 {
		fmt.Fprintf(&buf, "line-%05d-payload-padding-for-tmpfs-protection\n", i)
	}
	fullPayload := buf.Bytes()
	if len(fullPayload) <= maxLogBytes {
		t.Fatalf("test setup payload too small: %d", len(fullPayload))
	}
	if err := os.WriteFile(logPath, fullPayload, 0600); err != nil {
		t.Fatal(err)
	}

	if err := fsx.CapFileTail(logPath, maxLogBytes); err != nil {
		t.Fatalf("CapFileTail oversized failed: %v", err)
	}
	capped, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(capped)) != maxLogBytes/2 {
		t.Fatalf("expected capped size = %d (half of maxBytes), got %d", maxLogBytes/2, len(capped))
	}
	if !bytes.HasSuffix(fullPayload, capped) {
		t.Fatal("capped content must match exact latest tail of original log")
	}
	if !strings.Contains(string(capped), "line-09999-payload") {
		t.Fatal("latest log line missing after truncation")
	}

	// Idempotency: calling CapFileTail again immediately is a no-op
	if err := fsx.CapFileTail(logPath, maxLogBytes); err != nil {
		t.Fatal(err)
	}
	cappedAgain, _ := os.ReadFile(logPath)
	if !bytes.Equal(capped, cappedAgain) {
		t.Fatal("second CapFileTail call was not idempotent")
	}

	// 4. OpenCappedAppendFile truncates oversized file first, then appends new entries cleanly
	if err := os.WriteFile(logPath, fullPayload, 0640); err != nil {
		t.Fatal(err)
	}
	appFile, err := fsx.OpenCappedAppendFile(logPath, maxLogBytes, 0640)
	if err != nil {
		t.Fatalf("OpenCappedAppendFile oversized failed: %v", err)
	}
	const marker = "TAIL_APPEND_AFTER_CAP\n"
	if _, err := appFile.WriteString(marker); err != nil {
		t.Fatal(err)
	}
	_ = appFile.Close()

	afterAppend, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(afterAppend)) != maxLogBytes/2+int64(len(marker)) {
		t.Fatalf("unexpected size after OpenCappedAppendFile write: %d", len(afterAppend))
	}
	if !strings.HasSuffix(string(afterAppend), marker) {
		t.Fatal("appended marker missing at end of file")
	}

	// 5. Concurrent CapFileTail calls must not corrupt file or leave temp files
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_ = fsx.CapFileTail(logPath, 4096)
		})
	}
	wg.Wait()
	entries, err := os.ReadDir(filepath.Dir(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected no leaked temp files in log dir, got %d entries", len(entries))
	}
}
