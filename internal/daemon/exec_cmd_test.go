package daemon

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDaemonExec_TableDrivenBoundaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}

	t.Run("normal_output_and_stdio", func(t *testing.T) {
		out, err := outputCmdTimeout(t.Context(), 2*time.Second, "/bin/sh", "-c", "printf 'hello-daemon'")
		if err != nil {
			t.Fatalf("outputCmdTimeout failed: %v", err)
		}
		if string(out) != "hello-daemon" {
			t.Fatalf("got %q, want %q", string(out), "hello-daemon")
		}

		if err := runCmdTimeoutIO(t.Context(), 2*time.Second, nil, nil, nil, "/bin/sh", "-c", "true"); err != nil {
			t.Fatalf("runCmdTimeoutIO failed: %v", err)
		}
	})

	t.Run("nil_ctx_zero_timeout_and_empty_name", func(t *testing.T) {
		//nolint:staticcheck // intentionally verify nil context fallback
		out, err := combinedOutputCmdTimeout(nil, 0, "/bin/sh", "-c", "printf 'ok'")
		if err != nil || string(out) != "ok" {
			t.Fatalf("combinedOutputCmdTimeout nil ctx fallback = (%q, %v), want (%q, nil)", string(out), err, "ok")
		}
		if _, err := outputCmdTimeout(t.Context(), -time.Second, ""); err == nil {
			t.Fatalf("expected error for empty binary name")
		}
		if _, err := combinedOutputCmdTimeout(t.Context(), 0, ""); err == nil {
			t.Fatalf("expected error for empty binary name")
		}
		if err := runCmdTimeoutIO(t.Context(), 0, nil, nil, nil, "   "); err == nil {
			t.Fatalf("expected error for blank binary name")
		}
	})

	t.Run("discrete_arg_prevents_shell_injection", func(t *testing.T) {
		payload := "safe; echo PWNED"
		out, err := outputCmdTimeout(t.Context(), 2*time.Second, "/bin/echo", payload)
		if err != nil {
			t.Fatalf("echo failed: %v", err)
		}
		got := strings.TrimSpace(string(out))
		if got != payload {
			t.Fatalf("got %q, want literal %q", got, payload)
		}
	})

	t.Run("timeout_kills_hanging_process_and_subsync_cleans_tmp", func(t *testing.T) {
		start := time.Now()
		_, err := combinedOutputCmdTimeout(t.Context(), 80*time.Millisecond, "/bin/sh", "-c", "sleep 2")
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("expected timeout error from hanging command, got nil")
		}
		if elapsed > 600*time.Millisecond {
			t.Fatalf("command hang exceeded timeout budget: took %v (want < 600ms)", elapsed)
		}

		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "config.json")
		origContent := []byte(`{"outbounds":[{"tag":"orig"}]}`)
		if err := os.WriteFile(cfgPath, origContent, 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		fakeSB := filepath.Join(tmpDir, "fake-sing-box.sh")
		if err := os.WriteFile(fakeSB, []byte("#!/bin/sh\nsleep 2\n"), 0700); err != nil {
			t.Fatalf("write fake sing-box: %v", err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		d := &Daemon{
			ctx:                 ctx,
			subSyncCheckTimeout: 80 * time.Millisecond,
			subSyncBinOverride:  fakeSB,
		}
		subStart := time.Now()
		tmpOut, _, err := d.preValidateSubSyncConfig(cfgPath, `{"outbounds":[{"tag":"new"}]}`)
		subElapsed := time.Since(subStart)
		if err == nil || tmpOut != "" {
			t.Fatalf("expected subSync pre-validation timeout failure, got tmp=%q err=%v", tmpOut, err)
		}
		if subElapsed > 600*time.Millisecond {
			t.Fatalf("subSync pre-validation hung for %v (want < 600ms)", subElapsed)
		}
		if _, statErr := os.Stat(cfgPath + ".subsync.tmp"); !os.IsNotExist(statErr) {
			t.Fatalf("expected stale .subsync.tmp to be cleaned on failure")
		}
		gotOrig, _ := os.ReadFile(cfgPath)
		if string(gotOrig) != string(origContent) {
			t.Fatalf("expected target config.json untouched, got %q", string(gotOrig))
		}
	})

	t.Run("concurrent_execution_race_safe", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 12 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				out, err := outputCmdTimeout(t.Context(), time.Second, "/bin/sh", "-c", "printf 'race-ok'")
				if err != nil || string(out) != "race-ok" {
					t.Errorf("concurrent outputCmdTimeout = (%q, %v)", string(out), err)
				}
			}()
		}
		wg.Wait()
	})
}
