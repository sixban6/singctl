package webui

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWebExec_TableDrivenBoundaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}

	t.Run("fast_output_and_custom_env", func(t *testing.T) {
		out, err := outputWebCmdTimeout(2*time.Second, "/bin/sh", "-c", "printf 'webui-ok'")
		if err != nil {
			t.Fatalf("outputWebCmdTimeout failed: %v", err)
		}
		if string(out) != "webui-ok" {
			t.Fatalf("got %q, want %q", string(out), "webui-ok")
		}

		marker := filepath.Join(t.TempDir(), "env.txt")
		err = runWebCmdTimeout(2*time.Second, []string{"SINGCTL_TEST_VAL=propagated"}, nil, nil,
			"/bin/sh", "-c", `printf '%s' "$SINGCTL_TEST_VAL" > "$1"`, "--", marker)
		if err != nil {
			t.Fatalf("runWebCmdTimeout failed: %v", err)
		}
		got, err := os.ReadFile(marker)
		if err != nil {
			t.Fatalf("read env marker: %v", err)
		}
		if string(got) != "propagated" {
			t.Fatalf("env value = %q, want %q", string(got), "propagated")
		}
	})

	t.Run("zero_negative_timeout_and_empty_name", func(t *testing.T) {
		out, err := outputWebCmdTimeout(0, "/bin/sh", "-c", "printf 'zero-ok'")
		if err != nil || string(out) != "zero-ok" {
			t.Fatalf("zero timeout fallback = (%q, %v), want (%q, nil)", string(out), err, "zero-ok")
		}
		if _, err := outputWebCmdTimeout(-time.Second, ""); err == nil {
			t.Fatalf("expected error for empty binary name")
		}
		if err := runWebCmdTimeout(0, nil, nil, nil, "   "); err == nil {
			t.Fatalf("expected error for blank binary name")
		}
		if err := runWebCmdTimeout(time.Second, nil, nil, nil, "/nonexistent-singctl-bin-xyz"); err == nil {
			t.Fatalf("expected error for missing binary")
		}
	})

	t.Run("discrete_arg_prevents_shell_injection", func(t *testing.T) {
		payload := "safe; echo PWNED"
		out, err := outputWebCmdTimeout(2*time.Second, "/bin/echo", payload)
		if err != nil {
			t.Fatalf("echo failed: %v", err)
		}
		if got := strings.TrimSpace(string(out)); got != payload {
			t.Fatalf("got %q, want literal %q", got, payload)
		}
	})

	t.Run("timeout_kills_hanging_process", func(t *testing.T) {
		start := time.Now()
		err := runWebCmdTimeout(80*time.Millisecond, nil, nil, nil, "/bin/sh", "-c", "sleep 2")
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("expected timeout error from hanging runWebCmdTimeout, got nil")
		}
		if elapsed > 600*time.Millisecond {
			t.Fatalf("runWebCmdTimeout hang exceeded budget: %v (want < 600ms)", elapsed)
		}

		start2 := time.Now()
		_, err2 := outputWebCmdTimeout(80*time.Millisecond, "/bin/sh", "-c", "sleep 2")
		elapsed2 := time.Since(start2)
		if err2 == nil {
			t.Fatalf("expected timeout error from hanging outputWebCmdTimeout, got nil")
		}
		if elapsed2 > 600*time.Millisecond {
			t.Fatalf("outputWebCmdTimeout hang exceeded budget: %v (want < 600ms)", elapsed2)
		}
	})

	t.Run("concurrent_invocations_race_safe", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 12 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				out, err := outputWebCmdTimeout(time.Second, "/bin/sh", "-c", "printf 'race-web'")
				if err != nil || string(out) != "race-web" {
					t.Errorf("concurrent outputWebCmdTimeout = (%q, %v)", string(out), err)
				}
			}()
		}
		wg.Wait()
	})
}
