// 文件职责：验证 execx 有界命令执行器的超时终止、孙进程占管道防挂起（WaitDelay）、洁净 LC_ALL=C 环境与 Runner 契约。
package execx_test

import (
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/common/execx"
)

func TestRunner_RunAndCombinedOutput_TableDriven(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test helper requires unix")
	}

	r := execx.Active(nil)
	tests := []struct {
		name       string
		timeout    time.Duration
		bin        string
		args       []string
		wantSubstr string
		wantErr    bool
	}{
		{
			name:       "normal stdout+stderr capture with forced LC_ALL=C",
			timeout:    2 * time.Second,
			bin:        "/bin/sh",
			args:       []string{"-c", `printf "%s" "$LC_ALL"; echo "-err" >&2`},
			wantSubstr: "C-err",
		},
		{
			name:    "empty command name rejected",
			timeout: time.Second,
			bin:     "   ",
			wantErr: true,
		},
		{
			name:    "non-zero exit returns error",
			timeout: time.Second,
			bin:     "/bin/sh",
			args:    []string{"-c", "echo fail >&2; exit 7"},
			wantErr: true,
		},
		{
			name:    "timeout kills hung command with grandchild holding pipe (WaitDelay)",
			timeout: 150 * time.Millisecond,
			bin:     "/bin/sh",
			args:    []string{"-c", "(sleep 10 &) ; sleep 10"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LC_ALL", "zh_CN.UTF-8")
			start := time.Now()
			out, err := r.CombinedOutput(t.Context(), tc.timeout, tc.bin, tc.args...)
			elapsed := time.Since(start)

			if (err != nil) != tc.wantErr {
				t.Fatalf("CombinedOutput err=%v, wantErr=%v (out=%q)", err, tc.wantErr, string(out))
			}
			if tc.wantSubstr != "" && !strings.Contains(string(out), tc.wantSubstr) {
				t.Fatalf("output %q missing %q", string(out), tc.wantSubstr)
			}
			if tc.timeout == 150*time.Millisecond && elapsed > 2*time.Second {
				t.Fatalf("WaitDelay failed to bound hung grandchild pipe: took %v", elapsed)
			}
		})
	}
}

func TestOutput_RunIO_CleanEnv_And_Concurrency(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test helper requires unix")
	}

	if err := execx.Run(t.Context(), time.Second, "/bin/sh", "-c", "exit 0"); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	out, err := execx.Output(nil, 0, "/bin/sh", "-c", `printf "ok:%s" "$LC_ALL"`)
	if err != nil || string(out) != "ok:C" {
		t.Fatalf("Output = (%q, %v), want (\"ok:C\", nil)", string(out), err)
	}

	// Verify CleanEnv strips requested keys, deduplicates overrides, and drops empty KEY=
	t.Setenv("TEST_STRIP_ME", "secret")
	t.Setenv("TEST_OVERRIDE", "old")
	env := execx.CleanEnv([]string{"TEST_STRIP_ME"}, "TEST_OVERRIDE=new", "TEST_EMPTY_DROP=")
	var sawOverride, sawStrip bool
	for _, kv := range env {
		if kv == "TEST_STRIP_ME=secret" {
			sawStrip = true
		}
		if kv == "TEST_OVERRIDE=new" {
			sawOverride = true
		}
	}
	if sawStrip || !sawOverride {
		t.Fatalf("CleanEnv unexpected result: sawStrip=%v sawOverride=%v", sawStrip, sawOverride)
	}

	// RunIO with custom env and captured file stdout
	outFile, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()
	if err := execx.RunIO(t.Context(), time.Second, execx.CleanEnv(nil, "CUSTOM_VAR=hello"), nil, outFile, nil, "/bin/sh", "-c", `printf "%s" "$CUSTOM_VAR"`); err != nil {
		t.Fatalf("RunIO failed: %v", err)
	}
	raw, _ := os.ReadFile(outFile.Name())
	if string(raw) != "hello" {
		t.Fatalf("RunIO stdout = %q, want hello", string(raw))
	}

	// Cancelled parent context fails fast
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := execx.DefaultRunner.Run(execx.DefaultRunner{}, ctx, 5*time.Second, "/bin/sh", "-c", "sleep 5"); err == nil {
		t.Fatal("expected error on pre-cancelled context")
	}

	// Concurrent safety under -race
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, _ = execx.CombinedOutput(t.Context(), time.Second, "/bin/sh", "-c", "printf ping")
		})
	}
	wg.Wait()
}
