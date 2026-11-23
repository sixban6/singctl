// 文件职责：全面测试 tailscaled OOM 免疫状态探测与 -1000 幂等保护（覆盖正常、未保护、已保护、缺失、权限与非 Linux 边界）。
package safecommit_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"singctl/internal/safecommit"
)

func makeFakeProcEntry(t *testing.T, procRoot, pid, comm, oomAdj string, adjPerm os.FileMode) string {
	t.Helper()
	pidDir := filepath.Join(procRoot, pid)
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", pidDir, err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte(comm+"\n"), 0644); err != nil {
		t.Fatalf("write comm: %v", err)
	}
	adjPath := filepath.Join(pidDir, "oom_score_adj")
	if oomAdj != "" {
		if adjPerm == 0 {
			adjPerm = 0644
		}
		if err := os.WriteFile(adjPath, []byte(oomAdj), adjPerm); err != nil {
			t.Fatalf("write oom_score_adj: %v", err)
		}
	}
	return adjPath
}

func TestInspectTailscaledOOM_Table(t *testing.T) {
	t.Run("non_linux_empty_procRoot_returns_not_found", func(t *testing.T) {
		if runtime.GOOS == "linux" {
			t.Skip("non-linux guard test")
		}
		st := safecommit.InspectTailscaledOOM("")
		if st.Found || st.Protected {
			t.Fatalf("expected Found=false on %s with empty procRoot, got %+v", runtime.GOOS, st)
		}
	})

	t.Run("missing_procRoot_returns_not_found", func(t *testing.T) {
		st := safecommit.InspectTailscaledOOM(filepath.Join(t.TempDir(), "nonexistent"))
		if st.Found || st.Protected {
			t.Fatalf("expected Found=false for missing procRoot, got %+v", st)
		}
	})

	cases := []struct {
		name          string
		setup         func(t *testing.T, root string)
		wantFound     bool
		wantPID       int
		wantScore     int
		wantProtected bool
	}{
		{
			name: "no_tailscaled_among_other_procs",
			setup: func(t *testing.T, root string) {
				makeFakeProcEntry(t, root, "1", "procd", "0", 0644)
				makeFakeProcEntry(t, root, "42", "sing-box", "0", 0644)
				_ = os.WriteFile(filepath.Join(root, "meminfo"), []byte("MemTotal: 524288 kB\n"), 0644)
			},
			wantFound: false,
		},
		{
			name: "tailscaled_unprotected_default_zero",
			setup: func(t *testing.T, root string) {
				makeFakeProcEntry(t, root, "100", "dnsmasq", "0", 0644)
				makeFakeProcEntry(t, root, "512", "tailscaled", "0\n", 0644)
			},
			wantFound:     true,
			wantPID:       512,
			wantScore:     0,
			wantProtected: false,
		},
		{
			name: "tailscaled_protected_minus_1000",
			setup: func(t *testing.T, root string) {
				makeFakeProcEntry(t, root, "777", "tailscaled", "-1000\n", 0644)
			},
			wantFound:     true,
			wantPID:       777,
			wantScore:     -1000,
			wantProtected: true,
		},
		{
			name: "tailscaled_positive_oom_score_unprotected",
			setup: func(t *testing.T, root string) {
				makeFakeProcEntry(t, root, "888", "tailscaled", "300", 0644)
			},
			wantFound:     true,
			wantPID:       888,
			wantScore:     300,
			wantProtected: false,
		},
		{
			name: "tailscaled_missing_oom_score_adj",
			setup: func(t *testing.T, root string) {
				makeFakeProcEntry(t, root, "999", "tailscaled", "", 0644)
			},
			wantFound:     true,
			wantPID:       999,
			wantScore:     0,
			wantProtected: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.setup(t, root)
			got := safecommit.InspectTailscaledOOM(root)
			if got.Found != tc.wantFound || got.PID != tc.wantPID || got.ScoreAdj != tc.wantScore || got.Protected != tc.wantProtected {
				t.Fatalf("InspectTailscaledOOM = %+v, want Found=%v PID=%d ScoreAdj=%d Protected=%v",
					got, tc.wantFound, tc.wantPID, tc.wantScore, tc.wantProtected)
			}
			if got.Message == "" {
				t.Fatalf("expected non-empty descriptive Message, got %+v", got)
			}
			if strings.Contains(got.Message, "-1000") || strings.Contains(got.Message, "oom_score_adj") {
				t.Fatalf("expected concise user-facing OOM Message without -1000/oom_score_adj details, got %q", got.Message)
			}
		})
	}
}

func TestProtectTailscaledOOM(t *testing.T) {
	t.Run("writes_minus_1000_when_unprotected", func(t *testing.T) {
		root := t.TempDir()
		adjPath := makeFakeProcEntry(t, root, "404", "tailscaled", "0\n", 0644)

		st, err := safecommit.ProtectTailscaledOOM(root)
		if err != nil {
			t.Fatalf("ProtectTailscaledOOM unexpected error: %v", err)
		}
		if !st.Found || !st.Protected || st.PID != 404 || st.ScoreAdj != -1000 {
			t.Fatalf("unexpected protected status: %+v", st)
		}
		raw, err := os.ReadFile(adjPath)
		if err != nil {
			t.Fatalf("read adjPath: %v", err)
		}
		if strings.TrimSpace(string(raw)) != "-1000" {
			t.Fatalf("expected -1000 written to oom_score_adj, got %q", string(raw))
		}
	})

	t.Run("idempotent_when_already_protected", func(t *testing.T) {
		root := t.TempDir()
		// Even read-only file succeeds because ProtectTailscaledOOM must short-circuit without writing.
		makeFakeProcEntry(t, root, "405", "tailscaled", "-1000\n", 0444)

		st, err := safecommit.ProtectTailscaledOOM(root)
		if err != nil {
			t.Fatalf("expected idempotent success when already -1000, got err=%v", err)
		}
		if !st.Found || !st.Protected || st.ScoreAdj != -1000 {
			t.Fatalf("unexpected status: %+v", st)
		}
	})

	t.Run("returns_error_when_not_found", func(t *testing.T) {
		root := t.TempDir()
		st, err := safecommit.ProtectTailscaledOOM(root)
		if !errors.Is(err, safecommit.ErrTailscaledNotFound) {
			t.Fatalf("expected ErrTailscaledNotFound, got st=%+v err=%v", st, err)
		}
		if st.Found {
			t.Fatalf("expected Found=false, got %+v", st)
		}
	})

	t.Run("returns_error_when_adj_unwritable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses 0444 write check")
		}
		root := t.TempDir()
		makeFakeProcEntry(t, root, "406", "tailscaled", "100\n", 0444)
		_, err := safecommit.ProtectTailscaledOOM(root)
		if err == nil {
			t.Fatal("expected error writing read-only oom_score_adj")
		}
	})
}
