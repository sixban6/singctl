// 文件职责：测试 Tailscale 状态探测在守护进程未运行时的 0ms 快路径跳过与二进制版本号指纹缓存。
package tailscale_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/tailscale"
)

func TestInspectHostStatus_FastSkipsStoppedDaemonAndCachesVersion(t *testing.T) {
	binDir := t.TempDir()
	fakeTS := filepath.Join(binDir, "tailscale")
	verCountFile := filepath.Join(binDir, "ver.count")
	statusCountFile := filepath.Join(binDir, "status.count")

	writeScript := func(ver string) {
		script := "#!/bin/sh\n" +
			"if [ \"$1\" = \"version\" ]; then\n" +
			"  echo x >> \"" + verCountFile + "\"\n" +
			"  echo \"" + ver + "\"\n" +
			"  exit 0\n" +
			"fi\n" +
			"if [ \"$1\" = \"status\" ]; then\n" +
			"  echo x >> \"" + statusCountFile + "\"\n" +
			"  sleep 3\n" +
			"  exit 1\n" +
			"fi\n" +
			"exit 1\n"
		if err := os.WriteFile(fakeTS, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeScript("1.104.8")

	start := time.Now()
	for range 3 {
		st := tailscale.InspectHostStatus(t.Context(), tailscale.HostStatusOptions{
			BinPath: fakeTS,
			DaemonProcProbe: func() bool {
				return false
			},
		})
		if st["installed"] != true || st["running"] != false || st["version"] != "1.104.8" {
			t.Fatalf("unexpected InspectHostStatus when daemon stopped: %+v", st)
		}
	}
	elapsed := time.Since(start)
	if elapsed > 600*time.Millisecond {
		t.Fatalf("InspectHostStatus took %v when tailscaled is stopped (expected fast-path skip < 600ms)", elapsed)
	}
	if _, err := os.Stat(statusCountFile); !os.IsNotExist(err) {
		t.Fatal("expected 'tailscale status' NOT to be invoked when DaemonProcProbe returns false")
	}

	rawVerCalls, err := os.ReadFile(verCountFile)
	if err != nil {
		t.Fatalf("read version call counter: %v", err)
	}
	if calls := len(strings.Fields(string(rawVerCalls))); calls != 1 {
		t.Fatalf("expected tailscale version cached (1 exec across 3 calls), got %d execs", calls)
	}

	// Updating binary content & mtime invalidates version cache
	writeScript("1.104.9-new")
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(fakeTS, future, future)

	st2 := tailscale.InspectHostStatus(t.Context(), tailscale.HostStatusOptions{
		BinPath:         fakeTS,
		DaemonProcProbe: func() bool { return false },
	})
	if st2["version"] != "1.104.9-new" {
		t.Fatalf("expected updated version 1.104.9-new after binary change, got %+v", st2["version"])
	}
}
