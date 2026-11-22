// 文件职责：覆盖 daemon 状态存储隔离注入、0600 原子落盘、ClashAPI DNS 探活与关键日志过滤单元测试。
package daemon_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"singctl/internal/daemon"
)

func TestStateStore_IsolatedPaths_Atomic0600_And_Race(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	storeA := daemon.NewStateStore(daemon.Paths{
		PidFile:   filepath.Join(dirA, "a.pid"),
		StateFile: filepath.Join(dirA, "a.state"),
		LogFile:   filepath.Join(dirA, "a.log"),
	})
	storeB := daemon.NewStateStore(daemon.Paths{
		PidFile:   filepath.Join(dirB, "b.pid"),
		StateFile: filepath.Join(dirB, "b.state"),
		LogFile:   filepath.Join(dirB, "b.log"),
	})

	storeA.Update(func(snap *daemon.DaemonRuntimeSnapshot) {
		snap.DaemonVersion = "vA"
		snap.Total = 3
	})
	storeB.Update(func(snap *daemon.DaemonRuntimeSnapshot) {
		snap.DaemonVersion = "vB"
		snap.Total = 7
	})

	if gotA := storeA.Load(); gotA.DaemonVersion != "vA" || gotA.Total != 3 {
		t.Fatalf("storeA isolated snapshot mismatch: %+v", gotA)
	}
	if gotB := storeB.Load(); gotB.DaemonVersion != "vB" || gotB.Total != 7 {
		t.Fatalf("storeB isolated snapshot mismatch: %+v", gotB)
	}

	fi, err := os.Stat(filepath.Join(dirA, "a.state"))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 perm on state file, got %v err=%v", fi, err)
	}

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			storeA.AppendEvent(daemon.WatchdogEventRecord{
				Action:  "TEST",
				Healthy: true,
				Summary: string(rune('A' + i)),
			})
			_ = storeA.Load()
		})
	}
	wg.Wait()
}

func TestIsKeyWatchdogLogLine_And_ClashDNSHealth(t *testing.T) {
	if !daemon.IsKeyWatchdogLogLine("[2026-11-22 12:00:00] [WATCHDOG] action=RESTART") ||
		!daemon.IsKeyWatchdogLogLine("2026/11/22 [INFO] [GroupFailover] switched") ||
		!daemon.IsKeyWatchdogLogLine("Daemon started successfully") ||
		daemon.IsKeyWatchdogLogLine("2026/11/22 [INFO] routine heartbeat debug") {
		t.Fatal("unexpected IsKeyWatchdogLogLine classification")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dns-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/dns/query" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Status": 0,
				"Answer": []map[string]any{
					{"Name": "cn.bing.com", "Type": 1, "TTL": 60, "data": "198.51.100.77"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if ok, _, _ := daemon.CheckDNSHealthAgainstEndpoints([]string{srv.URL}, "wrong"); ok {
		t.Fatal("expected auth failure on wrong secret")
	}
	ok, lat, detail := daemon.CheckDNSHealthAgainstEndpoints([]string{srv.URL}, "dns-secret")
	if !ok || lat <= 0 || detail == "" {
		t.Fatalf("CheckDNSHealthAgainstEndpoints = (%v, %d, %q)", ok, lat, detail)
	}
}
