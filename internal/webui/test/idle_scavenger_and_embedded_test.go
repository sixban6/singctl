// 文件职责：验证 WebUI 3 分钟冷态闲置物理内存归还（IdleScavenger）、共享 config.Store 注入及合体模式后台命令兼容。
package webui_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/webui"
)

func TestIdleScavenger_ThreeMinuteColdIdleOneShotAndReArm(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var clockMu sync.Mutex
	curNow := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	advanceClock := func(d time.Duration) {
		clockMu.Lock()
		curNow = curNow.Add(d)
		clockMu.Unlock()
	}
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return curNow
	}

	var scavengeCount atomic.Int32
	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		SkipAdGuardProbeForTest: true,
		IdleThreshold:           3 * time.Minute,
		IdleCheckInterval:       15 * time.Millisecond,
		NowFunc:                 nowFn,
		ScavengeFunc: func() {
			scavengeCount.Add(1)
		},
	})

	// Initial request updates atomic.Int64 timestamp
	req1 := httptest.NewRequest(http.MethodGet, "/api/auth/check", nil)
	rec1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec1.Code)
	}
	ts1 := srv.LastRequestUnixNano()
	if ts1 != curNow.UnixNano() {
		t.Fatalf("expected LastRequestUnixNano=%d, got %d", curNow.UnixNano(), ts1)
	}

	// Before 3 minutes (2m59s): must NOT scavenge
	advanceClock(2*time.Minute + 59*time.Second)
	if srv.MaybeScavengeIdle() || scavengeCount.Load() != 0 {
		t.Fatalf("expected 0 scavenges at 2m59s idle, got %d", scavengeCount.Load())
	}

	// Reach >= 3 minutes idle: scavenges ONCE
	advanceClock(2 * time.Second) // 3m01s
	if !srv.MaybeScavengeIdle() || scavengeCount.Load() != 1 {
		t.Fatalf("expected exactly 1 scavenge at 3m01s idle, got %d", scavengeCount.Load())
	}

	// Continuous silence (multiple checks at +5m, +30m, +2h): ZERO duplicate GC wakeups!
	for _, step := range []time.Duration{5 * time.Minute, 30 * time.Minute, 2 * time.Hour} {
		advanceClock(step)
		if srv.MaybeScavengeIdle() {
			t.Fatalf("expected 0 duplicate scavenge during continuous silence (+%s)", step)
		}
	}
	if scavengeCount.Load() != 1 {
		t.Fatalf("expected scavengeCount to remain 1 during prolonged silence, got %d", scavengeCount.Load())
	}

	// New HTTP request arrives -> re-arms active epoch and updates timestamp
	advanceClock(10 * time.Second)
	req2 := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)
	if srv.LastRequestUnixNano() != nowFn().UnixNano() {
		t.Fatal("expected LastRequestUnixNano updated on second request")
	}

	// 1 minute after new request: must NOT scavenge
	advanceClock(1 * time.Minute)
	if srv.MaybeScavengeIdle() || scavengeCount.Load() != 1 {
		t.Fatal("expected no scavenge 1m after fresh request")
	}

	// 3 minutes after second request: scavenges once again (count == 2)
	advanceClock(2 * time.Minute)
	if !srv.MaybeScavengeIdle() || scavengeCount.Load() != 2 {
		t.Fatalf("expected second scavenge after re-armed 3m idle, got count=%d", scavengeCount.Load())
	}
}

func TestIdleScavenger_ServeContextIntegrationAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600); err != nil {
		t.Fatal(err)
	}

	readyCh := make(chan string, 1)
	scavengedCh := make(chan struct{}, 4)
	var totalScavenges atomic.Int32

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		Listen:                  "127.0.0.1:0",
		SkipAdGuardProbeForTest: true,
		IdleThreshold:           35 * time.Millisecond,
		IdleCheckInterval:       10 * time.Millisecond,
		OnReady: func(addr string) {
			readyCh <- addr
		},
		ScavengeFunc: func() {
			totalScavenges.Add(1)
			select {
			case scavengedCh <- struct{}{}:
			default:
			}
		},
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	doneErr := make(chan error, 1)
	go func() {
		doneErr <- srv.ServeContext(ctx)
	}()

	var addr string
	select {
	case addr = <-readyCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for ServeContext OnReady")
	}

	// Concurrent burst of HTTP requests under -race
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get("http://" + addr + "/api/auth/check")
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	// Wait for idle scavenger to fire once after 35ms silence
	select {
	case <-scavengedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for background IdleScavenger in ServeContext")
	}

	// Stay completely idle for 60ms more (6 check intervals): count must remain 1!
	time.Sleep(60 * time.Millisecond)
	if got := totalScavenges.Load(); got != 1 {
		t.Fatalf("expected exactly 1 scavenge while continuously idle, got %d", got)
	}

	cancel()
	select {
	case err := <-doneErr:
		if err != nil {
			t.Fatalf("ServeContext shutdown error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeContext hung on shutdown")
	}
}

func TestWebUIServer_SharedConfigStoreInjection(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 42\n  down: 300\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sharedStore := config.NewStore(cfgPath)

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		ConfigStore:             sharedStore,
		SkipAdGuardProbeForTest: true,
	})
	if srv.ConfigStore() != sharedStore {
		t.Fatalf("expected Server.ConfigStore() to reuse injected *config.Store (%p != %p)", srv.ConfigStore(), sharedStore)
	}
	if got := srv.ReadConfigOrEmpty().Hy2.Up; got != 42 {
		t.Fatalf("expected Hy2.Up=42 from shared store, got %d", got)
	}
}

func TestWebBackground_EmbeddedModeIdempotentStartStatusAndRestart(t *testing.T) {
	tmpDir := t.TempDir()
	prevStateOverride := webui.WebStatePathOverride
	webui.WebStatePathOverride = filepath.Join(tmpDir, "nonexistent-standalone-web.pid")
	defer func() { webui.WebStatePathOverride = prevStateOverride }()

	var restartedCfg string
	var restartCalls atomic.Int32
	deps := webui.BackgroundDeps{
		EmbeddedStatus: func() (webui.WebState, bool) {
			return webui.WebState{
				Pid:        4321,
				Listen:     ":8090",
				ConfigPath: "/etc/singctl/singctl.yaml",
				Embedded:   true,
			}, true
		},
		RestartDaemon: func(configPath string) error {
			restartCalls.Add(1)
			restartedCfg = configPath
			return nil
		},
	}

	st, running := webui.WebStatusWithDeps(deps)
	if !running || !st.Embedded || st.Pid != 4321 || st.Listen != ":8090" {
		t.Fatalf("expected embedded WebStatus running=true pid=4321, got running=%v st=%+v", running, st)
	}

	// StartBackgroundWithDeps must return nil idempotently without spawning child or creating standalone pid file
	for range 2 {
		if err := webui.StartBackgroundWithDeps(webui.Options{Listen: ":8090"}, deps); err != nil {
			t.Fatalf("expected idempotent nil from StartBackgroundWithDeps when embedded, got %v", err)
		}
	}
	if _, err := os.Stat(webui.WebStatePathOverride); !os.IsNotExist(err) {
		t.Fatal("expected no standalone web.pid created when already embedded in daemon")
	}

	// RestartWebWithDeps must delegate to RestartDaemon smoothly
	if err := webui.RestartWebWithDeps("/custom/singctl.yaml", deps); err != nil {
		t.Fatalf("RestartWebWithDeps failed: %v", err)
	}
	if restartCalls.Load() != 1 || restartedCfg != "/custom/singctl.yaml" {
		t.Fatalf("expected RestartDaemon called once with /custom/singctl.yaml, got calls=%d cfg=%q", restartCalls.Load(), restartedCfg)
	}

	// TrimWebLog caps oversized web.log <= 256 KiB with 0600 and preserves tail
	webLog := filepath.Join(tmpDir, "singctl-web.log")
	oversized := append(bytes.Repeat([]byte("2026/11/22 [INFO] webui access line\n"), 9000), []byte("TAIL_KEEP_OK\n")...)
	if err := os.WriteFile(webLog, oversized, 0644); err != nil {
		t.Fatal(err)
	}
	trimmed, err := webui.TrimWebLog(webLog, webui.MaxLowMemWebLogBytes)
	if err != nil || !trimmed {
		t.Fatalf("expected TrimWebLog (true, nil), got (%v, %v)", trimmed, err)
	}
	fi, err := os.Stat(webLog)
	if err != nil || fi.Size() > webui.MaxLowMemWebLogBytes || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected trimmed web.log <= 256 KiB and 0600, got size=%d mode=%o err=%v", fi.Size(), fi.Mode().Perm(), err)
	}
	after, _ := os.ReadFile(webLog)
	if !strings.Contains(string(after), "TAIL_KEEP_OK") {
		t.Fatal("expected latest tail line preserved after TrimWebLog")
	}
}
