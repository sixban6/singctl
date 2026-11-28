// 文件职责：覆盖独立 WebUI 触发单进程合体动作时完整输出 exit 0 + restarting:true 并优雅释放监听端口与 PID 文件的端到端与边界测试。
package webui_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/daemon"
	"singctl/internal/webui"
)

func writeFakeSingctlScript(t *testing.T, exitCode int, stdoutLine string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell script test")
	}
	scriptPath := filepath.Join(t.TempDir(), "fake-singctl.sh")
	body := "#!/bin/sh\necho '" + stdoutLine + "'\nexit " + string(rune('0'+exitCode)) + "\n"
	if err := os.WriteFile(scriptPath, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return scriptPath
}

func parseNDJSONEvents(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var events []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("invalid NDJSON line %q: %v", line, err)
		}
		events = append(events, ev)
	}
	return events
}

func TestStandaloneWebUI_ActionHandoffFlushesStreamThenReleasesPortAndPid(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell script test")
	}
	for _, actionName := range []string{"sb-start", "sb-restart", "dm-start", "dm-restart"} {
		t.Run(actionName, func(t *testing.T) {
			tmpDir := t.TempDir()
			cfgPath := filepath.Join(tmpDir, "singctl.yaml")
			if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600); err != nil {
				t.Fatal(err)
			}

			stateFile := filepath.Join(tmpDir, "singctl-web.pid")
			prevState := webui.WebStatePathOverride
			webui.WebStatePathOverride = stateFile
			defer func() { webui.WebStatePathOverride = prevState }()

			if err := webui.WriteWebStateAtomic(webui.WebState{
				Pid:        os.Getpid(),
				Listen:     "127.0.0.1:0",
				ConfigPath: cfgPath,
			}); err != nil {
				t.Fatal(err)
			}

			fakeBin := writeFakeSingctlScript(t, 0, "Watchdog daemon started")
			readyCh := make(chan string, 1)

			srv := webui.New(webui.Options{
				ConfigPath:              cfgPath,
				Listen:                  "127.0.0.1:0",
				ExecutablePath:          fakeBin,
				SkipAdGuardProbeForTest: true,
				EmbeddedInDaemon:        false,
				UnifiedHandoffCheck:     func() bool { return true },
				HandoffShutdownDelay:    50 * time.Millisecond,
				OnReady: func(addr string) {
					readyCh <- addr
				},
			})

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			serveErrCh := make(chan error, 1)
			go func() {
				serveErrCh <- srv.ServeContext(ctx)
			}()

			var addr string
			select {
			case addr = <-readyCh:
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for standalone WebUI OnReady")
			}

			// Execute real HTTP POST /api/action and read complete NDJSON stream with zero network error.
			reqBody := `{"name":"` + actionName + `"}`
			resp, err := http.Post("http://"+addr+"/api/action", "application/json", strings.NewReader(reqBody))
			if err != nil {
				t.Fatalf("POST /api/action failed: %v", err)
			}
			var raw bytes.Buffer
			if _, err := raw.ReadFrom(resp.Body); err != nil {
				_ = resp.Body.Close()
				t.Fatalf("stream interrupted (network error): %v", err)
			}
			_ = resp.Body.Close()

			events := parseNDJSONEvents(t, raw.Bytes())
			if len(events) < 2 {
				t.Fatalf("expected at least start + exit NDJSON events, got %v", events)
			}
			last := events[len(events)-1]
			if last["t"] != "exit" || last["code"] != float64(0) || last["restarting"] != true {
				t.Fatalf("expected final exit event {t:exit, code:0, restarting:true}, got %+v", last)
			}

			// Standalone server must gracefully exit within 1.5s, freeing port and removing own web.pid.
			select {
			case err := <-serveErrCh:
				if err != nil {
					t.Fatalf("expected nil from ServeContext after graceful handoff shutdown, got %v", err)
				}
			case <-time.After(1500 * time.Millisecond):
				t.Fatal("timed out waiting for standalone WebUI graceful shutdown after handoff")
			}

			if _, err := os.Stat(stateFile); !os.IsNotExist(err) {
				t.Fatalf("expected standalone web.pid removed on graceful handoff exit, stat err=%v", err)
			}

			// Verify the port is immediately bindable by the incoming embedded daemon WebUI.
			rebindLn, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatalf("expected port %s freed immediately after handoff, re-listen failed: %v", addr, err)
			}
			_ = rebindLn.Close()
		})
	}
}

func TestWebUI_ActionHandoffConditions_TableDriven(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell script test")
	}

	okBin := writeFakeSingctlScript(t, 0, "ok")
	failBin := writeFakeSingctlScript(t, 1, "boom")

	tests := []struct {
		name            string
		action          string
		bin             string
		embedded        bool
		unifiedActive   bool
		wantCode        float64
		wantRestarting  bool
		wantShutdownReq bool
	}{
		{
			name:            "standalone_sb_start_unified_active_hands_off",
			action:          "sb-start",
			bin:             okBin,
			embedded:        false,
			unifiedActive:   true,
			wantCode:        0,
			wantRestarting:  true,
			wantShutdownReq: true,
		},
		{
			name:            "standalone_sb_stop_never_hands_off",
			action:          "sb-stop",
			bin:             okBin,
			embedded:        false,
			unifiedActive:   true,
			wantCode:        0,
			wantRestarting:  false,
			wantShutdownReq: false,
		},
		{
			name:            "standalone_failed_sb_start_never_hands_off",
			action:          "sb-start",
			bin:             failBin,
			embedded:        false,
			unifiedActive:   true,
			wantCode:        1,
			wantRestarting:  false,
			wantShutdownReq: false,
		},
		{
			name:            "embedded_daemon_webui_never_self_hands_off",
			action:          "sb-start",
			bin:             okBin,
			embedded:        true,
			unifiedActive:   true,
			wantCode:        0,
			wantRestarting:  false,
			wantShutdownReq: false,
		},
		{
			name:            "standalone_high_ram_non_unified_never_hands_off",
			action:          "dm-start",
			bin:             okBin,
			embedded:        false,
			unifiedActive:   false,
			wantCode:        0,
			wantRestarting:  false,
			wantShutdownReq: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "singctl.yaml")
			_ = os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600)

			srv := webui.New(webui.Options{
				ConfigPath:              cfgPath,
				ExecutablePath:          tc.bin,
				SkipAdGuardProbeForTest: true,
				EmbeddedInDaemon:        tc.embedded,
				UnifiedHandoffCheck:     func() bool { return tc.unifiedActive },
				HandoffShutdownDelay:    15 * time.Millisecond,
			})

			req := httptest.NewRequest(http.MethodPost, "/api/action", strings.NewReader(`{"name":"`+tc.action+`"}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			events := parseNDJSONEvents(t, rec.Body.Bytes())
			last := events[len(events)-1]
			if last["t"] != "exit" || last["code"] != tc.wantCode || last["restarting"] != tc.wantRestarting {
				t.Fatalf("unexpected exit event %+v (want code=%v restarting=%v)", last, tc.wantCode, tc.wantRestarting)
			}

			time.Sleep(50 * time.Millisecond)
			if got := srv.ShutdownRequested(); got != tc.wantShutdownReq {
				t.Fatalf("ShutdownRequested() = %v, want %v", got, tc.wantShutdownReq)
			}
		})
	}
}

func TestBuildCleanSubprocessEnv_StripsDeferWebHandoffAndRequestShutdownRaceSafe(t *testing.T) {
	t.Setenv(daemon.EnvDeferWebHandoff, "1")
	t.Setenv(daemon.EnvDaemonized, "1")
	env := webui.BuildCleanSubprocessEnv("TERM=dumb")
	for _, kv := range env {
		if strings.HasPrefix(kv, daemon.EnvDeferWebHandoff+"=") {
			t.Fatalf("expected BuildCleanSubprocessEnv to strip %s, found %q", daemon.EnvDeferWebHandoff, kv)
		}
		if strings.HasPrefix(kv, daemon.EnvDaemonized+"=") {
			t.Fatalf("expected BuildCleanSubprocessEnv to strip %s, found %q", daemon.EnvDaemonized, kv)
		}
	}

	srv := webui.New(webui.Options{SkipAdGuardProbeForTest: true})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv.RequestShutdown()
			_ = srv.ShutdownRequested()
		}()
	}
	wg.Wait()
	if !srv.ShutdownRequested() {
		t.Fatal("expected ShutdownRequested() == true after RequestShutdown()")
	}
}
