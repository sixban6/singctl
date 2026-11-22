// 文件职责：覆盖服务端服务动作编排、Caddy 热重载回退、配置预检拒绝与重载失败 0600 自动回滚边界单测。
package serverweb_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/common/execx"
	"singctl/internal/serverweb"
)

type recordedCmdCall struct {
	kind string
	name string
	args []string
}

type fakeServiceCmdRunner struct {
	mu          sync.Mutex
	calls       []recordedCmdCall
	runErrFn    func(callIdx int, name string, args []string) error
	outputErrFn func(callIdx int, name string, args []string) ([]byte, error)
}

func (f *fakeServiceCmdRunner) Run(_ context.Context, _ time.Duration, name string, args ...string) error {
	f.mu.Lock()
	idx := len(f.calls)
	f.calls = append(f.calls, recordedCmdCall{
		kind: "run",
		name: name,
		args: append([]string(nil), args...),
	})
	fn := f.runErrFn
	f.mu.Unlock()
	if fn != nil {
		return fn(idx, name, args)
	}
	return nil
}

func (f *fakeServiceCmdRunner) CombinedOutput(_ context.Context, _ time.Duration, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	idx := len(f.calls)
	f.calls = append(f.calls, recordedCmdCall{
		kind: "output",
		name: name,
		args: append([]string(nil), args...),
	})
	fn := f.outputErrFn
	f.mu.Unlock()
	if fn != nil {
		return fn(idx, name, args)
	}
	return nil, nil
}

func (f *fakeServiceCmdRunner) snapshotCalls() []recordedCmdCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCmdCall(nil), f.calls...)
}

func newTestServerWithRunner(t *testing.T, runner execx.Runner, cfgPaths map[string]string, sbBin string) (*serverweb.Server, string) {
	t.Helper()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  substore_domain: "sub.example.com"
`), 0600); err != nil {
		t.Fatal(err)
	}
	srv := serverweb.New(serverweb.Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		AuditFilePath: filepath.Join(tmpDir, ".audit.json"),
		BanFilePath:   filepath.Join(tmpDir, ".bans.json"),
		Username:      "opsadmin",
		Password:      "TestPassword123",
	})
	t.Cleanup(srv.Limiter().Close)
	srv.SniffTracker().EnableSystemProbe = false
	srv.SetDeps(serverweb.Deps{
		CmdRunner:          runner,
		ServiceConfigPaths: cfgPaths,
		SingBoxBin:         sbBin,
	})
	return srv, tmpDir
}

func doAuthedServiceJSON(srv *serverweb.Server, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.SetBasicAuth("opsadmin", "TestPassword123")
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:41000"
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	return rec
}

func TestServerWebExec_TableDrivenBoundaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}

	t.Run("normal_runner_handleAction_and_caddy_reload_fallback", func(t *testing.T) {
		out, err := execx.CombinedOutput(t.Context(), 2*time.Second, "/bin/sh", "-c", "printf 'srv-ok'")
		if err != nil || string(out) != "srv-ok" {
			t.Fatalf("execx.CombinedOutput = (%q, %v), want (%q, nil)", string(out), err, "srv-ok")
		}

		fake := &fakeServiceCmdRunner{
			runErrFn: func(_ int, name string, args []string) error {
				if name == "caddy" && len(args) > 0 && args[0] == "reload" {
					return errors.New("admin endpoint unavailable")
				}
				return nil
			},
		}
		srv, _ := newTestServerWithRunner(t, fake, nil, "")

		rec := doAuthedServiceJSON(srv, http.MethodPost, "/api/server/action", `{"action":"restart-singbox"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("handleAction restart-singbox status = %d, body = %s", rec.Code, rec.Body.String())
		}

		rec2 := doAuthedServiceJSON(srv, http.MethodPost, "/api/server/service/action", `{"service":"caddy","action":"reload"}`)
		if rec2.Code != http.StatusOK {
			t.Fatalf("handleServiceAction caddy reload fallback status = %d, body = %s", rec2.Code, rec2.Body.String())
		}

		calls := fake.snapshotCalls()
		if len(calls) != 3 {
			t.Fatalf("expected 3 runner calls (restart sing-box, caddy reload, systemctl reload caddy), got %d: %+v", len(calls), calls)
		}
		if calls[2].name != "systemctl" || strings.Join(calls[2].args, " ") != "reload caddy" {
			t.Fatalf("expected fallback call systemctl reload caddy, got %+v", calls[2])
		}
	})

	t.Run("nil_ctx_empty_name_and_bad_requests", func(t *testing.T) {
		r := execx.DefaultRunner{}
		//nolint:staticcheck // intentionally verify nil context fallback
		if err := r.Run(nil, 0, "/bin/sh", "-c", "true"); err != nil {
			t.Fatalf("DefaultRunner nil ctx Run failed: %v", err)
		}
		if err := execx.Run(t.Context(), 0, "   "); err == nil {
			t.Fatalf("expected error for empty binary name")
		}

		fake := &fakeServiceCmdRunner{}
		srv, _ := newTestServerWithRunner(t, fake, nil, "")

		rec1 := doAuthedServiceJSON(srv, http.MethodPost, "/api/server/action", `{broken`)
		if rec1.Code != http.StatusBadRequest {
			t.Fatalf("invalid json status = %d, want 400", rec1.Code)
		}

		rec2 := doAuthedServiceJSON(srv, http.MethodPost, "/api/server/service/action", `{"service":"unknown","action":"restart"}`)
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("unknown service status = %d, want 400", rec2.Code)
		}
		if got := len(fake.snapshotCalls()); got != 0 {
			t.Fatalf("expected 0 runner calls on invalid inputs, got %d", got)
		}
	})

	t.Run("timeout_kills_hanging_process", func(t *testing.T) {
		start := time.Now()
		err := execx.Run(t.Context(), 80*time.Millisecond, "/bin/sh", "-c", "sleep 2")
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("expected timeout error from hanging execx.Run, got nil")
		}
		if elapsed > 600*time.Millisecond {
			t.Fatalf("execx.Run hung for %v (want < 600ms)", elapsed)
		}

		start2 := time.Now()
		_, err2 := execx.CombinedOutput(t.Context(), 80*time.Millisecond, "/bin/sh", "-c", "sleep 2")
		elapsed2 := time.Since(start2)
		if err2 == nil {
			t.Fatalf("expected timeout error from hanging execx.CombinedOutput, got nil")
		}
		if elapsed2 > 600*time.Millisecond {
			t.Fatalf("execx.CombinedOutput hung for %v (want < 600ms)", elapsed2)
		}
	})

	t.Run("update_service_config_precheck_rejects_and_reload_timeout_rolls_back", func(t *testing.T) {
		oldCfg := `{"log":{"level":"info"},"outbounds":[{"tag":"orig"}]}`
		newCfg := `{"log":{"level":"warn"},"outbounds":[{"tag":"new"}]}`

		// Case 1: Pre-check failure leaves target config file untouched
		fakePrecheckFail := &fakeServiceCmdRunner{
			outputErrFn: func(_ int, _ string, _ []string) ([]byte, error) {
				return []byte("invalid outbound syntax"), errors.New("exit status 1")
			},
		}
		srv1, dir1 := newTestServerWithRunner(t, fakePrecheckFail, nil, "")
		sbPath1 := filepath.Join(dir1, "singbox.json")
		if err := os.WriteFile(sbPath1, []byte(oldCfg), 0600); err != nil {
			t.Fatal(err)
		}
		srv1.SetDeps(serverweb.Deps{
			CmdRunner:          fakePrecheckFail,
			ServiceConfigPaths: map[string]string{"singbox": sbPath1},
			SingBoxBin:         "/usr/local/bin/fake-sing-box",
		})

		rec1 := doAuthedServiceJSON(srv1, http.MethodPut, "/api/server/service/config",
			`{"service":"singbox","content":`+`"`+strings.ReplaceAll(newCfg, `"`, `\"`)+`"}`)
		if rec1.Code != http.StatusBadRequest {
			t.Fatalf("precheck failure status = %d, want 400: %s", rec1.Code, rec1.Body.String())
		}
		got1, _ := os.ReadFile(sbPath1)
		if string(got1) != oldCfg {
			t.Fatalf("config modified on precheck failure: got %q, want %q", string(got1), oldCfg)
		}

		// Case 2: Pre-check passes, initial restart fails/times out -> automatic 0600 rollback + rollback restart
		var runCount int
		fakeReloadFail := &fakeServiceCmdRunner{
			runErrFn: func(_ int, _ string, _ []string) error {
				runCount++
				if runCount == 1 {
					return context.DeadlineExceeded
				}
				return nil
			},
		}
		srv2, dir2 := newTestServerWithRunner(t, fakeReloadFail, nil, "")
		sbPath2 := filepath.Join(dir2, "singbox.json")
		if err := os.WriteFile(sbPath2, []byte(oldCfg), 0600); err != nil {
			t.Fatal(err)
		}
		srv2.SetDeps(serverweb.Deps{
			CmdRunner:          fakeReloadFail,
			ServiceConfigPaths: map[string]string{"singbox": sbPath2},
			SingBoxBin:         "/usr/local/bin/fake-sing-box",
		})

		rec2 := doAuthedServiceJSON(srv2, http.MethodPut, "/api/server/service/config",
			`{"service":"singbox","content":`+`"`+strings.ReplaceAll(newCfg, `"`, `\"`)+`"}`)
		if rec2.Code != http.StatusInternalServerError {
			t.Fatalf("reload failure status = %d, want 500: %s", rec2.Code, rec2.Body.String())
		}
		got2, _ := os.ReadFile(sbPath2)
		if string(got2) != oldCfg {
			t.Fatalf("expected rollback to restore oldCfg, got %q", string(got2))
		}
		fi, err := os.Stat(sbPath2)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("expected rolled-back config mode 0600, got %v (err=%v)", fi.Mode().Perm(), err)
		}
		if runCount != 2 {
			t.Fatalf("expected 2 systemctl restart calls (failed reload + rollback restart), got %d", runCount)
		}
	})

	t.Run("concurrent_runner_and_handlers_race_safe", func(t *testing.T) {
		fake := &fakeServiceCmdRunner{}
		srv, _ := newTestServerWithRunner(t, fake, nil, "")

		var wg sync.WaitGroup
		for range 12 {
			wg.Go(func() {
				rec := doAuthedServiceJSON(srv, http.MethodPost, "/api/server/action", `{"action":"restart-caddy"}`)
				if rec.Code != http.StatusOK {
					t.Errorf("concurrent handleAction status = %d: %s", rec.Code, rec.Body.String())
				}
			})
		}
		wg.Wait()
	})
}
