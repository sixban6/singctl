// 文件职责：覆盖服务端 QUIC/UDP Socket 缓冲状态探测、防断连异步重载 Caddy、预设校验与只读容器报错单测。
package serverweb_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/common/socktune"
	"singctl/internal/serverweb"
)

type fakeServerSockKernel struct {
	mu           sync.Mutex
	files        map[string][]byte
	baseDir      string
	readOnlyProc bool
}

func newFakeServerSockKernel(t *testing.T, memKB string) *fakeServerSockKernel {
	t.Helper()
	return &fakeServerSockKernel{
		baseDir: t.TempDir(),
		files: map[string][]byte{
			"/proc/meminfo":                                     []byte("MemTotal:       " + memKB + " kB\n"),
			"/proc/sys/net/core/rmem_max":                       []byte("212992\n"),
			"/proc/sys/net/core/wmem_max":                       []byte("212992\n"),
			"/proc/sys/net/core/rmem_default":                   []byte("212992\n"),
			"/proc/sys/net/core/wmem_default":                   []byte("212992\n"),
			"/proc/sys/net/core/default_qdisc":                  []byte("fq_codel\n"),
			"/proc/sys/net/ipv4/tcp_congestion_control":         []byte("cubic\n"),
			"/proc/sys/net/ipv4/tcp_available_congestion_control": []byte("reno cubic bbr\n"),
			"/proc/net/snmp": []byte("Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\nUdp: 90000 0 0 80000 3200 12\n"),
		},
	}
}

func (k *fakeServerSockKernel) env() *socktune.Env {
	quicFile := filepath.Join(k.baseDir, "99-quic-buffer.conf")
	conflictFile := filepath.Join(k.baseDir, "99-singctl-bbr.conf")
	return &socktune.Env{
		GOOS:                "linux",
		QuicSysctlFile:      quicFile,
		ConflictSysctlFiles: []string{conflictFile},
		ReadFile: func(path string) ([]byte, error) {
			k.mu.Lock()
			defer k.mu.Unlock()
			if b, ok := k.files[path]; ok {
				return slices.Clone(b), nil
			}
			return os.ReadFile(path)
		},
		WriteFile: func(path string, data []byte, perm os.FileMode) error {
			return os.WriteFile(path, data, perm)
		},
		WriteProc: func(path string, data []byte) error {
			k.mu.Lock()
			defer k.mu.Unlock()
			if k.readOnlyProc {
				return &fs.PathError{Op: "open", Path: path, Err: errors.New("read-only file system")}
			}
			k.files[path] = slices.Clone(data)
			return nil
		},
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			k.mu.Lock()
			defer k.mu.Unlock()
			if k.readOnlyProc {
				return []byte("sysctl: setting key: Read-only file system"), errors.New("exit status 255")
			}
			if name == "sysctl" && len(args) >= 2 && args[0] == "-p" {
				raw, err := os.ReadFile(args[1])
				if err != nil {
					return nil, err
				}
				for line := range strings.SplitSeq(string(raw), "\n") {
					tline := strings.TrimSpace(line)
					if tline == "" || strings.HasPrefix(tline, "#") {
						continue
					}
					if key, val, ok := strings.Cut(tline, "="); ok {
						procPath := "/proc/sys/" + strings.ReplaceAll(strings.TrimSpace(key), ".", "/")
						k.files[procPath] = []byte(strings.TrimSpace(val) + "\n")
					}
				}
			}
			return nil, nil
		},
	}
}

func TestServerWebSocketTune_GetApplyAsyncCaddyAndErrors(t *testing.T) {
	kernel := newFakeServerSockKernel(t, "1048576")
	caddyRestarted := make(chan struct{}, 4)

	runner := &fakeServiceCmdRunner{
		runErrFn: func(_ int, name string, args []string) error {
			if name == "systemctl" && len(args) >= 2 && args[0] == "restart" && args[1] == "caddy" {
				select {
				case caddyRestarted <- struct{}{}:
				default:
				}
			}
			return nil
		},
	}

	srv, _ := newTestServerWithRunner(t, runner, nil, "")
	srv.SeedStatusCaches(
		map[string]string{"caddy": "v2.9.0", "singbox": "v1.12.0", "subhub": "v1.14.0", "wireproxy": ""},
		[]serverweb.CertHealth{},
	)
	delay := 15 * time.Millisecond
	srv.SetDeps(serverweb.Deps{
		StatusProber: func() map[string]serverweb.ServiceProbeSnapshot {
			return map[string]serverweb.ServiceProbeSnapshot{
				"caddy":       {Running: true, PID: "100"},
				"sing-box":    {Running: true, PID: "200"},
				"singctl-sub": {Running: true, PID: "300"},
			}
		},
		SockTuneEnv:                  kernel.env(),
		CaddyAsyncRestartDelayForTest: &delay,
	})

	// 1. Unauthenticated access must fail 401.
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/server/socket-tune", nil)
	unauthReq.RemoteAddr = "127.0.0.1:41000"
	unauthRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated GET /api/server/socket-tune, got %d", unauthRec.Code)
	}

	// 2. GET /api/server/socket-tune returns 200 and flags Caddy default bottleneck.
	recGet := doAuthedServiceJSON(srv, http.MethodGet, "/api/server/socket-tune", "")
	if recGet.Code != http.StatusOK {
		t.Fatalf("GET /api/server/socket-tune status=%d body=%s", recGet.Code, recGet.Body.String())
	}
	var st socktune.Status
	if err := json.Unmarshal(recGet.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if !st.Supported || !st.DefaultBottleneck || st.RecommendedRmemDefault != 8388608 || st.UDPRcvbufErrors != 3200 {
		t.Fatalf("unexpected server socket-tune status: %+v", st)
	}

	// 3. GET /api/server/status includes system.socketTune without running commands.
	recOverview := doAuthedServiceJSON(srv, http.MethodGet, "/api/server/status", "")
	if recOverview.Code != http.StatusOK {
		t.Fatalf("GET /api/server/status status=%d body=%s", recOverview.Code, recOverview.Body.String())
	}
	var statusPayload struct {
		System struct {
			SocketTune *socktune.Status `json:"socketTune"`
		} `json:"system"`
	}
	if err := json.Unmarshal(recOverview.Body.Bytes(), &statusPayload); err != nil {
		t.Fatalf("decode server status: %v", err)
	}
	if statusPayload.System.SocketTune == nil || !statusPayload.System.SocketTune.DefaultBottleneck {
		t.Fatalf("expected system.socketTune with DefaultBottleneck=true, got %+v", statusPayload.System.SocketTune)
	}

	// 4. POST /api/server/socket-tune with defaultPreset=8m and restartCaddy=true flushes 200 then restarts caddy asynchronously.
	recApply := doAuthedServiceJSON(srv, http.MethodPost, "/api/server/socket-tune", `{"defaultPreset":"8m","restartCaddy":true}`)
	if recApply.Code != http.StatusOK {
		t.Fatalf("POST /api/server/socket-tune status=%d body=%s", recApply.Code, recApply.Body.String())
	}
	var applyResp struct {
		OK                   bool            `json:"ok"`
		AsyncCaddyRestart    bool            `json:"asyncCaddyRestart"`
		DefaultBufferChanged bool            `json:"defaultBufferChanged"`
		Status               socktune.Status `json:"status"`
	}
	if err := json.Unmarshal(recApply.Body.Bytes(), &applyResp); err != nil {
		t.Fatalf("decode apply response: %v", err)
	}
	if !applyResp.OK || !applyResp.AsyncCaddyRestart || !applyResp.DefaultBufferChanged || applyResp.Status.RmemDefault != 8388608 || !applyResp.Status.Optimal {
		t.Fatalf("unexpected apply response: %+v", applyResp)
	}
	select {
	case <-caddyRestarted:
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for async caddy restart")
	}

	// 5. POST with restartCaddy=false switches to 4m without restarting Caddy.
	beforeCalls := len(runner.snapshotCalls())
	recNoRestart := doAuthedServiceJSON(srv, http.MethodPost, "/api/server/socket-tune", `{"defaultPreset":"4m","restartCaddy":false}`)
	if recNoRestart.Code != http.StatusOK {
		t.Fatalf("POST 4m no-restart status=%d body=%s", recNoRestart.Code, recNoRestart.Body.String())
	}
	var noRestartResp struct {
		AsyncCaddyRestart bool            `json:"asyncCaddyRestart"`
		Status            socktune.Status `json:"status"`
	}
	_ = json.Unmarshal(recNoRestart.Body.Bytes(), &noRestartResp)
	if noRestartResp.AsyncCaddyRestart || noRestartResp.Status.RmemDefault != 4194304 {
		t.Fatalf("unexpected no-restart response: %+v", noRestartResp)
	}
	time.Sleep(40 * time.Millisecond)
	if len(runner.snapshotCalls()) != beforeCalls {
		t.Fatalf("expected 0 caddy restart calls when restartCaddy=false")
	}

	// 6. Invalid preset -> 400 Bad Request.
	recBad := doAuthedServiceJSON(srv, http.MethodPost, "/api/server/socket-tune", `{"defaultPreset":"999m"}`)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid preset, got %d: %s", recBad.Code, recBad.Body.String())
	}

	// 7. Container read-only /proc -> 400 Bad Request with descriptive hint.
	kernel.mu.Lock()
	kernel.readOnlyProc = true
	kernel.mu.Unlock()
	recRO := doAuthedServiceJSON(srv, http.MethodPost, "/api/server/socket-tune", `{"defaultPreset":"8m"}`)
	if recRO.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for read-only container procfs, got %d: %s", recRO.Code, recRO.Body.String())
	}
}
