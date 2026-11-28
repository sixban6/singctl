package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/safecommit"
	"singctl/internal/webui"
	"singctl/internal/wifiopt"
)

func newTestWifiWebServer(t *testing.T, password string) (*webui.Server, *int, *bool) {
	t.Helper()
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	wifiFile := filepath.Join(tmp, "wireless")
	sysctlFile := filepath.Join(tmp, "sysctl.conf")
	rcLocalFile := filepath.Join(tmp, "rc.local")
	_ = os.WriteFile(wifiFile, []byte("config wifi-device 'MT7986_1_1'\n\toption channel '1'\n"), 0600)
	_ = os.WriteFile(sysctlFile, []byte("# sysctl\n"), 0600)
	_ = os.WriteFile(rcLocalFile, []byte("#!/bin/sh\nexit 0\n"), 0700)

	var mu sync.Mutex
	reloads := 0
	wirelessRollbackCalled := false
	rpsPath := "/sys/class/net/eth0/queues/rx-0/rps_cpus"
	files := map[string][]byte{
		"/proc/net/dev":                              []byte("  ra0: 100 1000 10 0 0 0 0 0 100 1000 0 0 0 0 0 0\n rax0: 100 2000 0 0 0 0 0 0 100 2000 0 0 0 0 0 0\n"),
		"/tmp/dhcp.leases":                           []byte("1795550000 02:aa:bb:cc:dd:ee 192.168.89.137 dev-mbp *\n"),
		"/proc/meminfo":                              []byte("MemTotal:         235520 kB\n"),
		"/proc/sys/net/netfilter/nf_conntrack_max":   []byte("16384\n"),
		"/proc/sys/net/netfilter/nf_conntrack_count": []byte("250\n"),
		rpsPath: []byte("1\n"),
	}

	uciWireless := `wireless.MT7986_1_1=wifi-device
wireless.MT7986_1_1.type='mtwifi'
wireless.MT7986_1_1.phy='ra0'
wireless.MT7986_1_1.band='2g'
wireless.MT7986_1_1.channel='4'
wireless.MT7986_1_1.htmode='HE40'
wireless.MT7986_1_1.txpower='100'
wireless.default_MT7986_1_1=wifi-iface
wireless.default_MT7986_1_1.device='MT7986_1_1'
wireless.default_MT7986_1_1.mode='ap'
wireless.default_MT7986_1_1.ssid='homewifi'
wireless.default_MT7986_1_1.encryption='sae-mixed'
wireless.default_MT7986_1_1.key='TopSecretWifiKey'
wireless.default_MT7986_1_1.network='lan'
wireless.MT7986_1_2=wifi-device
wireless.MT7986_1_2.type='mtwifi'
wireless.MT7986_1_2.phy='rax0'
wireless.MT7986_1_2.band='5g'
wireless.MT7986_1_2.channel='auto'
wireless.MT7986_1_2.htmode='HE160'
wireless.MT7986_1_2.txpower='100'
wireless.default_MT7986_1_2=wifi-iface
wireless.default_MT7986_1_2.device='MT7986_1_2'
wireless.default_MT7986_1_2.mode='ap'
wireless.default_MT7986_1_2.ssid='homewifi-5G'
wireless.default_MT7986_1_2.encryption='sae-mixed'
wireless.default_MT7986_1_2.network='lan'
`
	uciNetwork := "network.lan=interface\nnetwork.lan.device='br-lan'\n"
	iwAll := `ra0       ESSID: "homewifi"
          Mode: Master  Channel: 4 (2.427 GHz)
          Tx-Power: 23 dBm
          Bit Rate: 286.0 MBit/s
          Hardware: 14C3:7986 14C3:7986 [MediaTek MT7986]
rax0      ESSID: "homewifi-5G"
          Mode: Master  Channel: 52 (5.260 GHz)
          Tx-Power: 23 dBm
          Bit Rate: 4803.0 MBit/s
          Hardware: 14C3:7986 14C3:7986 [MediaTek MT7986]
`

	wifiSvc := wifiopt.NewService(wifiopt.Env{
		WirelessFile:  wifiFile,
		SysctlFile:    sysctlFile,
		RCLocalFile:   rcLocalFile,
		PollInterval:  time.Millisecond,
		VerifyTimeout: 20 * time.Millisecond,
		CPUCount:      2,
		Now:           func() time.Time { return time.Unix(1795552000, 0) },
		Sleep:         func(context.Context, time.Duration) error { return nil },
		LookPath:      func(name string) (string, error) { return "/usr/sbin/" + name, nil },
		ReadFile: func(p string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			if p == wifiFile || p == sysctlFile || p == rcLocalFile {
				return os.ReadFile(p)
			}
			if b, ok := files[p]; ok {
				return slices.Clone(b), nil
			}
			return nil, os.ErrNotExist
		},
		WriteFile0600: func(p string, d []byte) error {
			mu.Lock()
			defer mu.Unlock()
			if p == wifiFile || p == sysctlFile || p == rcLocalFile {
				return os.WriteFile(p, d, 0600)
			}
			files[p] = slices.Clone(d)
			return nil
		},
		Glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "rps_cpus") {
				return []string{rpsPath}, nil
			}
			return nil, nil
		},
		ReloadWifi: func(context.Context) error {
			mu.Lock()
			reloads++
			mu.Unlock()
			return nil
		},
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			switch name {
			case "uci":
				if len(args) >= 2 && args[0] == "show" && args[1] == "wireless" {
					return []byte(uciWireless), nil
				}
				if len(args) >= 2 && args[0] == "show" && args[1] == "network" {
					return []byte(uciNetwork), nil
				}
				return nil, nil
			case "iwinfo":
				if len(args) == 0 {
					return []byte(iwAll), nil
				}
				if len(args) == 2 && args[1] == "scan" {
					if args[0] == "ra0" {
						return []byte("Cell 01 - Address: AA:BB:CC:DD:EE:01\nESSID: \"HiddenNeighbor\"\nMode: Master  Channel: 11\nSignal: -52 dBm\n"), nil
					}
					return []byte("Cell 01 - Address: AA:BB:CC:DD:EE:02\nESSID: \"Hidden5G\"\nMode: Master  Channel: 36\nSignal: -55 dBm\n"), nil
				}
				return nil, nil
			case "brctl":
				return []byte("bridge name\tbridge id\t\tSTP enabled\tinterfaces\nbr-lan\t\t7fff.1\tno\t\teth0.1\n\t\t\t\t\t\t\tra0\n\t\t\t\t\t\t\trax0\n"), nil
			case "sysctl":
				if len(args) >= 2 && args[0] == "-w" && strings.HasPrefix(args[1], "net.netfilter.nf_conntrack_max=") {
					files["/proc/sys/net/netfilter/nf_conntrack_max"] = []byte(strings.TrimPrefix(args[1], "net.netfilter.nf_conntrack_max=") + "\n")
				}
				return nil, nil
			}
			return nil, nil
		},
	})

	srv := webui.New(webui.Options{
		ConfigPath:                cfgPath,
		Password:                  password,
		WifiOptServiceForTest:     wifiSvc,
		SafeCommitStateDir:        filepath.Join(tmp, "sc"),
		SafeCommitProcRoot:        t.TempDir(),
		SafeCommitSpawnWatcher:    func(string) (int, error) { return 7001, nil },
		SafeCommitKillWatcher:     func(int) error { return nil },
		SafeCommitBaselineForTest: func() (bool, bool) { return true, true },
		SafeCommitRollbackOps: &safecommit.RollbackOps{
			ReloadOpenWrtWireless: func(context.Context) error {
				wirelessRollbackCalled = true
				return nil
			},
		},
	})
	return srv, &reloads, &wirelessRollbackCalled
}

func TestWifiAPI_AuthGuardOverviewScanApplyAndChassis(t *testing.T) {
	t.Run("requires_auth_when_password_configured", func(t *testing.T) {
		srv, _, _ := newTestWifiWebServer(t, "secret-pass")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/wifi/overview", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		rec2 := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/api/wifi/retest", bytes.NewBufferString(`{}`)))
		if rec2.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on POST /api/wifi/retest, got %d", rec2.Code)
		}
	})

	t.Run("overview_scan_dryrun_apply_safecommit_and_chassis", func(t *testing.T) {
		srv, reloads, _ := newTestWifiWebServer(t, "")

		// 1. GET /api/wifi/overview
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/wifi/overview", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/wifi/overview status=%d body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "TopSecretWifiKey") {
			t.Fatal("overview leaked plaintext Wi-Fi password")
		}
		var ov wifiopt.Overview
		if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
			t.Fatalf("decode overview: %v", err)
		}
		if !ov.Supported || len(ov.Radios) != 2 {
			t.Fatalf("unexpected overview: %+v", ov)
		}

		// 2. POST /api/wifi/scan
		rec = httptest.NewRecorder()
		reqScan := httptest.NewRequest(http.MethodPost, "/api/wifi/scan", bytes.NewBufferString(`{}`))
		reqScan.Header.Set("Content-Type", "application/json")
		srv.Mux.ServeHTTP(rec, reqScan)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /api/wifi/scan status=%d body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "HiddenNeighbor") {
			t.Fatal("scan leaked neighbor SSID")
		}
		var scan wifiopt.ScanResult
		if err := json.Unmarshal(rec.Body.Bytes(), &scan); err != nil {
			t.Fatalf("decode scan: %v", err)
		}
		if scan.Recommended2GCh != 1 || scan.Recommended5GCh != 149 {
			t.Fatalf("unexpected scan recs: 2g=%d 5g=%d", scan.Recommended2GCh, scan.Recommended5GCh)
		}

		// 3. POST /api/wifi/apply dryRun=true must NOT reload or arm SafeCommit
		reqDry := httptest.NewRequest(http.MethodPost, "/api/wifi/apply", bytes.NewBufferString(`{"action":"auto_optimize","recommended2gChannel":1,"recommended5gChannel":149,"dryRun":true}`))
		reqDry.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, reqDry)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /api/wifi/apply dryRun status=%d body=%s", rec.Code, rec.Body.String())
		}
		if *reloads != 0 {
			t.Fatalf("dryRun must not reload wifi, got reloads=%d", *reloads)
		}

		// 4. POST /api/wifi/apply real -> arms SafeCommit + reloads once
		reqApply := httptest.NewRequest(http.MethodPost, "/api/wifi/apply", bytes.NewBufferString(`{"action":"auto_optimize","recommended2gChannel":1,"recommended5gChannel":149}`))
		reqApply.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, reqApply)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /api/wifi/apply status=%d body=%s", rec.Code, rec.Body.String())
		}
		var applyResp struct {
			OK              bool   `json:"ok"`
			SafeCommitToken string `json:"safeCommitToken"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &applyResp); err != nil {
			t.Fatalf("decode apply: %v", err)
		}
		if !applyResp.OK || applyResp.SafeCommitToken == "" {
			t.Fatalf("expected ok + safeCommitToken, got %+v", applyResp)
		}

		// 5. Invalid action -> 400
		reqBad := httptest.NewRequest(http.MethodPost, "/api/wifi/apply", bytes.NewBufferString(`{"action":"rm -rf"}`))
		reqBad.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, reqBad)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid action, got %d", rec.Code)
		}

		// 6. POST /api/wifi/chassis
		reqChassis := httptest.NewRequest(http.MethodPost, "/api/wifi/chassis", bytes.NewBufferString(`{"enableRps":true,"tuneConntrack":true}`))
		reqChassis.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, reqChassis)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /api/wifi/chassis status=%d body=%s", rec.Code, rec.Body.String())
		}
		var chResp wifiopt.ChassisApplyResult
		if err := json.Unmarshal(rec.Body.Bytes(), &chResp); err != nil {
			t.Fatalf("decode chassis: %v", err)
		}
		if !chResp.OK || !chResp.Chassis.Optimal {
			t.Fatalf("expected optimal chassis, got %+v", chResp)
		}

		// 7. POST /api/wifi/retest resets stats baseline and returns fresh overview with statsScope="retest"
		reqRetest := httptest.NewRequest(http.MethodPost, "/api/wifi/retest", bytes.NewBufferString(`{}`))
		reqRetest.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, reqRetest)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /api/wifi/retest status=%d body=%s", rec.Code, rec.Body.String())
		}
		var retestOv wifiopt.Overview
		if err := json.Unmarshal(rec.Body.Bytes(), &retestOv); err != nil {
			t.Fatalf("decode retest overview: %v", err)
		}
		if !retestOv.Supported || retestOv.StatsScope != "retest" {
			t.Fatalf("expected retest overview with statsScope='retest', got %+v", retestOv)
		}

		// Subsequent GET /api/wifi/overview must retain the same retest baseline across requests!
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/wifi/overview?fresh=1", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/wifi/overview after retest status=%d", rec.Code)
		}
		var afterOv wifiopt.Overview
		if err := json.Unmarshal(rec.Body.Bytes(), &afterOv); err != nil {
			t.Fatalf("decode overview after retest: %v", err)
		}
		if afterOv.StatsScope != "retest" {
			t.Fatalf("expected persistent statsScope='retest' across requests, got %q", afterOv.StatsScope)
		}
	})

	t.Run("async_reload_flushes_response_before_reloading_wifi", func(t *testing.T) {
		tmp := t.TempDir()
		cfgPath := filepath.Join(tmp, "singctl.yaml")
		_ = os.WriteFile(cfgPath, []byte("subs: []\n"), 0600)
		wifiFile := filepath.Join(tmp, "wireless")
		_ = os.WriteFile(wifiFile, []byte("config wifi-device 'MT7986_1_2'\n\toption channel 'auto'\n"), 0600)

		reloadDone := make(chan struct{}, 1)
		var reloadedCount int
		var mu sync.Mutex
		wifiSvc := wifiopt.NewService(wifiopt.Env{
			WirelessFile:  wifiFile,
			PollInterval:  time.Millisecond,
			VerifyTimeout: 20 * time.Millisecond,
			CPUCount:      2,
			Now:           func() time.Time { return time.Unix(1795552000, 0) },
			Sleep:         func(context.Context, time.Duration) error { return nil },
			LookPath:      func(name string) (string, error) { return "/usr/sbin/" + name, nil },
			ReadFile: func(p string) ([]byte, error) {
				if p == wifiFile {
					return os.ReadFile(p)
				}
				return nil, os.ErrNotExist
			},
			WriteFile0600: func(p string, d []byte) error { return os.WriteFile(p, d, 0600) },
			Glob:          func(string) ([]string, error) { return nil, nil },
			ReloadWifi: func(context.Context) error {
				mu.Lock()
				reloadedCount++
				mu.Unlock()
				select {
				case reloadDone <- struct{}{}:
				default:
				}
				return nil
			},
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				switch name {
				case "uci":
					if len(args) >= 2 && args[0] == "show" && args[1] == "wireless" {
						return []byte("wireless.MT7986_1_2=wifi-device\nwireless.MT7986_1_2.type='mtwifi'\nwireless.MT7986_1_2.phy='rax0'\nwireless.MT7986_1_2.band='5g'\nwireless.MT7986_1_2.channel='auto'\nwireless.MT7986_1_2.htmode='HE160'\nwireless.default_MT7986_1_2=wifi-iface\nwireless.default_MT7986_1_2.device='MT7986_1_2'\nwireless.default_MT7986_1_2.mode='ap'\nwireless.default_MT7986_1_2.ssid='test5g'\nwireless.default_MT7986_1_2.network='wifi'\n"), nil
					}
					if len(args) >= 2 && args[0] == "show" && args[1] == "network" {
						return []byte("network.wifi=interface\nnetwork.wifi.device='br-lan.27'\n"), nil
					}
					return nil, nil
				case "iwinfo":
					return []byte("rax0      ESSID: \"test5g\"\n          Mode: Master  Channel: 52 (5.260 GHz)\n          Bit Rate: 4803.0 MBit/s\n"), nil
				case "brctl":
					return []byte("bridge name\tbridge id\t\tSTP enabled\tinterfaces\nbr-lan\t\t7fff.1\tno\t\trax0\n"), nil
				}
				return nil, nil
			},
		})

		delay := 15 * time.Millisecond
		srv := webui.New(webui.Options{
			ConfigPath:                  cfgPath,
			WifiOptServiceForTest:       wifiSvc,
			WifiAsyncReloadDelayForTest: &delay,
			SafeCommitStateDir:          filepath.Join(tmp, "sc"),
			SafeCommitProcRoot:          t.TempDir(),
			SafeCommitSpawnWatcher:      func(string) (int, error) { return 7002, nil },
			SafeCommitKillWatcher:       func(int) error { return nil },
			SafeCommitBaselineForTest:   func() (bool, bool) { return true, true },
		})

		req := httptest.NewRequest(http.MethodPost, "/api/wifi/apply", bytes.NewBufferString(`{"action":"auto_optimize","recommended5gChannel":149}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("async POST /api/wifi/apply status=%d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			OK              bool   `json:"ok"`
			AsyncReload     bool   `json:"asyncReload"`
			SafeCommitToken string `json:"safeCommitToken"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode async apply: %v", err)
		}
		if !resp.OK || !resp.AsyncReload || resp.SafeCommitToken == "" {
			t.Fatalf("expected ok + asyncReload=true + safeCommitToken, got %+v", resp)
		}
		// Immediately after HTTP response returns, reload must NOT have executed yet (proves response flushed first!).
		mu.Lock()
		earlyCount := reloadedCount
		mu.Unlock()
		if earlyCount != 0 {
			t.Fatalf("expected wifi reload deferred after HTTP flush, but already ran %d times", earlyCount)
		}
		// Wait for async goroutine to trigger reload.
		select {
		case <-reloadDone:
		case <-time.After(1 * time.Second):
			t.Fatal("timed out waiting for deferred async wifi reload")
		}
	})
}

func TestWifiAPI_ChassisSocketBufferTune(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	quicSysctl := filepath.Join(tmp, "99-quic-buffer.conf")
	sysctlFile := filepath.Join(tmp, "sysctl.conf")
	_ = os.WriteFile(sysctlFile, []byte("# sysctl\n"), 0644)

	var mu sync.Mutex
	files := map[string][]byte{
		"/proc/meminfo":                                     []byte("MemTotal:       490496 kB\n"),
		"/proc/sys/net/core/rmem_max":                       []byte("212992\n"),
		"/proc/sys/net/core/wmem_max":                       []byte("212992\n"),
		"/proc/sys/net/core/rmem_default":                   []byte("212992\n"),
		"/proc/sys/net/core/wmem_default":                   []byte("212992\n"),
		"/proc/sys/net/core/default_qdisc":                  []byte("fq_codel\n"),
		"/proc/sys/net/ipv4/tcp_congestion_control":         []byte("cubic\n"),
		"/proc/sys/net/ipv4/tcp_available_congestion_control": []byte("reno cubic bbr\n"),
		"/proc/net/snmp": []byte("Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\nUdp: 100 0 0 80 15 0\n"),
	}

	wifiSvc := wifiopt.NewService(wifiopt.Env{
		GOOS:           "linux",
		SysctlFile:     sysctlFile,
		QuicSysctlFile: quicSysctl,
		CPUCount:       2,
		ReadFile: func(p string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			if b, ok := files[p]; ok {
				return slices.Clone(b), nil
			}
			return os.ReadFile(p)
		},
		WriteFile0600: func(p string, d []byte) error {
			mu.Lock()
			defer mu.Unlock()
			if strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/sys/") {
				files[p] = slices.Clone(d)
				return nil
			}
			return os.WriteFile(p, d, 0644)
		},
		Glob: func(string) ([]string, error) { return nil, nil },
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
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
					if k, v, ok := strings.Cut(tline, "="); ok {
						procPath := "/proc/sys/" + strings.ReplaceAll(strings.TrimSpace(k), ".", "/")
						files[procPath] = []byte(strings.TrimSpace(v) + "\n")
					}
				}
			}
			return nil, nil
		},
	})

	srv := webui.New(webui.Options{
		ConfigPath:            cfgPath,
		WifiOptServiceForTest: wifiSvc,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/wifi/chassis", bytes.NewBufferString(`{"tuneSocketBuffer":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/wifi/chassis status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp wifiopt.ChassisApplyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode chassis result: %v", err)
	}
	if !resp.OK || !resp.RestartSingBoxRecommended || resp.Chassis.SocketBuffer == nil || !resp.Chassis.SocketBuffer.Optimal {
		t.Fatalf("expected RestartSingBoxRecommended + SocketBuffer optimal, got %+v", resp)
	}
	if resp.Chassis.SocketBuffer.RmemMax != 4194304 {
		t.Fatalf("expected 479MB tier rmemMax=4194304, got %d", resp.Chassis.SocketBuffer.RmemMax)
	}
}

func TestChassisAndCapabilities_StatusAndEndpoint(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	quicSysctl := filepath.Join(tmp, "99-quic-buffer.conf")
	sysctlFile := filepath.Join(tmp, "sysctl.conf")
	_ = os.WriteFile(sysctlFile, []byte("# sysctl\n"), 0644)

	var mu sync.Mutex
	files := map[string][]byte{
		"/proc/meminfo":                                     []byte("MemTotal:       1843200 kB\n"),
		"/proc/sys/net/core/rmem_max":                       []byte("212992\n"),
		"/proc/sys/net/core/wmem_max":                       []byte("212992\n"),
		"/proc/sys/net/core/rmem_default":                   []byte("212992\n"),
		"/proc/sys/net/core/wmem_default":                   []byte("212992\n"),
		"/proc/sys/net/core/default_qdisc":                  []byte("fq_codel\n"),
		"/proc/sys/net/ipv4/tcp_congestion_control":         []byte("cubic\n"),
		"/proc/sys/net/ipv4/tcp_available_congestion_control": []byte("reno cubic bbr\n"),
		"/proc/net/snmp": []byte("Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\nUdp: 100 0 0 80 0 0\n"),
	}

	wifiSvc := wifiopt.NewService(wifiopt.Env{
		GOOS:           "linux",
		IsOpenWrt:      func() bool { return false },
		SysctlFile:     sysctlFile,
		QuicSysctlFile: quicSysctl,
		CPUCount:       4,
		ReadFile: func(p string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			if b, ok := files[p]; ok {
				return slices.Clone(b), nil
			}
			return os.ReadFile(p)
		},
		WriteFile0600: func(p string, d []byte) error {
			mu.Lock()
			defer mu.Unlock()
			if strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/sys/") {
				files[p] = slices.Clone(d)
				return nil
			}
			return os.WriteFile(p, d, 0644)
		},
		Glob: func(string) ([]string, error) { return nil, nil },
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
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
					if k, v, ok := strings.Cut(tline, "="); ok {
						procPath := "/proc/sys/" + strings.ReplaceAll(strings.TrimSpace(k), ".", "/")
						files[procPath] = []byte(strings.TrimSpace(v) + "\n")
					}
				}
			}
			return nil, nil
		},
	})

	caps := webui.HostCapabilities{
		Firewall: true,
		Vlan:     false,
		Wifi:     false,
		Chassis:  true,
	}
	srvAuth := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		Password:                "pass1234",
		WifiOptServiceForTest:   wifiSvc,
		HostCapabilitiesForTest: &caps,
	})

	// Unauthenticated GET /api/chassis must return 401.
	recUnauth := httptest.NewRecorder()
	srvAuth.Mux.ServeHTTP(recUnauth, httptest.NewRequest(http.MethodGet, "/api/chassis", nil))
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated GET /api/chassis, got %d", recUnauth.Code)
	}

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		WifiOptServiceForTest:   wifiSvc,
		HostCapabilitiesForTest: &caps,
	})

	// GET /api/status exposes host.capabilities.
	recStatus := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recStatus, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if recStatus.Code != http.StatusOK {
		t.Fatalf("GET /api/status status=%d body=%s", recStatus.Code, recStatus.Body.String())
	}
	var stPayload struct {
		Host struct {
			Capabilities webui.HostCapabilities `json:"capabilities"`
		} `json:"host"`
	}
	if err := json.Unmarshal(recStatus.Body.Bytes(), &stPayload); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if !stPayload.Host.Capabilities.Firewall || stPayload.Host.Capabilities.Vlan || stPayload.Host.Capabilities.Wifi || !stPayload.Host.Capabilities.Chassis {
		t.Fatalf("unexpected capabilities: %+v", stPayload.Host.Capabilities)
	}

	// GET /api/chassis returns ChassisStatus with SocketBuffer without invoking wireless scans.
	recChassis := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recChassis, httptest.NewRequest(http.MethodGet, "/api/chassis", nil))
	if recChassis.Code != http.StatusOK {
		t.Fatalf("GET /api/chassis status=%d body=%s", recChassis.Code, recChassis.Body.String())
	}
	var ch wifiopt.ChassisStatus
	if err := json.Unmarshal(recChassis.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decode chassis: %v", err)
	}
	if !ch.Supported || ch.SocketBuffer == nil || ch.SocketBuffer.RecommendedRmemMax != 16777216 {
		t.Fatalf("unexpected GET /api/chassis payload: %+v", ch)
	}

	// POST /api/chassis works identically to POST /api/wifi/chassis.
	reqPost := httptest.NewRequest(http.MethodPost, "/api/chassis", bytes.NewBufferString(`{"tuneSocketBuffer":true}`))
	reqPost.Header.Set("Content-Type", "application/json")
	recPost := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusOK {
		t.Fatalf("POST /api/chassis status=%d body=%s", recPost.Code, recPost.Body.String())
	}
	var postResp wifiopt.ChassisApplyResult
	if err := json.Unmarshal(recPost.Body.Bytes(), &postResp); err != nil || !postResp.OK || !postResp.Chassis.Optimal {
		t.Fatalf("unexpected POST /api/chassis resp=%+v err=%v", postResp, err)
	}
}

