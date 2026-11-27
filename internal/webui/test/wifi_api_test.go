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
	})
}
