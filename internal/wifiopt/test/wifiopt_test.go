package wifiopt_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/wifiopt"
)

const sampleMTWifiUCI = `wireless.MT7981_1_1=wifi-device
wireless.MT7981_1_1.type='mtwifi'
wireless.MT7981_1_1.phy='ra0'
wireless.MT7981_1_1.band='2g'
wireless.MT7981_1_1.dbdc_main='1'
wireless.MT7981_1_1.channel='auto'
wireless.MT7981_1_1.txpower='100'
wireless.MT7981_1_1.htmode='HE40'
wireless.MT7981_1_1.mu_beamformer='1'
wireless.MT7981_1_1.country='AU'
wireless.MT7981_1_1.whnat='1'
wireless.default_MT7981_1_1=wifi-iface
wireless.default_MT7981_1_1.device='MT7981_1_1'
wireless.default_MT7981_1_1.mode='ap'
wireless.default_MT7981_1_1.ssid='homewifi'
wireless.default_MT7981_1_1.encryption='sae-mixed'
wireless.default_MT7981_1_1.key='SuperSecretTestPass99'
wireless.default_MT7981_1_1.network='guest_lan'
wireless.MT7981_1_2=wifi-device
wireless.MT7981_1_2.type='mtwifi'
wireless.MT7981_1_2.phy='rax0'
wireless.MT7981_1_2.band='5g'
wireless.MT7981_1_2.dbdc_main='0'
wireless.MT7981_1_2.channel='auto'
wireless.MT7981_1_2.txpower='100'
wireless.MT7981_1_2.htmode='HE160'
wireless.MT7981_1_2.mu_beamformer='1'
wireless.MT7981_1_2.country='AU'
wireless.MT7981_1_2.disabled='1'
wireless.MT7981_1_2.whnat='1'
wireless.default_MT7981_1_2=wifi-iface
wireless.default_MT7981_1_2.device='MT7981_1_2'
wireless.default_MT7981_1_2.network='lan'
wireless.default_MT7981_1_2.mode='ap'
wireless.default_MT7981_1_2.ssid='Old5G'
wireless.default_MT7981_1_2.encryption='sae-mixed'
wireless.default_MT7981_1_2.disabled='1'
wireless.wifinet2=wifi-iface
wireless.wifinet2.device='MT7981_1_1'
wireless.wifinet2.mode='ap'
wireless.wifinet2.ssid='iot'
wireless.wifinet2.isolate='1'
wireless.wifinet2.network='iot'
wireless.wifinet2.encryption='psk2'
wireless.wifinet2.disabled='0'
`

const sampleNetworkUCI = `network.lan=interface
network.lan.device='br-lan'
network.guest_lan=interface
network.guest_lan.device='br-v8'
network.iot=interface
network.iot.device='iot-br'
`

const sampleIwinfoAll = `ra0       ESSID: "homewifi"
          Access Point: 02:00:00:00:00:01
          Mode: Master  Channel: 4 (2.427 GHz)
          Tx-Power: 23 dBm  Link Quality: 100/100
          Bit Rate: 286.0 MBit/s
          Encryption: mixed WPA2/WPA3 PSK/SAE (CCMP)
          Type: mtk  HW Mode(s): 802.11nax
          Hardware: 14C3:7981 14C3:7981 [MediaTek MT7981]

ra1       ESSID: "iot"
          Access Point: 02:00:00:00:00:02
          Mode: Master  Channel: 4 (2.427 GHz)
          Tx-Power: 23 dBm  Link Quality: 100/100
          Bit Rate: 286.0 MBit/s
          Encryption: WPA2 PSK (CCMP)
          Type: mtk  HW Mode(s): 802.11nax
          Hardware: 14C3:7981 14C3:7981 [MediaTek MT7981]

rax0      ESSID: "Old5G"
          Access Point: 00:00:00:00:00:00
          Mode: Master  Channel: unknown (unknown)
          Tx-Power: unknown  Link Quality: 100/100
          Bit Rate: unknown
          Encryption: unknown
          Type: mtk  HW Mode(s): unknown
          Hardware: 14C3:7981 14C3:7981 [MediaTek MT7981]
`

const sampleRa0Assoc = `02:11:22:33:44:55  -72 dBm / unknown (SNR -72)  0 ms ago
	RX: 145.0 MBit/s, HE-MCS 6, 20MHz, HE-NSS 2, HE-GI 1, HE-DCM 0         0 Pkts.
	TX: 172.0 MBit/s, HE-MCS 7, 20MHz, HE-NSS 2, HE-GI 0, HE-DCM 0         0 Pkts.

02:11:22:33:44:66  -93 dBm / unknown (SNR -93)  0 ms ago
	RX: 78.0 MBit/s, MCS 12, 20MHz                     0 Pkts.
	TX: 14.0 MBit/s, MCS 1, 20MHz                      0 Pkts.
`

const sampleProcNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 1813903 175776    0    0    0     0          0         0 940188 125158    0    0    0     0       0          0
   ra0: 7241373 100000 13700    0    0     0          0         0 745227 551656    0    0    0     0       0          0
   ra1: 2220080  49228    0    0    0     0          0         0 210220  13556    0    0    0     0       0          0
  rax0:       0       0    0    0    0     0          0         0      0       0    0    0    0     0       0          0
`

const sampleDHCPLeases = `1795550000 02:11:22:33:44:55 192.168.89.137 test-laptop *
1795550000 02:11:22:33:44:66 192.168.89.146 test-phone *
`

const sampleScan2G = `Cell 01 - Address: AA:BB:CC:DD:EE:01
          ESSID: "NeighborPrivateWifiA"
          Mode: Master  Channel: 1
          Signal: -97 dBm  Quality: 10/70
Cell 02 - Address: AA:BB:CC:DD:EE:02
          ESSID: "NeighborPrivateWifiB"
          Mode: Master  Channel: 6
          Signal: -60 dBm  Quality: 50/70
Cell 03 - Address: AA:BB:CC:DD:EE:03
          ESSID: "NeighborPrivateWifiC"
          Mode: Master  Channel: 11
          Signal: -51 dBm  Quality: 60/70
Cell 04 - Address: AA:BB:CC:DD:EE:04
          ESSID: "NeighborPrivateWifiD"
          Mode: Master  Channel: 11
          Signal: -58 dBm  Quality: 55/70
`

const sampleScan5G = `Cell 01 - Address: AA:BB:CC:DD:EE:11
          ESSID: "Neighbor5GA"
          Mode: Master  Channel: 36
          Signal: -55 dBm  Quality: 58/70
Cell 02 - Address: AA:BB:CC:DD:EE:12
          ESSID: "Neighbor5GB"
          Mode: Master  Channel: 52
          Signal: -62 dBm  Quality: 48/70
Cell 03 - Address: AA:BB:CC:DD:EE:13
          ESSID: "Neighbor5GC"
          Mode: Master  Channel: 149
          Signal: -89 dBm  Quality: 18/70
`

func newFakeMTWifiEnv(t *testing.T, brctlAfterReload string) (*wifiopt.Env, *[]string, *int) {
	t.Helper()
	tmp := t.TempDir()
	wifiFile := filepath.Join(tmp, "wireless")
	sysctlFile := filepath.Join(tmp, "sysctl.conf")
	rcLocalFile := filepath.Join(tmp, "rc.local")
	if err := os.WriteFile(wifiFile, []byte("config wifi-device 'MT7981_1_1'\n\toption channel 'auto'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sysctlFile, []byte("# sysctl\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rcLocalFile, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var uciCalls []string
	reloads := 0

	rpsPath := "/sys/class/net/eth0/queues/rx-0/rps_cpus"
	files := map[string][]byte{
		"/proc/net/dev":                             []byte(sampleProcNetDev),
		"/tmp/dhcp.leases":                          []byte(sampleDHCPLeases),
		"/proc/meminfo":                             []byte("MemTotal:         235520 kB\nMemAvailable:     108000 kB\n"),
		"/proc/sys/net/netfilter/nf_conntrack_max":  []byte("16384\n"),
		"/proc/sys/net/netfilter/nf_conntrack_count": []byte("420\n"),
		rpsPath: []byte("1\n"),
	}

	env := &wifiopt.Env{
		WirelessFile:  wifiFile,
		SysctlFile:    sysctlFile,
		RCLocalFile:   rcLocalFile,
		PollInterval:  time.Millisecond,
		VerifyTimeout: 25 * time.Millisecond,
		CPUCount:      2,
		Now:           func() time.Time { return time.Unix(1795551000, 0) },
		Sleep:         func(context.Context, time.Duration) error { return nil },
		LookPath: func(file string) (string, error) {
			switch file {
			case "uci", "iwinfo", "wifi", "brctl", "sysctl":
				return "/usr/sbin/" + file, nil
			default:
				return "", errors.New("not found")
			}
		},
		ReadFile: func(path string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			if path == wifiFile || path == sysctlFile || path == rcLocalFile {
				return os.ReadFile(path)
			}
			if b, ok := files[path]; ok {
				return slices.Clone(b), nil
			}
			return nil, os.ErrNotExist
		},
		WriteFile0600: func(path string, data []byte) error {
			mu.Lock()
			defer mu.Unlock()
			if path == wifiFile || path == sysctlFile || path == rcLocalFile {
				return os.WriteFile(path, data, 0600)
			}
			files[path] = slices.Clone(data)
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
					return []byte(sampleMTWifiUCI), nil
				}
				if len(args) >= 2 && args[0] == "show" && args[1] == "network" {
					return []byte(sampleNetworkUCI), nil
				}
				uciCalls = append(uciCalls, strings.Join(args, " "))
				return nil, nil
			case "iwinfo":
				if len(args) == 0 {
					return []byte(sampleIwinfoAll), nil
				}
				if len(args) == 2 && args[1] == "assoclist" {
					if args[0] == "ra0" {
						return []byte(sampleRa0Assoc), nil
					}
					return nil, nil
				}
				if len(args) == 2 && args[1] == "scan" {
					if args[0] == "ra0" {
						return []byte(sampleScan2G), nil
					}
					if args[0] == "rax0" {
						return []byte(sampleScan5G), nil
					}
				}
				return nil, nil
			case "brctl":
				if reloads > 0 && brctlAfterReload != "" {
					return []byte(brctlAfterReload), nil
				}
				return []byte("bridge name\tbridge id\t\tSTP enabled\tinterfaces\nbr-v8\t\t7fff.1\tno\t\teth0.8\n\t\t\t\t\t\t\tra0\niot-br\t\t7fff.2\tno\t\teth0.3\n\t\t\t\t\t\t\tra1\n"), nil
			case "sysctl":
				if len(args) >= 2 && args[0] == "-w" && strings.HasPrefix(args[1], "net.netfilter.nf_conntrack_max=") {
					val := strings.TrimPrefix(args[1], "net.netfilter.nf_conntrack_max=")
					files["/proc/sys/net/netfilter/nf_conntrack_max"] = []byte(val + "\n")
				}
				return nil, nil
			default:
				return nil, errors.New("unexpected cmd: " + name)
			}
		},
	}
	return env, &uciCalls, &reloads
}

func TestOverview_MTWifiDiagnosisAndSecurity(t *testing.T) {
	env, _, _ := newFakeMTWifiEnv(t, "")
	svc := wifiopt.NewService(*env)

	ov, err := svc.Overview(t.Context())
	if err != nil {
		t.Fatalf("Overview failed: %v", err)
	}
	if !ov.Supported || ov.Driver != "mtwifi" {
		t.Fatalf("expected supported mtwifi, got supported=%v driver=%q", ov.Supported, ov.Driver)
	}
	if len(ov.Radios) != 2 {
		t.Fatalf("expected 2 radios, got %d", len(ov.Radios))
	}
	if ov.HealthScore >= 75 {
		t.Fatalf("expected degraded health score for disabled 5G + overlapping ch4 + high err rate, got %d", ov.HealthScore)
	}

	// Never leak Wi-Fi password in Overview JSON!
	raw, _ := json.Marshal(ov)
	if strings.Contains(string(raw), "SuperSecretTestPass99") {
		t.Fatal("Overview JSON leaked plaintext Wi-Fi password!")
	}

	// Must diagnose disabled 5G, overlapping 2.4G ch4, HE40 on 2.4G, and weak client / high rx errors.
	ids := make(map[string]bool)
	for _, d := range ov.Diagnostics {
		ids[d.ID] = true
	}
	for _, want := range []string{"radio_5g_disabled", "ch_2g_overlap", "htmode_2g_wide"} {
		if !ids[want] {
			t.Errorf("missing expected diagnosis %q; got %+v", want, ov.Diagnostics)
		}
	}
	if len(ov.AutoOptimizePlan) == 0 {
		t.Fatal("expected non-empty AutoOptimizePlan")
	}

	// Verify clients enriched with DHCP hostnames & weak signal flagged.
	if len(ov.Clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(ov.Clients))
	}
	foundWeak := false
	for _, c := range ov.Clients {
		if c.Hostname == "test-phone" && c.WeakSignal {
			foundWeak = true
		}
	}
	if !foundWeak {
		t.Errorf("expected test-phone (-93 dBm) flagged weakSignal=true, got %+v", ov.Clients)
	}

	// Chassis check: 2-core RPS mask=1 -> not balanced; 230MB RAM conntrack 16384 -> recommend 32768.
	if ov.Chassis.RPSOptimal || ov.Chassis.ConntrackOptimal || ov.Chassis.RecommendedConntrack != 32768 {
		t.Errorf("unexpected chassis status: %+v", ov.Chassis)
	}
}

func TestOverview_NonWirelessHostGraceful(t *testing.T) {
	svc := wifiopt.NewService(wifiopt.Env{
		LookPath: func(string) (string, error) { return "", errors.New("not found") },
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		Glob:     func(string) ([]string, error) { return nil, nil },
		CPUCount: 4,
	})

	ov, err := svc.Overview(t.Context())
	if err != nil {
		t.Fatalf("Overview on non-wireless host should not error: %v", err)
	}
	if ov.Supported {
		t.Fatal("expected supported=false when uci/iwinfo absent")
	}
	if ov.UnsupportedHint == "" {
		t.Fatal("expected helpful unsupportedHint")
	}
}

func TestScan_OptimalChannelSelectionAndPrivacySanitization(t *testing.T) {
	env, _, _ := newFakeMTWifiEnv(t, "")
	svc := wifiopt.NewService(*env)

	res, err := svc.Scan(t.Context())
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	// Channel 1 (-97 dBm) must beat Ch6 (-60 dBm) and Ch11 (-51 dBm, 2 APs)!
	if res.Recommended2GCh != 1 {
		t.Fatalf("expected recommended 2.4G channel 1, got %d (stats=%+v)", res.Recommended2GCh, res.Channels2G)
	}
	// Channel 149 (-89 dBm, non-DFS) must beat Ch36 (-55 dBm) and DFS Ch52!
	if res.Recommended5GCh != 149 {
		t.Fatalf("expected recommended 5G channel 149, got %d (stats=%+v)", res.Recommended5GCh, res.Channels5G)
	}

	// Privacy rule: neighbor SSIDs & BSSIDs MUST NEVER appear in JSON output.
	raw, _ := json.Marshal(res)
	s := string(raw)
	for _, secret := range []string{"NeighborPrivateWifiA", "NeighborPrivateWifiB", "Neighbor5GA", "AA:BB:CC:DD:EE:01"} {
		if strings.Contains(s, secret) {
			t.Fatalf("Scan leaked neighbor privacy info %q!", secret)
		}
	}
}

func TestApply_DualBandMergeAndAutoOptimize(t *testing.T) {
	bridgeOK := "bridge name\tbridge id\t\tSTP enabled\tinterfaces\nbr-v8\t\t7fff.1\tno\t\teth0.8\n\t\t\t\t\t\t\tra0\n\t\t\t\t\t\t\trax0\niot-br\t\t7fff.2\tno\t\teth0.3\n\t\t\t\t\t\t\tra1\n"

	t.Run("dual_band_merge_copies_secret_without_leaking", func(t *testing.T) {
		env, uciCalls, reloads := newFakeMTWifiEnv(t, bridgeOK)
		svc := wifiopt.NewService(*env)

		res, err := svc.Apply(t.Context(), wifiopt.ApplyRequest{
			Action:          "dual_band_merge",
			SourceSection:   "default_MT7981_1_1",
			Recommended5GCh: 149,
		})
		if err != nil {
			t.Fatalf("Apply dual_band_merge failed: %v", err)
		}
		if !res.OK || !res.Reloaded || !res.BridgeVerified {
			t.Fatalf("unexpected apply result: %+v", res)
		}
		if *reloads != 1 {
			t.Fatalf("expected exactly 1 wifi reload, got %d", *reloads)
		}

		// Verify key copied via UCI set, but NEVER leaked in ApplyResult JSON!
		joined := strings.Join(*uciCalls, "\n")
		if !strings.Contains(joined, "set wireless.default_MT7981_1_2.ssid=homewifi") ||
			!strings.Contains(joined, "set wireless.default_MT7981_1_2.network=guest_lan") ||
			!strings.Contains(joined, "set wireless.default_MT7981_1_2.key=SuperSecretTestPass99") ||
			!strings.Contains(joined, "commit wireless") {
			t.Fatalf("missing expected UCI commands:\n%s", joined)
		}
		raw, _ := json.Marshal(res)
		if strings.Contains(string(raw), "SuperSecretTestPass99") {
			t.Fatal("ApplyResult leaked plaintext Wi-Fi password!")
		}
	})

	t.Run("auto_optimize_bridge_timeout_triggers_atomic_rollback", func(t *testing.T) {
		// Bridge missing rax0 after reload -> must rollback!
		bridgeBroken := "bridge name\tbridge id\t\tSTP enabled\tinterfaces\nbr-v8\t\t7fff.1\tno\t\teth0.8\n\t\t\t\t\t\t\tra0\n"
		env, _, reloads := newFakeMTWifiEnv(t, bridgeBroken)
		origContent, _ := os.ReadFile(env.WirelessFile)
		// Simulate wireless file mutation during apply
		origRun := env.RunCmd
		env.RunCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "uci" && len(args) >= 1 && args[0] == "commit" {
				_ = os.WriteFile(env.WirelessFile, []byte("mutated-broken-wireless\n"), 0600)
			}
			return origRun(ctx, name, args...)
		}

		svc := wifiopt.NewService(*env)
		_, err := svc.Apply(t.Context(), wifiopt.ApplyRequest{
			Action:          "auto_optimize",
			Recommended2GCh: 1,
			Recommended5GCh: 149,
		})
		if !errors.Is(err, wifiopt.ErrBridgeVerifyFailed) {
			t.Fatalf("expected ErrBridgeVerifyFailed, got %v", err)
		}
		if *reloads != 2 {
			t.Fatalf("expected 2 wifi reloads (apply + rollback), got %d", *reloads)
		}
		restored, _ := os.ReadFile(env.WirelessFile)
		if string(restored) != string(origContent) {
			t.Fatalf("wireless file not rolled back: got %q want %q", string(restored), string(origContent))
		}
	})

	t.Run("rejects_injection_and_invalid_inputs", func(t *testing.T) {
		env, _, _ := newFakeMTWifiEnv(t, bridgeOK)
		svc := wifiopt.NewService(*env)

		badCases := []wifiopt.ApplyRequest{
			{Action: "unknown_action"},
			{Action: "dual_band_merge", SourceSection: "default_MT7981_1_1; rm -rf /"},
			{Action: "tune_radio", Radios: []wifiopt.RadioPatch{{Device: "MT7981_1_1", Channel: "$(id)"}}},
			{Action: "tune_radio", Radios: []wifiopt.RadioPatch{{Device: "MT7981_1_1", HTMode: "HE999"}}},
			{Action: "tune_radio", Radios: []wifiopt.RadioPatch{{Device: "nonexistent_dev", Channel: "1"}}},
		}
		for _, tc := range badCases {
			if _, err := svc.Apply(t.Context(), tc); err == nil {
				t.Errorf("expected error for invalid request %+v, got nil", tc)
			}
		}
	})

	t.Run("dsa_bridge_vlan_suffix_matches_parent_bridge", func(t *testing.T) {
		dsaBridge := "bridge name\tbridge id\t\tSTP enabled\tinterfaces\nbr-lan\t\t7fff.1\tno\t\teth0\n\t\t\t\t\t\t\tra0\n\t\t\t\t\t\t\trax0\n\t\t\t\t\t\t\tra1\n"
		env, _, reloads := newFakeMTWifiEnv(t, dsaBridge)
		origRun := env.RunCmd
		env.RunCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "uci" && len(args) >= 2 && args[0] == "show" && args[1] == "network" {
				return []byte("network.lan=interface\nnetwork.lan.device='br-lan.1'\nnetwork.guest_lan=interface\nnetwork.guest_lan.device='br-lan.27'\nnetwork.iot=interface\nnetwork.iot.device='br-lan.28'\n"), nil
			}
			return origRun(ctx, name, args...)
		}
		svc := wifiopt.NewService(*env)
		res, err := svc.Apply(t.Context(), wifiopt.ApplyRequest{
			Action:          "auto_optimize",
			Recommended2GCh: 1,
			Recommended5GCh: 149,
		})
		if err != nil {
			t.Fatalf("DSA bridge-vlan Apply failed: %v", err)
		}
		if !res.OK || !res.BridgeVerified || *reloads != 1 {
			t.Fatalf("expected DSA parent bridge match with 1 reload, got res=%+v reloads=%d", res, *reloads)
		}
	})
}

func TestChassis_ApplyRPSAndConntrackIdempotent(t *testing.T) {
	env, _, _ := newFakeMTWifiEnv(t, "")
	svc := wifiopt.NewService(*env)

	res, err := svc.ApplyChassis(t.Context(), wifiopt.ChassisApplyRequest{
		EnableRPS:     true,
		TuneConntrack: true,
	})
	if err != nil {
		t.Fatalf("ApplyChassis failed: %v", err)
	}
	if !res.OK || !res.Chassis.RPSOptimal || !res.Chassis.ConntrackOptimal || res.Chassis.ConntrackMax != 32768 {
		t.Fatalf("expected optimal chassis after apply, got %+v", res)
	}

	// Verify persistence written cleanly and idempotent on second run.
	rcRaw, _ := os.ReadFile(env.RCLocalFile)
	if !strings.Contains(string(rcRaw), "singctl-rps") {
		t.Fatalf("expected rc.local RPS persistence marker, got:\n%s", string(rcRaw))
	}
	sysRaw, _ := os.ReadFile(env.SysctlFile)
	if !strings.Contains(string(sysRaw), "net.netfilter.nf_conntrack_max=32768") {
		t.Fatalf("expected sysctl.conf persistence, got:\n%s", string(sysRaw))
	}

	// Second apply must remain idempotent (no duplicate marker lines).
	if _, err := svc.ApplyChassis(t.Context(), wifiopt.ChassisApplyRequest{
		EnableRPS:     true,
		TuneConntrack: true,
	}); err != nil {
		t.Fatalf("second ApplyChassis failed: %v", err)
	}
	rcRaw2, _ := os.ReadFile(env.RCLocalFile)
	if strings.Count(string(rcRaw2), "singctl-rps-begin") != 1 {
		t.Fatalf("expected idempotent single RPS block in rc.local, got:\n%s", string(rcRaw2))
	}
}

func TestOverview_ConcurrentRaceSafe(t *testing.T) {
	env, _, _ := newFakeMTWifiEnv(t, "")
	svc := wifiopt.NewService(*env)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ov, err := svc.Overview(t.Context())
			if err != nil || ov == nil || !ov.Supported {
				t.Errorf("concurrent Overview failed: ov=%+v err=%v", ov, err)
			}
		}()
	}
	wg.Wait()
}
