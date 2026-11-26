// 文件职责：验证软硬件流量卸载（OpenWrt UCI fw3/fw4、TurboACC、MediaTek HNAT、SFE）状态探测、0600 快照还原、BBR/FullCone 保留与内核回读校验。
package gateway_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/gateway"
	"singctl/internal/platform/servicemgr"
)

func TestFlowOffload_StandardOpenWrtFW4ToggleAndBackupRestore(t *testing.T) {
	dir := t.TempDir()
	backupPath := filepath.Join(dir, "flow-offload-backup.json")

	var (
		cmds      []string
		swOffload = "1"
		hwOffload = "1"
		fw4Active = true
	)

	deps := func() gateway.FlowOffloadDeps {
		return gateway.FlowOffloadDeps{
			BackupPath:         backupPath,
			TurboACCConfigPath: filepath.Join(dir, "nonexistent-turboacc"),
			ProcModulesPath:    filepath.Join(dir, "proc-modules"),
			HNATHookTogglePath: filepath.Join(dir, "nonexistent-hook_toggle"),
			HNATSettingPath:    filepath.Join(dir, "nonexistent-hnat_setting"),
			FastClassifierPath: filepath.Join(dir, "nonexistent-sfe"),
			IsOpenWrt:          func() bool { return true },
			HasCommand:         func(name string) bool { return name == "uci" || name == "fw4" },
			ReadFile:           os.ReadFile,
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				line := strings.TrimSpace(name + " " + strings.Join(args, " "))
				cmds = append(cmds, line)
				switch line {
				case "uci -q get firewall.@defaults[0].flow_offloading":
					return []byte(swOffload + "\n"), nil
				case "uci -q get firewall.@defaults[0].flow_offloading_hw":
					return []byte(hwOffload + "\n"), nil
				case "uci -q get firewall.@defaults[0].fullcone":
					return nil, os.ErrNotExist
				case "uci set firewall.@defaults[0].flow_offloading=0":
					swOffload = "0"
				case "uci set firewall.@defaults[0].flow_offloading=1":
					swOffload = "1"
				case "uci set firewall.@defaults[0].flow_offloading_hw=0":
					hwOffload = "0"
				case "uci set firewall.@defaults[0].flow_offloading_hw=1":
					hwOffload = "1"
				case "fw4 reload":
					fw4Active = (swOffload == "1" || hwOffload == "1")
					modLine := "nft_flow_offload 12288 0 - Live 0x0\n"
					if fw4Active {
						modLine = "nft_flow_offload 12288 1 nf_tables, Live 0x0\n"
					}
					_ = os.WriteFile(filepath.Join(dir, "proc-modules"), []byte(modLine), 0644)
				}
				return []byte("ok\n"), nil
			},
		}
	}

	modVal := func() string {
		if fw4Active {
			return "nft_flow_offload 12288 1 nf_tables, Live 0x0\n"
		}
		return "nft_flow_offload 12288 0 - Live 0x0\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "proc-modules"), []byte(modVal()), 0644); err != nil {
		t.Fatal(err)
	}

	st := gateway.ProbeFlowOffloadStatus(t.Context(), deps())
	if !st.Supported || !st.Enabled || !st.UCISoftware || !st.UCIHardware || !st.KernelFlowActive {
		t.Fatalf("unexpected initial fw4 offload probe: %+v", st)
	}

	// 1. Disable writes 0600 backup, clears UCI, reloads fw4, and reads back clean kernel state.
	fw4Active = false // simulated fw4 reload clears flowtable reference immediately
	resOff, err := gateway.ApplyFlowOffload(t.Context(), false, deps())
	if err != nil {
		t.Fatalf("ApplyFlowOffload(false) failed: %v", err)
	}
	// Rewrite proc-modules to match fw4 reload result before probing or make RunCmd update it.
	if resOff.Enabled || !resOff.AppliedLive || resOff.RebootRequired {
		t.Fatalf("unexpected disable result: %+v", resOff)
	}
	if !slices.Contains(cmds, "fw4 reload") {
		t.Fatalf("expected fw4 reload command, got %v", cmds)
	}
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("expected backup file at %s: %v", backupPath, err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected backup perm 0600, got %#o", info.Mode().Perm())
	}
	origBackup, _ := os.ReadFile(backupPath)

	// 2. Idempotent second disable must NOT overwrite original backup snapshot with all-zero values.
	if _, err := gateway.ApplyFlowOffload(t.Context(), false, deps()); err != nil {
		t.Fatalf("second ApplyFlowOffload(false) failed: %v", err)
	}
	afterSecondBackup, _ := os.ReadFile(backupPath)
	if string(afterSecondBackup) != string(origBackup) {
		t.Fatalf("idempotent disable overwrote existing 0600 backup:\nbefore=%s\nafter=%s", origBackup, afterSecondBackup)
	}

	// 3. Re-enable restores exact 1:1 UCI hardware+software offload from backup without reboot.
	if err := os.WriteFile(filepath.Join(dir, "proc-modules"), []byte("nft_flow_offload 12288 1 nf_tables, Live 0x0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	resOn, err := gateway.ApplyFlowOffload(t.Context(), true, deps())
	if err != nil {
		t.Fatalf("ApplyFlowOffload(true) failed: %v", err)
	}
	if !resOn.Enabled || !resOn.RestoredBackup || !resOn.AppliedLive || resOn.RebootRequired {
		t.Fatalf("unexpected re-enable result: %+v", resOn)
	}
	if swOffload != "1" || hwOffload != "1" {
		t.Fatalf("expected both sw/hw offload restored to 1, got sw=%s hw=%s", swOffload, hwOffload)
	}
}

func TestFlowOffload_TurboACCMediaTekHNATPreservesBBRAndHotTogglesWithoutReboot(t *testing.T) {
	dir := t.TempDir()
	backupPath := filepath.Join(dir, "flow-offload-backup.json")
	turboPath := filepath.Join(dir, "turboacc")
	procModPath := filepath.Join(dir, "modules")
	hookPath := filepath.Join(dir, "hook_toggle")
	settingPath := filepath.Join(dir, "hnat_setting")

	turboOpts := map[string]string{
		"fastpath":                       "mediatek_hnat",
		"fastpath_mh_eth_hnat":           "1",
		"fastpath_mh_eth_hnat_v6":        "1",
		"fastpath_mh_eth_hnat_bind_rate": "30",
		"fastpath_mh_eth_hnat_macvlan":   "0",
		"tcpcca":                         "bbr",
		"fullcone":                       "1",
	}
	syncTurboFile := func() {
		var b strings.Builder
		b.WriteString("config turboacc 'config'\n")
		for k, v := range turboOpts {
			b.WriteString("\toption " + k + " '" + v + "'\n")
		}
		if err := os.WriteFile(turboPath, []byte(b.String()), 0644); err != nil {
			t.Fatal(err)
		}
	}
	syncTurboFile()

	// Note: mtkhnat has refcnt=1 pinned by mt_wifi, xt_FLOWOFFLOAD has refcnt=0!
	if err := os.WriteFile(procModPath, []byte("mtkhnat 102400 1 mt_wifi, Live 0x0\nxt_FLOWOFFLOAD 16384 0 - Live 0x0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte("enabled\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var settingWrites []string
	var fwCalls []string
	mockMgr := servicemgr.NewMock()

	deps := gateway.FlowOffloadDeps{
		BackupPath:         backupPath,
		TurboACCConfigPath: turboPath,
		ProcModulesPath:    procModPath,
		HNATHookTogglePath: hookPath,
		HNATSettingPath:    settingPath,
		FastClassifierPath: filepath.Join(dir, "nonexistent-sfe"),
		IsOpenWrt:          func() bool { return true },
		HasCommand:         func(name string) bool { return name == "uci" },
		ServiceMgr:         mockMgr,
		ReadFile:           os.ReadFile,
		WriteFile: func(path string, data []byte) error {
			switch path {
			case hookPath:
				if strings.TrimSpace(string(data)) == "0" {
					return os.WriteFile(hookPath, []byte("disabled\n"), 0644)
				}
				return os.WriteFile(hookPath, []byte("enabled\n"), 0644)
			case settingPath:
				settingWrites = append(settingWrites, strings.TrimSpace(string(data)))
				return nil
			default:
				return os.WriteFile(path, data, 0644)
			}
		},
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
			fwCalls = append(fwCalls, cmd)
			if name == "uci" && len(args) >= 2 && args[0] == "set" {
				kv := strings.SplitN(args[1], "=", 2)
				if len(kv) == 2 && strings.HasPrefix(kv[0], "turboacc.config.") {
					key := strings.TrimPrefix(kv[0], "turboacc.config.")
					turboOpts[key] = kv[1]
					syncTurboFile()
				}
			}
			if name == "uci" && len(args) == 3 && args[0] == "-q" && args[1] == "get" {
				if args[2] == "firewall.@defaults[0].fullcone" {
					return []byte("1\n"), nil
				}
				return nil, os.ErrNotExist
			}
			return []byte("ok\n"), nil
		},
	}

	// 1. Initial probe accurately detects HNAT active, does NOT treat xt_FLOWOFFLOAD(0) as active, and detects BBR+FullCone.
	st := gateway.ProbeFlowOffloadStatus(t.Context(), deps)
	if !st.Supported || !st.Enabled || !st.TurboACCPresent || !st.HNATSupported || !st.HNATActive || st.KernelFlowActive {
		t.Fatalf("unexpected ax3000t initial probe: %+v", st)
	}
	if st.TurboACCFastpath != "mediatek_hnat" {
		t.Fatalf("expected fastpath=mediatek_hnat, got %q", st.TurboACCFastpath)
	}
	if !slices.Contains(st.PreservedFeatures, "TCP BBR 拥塞控制") || !slices.Contains(st.PreservedFeatures, "FullCone NAT") {
		t.Fatalf("expected BBR & FullCone preserved features, got %v", st.PreservedFeatures)
	}

	// 2. Disable clears fastpath & writes 0 to hook_toggle while leaving tcpcca=bbr & fullcone=1 untouched.
	resOff, err := gateway.ApplyFlowOffload(t.Context(), false, deps)
	if err != nil {
		t.Fatalf("disable HNAT failed: %v", err)
	}
	if resOff.Enabled || !resOff.AppliedLive || resOff.RebootRequired {
		t.Fatalf("expected live disable without reboot, got %+v", resOff)
	}
	if resOff.Status.HNATActive || resOff.Status.Enabled {
		t.Fatalf("expected HNATActive=false after hook_toggle=0 even with mtkhnat module pinned by mt_wifi: %+v", resOff.Status)
	}
	if turboOpts["fastpath"] != "none" || turboOpts["fastpath_mh_eth_hnat"] != "0" {
		t.Fatalf("expected turboacc fastpath disabled, got %+v", turboOpts)
	}
	if turboOpts["tcpcca"] != "bbr" || turboOpts["fullcone"] != "1" {
		t.Fatalf("BBR or FullCone was unexpectedly altered: %+v", turboOpts)
	}
	if !slices.Contains(mockMgr.Calls(), "reload firewall") {
		t.Fatalf("expected servicemgr firewall reload, got %v", mockMgr.Calls())
	}

	// 3. Re-enable restores mediatek_hnat + hook_toggle=1 + hnat_setting without reboot.
	resOn, err := gateway.ApplyFlowOffload(t.Context(), true, deps)
	if err != nil {
		t.Fatalf("re-enable HNAT failed: %v", err)
	}
	if !resOn.Enabled || !resOn.RestoredBackup || !resOn.AppliedLive || resOn.RebootRequired {
		t.Fatalf("expected live HNAT restore without reboot, got %+v", resOn)
	}
	if !resOn.Status.HNATActive || resOn.Status.TurboACCFastpath != "mediatek_hnat" {
		t.Fatalf("expected mediatek_hnat & HNATActive restored, got %+v", resOn.Status)
	}
	if !slices.Contains(settingWrites, "8 1") || !slices.Contains(settingWrites, "11 30") {
		t.Fatalf("expected hnat_setting restore (8 1, 11 30), got %v", settingWrites)
	}
}

func TestFlowOffload_EnableWithoutPriorBackupDefaultsCleanly(t *testing.T) {
	t.Run("turboacc_hnat_without_backup", func(t *testing.T) {
		dir := t.TempDir()
		turboPath := filepath.Join(dir, "turboacc")
		hookPath := filepath.Join(dir, "hook_toggle")
		_ = os.WriteFile(turboPath, []byte("config turboacc 'config'\n\toption fastpath 'none'\n\toption fastpath_mh_eth_hnat '0'\n"), 0644)
		_ = os.WriteFile(hookPath, []byte("disabled\n"), 0644)
		var uciSets []string
		deps := gateway.FlowOffloadDeps{
			BackupPath:         filepath.Join(dir, "no-backup.json"),
			TurboACCConfigPath: turboPath,
			ProcModulesPath:    filepath.Join(dir, "no-mod"),
			HNATHookTogglePath: hookPath,
			HNATSettingPath:    filepath.Join(dir, "hnat_setting"),
			FastClassifierPath: filepath.Join(dir, "no-sfe"),
			IsOpenWrt:          func() bool { return true },
			HasCommand:         func(name string) bool { return name == "uci" },
			ServiceMgr:         servicemgr.NewMock(),
			ReadFile:           os.ReadFile,
			WriteFile: func(path string, data []byte) error {
				if path == hookPath {
					return os.WriteFile(hookPath, []byte("enabled\n"), 0644)
				}
				return os.WriteFile(path, data, 0644)
			},
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "uci" && len(args) >= 2 && args[0] == "set" {
					uciSets = append(uciSets, args[1])
					return nil, nil
				}
				if (name == "uci" && len(args) >= 1 && args[0] == "commit") || name == "fw4" {
					return nil, nil
				}
				return nil, os.ErrNotExist
			},
		}
		res, err := gateway.ApplyFlowOffload(t.Context(), true, deps)
		if err != nil {
			t.Fatalf("ApplyFlowOffload(true) without backup failed: %v", err)
		}
		if res.RestoredBackup || !res.Enabled || !res.AppliedLive {
			t.Fatalf("unexpected default HNAT enable result: %+v", res)
		}
		if !slices.Contains(uciSets, "turboacc.config.fastpath=mediatek_hnat") {
			t.Fatalf("expected turboacc.config.fastpath=mediatek_hnat, got %v", uciSets)
		}
	})

	t.Run("standard_uci_without_backup", func(t *testing.T) {
		dir := t.TempDir()
		sw := "0"
		deps := gateway.FlowOffloadDeps{
			BackupPath:         filepath.Join(dir, "no-backup.json"),
			TurboACCConfigPath: filepath.Join(dir, "no-turbo"),
			ProcModulesPath:    filepath.Join(dir, "no-mod"),
			HNATHookTogglePath: filepath.Join(dir, "no-hook"),
			FastClassifierPath: filepath.Join(dir, "no-sfe"),
			IsOpenWrt:          func() bool { return true },
			HasCommand:         func(name string) bool { return name == "uci" || name == "fw4" },
			ReadFile:           os.ReadFile,
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				cmd := name + " " + strings.Join(args, " ")
				switch cmd {
				case "uci set firewall.@defaults[0].flow_offloading=1":
					sw = "1"
					return nil, nil
				case "uci commit firewall", "fw4 reload":
					return nil, nil
				case "uci -q get firewall.@defaults[0].flow_offloading":
					return []byte(sw + "\n"), nil
				}
				return nil, os.ErrNotExist
			},
		}
		res, err := gateway.ApplyFlowOffload(t.Context(), true, deps)
		if err != nil {
			t.Fatalf("ApplyFlowOffload(true) UCI fallback failed: %v", err)
		}
		if !res.Enabled || !res.AppliedLive || res.RebootRequired {
			t.Fatalf("unexpected UCI enable result: %+v", res)
		}
	})
}

func TestFlowOffload_StubbornKernelReadbackRequiresRebootAndUnsupportedHostErrors(t *testing.T) {
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "hook_toggle")
	_ = os.WriteFile(hookPath, []byte("enabled\n"), 0644)

	deps := gateway.FlowOffloadDeps{
		BackupPath:         filepath.Join(dir, "backup.json"),
		TurboACCConfigPath: filepath.Join(dir, "no-turbo"),
		ProcModulesPath:    filepath.Join(dir, "no-mod"),
		HNATHookTogglePath: hookPath,
		FastClassifierPath: filepath.Join(dir, "no-sfe"),
		IsOpenWrt:          func() bool { return true },
		HasCommand:         func(name string) bool { return name == "uci" },
		ServiceMgr:         servicemgr.NewMock(),
		ReadFile:           os.ReadFile,
		WriteFile:          func(string, []byte) error { return nil }, // hook_toggle stays "enabled"
		RunCmd:             func(context.Context, string, ...string) ([]byte, error) { return []byte("0\n"), nil },
	}
	res, err := gateway.ApplyFlowOffload(t.Context(), false, deps)
	if err != nil {
		t.Fatalf("unexpected error on stubborn driver: %v", err)
	}
	if res.AppliedLive || !res.RebootRequired || !strings.Contains(res.Message, "重启") {
		t.Fatalf("expected RebootRequired=true when kernel hook refuses to flip, got %+v", res)
	}

	unsupported := gateway.FlowOffloadDeps{
		TurboACCConfigPath: filepath.Join(dir, "no-turbo"),
		ProcModulesPath:    filepath.Join(dir, "no-mod"),
		HNATHookTogglePath: filepath.Join(dir, "no-hook"),
		FastClassifierPath: filepath.Join(dir, "no-sfe"),
		IsOpenWrt:          func() bool { return false },
		HasCommand:         func(string) bool { return false },
		ReadFile:           os.ReadFile,
	}
	if st := gateway.ProbeFlowOffloadStatus(t.Context(), unsupported); st.Supported {
		t.Fatalf("expected Supported=false on non-OpenWrt host without offload, got %+v", st)
	}
	if _, err := gateway.ApplyFlowOffload(t.Context(), false, unsupported); err == nil {
		t.Fatal("expected error applying flow offload on unsupported host")
	}
}

func TestFlowOffload_ConcurrentProbeRaceSafe(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "modules"), []byte("xt_FLOWOFFLOAD 16384 0 - Live 0x0\n"), 0644)
	deps := gateway.FlowOffloadDeps{
		BackupPath:         filepath.Join(dir, "backup.json"),
		TurboACCConfigPath: filepath.Join(dir, "no-turbo"),
		ProcModulesPath:    filepath.Join(dir, "modules"),
		HNATHookTogglePath: filepath.Join(dir, "no-hook"),
		FastClassifierPath: filepath.Join(dir, "no-sfe"),
		IsOpenWrt:          func() bool { return true },
		HasCommand:         func(name string) bool { return name == "uci" },
		ReadFile:           os.ReadFile,
		RunCmd:             func(context.Context, string, ...string) ([]byte, error) { return []byte("0\n"), nil },
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			st := gateway.ProbeFlowOffloadStatus(t.Context(), deps)
			if !st.Supported || st.Enabled {
				t.Errorf("unexpected concurrent probe result: %+v", st)
			}
		})
	}
	wg.Wait()
}
