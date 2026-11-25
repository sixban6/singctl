// 文件职责：测试小内存路由器通用宿主机自适应调优（/tmp 残留大备份清理、sysctl 内存与连接跟踪上限、zram 最优算法、OpenWrt logd/冗余 web 清理与 tailscale 护栏）。
package daemon_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/daemon"
	"singctl/internal/platform/servicemgr"
)

func TestLowMemHostTune_UniversalReconcileAndSafetyGuards(t *testing.T) {
	const mib = 1024 * 1024

	// 1. SelectBestZramCompAlgo prefers zstd > lz4 > lzo-rle
	algoCases := []struct {
		raw  string
		want string
	}{
		{"[lzo] lzo-rle", "lzo-rle"},
		{"lzo [lzo-rle]", ""},
		{"[lzo] lzo-rle lz4 zstd", "zstd"},
		{"[lzo] lz4 lzo-rle", "lz4"},
		{"[zstd] lz4 lzo", ""},
		{"", ""},
	}
	for _, tc := range algoCases {
		if got := daemon.SelectBestZramCompAlgo(tc.raw); got != tc.want {
			t.Fatalf("SelectBestZramCompAlgo(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	// 2. Full end-to-end offline reconcile on a simulated 224MiB OpenWrt router (strictly in t.TempDir())
	root := t.TempDir()
	tmpDir := filepath.Join(root, "tmp")
	procSysDir := filepath.Join(root, "proc", "sys")
	sysctlDir := filepath.Join(root, "etc", "sysctl.d")
	initdDir := filepath.Join(root, "etc", "init.d")
	rcdDir := filepath.Join(root, "etc", "rc.d")
	zramAlgoPath := filepath.Join(root, "sys", "block", "zram0", "comp_algorithm")
	for _, d := range []string{
		tmpDir,
		filepath.Join(procSysDir, "net", "netfilter"),
		filepath.Join(procSysDir, "vm"),
		sysctlDir,
		initdDir,
		rcdDir,
		filepath.Dir(zramAlgoPath),
	} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Seed stale 2MiB binary backups + safe config backups + unrelated large file
	bigBin := bytes.Repeat([]byte("A"), 2*mib)
	stale1 := filepath.Join(tmpDir, "singctl.v182.bak")
	stale2 := filepath.Join(tmpDir, "singctl.v1.14.179.bak")
	stale3 := filepath.Join(tmpDir, "singctl.bak.20261125")
	keepYAML := filepath.Join(tmpDir, "singctl.yaml.v182.bak")
	keepOther := filepath.Join(tmpDir, "other-app.bak")
	for p, data := range map[string][]byte{
		stale1:    bigBin,
		stale2:    bigBin,
		stale3:    bigBin,
		keepYAML:  bytes.Repeat([]byte("y"), 2*mib),
		keepOther: bigBin,
	} {
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Seed proc/sys values typical of 224MiB OpenWrt defaults (plus over-high min_free_kbytes=8192 that causes low-watermark MemAvailable inversion)
	_ = os.WriteFile(filepath.Join(procSysDir, "net", "netfilter", "nf_conntrack_max"), []byte("65536\n"), 0644)
	_ = os.WriteFile(filepath.Join(procSysDir, "vm", "vfs_cache_pressure"), []byte("100\n"), 0644)
	_ = os.WriteFile(filepath.Join(procSysDir, "vm", "min_free_kbytes"), []byte("8192\n"), 0644)
	_ = os.WriteFile(zramAlgoPath, []byte("[lzo] lzo-rle\n"), 0644)

	// Seed OpenWrt tailscale init script + duplicate S80tailscale + redundant S95singctl-web
	tsInit := filepath.Join(initdDir, "tailscale")
	_ = os.WriteFile(tsInit, []byte("#!/bin/sh /etc/rc.common\nUSE_PROCD=1\nstart_service() {\n    procd_open_instance\n    procd_set_param command /usr/sbin/tailscaled\n    procd_close_instance\n}\n"), 0755)
	_ = os.WriteFile(filepath.Join(initdDir, "singctl-web"), []byte("#!/bin/sh /etc/rc.common\n"), 0755)
	_ = os.Symlink("../init.d/tailscale", filepath.Join(rcdDir, "S80tailscale"))
	_ = os.Symlink("../init.d/tailscale", filepath.Join(rcdDir, "S99tailscale"))
	_ = os.Symlink("../init.d/singctl-web", filepath.Join(rcdDir, "S95singctl-web"))

	mockMgr := servicemgr.NewMock()
	var uciCalls []string
	uciState := map[string]string{
		"system.@system[0].log_size":       "512",
		"system.@system[0].zram_comp_algo": "lzo",
	}
	deps := daemon.LowMemHostTuneDeps{
		TotalRAMBytes:       224 * mib,
		IsOpenWrt:           true,
		WebEmbedded:         true,
		TmpDir:              tmpDir,
		ProcSysRoot:         procSysDir,
		SysctlConfPath:      filepath.Join(sysctlDir, "99-singctl-lowmem.conf"),
		ZramCompAlgoPath:    zramAlgoPath,
		TailscaleInitdPath:  tsInit,
		TailscaleSystemd:    filepath.Join(root, "missing.service"),
		OpenWrtRcdDir:       rcdDir,
		ServiceMgr:          mockMgr,
		RestartTailscaleNow: false,
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			uciCalls = append(uciCalls, strings.Join(args, " "))
			if len(args) >= 2 && args[0] == "get" {
				return uciState[args[1]], nil
			}
			if len(args) >= 2 && args[0] == "set" {
				if k, v, ok := strings.Cut(args[1], "="); ok {
					uciState[k] = v
				}
			}
			return "", nil
		},
	}

	res := daemon.ReconcileLowMemHost(t.Context(), deps)
	if res.RemovedTmpBackups != 3 || res.FreedTmpBytes < 6*mib {
		t.Fatalf("expected 3 stale binary backups removed (>=6MiB), got %+v", res)
	}
	for _, gone := range []string{stale1, stale2, stale3} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("expected %s deleted", gone)
		}
	}
	for _, kept := range []string{keepYAML, keepOther} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("expected %s preserved, err=%v", kept, err)
		}
	}

	// Verify sysctl live + persistent file (min_free_kbytes capped <= 4096 to avoid DMA32 low-watermark MemAvailable inversion)
	for rel, want := range map[string]string{
		"net/netfilter/nf_conntrack_max": "16384",
		"vm/vfs_cache_pressure":          "150",
		"vm/min_free_kbytes":             "4096",
	} {
		raw, err := os.ReadFile(filepath.Join(procSysDir, rel))
		if err != nil || strings.TrimSpace(string(raw)) != want {
			t.Fatalf("proc/sys/%s = %q (err=%v), want %q", rel, strings.TrimSpace(string(raw)), err, want)
		}
	}
	sysctlFile, err := os.ReadFile(deps.SysctlConfPath)
	if err != nil || !strings.Contains(string(sysctlFile), "net.netfilter.nf_conntrack_max = 16384") {
		t.Fatalf("expected persisted sysctl conf, got err=%v content:\n%s", err, string(sysctlFile))
	}

	// Verify zram algo + log_size UCI updates + servicemgr calls + tailscale env + redundant web disable
	if uciState["system.@system[0].zram_comp_algo"] != "lzo-rle" {
		t.Fatalf("expected zram_comp_algo=lzo-rle, got %q", uciState["system.@system[0].zram_comp_algo"])
	}
	if uciState["system.@system[0].log_size"] != "64" {
		t.Fatalf("expected log_size=64, got %q", uciState["system.@system[0].log_size"])
	}
	if !res.TailscaleEnvUpdated {
		t.Fatalf("expected TailscaleEnvUpdated=true, got %+v", res)
	}
	if !res.DisabledStandaloneWeb {
		t.Fatalf("expected DisabledStandaloneWeb=true when WebEmbedded && S95singctl-web present")
	}

	// Verify > 512 MiB host is completely untouched (zero-op)
	bigDeps := deps
	bigDeps.TotalRAMBytes = 1024 * mib
	bigRes := daemon.ReconcileLowMemHost(t.Context(), bigDeps)
	if bigRes.AppliedAny() {
		t.Fatalf("expected zero-op on 1GiB host, got %+v", bigRes)
	}
}
