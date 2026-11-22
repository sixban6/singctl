// 文件职责：验证宿主机零阻塞实时资源遥测解析函数、并发安全 CPUSampler 差值计算及 CollectHostTelemetryWithDeps 全边界行为。
package sysinfo_test

import (
	"encoding/json"
	"errors"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/common/sysinfo"
)

func TestParseUptime_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    int64
		wantErr bool
	}{
		{"normal_linux_proc_uptime", "123456.78 234567.89\n", 123456, false},
		{"zero_uptime", "0.00 0.00", 0, false},
		{"integer_single_field", "  86400 \n", 86400, false},
		{"subsecond_uptime", "0.99 0.50", 0, false},
		{"very_large_uptime", "315360000.5 100.0", 315360000, false},
		{"empty_string", "", 0, true},
		{"whitespace_only", "   \t\n ", 0, true},
		{"non_numeric", "abc 123.4", 0, true},
		{"negative_value", "-12.5 10.0", 0, true},
		{"nan_value", "NaN 10.0", 0, true},
		{"inf_value", "+Inf 10.0", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sysinfo.ParseUptime(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseUptime(%q) = %d, want error", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseUptime(%q) unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("ParseUptime(%q) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseLoadAvg_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    [3]float64
		wantErr bool
	}{
		{"normal_linux_loadavg", "0.15 0.22 0.18 1/123 4567\n", [3]float64{0.15, 0.22, 0.18}, false},
		{"exact_three_fields", "1.50 2.75 3.00", [3]float64{1.5, 2.75, 3.0}, false},
		{"zero_load", "0.00 0.00 0.00 1/64 99", [3]float64{0, 0, 0}, false},
		{"empty_string", "", [3]float64{}, true},
		{"too_few_fields", "0.15 0.22", [3]float64{}, true},
		{"invalid_number", "0.15 bad 0.18 1/12 9", [3]float64{}, true},
		{"negative_load", "0.15 -0.1 0.18", [3]float64{}, true},
		{"nan_load", "NaN 0.1 0.2", [3]float64{}, true},
		{"inf_load", "0.1 Inf 0.2", [3]float64{}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sysinfo.ParseLoadAvg(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseLoadAvg(%q) = %v, want error", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLoadAvg(%q) unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("ParseLoadAvg(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseCPUStat_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    sysinfo.CPUSample
		wantErr bool
	}{
		{
			name: "full_10_columns_ignores_guest_double_count",
			raw: "cpu  100 20 30 800 50 10 5 5 12 3\n" +
				"cpu0 50 10 15 400 25 5 2 2 6 1\n",
			// total = 100+20+30+800+50+10+5+5 = 1020; idle = 800+50 = 850
			want: sysinfo.CPUSample{Total: 1020, Idle: 850},
		},
		{
			name: "minimal_4_columns_without_iowait",
			raw:  "cpu 100 50 50 300\n",
			want: sysinfo.CPUSample{Total: 500, Idle: 300},
		},
		{
			name: "cpu_summary_after_blank_lines",
			raw:  "\n\n  cpu   10 0 20 60 10\nintr 123\n",
			want: sysinfo.CPUSample{Total: 100, Idle: 70},
		},
		{
			name:    "only_cpu0_no_aggregate_line",
			raw:     "cpu0 10 20 30 40 50\n",
			wantErr: true,
		},
		{
			name:    "empty_input",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "too_few_columns",
			raw:     "cpu 10 20 30\n",
			wantErr: true,
		},
		{
			name:    "corrupt_counter",
			raw:     "cpu 10 20 oops 40 50\n",
			wantErr: true,
		},
		{
			name:    "negative_counter",
			raw:     "cpu 10 -5 30 40 50\n",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sysinfo.ParseCPUStat(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseCPUStat(%q) = %+v, want error", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCPUStat(%q) unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("ParseCPUStat(%q) = %+v, want %+v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestCPUSampler_ZeroBlockDeltaPrimeEdgeCasesAndRace(t *testing.T) {
	t.Run("nil_sampler_safe", func(t *testing.T) {
		var s *sysinfo.CPUSampler
		s.Prime()
		if pct, ok := s.SamplePercent(); ok || pct != 0 {
			t.Fatalf("nil sampler returned (%v, %v), want (0, false)", pct, ok)
		}
	})

	t.Run("first_sample_sets_baseline_second_returns_exact_delta", func(t *testing.T) {
		seq := []string{
			"cpu 100 0 0 900 0 0 0 0 0 0\n",  // total=1000, idle=900
			"cpu 225 0 25 1150 0 0 0 0 0 0\n", // total=1400 (d=400), idle=1150 (d=250) -> busy=150/400 = 37.5%
			"cpu 225 0 25 1150 0 0 0 0 0 0\n", // deltaTotal=0 -> (0, false)
			"cpu 525 0 25 1150 0 0 0 0 0 0\n", // total=1700 (d=300), idle=1150 (d=0) -> 100.0%
			"cpu 525 0 25 1250 0 0 0 0 0 0\n", // total=1800 (d=100), idle=1250 (d=100) -> 0.0%
			"cpu 10 0 0 90 0 0 0 0 0 0\n",     // counter reset total<prev -> (0, false)
			"cpu 43 0 0 157 0 0 0 0 0 0\n",    // total=200 (d=100), idle=157 (d=67) -> 33.0%
		}
		var idx int
		sampler := sysinfo.NewCPUSamplerWithReader(func() (string, error) {
			if idx >= len(seq) {
				return "", errors.New("eof")
			}
			v := seq[idx]
			idx++
			return v, nil
		})

		start := time.Now()
		if pct, ok := sampler.SamplePercent(); ok || pct != 0 {
			t.Fatalf("first sample = (%v, %v), want (0, false)", pct, ok)
		}
		if pct, ok := sampler.SamplePercent(); !ok || pct != 37.5 {
			t.Fatalf("second sample = (%v, %v), want (37.5, true)", pct, ok)
		}
		if pct, ok := sampler.SamplePercent(); ok || pct != 0 {
			t.Fatalf("zero-delta sample = (%v, %v), want (0, false)", pct, ok)
		}
		if pct, ok := sampler.SamplePercent(); !ok || pct != 100.0 {
			t.Fatalf("full-busy sample = (%v, %v), want (100.0, true)", pct, ok)
		}
		if pct, ok := sampler.SamplePercent(); !ok || pct != 0.0 {
			t.Fatalf("full-idle sample = (%v, %v), want (0.0, true)", pct, ok)
		}
		if pct, ok := sampler.SamplePercent(); ok || pct != 0 {
			t.Fatalf("counter-reset sample = (%v, %v), want (0, false)", pct, ok)
		}
		if pct, ok := sampler.SamplePercent(); !ok || pct != 33.0 {
			t.Fatalf("post-reset sample = (%v, %v), want (33.0, true)", pct, ok)
		}
		// Must never sleep
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("CPUSampler took %v, expected zero-block execution", elapsed)
		}
	})

	t.Run("prime_enables_first_request_and_is_idempotent", func(t *testing.T) {
		seq := []string{
			"cpu 100 0 0 900 0\n",             // Prime baseline: total=1000, idle=900
			"cpu 100 0 0 900 0\n",             // Second Prime ignored (already primed)
			"cpu 133 0 0 967 0\n",             // First SamplePercent: dTotal=100, dIdle=67 -> 33.0% (or rounding check)
			"cpu 134 0 0 969 0\n",             // dTotal=3, dIdle=2 -> 1/3*100 = 33.333... -> 33.3
		}
		var idx int
		sampler := sysinfo.NewCPUSamplerWithReader(func() (string, error) {
			v := seq[idx]
			idx++
			return v, nil
		})
		sampler.Prime()
		sampler.Prime() // idempotent: must not advance or wipe baseline
		if idx != 1 {
			t.Fatalf("second Prime should be no-op once baseline exists, read count = %d", idx)
		}
		// Reset idx to point directly to sample 2 ("cpu 133...") to verify baseline stayed intact
		idx = 2
		if pct, ok := sampler.SamplePercent(); !ok || pct != 33.0 {
			t.Fatalf("first SamplePercent after Prime = (%v, %v), want (33.0, true)", pct, ok)
		}
		if pct, ok := sampler.SamplePercent(); !ok || pct != 33.3 {
			t.Fatalf("rounding SamplePercent = (%v, %v), want (33.3, true)", pct, ok)
		}
	})

	t.Run("read_error_and_anomalous_idle_clamped", func(t *testing.T) {
		call := 0
		sampler := sysinfo.NewCPUSamplerWithReader(func() (string, error) {
			call++
			switch call {
			case 1:
				return "", errors.New("io error")
			case 2:
				return "cpu 100 0 0 500 0\n", nil // total=600, idle=500
			case 3:
				return "cpu 100 0 0 700 0\n", nil // total=800 (d=200), idle=700 (d=200) -> 0.0%
			case 4:
				return "cpu 500 0 0 600 0\n", nil // total=1100 (d=300), idle decreased 700->600 -> clamp to 100.0%
			default:
				return "bad data", nil
			}
		})
		if pct, ok := sampler.SamplePercent(); ok || pct != 0 {
			t.Fatalf("error read = (%v, %v), want (0, false)", pct, ok)
		}
		if pct, ok := sampler.SamplePercent(); ok || pct != 0 {
			t.Fatalf("baseline read = (%v, %v), want (0, false)", pct, ok)
		}
		if pct, ok := sampler.SamplePercent(); !ok || pct != 0.0 {
			t.Fatalf("all idle read = (%v, %v), want (0.0, true)", pct, ok)
		}
		if pct, ok := sampler.SamplePercent(); !ok || pct != 100.0 {
			t.Fatalf("idle decrease clamp = (%v, %v), want (100.0, true)", pct, ok)
		}
		if pct, ok := sampler.SamplePercent(); ok || pct != 0 {
			t.Fatalf("corrupt read = (%v, %v), want (0, false)", pct, ok)
		}
	})

	t.Run("concurrent_race_safety", func(t *testing.T) {
		var tick atomic.Uint64
		sampler := sysinfo.NewCPUSamplerWithReader(func() (string, error) {
			n := tick.Add(1)
			busy := n * 25
			idle := n * 75
			return "cpu " + u64(busy) + " 0 0 " + u64(idle) + " 0\n", nil
		})
		var wg sync.WaitGroup
		for range 12 {
			wg.Go(func() {
				sampler.Prime()
				for range 20 {
					pct, ok := sampler.SamplePercent()
					if ok && (pct < 0 || pct > 100 || math.IsNaN(pct)) {
						t.Errorf("out-of-range pct=%v", pct)
					}
				}
			})
		}
		wg.Wait()
	})
}

func u64(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func TestCollectHostTelemetryWithDeps_OpenWrtLinuxFallbackAndJSON(t *testing.T) {
	const mib = 1024 * 1024
	fixedTime := time.Unix(1760000000, 0)

	t.Run("openwrt_prefers_overlay_and_reads_tmp_with_real_mem_excluding_cache", func(t *testing.T) {
		reads := 0
		sampler := sysinfo.NewCPUSamplerWithReader(func() (string, error) {
			reads++
			if reads == 1 {
				return "cpu 100 0 0 900 0\n", nil
			}
			return "cpu 120 0 5 975 0\n", nil // dTotal=100, dIdle=75 -> 25.0%
		})
		sampler.Prime()

		deps := sysinfo.TelemetryDeps{
			ReadUptimeSec: func() int64 { return 98765 },
			ReadLoadAvg:   func() [3]float64 { return [3]float64{0.42, 0.35, 0.28} },
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				// 512MiB total, 300MiB available (cache already excluded from Used!), 64MiB swap with 16MiB used
				return sysinfo.MemInfo{
					TotalBytes:     512 * mib,
					FreeBytes:      64 * mib,
					AvailableBytes: 300 * mib,
					CachedBytes:    200 * mib,
					SwapTotalBytes: 64 * mib,
					SwapFreeBytes:  48 * mib,
				}, nil
			},
			Statfs: func(path string) (sysinfo.DiskSpace, error) {
				switch path {
				case "/overlay":
					return sysinfo.DiskSpace{TotalBytes: 64 * mib, UsedBytes: 16 * mib, AvailBytes: 48 * mib, UsedPercent: 25}, nil
				case "/tmp":
					return sysinfo.DiskSpace{TotalBytes: 256 * mib, UsedBytes: 12 * mib, AvailBytes: 244 * mib, UsedPercent: 5}, nil
				default:
					return sysinfo.DiskSpace{}, errors.New("unexpected path " + path)
				}
			},
			IsOpenWrt: func() bool { return true },
			NumCPU:    func() int { return 4 },
			Now:       func() time.Time { return fixedTime },
		}

		got := sysinfo.CollectHostTelemetryWithDeps(sampler, deps)
		if got.UptimeSec != 98765 || got.CPUCores != 4 || !got.CPUReady || got.CPUPercent != 25.0 {
			t.Fatalf("unexpected CPU/Uptime: %+v", got)
		}
		if got.LoadAvg != ([3]float64{0.42, 0.35, 0.28}) {
			t.Fatalf("LoadAvg = %v", got.LoadAvg)
		}
		// UsedBytes must be Total - Avail = 212 MiB (not Total - Free!)
		if got.Mem.TotalBytes != 512*mib || got.Mem.AvailBytes != 300*mib || got.Mem.UsedBytes != 212*mib {
			t.Fatalf("unexpected MemTelemetry: %+v", got.Mem)
		}
		if got.Mem.UsedPercent != 41 || !got.Mem.LowMemory {
			t.Fatalf("Mem UsedPercent=%d LowMemory=%v, want 41, true", got.Mem.UsedPercent, got.Mem.LowMemory)
		}
		if got.Mem.SwapTotalBytes != 64*mib || got.Mem.SwapUsedBytes != 16*mib {
			t.Fatalf("unexpected Swap: %+v", got.Mem)
		}
		if got.Disk.MountPath != "/overlay" || got.Disk.Label != "闪存 (/overlay)" || got.Disk.UsedPercent != 25 {
			t.Fatalf("unexpected primary OpenWrt disk: %+v", got.Disk)
		}
		if got.TmpDisk == nil || got.TmpDisk.MountPath != "/tmp" || got.TmpDisk.Label != "内存盘 (/tmp)" || got.TmpDisk.UsedPercent != 5 {
			t.Fatalf("unexpected TmpDisk: %+v", got.TmpDisk)
		}
		if !got.IsOpenWrt || got.CollectedAt != fixedTime.Unix() {
			t.Fatalf("IsOpenWrt=%v CollectedAt=%d", got.IsOpenWrt, got.CollectedAt)
		}

		// Verify clean JSON tags
		rawJSON, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(rawJSON, &m); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		for _, key := range []string{"uptimeSec", "cpuCores", "cpuPercent", "cpuReady", "loadAvg", "mem", "disk", "tmpDisk", "isOpenWrt", "collectedAt"} {
			if _, ok := m[key]; !ok {
				t.Errorf("missing expected JSON field %q in %s", key, string(rawJSON))
			}
		}
	})

	t.Run("openwrt_overlay_unavailable_falls_back_to_root_and_linux_non_openwrt", func(t *testing.T) {
		deps := sysinfo.TelemetryDeps{
			ReadUptimeSec: func() int64 { return 60 },
			ReadLoadAvg:   func() [3]float64 { return [3]float64{0.1, 0.2, 0.3} },
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				// Edge case: Avail > Total and SwapFree > SwapTotal must not underflow
				return sysinfo.MemInfo{
					TotalBytes:     2048 * mib,
					AvailableBytes: 4096 * mib,
					SwapTotalBytes: 100,
					SwapFreeBytes:  200,
				}, nil
			},
			Statfs: func(path string) (sysinfo.DiskSpace, error) {
				if path == "/overlay" {
					return sysinfo.DiskSpace{}, errors.New("no overlay")
				}
				if path == "/" {
					return sysinfo.DiskSpace{TotalBytes: 10 * 1024 * mib, UsedBytes: 2 * 1024 * mib, AvailBytes: 8 * 1024 * mib, UsedPercent: 20}, nil
				}
				return sysinfo.DiskSpace{}, errors.ErrUnsupported
			},
			IsOpenWrt: func() bool { return true },
			NumCPU:    func() int { return 2 },
			Now:       func() time.Time { return fixedTime },
		}

		got := sysinfo.CollectHostTelemetryWithDeps(nil, deps)
		if got.CPUReady || got.CPUPercent != 0 {
			t.Fatalf("nil sampler should yield CPUReady=false, got %+v", got)
		}
		if got.Mem.UsedBytes != 0 || got.Mem.AvailBytes != 2048*mib || got.Mem.SwapUsedBytes != 0 || got.Mem.LowMemory {
			t.Fatalf("edge-case mem underflow check failed: %+v", got.Mem)
		}
		if got.Disk.MountPath != "/" || got.Disk.Label != "根分区 (/)" {
			t.Fatalf("expected fallback to root disk, got %+v", got.Disk)
		}
		if got.TmpDisk != nil {
			t.Fatalf("expected TmpDisk=nil when /tmp statfs unsupported, got %+v", got.TmpDisk)
		}
	})

	t.Run("all_deps_errors_graceful_and_host_defaults_no_panic", func(t *testing.T) {
		deps := sysinfo.TelemetryDeps{
			ReadUptimeSec: func() int64 { return 0 },
			ReadLoadAvg:   func() [3]float64 { return [3]float64{} },
			ReadMemInfo:   func() (sysinfo.MemInfo, error) { return sysinfo.MemInfo{}, errors.New("denied") },
			Statfs:        func(string) (sysinfo.DiskSpace, error) { return sysinfo.DiskSpace{}, errors.New("denied") },
			IsOpenWrt:     func() bool { return false },
			NumCPU:        func() int { return 1 },
			Now:           func() time.Time { return fixedTime },
		}
		got := sysinfo.CollectHostTelemetryWithDeps(nil, deps)
		if got.Mem.TotalBytes != 0 || got.Disk.TotalBytes != 0 || got.TmpDisk != nil {
			t.Fatalf("expected clean zero metrics on errors, got %+v", got)
		}

		// Production host helpers must compile and never panic on macOS/Windows/Linux
		s := sysinfo.NewCPUSampler()
		s.Prime()
		_ = sysinfo.ReadUptimeSec()
		_ = sysinfo.ReadLoadAvg()
		_, err := sysinfo.ReadCPUStat()
		if runtime.GOOS != "linux" && err == nil {
			t.Fatalf("expected non-nil error from ReadCPUStat on %s", runtime.GOOS)
		}
		hostTel := sysinfo.CollectHostTelemetry(s)
		if hostTel.CPUCores <= 0 || hostTel.CollectedAt <= 0 {
			t.Fatalf("expected valid host CPUCores and CollectedAt, got %+v", hostTel)
		}
	})
}
