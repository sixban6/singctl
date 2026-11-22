// 文件职责：验证 sysinfo 小闪存阈值常量、IsLowFlashSpace 与 IsLowFlashHostWithDeps 在 128MB OpenWrt、大盘 x86 OpenWrt、普通 VPS 及非 Linux 平台的判定边界。
package sysinfo_test

import (
	"errors"
	"math"
	"os"
	"runtime"
	"sync"
	"testing"

	"singctl/internal/common/sysinfo"
)

func TestLowFlashThresholds_And_IsLowFlashSpace(t *testing.T) {
	const mib uint64 = 1024 * 1024

	if sysinfo.LowFlashTotalThresholdBytes != 160*mib {
		t.Fatalf("LowFlashTotalThresholdBytes = %d, want %d", sysinfo.LowFlashTotalThresholdBytes, 160*mib)
	}
	if sysinfo.LowFlashAvailThresholdBytes != 64*mib {
		t.Fatalf("LowFlashAvailThresholdBytes = %d, want %d", sysinfo.LowFlashAvailThresholdBytes, 64*mib)
	}

	cases := []struct {
		name string
		ds   sysinfo.DiskSpace
		want bool
	}{
		{"zero_unknown_disk_not_low", sysinfo.DiskSpace{}, false},
		{"one_byte_total", sysinfo.DiskSpace{TotalBytes: 1}, true},
		{"n60pro_83mib_overlay_40mib_avail", sysinfo.DiskSpace{TotalBytes: 83 * mib, AvailBytes: 40 * mib}, true},
		{"ax3000t_100mib_overlay_72mib_avail", sysinfo.DiskSpace{TotalBytes: 100 * mib, AvailBytes: 72 * mib}, true},
		{"exact_total_160mib_boundary_high_avail", sysinfo.DiskSpace{TotalBytes: 160 * mib, AvailBytes: 120 * mib}, true},
		{"total_160mib_plus_1_avail_64mib_plus_1", sysinfo.DiskSpace{TotalBytes: 160*mib + 1, AvailBytes: 64*mib + 1}, false},
		{"total_160mib_plus_1_exact_avail_64mib", sysinfo.DiskSpace{TotalBytes: 160*mib + 1, AvailBytes: 64 * mib}, true},
		{"zero_total_avail_64mib", sysinfo.DiskSpace{TotalBytes: 0, AvailBytes: 64 * mib}, true},
		{"zero_total_avail_64mib_plus_1", sysinfo.DiskSpace{TotalBytes: 0, AvailBytes: 64*mib + 1}, false},
		{"large_20gb_disk_50mb_avail_space_helper_true", sysinfo.DiskSpace{TotalBytes: 20 * 1024 * mib, AvailBytes: 50 * mib}, true},
		{"large_20gb_disk_10gb_avail", sysinfo.DiskSpace{TotalBytes: 20 * 1024 * mib, AvailBytes: 10 * 1024 * mib}, false},
		{"max_uint64_disk", sysinfo.DiskSpace{TotalBytes: math.MaxUint64, AvailBytes: math.MaxUint64}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sysinfo.IsLowFlashSpace(tc.ds); got != tc.want {
				t.Fatalf("IsLowFlashSpace(%+v) = %v, want %v", tc.ds, got, tc.want)
			}
		})
	}
}

func TestIsLowFlashHostWithDeps_BoundariesAndAntiFalsePositive(t *testing.T) {
	const (
		mib uint64 = 1024 * 1024
		gib uint64 = 1024 * mib
	)

	cases := []struct {
		name         string
		isOpenWrt    bool
		statfs       func(path string) (sysinfo.DiskSpace, error)
		want         bool
		wantFirstKey string
	}{
		{
			name:      "openwrt_128mb_nand_n60pro_overlay_83mib_40mib",
			isOpenWrt: true,
			statfs: func(path string) (sysinfo.DiskSpace, error) {
				if path == "/overlay" {
					return sysinfo.DiskSpace{TotalBytes: 83 * mib, AvailBytes: 40 * mib}, nil
				}
				return sysinfo.DiskSpace{TotalBytes: 16 * gib, AvailBytes: 12 * gib}, nil
			},
			want:         true,
			wantFirstKey: "/overlay",
		},
		{
			name:      "openwrt_256mb_nand_low_avail_50mib",
			isOpenWrt: true,
			statfs: func(path string) (sysinfo.DiskSpace, error) {
				if path == "/overlay" {
					return sysinfo.DiskSpace{TotalBytes: 200 * mib, AvailBytes: 50 * mib}, nil
				}
				return sysinfo.DiskSpace{}, os.ErrNotExist
			},
			want:         true,
			wantFirstKey: "/overlay",
		},
		{
			name:      "openwrt_overlay_unreadable_falls_back_to_root_low_flash",
			isOpenWrt: true,
			statfs: func(path string) (sysinfo.DiskSpace, error) {
				if path == "/overlay" {
					return sysinfo.DiskSpace{}, os.ErrNotExist
				}
				if path == "/" {
					return sysinfo.DiskSpace{TotalBytes: 96 * mib, AvailBytes: 42 * mib}, nil
				}
				return sysinfo.DiskSpace{}, os.ErrNotExist
			},
			want:         true,
			wantFirstKey: "/overlay",
		},
		{
			name:      "openwrt_x86_n4120_big_overlay_not_low_flash",
			isOpenWrt: true,
			statfs: func(path string) (sysinfo.DiskSpace, error) {
				if path == "/overlay" {
					return sysinfo.DiskSpace{TotalBytes: 16 * gib, AvailBytes: 12 * gib}, nil
				}
				return sysinfo.DiskSpace{TotalBytes: 16 * gib, AvailBytes: 12 * gib}, nil
			},
			want:         false,
			wantFirstKey: "/overlay",
		},
		{
			name:      "openwrt_x86_n4120_no_overlay_falls_back_to_big_root",
			isOpenWrt: true,
			statfs: func(path string) (sysinfo.DiskSpace, error) {
				if path == "/overlay" {
					return sysinfo.DiskSpace{}, os.ErrNotExist
				}
				return sysinfo.DiskSpace{TotalBytes: 32 * gib, AvailBytes: 24 * gib}, nil
			},
			want:         false,
			wantFirstKey: "/overlay",
		},
		{
			name:      "normal_linux_20gb_vps_with_only_50mb_avail_must_NOT_trigger_low_flash",
			isOpenWrt: false,
			statfs: func(path string) (sysinfo.DiskSpace, error) {
				if path == "/" {
					return sysinfo.DiskSpace{TotalBytes: 20 * gib, AvailBytes: 50 * mib}, nil
				}
				return sysinfo.DiskSpace{}, os.ErrNotExist
			},
			want:         false,
			wantFirstKey: "/",
		},
		{
			name:      "normal_linux_vps_ample_disk",
			isOpenWrt: false,
			statfs: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{TotalBytes: 40 * gib, AvailBytes: 30 * gib}, nil
			},
			want:         false,
			wantFirstKey: "/",
		},
		{
			name:      "non_openwrt_embedded_linux_tiny_root_128mib_triggers_low_flash",
			isOpenWrt: false,
			statfs: func(path string) (sysinfo.DiskSpace, error) {
				if path == "/" {
					return sysinfo.DiskSpace{TotalBytes: 128 * mib, AvailBytes: 80 * mib}, nil
				}
				return sysinfo.DiskSpace{}, os.ErrNotExist
			},
			want:         true,
			wantFirstKey: "/",
		},
		{
			name:      "non_openwrt_embedded_exact_160mib_root",
			isOpenWrt: false,
			statfs: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{TotalBytes: 160 * mib, AvailBytes: 100 * mib}, nil
			},
			want:         true,
			wantFirstKey: "/",
		},
		{
			name:      "non_openwrt_160mib_plus_1_root_with_10mb_avail_must_NOT_trigger",
			isOpenWrt: false,
			statfs: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{TotalBytes: 160*mib + 1, AvailBytes: 10 * mib}, nil
			},
			want:         false,
			wantFirstKey: "/",
		},
		{
			name:      "unsupported_statfs_platform_returns_false",
			isOpenWrt: false,
			statfs: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{}, errors.ErrUnsupported
			},
			want:         false,
			wantFirstKey: "/",
		},
		{
			name:      "openwrt_both_statfs_fail_returns_false",
			isOpenWrt: true,
			statfs: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{}, errors.New("permission denied")
			},
			want:         false,
			wantFirstKey: "/overlay",
		},
		{
			name:      "zero_disk_space_returns_false",
			isOpenWrt: true,
			statfs: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{}, nil
			},
			want:         false,
			wantFirstKey: "/overlay",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var queried []string
			got := sysinfo.IsLowFlashHostWithDeps(
				func() bool { return tc.isOpenWrt },
				func(p string) (sysinfo.DiskSpace, error) {
					queried = append(queried, p)
					return tc.statfs(p)
				},
			)
			if got != tc.want {
				t.Fatalf("IsLowFlashHostWithDeps() = %v, want %v (queried=%v)", got, tc.want, queried)
			}
			if tc.wantFirstKey != "" && (len(queried) == 0 || queried[0] != tc.wantFirstKey) {
				t.Fatalf("expected first statfs path %q, got %v", tc.wantFirstKey, queried)
			}
		})
	}

	t.Run("non_linux_host_and_concurrent_safety", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				got := sysinfo.IsLowFlashHost()
				if runtime.GOOS != "linux" && got {
					t.Errorf("expected IsLowFlashHost()=false on non-linux %s", runtime.GOOS)
				}
				_ = sysinfo.IsLowFlashHostWithDeps(nil, func(string) (sysinfo.DiskSpace, error) {
					return sysinfo.DiskSpace{TotalBytes: 20 * gib, AvailBytes: 10 * gib}, nil
				})
			})
		}
		wg.Wait()
	})
}
