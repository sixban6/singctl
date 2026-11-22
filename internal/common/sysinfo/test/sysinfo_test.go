// 文件职责：验证 sysinfo 发行版识别（OpenWrt/Debian）、磁盘 Statfs、/proc/meminfo 解析、POSIX 时区初始化与字节格式化。
package sysinfo_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"singctl/internal/common/sysinfo"
)

func TestDistroDetection_AtRoot(t *testing.T) {
	owrtRoot := t.TempDir()
	_ = os.MkdirAll(filepath.Join(owrtRoot, "etc"), 0755)
	_ = os.WriteFile(filepath.Join(owrtRoot, "etc", "openwrt_release"), []byte("DISTRIB_ID='ImmortalWrt'\n"), 0644)
	if !sysinfo.IsOpenWrtAt(owrtRoot) {
		t.Fatal("expected IsOpenWrtAt=true when /etc/openwrt_release exists")
	}
	if sysinfo.IsDebianAt(owrtRoot) {
		t.Fatal("expected IsDebianAt=false on OpenWrt root")
	}

	debRoot := t.TempDir()
	_ = os.MkdirAll(filepath.Join(debRoot, "etc"), 0755)
	_ = os.WriteFile(filepath.Join(debRoot, "etc", "os-release"), []byte("ID=ubuntu\nID_LIKE=debian\n"), 0644)
	if !sysinfo.IsDebianAt(debRoot) {
		t.Fatal("expected IsDebianAt=true for ubuntu/debian os-release")
	}
	if sysinfo.IsOpenWrtAt(debRoot) {
		t.Fatal("expected IsOpenWrtAt=false on Debian root")
	}

	// Host helpers must not panic
	_ = sysinfo.IsOpenWrt()
	_ = sysinfo.IsDebian()
}

func TestStatfs_And_MemInfo(t *testing.T) {
	// Non-existent nested path walks up to existing temp parent cleanly
	nestedNonExistent := filepath.Join(t.TempDir(), "not", "created", "yet")
	ds, err := sysinfo.Statfs(nestedNonExistent)
	if runtime.GOOS == "windows" {
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("expected ErrUnsupported on windows, got %v", err)
		}
	} else {
		if err != nil {
			t.Fatalf("Statfs failed: %v", err)
		}
		if ds.TotalBytes == 0 || ds.AvailBytes == 0 {
			t.Fatalf("expected positive disk space on temp dir, got %+v", ds)
		}
	}

	rawMem := `MemTotal:        2048000 kB
MemFree:          256000 kB
Buffers:           64000 kB
Cached:           512000 kB
SwapTotal:       1024000 kB
SwapFree:         512000 kB
`
	mi := sysinfo.ParseMemInfo(rawMem)
	if mi.TotalBytes != 2048000*1024 {
		t.Fatalf("TotalBytes = %d, want %d", mi.TotalBytes, 2048000*1024)
	}
	// Fallback AvailableBytes = Free + Buffers + Cached when MemAvailable is absent (older kernels)
	wantAvail := uint64(256000+64000+512000) * 1024
	if mi.AvailableBytes != wantAvail {
		t.Fatalf("AvailableBytes fallback = %d, want %d", mi.AvailableBytes, wantAvail)
	}
	if mi.SwapFreeBytes != 512000*1024 {
		t.Fatalf("SwapFreeBytes = %d, want %d", mi.SwapFreeBytes, 512000*1024)
	}

	miWithAvail := sysinfo.ParseMemInfo("MemTotal: 1000 kB\nMemAvailable: 600 kB\n")
	if miWithAvail.AvailableBytes != 600*1024 {
		t.Fatalf("AvailableBytes explicit = %d, want %d", miWithAvail.AvailableBytes, 600*1024)
	}
	_, _ = sysinfo.ReadMemInfo()
}

func TestTimezone_POSIXAndOpenWrtFiles(t *testing.T) {
	t.Setenv("TZ", "")
	cases := []struct {
		spec       string
		wantOffset int
		wantNil    bool
	}{
		{"CST-8", 8 * 3600, false},
		{"<+08>-8", 8 * 3600, false},
		{"IST-5:30", 5*3600 + 30*60, false},
		{"EST5EDT,M3.2.0,M11.1.0", -5 * 3600, false},
		{"Asia/Shanghai", 8 * 3600, false},
		{"UTC", 0, false},
		{"", 0, true},
		{"<>invalid", 0, true},
	}
	for _, tc := range cases {
		loc := sysinfo.ParsePOSIXTZLocation(tc.spec)
		if tc.wantNil {
			if loc != nil {
				t.Fatalf("ParsePOSIXTZLocation(%q) = %v, want nil", tc.spec, loc)
			}
			continue
		}
		if loc == nil {
			t.Fatalf("ParsePOSIXTZLocation(%q) = nil", tc.spec)
		}
		_, off := time.Date(2026, 1, 15, 12, 0, 0, 0, loc).Zone()
		if off != tc.wantOffset {
			t.Fatalf("ParsePOSIXTZLocation(%q) offset = %d, want %d", tc.spec, off, tc.wantOffset)
		}
	}

	dir := t.TempDir()
	tzFile := filepath.Join(dir, "TZ")
	uciFile := filepath.Join(dir, "system")
	_ = os.WriteFile(uciFile, []byte("config system\n\toption zonename 'Asia/Tokyo'\n\toption timezone 'JST-9'\n"), 0644)
	loc := sysinfo.ResolveLocalLocationFromFiles(tzFile, uciFile)
	_, off := time.Date(2026, 6, 1, 0, 0, 0, 0, loc).Zone()
	if off != 9*3600 {
		t.Fatalf("ResolveLocalLocationFromFiles offset = %d, want %d", off, 9*3600)
	}
	sysinfo.InitLocalTimezone()
}

func TestFormatBytes_DiskBytes_And_Rate(t *testing.T) {
	if got := sysinfo.FormatBytes(512); got != "512 B" {
		t.Fatalf("FormatBytes(512) = %q", got)
	}
	if got := sysinfo.FormatBytes(2 * 1024 * 1024); got != "2.0 MB" {
		t.Fatalf("FormatBytes(2MB) = %q", got)
	}
	if got := sysinfo.FormatDiskBytes(25 * 1024 * 1024 * 1024); got != "25G" {
		t.Fatalf("FormatDiskBytes(25GB) = %q, want 25G", got)
	}
	if got := sysinfo.FormatRate(125_000_000); got != "1.00 Gbps" {
		t.Fatalf("FormatRate(125MB/s) = %q, want 1.00 Gbps", got)
	}
}
