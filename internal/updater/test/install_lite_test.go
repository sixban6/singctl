// 文件职责：验证 install.sh 在 OpenWrt 低内存/小闪存及 --lite 下的精简包优先选择与缺失时平滑回退标准包。
package updater_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func resolveRepoInstallSh(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "install.sh"))
	if err != nil {
		t.Fatalf("resolve install.sh: %v", err)
	}
	return p
}

func TestInstallScript_LitePackageSelectionAndFallback(t *testing.T) {
	installSh := resolveRepoInstallSh(t)

	runBuildURL := func(t *testing.T, osName, arch, isOpenWrt, preRole, memInfo, diskAvailKB string, cliArgs ...string) string {
		t.Helper()
		dir := t.TempDir()
		rootfs := filepath.Join(dir, "rootfs")
		if err := os.MkdirAll(filepath.Join(rootfs, "proc"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0755); err != nil {
			t.Fatal(err)
		}
		memPath := filepath.Join(rootfs, "proc", "meminfo")
		if memInfo != "" {
			if err := os.WriteFile(memPath, []byte(memInfo), 0644); err != nil {
				t.Fatal(err)
			}
		}
		if isOpenWrt == "true" {
			_ = os.WriteFile(filepath.Join(rootfs, "etc", "openwrt_release"), []byte("DISTRIB_ID='ImmortalWrt'\n"), 0644)
		}

		harness := filepath.Join(dir, "check_url.sh")
		script := fmt.Sprintf(`#!/bin/sh
set -e
export SINGCTL_INSTALL_LIB_ONLY=1
export SINGCTL_ROOT_PREFIX=%q
export SINGCTL_MEMINFO_PATH=%q
export SINGCTL_MOCK_DISK_AVAIL_KB=%q
. %q
OS=%q
ARCH=%q
IS_OPENWRT=%q
PRE_EXISTING_ROLE=%q
LATEST_VERSION="v1.14.200"
build_download_url "$@"
printf "PKG=%%s FALLBACK=%%s\n" "$PACKAGE_FILENAME" "${FALLBACK_PACKAGE_FILENAME:-}"
`, rootfs, memPath, diskAvailKB, installSh, osName, arch, isOpenWrt, preRole)
		if err := os.WriteFile(harness, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}

		out, err := exec.CommandContext(t.Context(), "sh", append([]string{harness}, cliArgs...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("build_download_url failed: %v\nOutput:\n%s", err, string(out))
		}
		return string(out)
	}

	// 1. Real n60pro profile: OpenWrt arm64, MemTotal=491040 kB, MemAvailable=210260 kB, /overlay=51916 kB
	outN60 := runBuildURL(t, "linux", "arm64", "true", "", "MemTotal: 491040 kB\nMemAvailable: 210260 kB\n", "51916")
	if !strings.Contains(outN60, "PKG=singctl-linux-arm64-lite.tar.gz FALLBACK=singctl-linux-arm64.tar.gz") {
		t.Fatalf("expected n60pro OpenWrt to auto-select -lite with standard fallback, got:\n%s", outN60)
	}

	// 2. OpenWrt with 1GB RAM but small flash (< 100MB = 65536 KiB) still picks -lite
	outSmallFlash := runBuildURL(t, "linux", "amd64", "true", "", "MemTotal: 1048576 kB\nMemAvailable: 800000 kB\n", "65536")
	if !strings.Contains(outSmallFlash, "PKG=singctl-linux-amd64-lite.tar.gz FALLBACK=singctl-linux-amd64.tar.gz") {
		t.Fatalf("expected small-flash OpenWrt to auto-select -lite, got:\n%s", outSmallFlash)
	}

	// 3. OpenWrt with 2GB RAM and 2GB disk picks standard package unless --lite is passed
	outBigRouter := runBuildURL(t, "linux", "amd64", "true", "", "MemTotal: 2097152 kB\nMemAvailable: 1800000 kB\n", "2097152")
	if !strings.Contains(outBigRouter, "PKG=singctl-linux-amd64.tar.gz FALLBACK=") {
		t.Fatalf("expected 2GB RAM/disk OpenWrt to pick standard package, got:\n%s", outBigRouter)
	}
	outExplicitLite := runBuildURL(t, "linux", "amd64", "false", "", "MemTotal: 4194304 kB\nMemAvailable: 3500000 kB\n", "10485760", "--lite")
	if !strings.Contains(outExplicitLite, "PKG=singctl-linux-amd64-lite.tar.gz") {
		t.Fatalf("expected --lite to select -lite package on linux, got:\n%s", outExplicitLite)
	}

	// 4. Server role NEVER auto-picks -lite (needs serverweb embedded UI)
	outServer := runBuildURL(t, "linux", "amd64", "false", "server", "MemTotal: 491040 kB\nMemAvailable: 210260 kB\n", "512000")
	if !strings.Contains(outServer, "PKG=singctl-linux-amd64.tar.gz FALLBACK=") {
		t.Fatalf("expected server role to always keep standard package, got:\n%s", outServer)
	}

	// 5. Fallback verification: when -lite returns 404 across all sources, download_and_extract smoothly falls back to standard tar.gz + verifies sha256!
	dir := t.TempDir()
	stdTarBytes, stdSHA := buildTestSingCtlTarGz(t, map[string]string{
		"singctl-linux-arm64/singctl": "#!/bin/sh\necho fallback-ok\n",
	})
	stdServePath := filepath.Join(dir, "std.tar.gz")
	checksumsServePath := filepath.Join(dir, "checksums.txt")
	_ = os.WriteFile(stdServePath, stdTarBytes, 0644)
	_ = os.WriteFile(checksumsServePath, []byte(fmt.Sprintf("%s  singctl-linux-arm64.tar.gz\n", stdSHA)), 0644)

	binDir := filepath.Join(dir, "mock-bin")
	_ = os.MkdirAll(binDir, 0755)
	mockCurl := fmt.Sprintf(`#!/bin/sh
out=""
url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) shift; out="$1" ;;
        http*://*) url="$1" ;;
    esac
    shift
done
case "$url" in
    *singctl-linux-arm64-lite.tar.gz)
        exit 22
        ;;
    *singctl-linux-arm64.tar.gz)
        cp %q "$out"
        exit 0
        ;;
    *checksums.txt)
        cp %q "$out"
        exit 0
        ;;
esac
exit 22
`, stdServePath, checksumsServePath)
	_ = os.WriteFile(filepath.Join(binDir, "curl"), []byte(mockCurl), 0755)

	extractTemp := filepath.Join(dir, "tmp-install")
	fallbackHarness := filepath.Join(dir, "fallback_test.sh")
	fallbackScript := fmt.Sprintf(`#!/bin/sh
set -e
export PATH=%q:"$PATH"
export SINGCTL_INSTALL_LIB_ONLY=1
. %q
OS="linux"
ARCH="arm64"
IS_OPENWRT="true"
LATEST_VERSION="v1.14.200"
TEMP_DIR=%q
build_download_url --lite
download_and_extract
printf "FINAL_PKG=%%s\n" "$PACKAGE_FILENAME"
`, binDir, installSh, extractTemp)
	_ = os.WriteFile(fallbackHarness, []byte(fallbackScript), 0755)

	fbOut, err := exec.CommandContext(t.Context(), "sh", fallbackHarness).CombinedOutput()
	if err != nil {
		t.Fatalf("download_and_extract fallback failed: %v\nOutput:\n%s", err, string(fbOut))
	}
	if !strings.Contains(string(fbOut), "FINAL_PKG=singctl-linux-arm64.tar.gz") {
		t.Fatalf("expected fallback to singctl-linux-arm64.tar.gz, got:\n%s", string(fbOut))
	}
	if _, err := os.Stat(filepath.Join(extractTemp, "singctl.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("expected tar.gz archive to be removed from TEMP_DIR immediately after extraction")
	}
}
