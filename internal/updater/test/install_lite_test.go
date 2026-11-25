// 文件职责：验证 install.sh 在 OpenWrt 低内存/小闪存及 --lite 下的精简包优先选择与缺失时平滑回退标准包。
package updater_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"singctl/internal/config"
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

func TestInstallScript_SlowDirectCircuitBreakerAndMirrorAffinity(t *testing.T) {
	installSh := resolveRepoInstallSh(t)
	dir := t.TempDir()

	stdTarBytes, stdSHA := buildTestSingCtlTarGz(t, map[string]string{
		"singctl-linux-arm64/singctl": "#!/bin/sh\necho ok\n",
	})
	stdServePath := filepath.Join(dir, "std.tar.gz")
	checksumsServePath := filepath.Join(dir, "checksums.txt")
	if err := os.WriteFile(stdServePath, stdTarBytes, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checksumsServePath, []byte(fmt.Sprintf("%s  singctl-linux-arm64.tar.gz\n", stdSHA)), 0644); err != nil {
		t.Fatal(err)
	}

	binDir := filepath.Join(dir, "mock-bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	tracePath := filepath.Join(dir, "curl-trace.log")

	mockCurl := fmt.Sprintf(`#!/bin/sh
echo "CALL $*" >> %q
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
    https://ghfast.top/https://api.github.com/*)
        printf '{"tag_name": "v1.14.195"}\n'
        exit 0
        ;;
    https://ghfast.top/https://github.com/*/singctl-linux-arm64.tar.gz)
        cp %q "$out"
        exit 0
        ;;
    https://ghfast.top/https://github.com/*/checksums.txt)
        cp %q "$out"
        exit 0
        ;;
    https://api.github.com/*|https://github.com/*)
        exit 28
        ;;
esac
exit 22
`, tracePath, stdServePath, checksumsServePath)
	if err := os.WriteFile(filepath.Join(binDir, "curl"), []byte(mockCurl), 0755); err != nil {
		t.Fatal(err)
	}

	t.Run("mirror_affinity_from_get_latest_version_skips_direct_download_and_checksums", func(t *testing.T) {
		_ = os.WriteFile(tracePath, nil, 0644)
		tmpInstall := filepath.Join(dir, "tmp-a")
		harness := filepath.Join(dir, "case_a.sh")
		script := fmt.Sprintf(`#!/bin/sh
set -e
export PATH=%q:"$PATH"
export SINGCTL_INSTALL_LIB_ONLY=1
. %q
OS="linux"
ARCH="arm64"
IS_OPENWRT="false"
TEMP_DIR=%q
get_latest_version
printf "AFTER_VERSION_PREFER_MIRROR=%%s\n" "${PREFER_MIRROR:-}"
build_download_url --full
download_and_extract
printf "FINAL_PREFER_MIRROR=%%s\n" "${PREFER_MIRROR:-}"
`, binDir, installSh, tmpInstall)
		_ = os.WriteFile(harness, []byte(script), 0755)
		out, err := exec.CommandContext(t.Context(), "sh", harness).CombinedOutput()
		if err != nil {
			t.Fatalf("case_a harness failed: %v\nOutput:\n%s", err, string(out))
		}
		if !strings.Contains(string(out), "AFTER_VERSION_PREFER_MIRROR=true") {
			t.Fatalf("expected PREFER_MIRROR=true after get_latest_version fell back to ghfast.top, got:\n%s", string(out))
		}
		traceBytes, _ := os.ReadFile(tracePath)
		trace := string(traceBytes)
		if strings.Contains(trace, "CALL ") && strings.Contains(trace, " https://github.com/sixban6/singctl/releases/download/") {
			for line := range strings.SplitSeq(trace, "\n") {
				if strings.Contains(line, "https://github.com/sixban6/singctl/releases/download/") &&
					!strings.Contains(line, "https://ghfast.top/") &&
					!strings.Contains(line, "https://gh-proxy.com/") {
					t.Fatalf("expected mirror affinity to skip direct download/checksums URL, trace line:\n%s", line)
				}
			}
		}
		if !strings.Contains(trace, "https://ghfast.top/https://github.com/sixban6/singctl/releases/download/v1.14.195/singctl-linux-arm64.tar.gz") ||
			!strings.Contains(trace, "https://ghfast.top/https://github.com/sixban6/singctl/releases/download/v1.14.195/checksums.txt") {
			t.Fatalf("expected ghfast.top mirror calls in trace, got:\n%s", trace)
		}
	})

	t.Run("direct_download_enforces_speed_limit_circuit_breaker_and_sets_mirror_affinity", func(t *testing.T) {
		_ = os.WriteFile(tracePath, nil, 0644)
		tmpInstall := filepath.Join(dir, "tmp-b")
		harness := filepath.Join(dir, "case_b.sh")
		script := fmt.Sprintf(`#!/bin/sh
set -e
export PATH=%q:"$PATH"
export SINGCTL_INSTALL_LIB_ONLY=1
. %q
OS="linux"
ARCH="arm64"
IS_OPENWRT="false"
LATEST_VERSION="v1.14.195"
PREFER_MIRROR="false"
TEMP_DIR=%q
build_download_url --full
download_and_extract
printf "PREFER_MIRROR=%%s\n" "${PREFER_MIRROR:-}"
`, binDir, installSh, tmpInstall)
		_ = os.WriteFile(harness, []byte(script), 0755)
		out, err := exec.CommandContext(t.Context(), "sh", harness).CombinedOutput()
		if err != nil {
			t.Fatalf("case_b harness failed: %v\nOutput:\n%s", err, string(out))
		}
		if !strings.Contains(string(out), "PREFER_MIRROR=true") {
			t.Fatalf("expected PREFER_MIRROR=true after direct download fallback, got:\n%s", string(out))
		}
		traceBytes, _ := os.ReadFile(tracePath)
		trace := string(traceBytes)
		foundCircuitBreaker := false
		for line := range strings.SplitSeq(trace, "\n") {
			if strings.Contains(line, "https://github.com/sixban6/singctl/releases/download/v1.14.195/singctl-linux-arm64.tar.gz") &&
				!strings.Contains(line, "ghfast.top") &&
				strings.Contains(line, "--speed-limit 102400") &&
				strings.Contains(line, "--speed-time 5") {
				foundCircuitBreaker = true
			}
			if strings.Contains(line, "https://github.com/sixban6/singctl/releases/download/v1.14.195/checksums.txt") &&
				!strings.Contains(line, "ghfast.top") &&
				!strings.Contains(line, "gh-proxy.com") {
				t.Fatalf("expected verify_checksum to reuse mirror affinity without retrying direct checksums.txt:\n%s", trace)
			}
		}
		if !foundCircuitBreaker {
			t.Fatalf("expected direct curl invocation to carry --speed-limit 102400 --speed-time 5, got trace:\n%s", trace)
		}
	})
}

func TestInstallScript_WriteGatewayConfigPreserves4SpaceAndHealsMixedIndentation(t *testing.T) {
	installSh := resolveRepoInstallSh(t)

	runWriteGateway := func(t *testing.T, initialYAML, mode, mainIP string) []byte {
		t.Helper()
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "singctl.yaml")
		if err := os.WriteFile(cfgPath, []byte(initialYAML), 0644); err != nil {
			t.Fatal(err)
		}
		harness := filepath.Join(dir, "write_gw.sh")
		script := fmt.Sprintf(`#!/bin/sh
set -e
export SINGCTL_INSTALL_LIB_ONLY=1
. %q
CONFIG_FILE=%q
write_gateway_config %q %q
`, installSh, cfgPath, mode, mainIP)
		if err := os.WriteFile(harness, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
		out, err := exec.CommandContext(t.Context(), "sh", harness).CombinedOutput()
		if err != nil {
			t.Fatalf("write_gateway_config failed: %v\nOutput:\n%s", err, string(out))
		}
		st, err := os.Stat(cfgPath)
		if err != nil {
			t.Fatalf("stat cfgPath: %v", err)
		}
		if perm := st.Mode().Perm(); perm != 0600 {
			t.Fatalf("expected CONFIG_FILE permission 0600, got %04o", perm)
		}
		got, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatalf("read cfgPath: %v", err)
		}
		if _, err := config.Load(cfgPath); err != nil {
			t.Fatalf("config.Load after write_gateway_config failed: %v\nYAML:\n%s", err, string(got))
		}
		return got
	}

	t.Run("preserves_4space_indent_after_internal_migrate", func(t *testing.T) {
		migrated4Space := strings.Join([]string{
			"subs:",
			"    - name: main",
			"      url: https://sub.example.com/client",
			"gateway: # (可选) 客户端网关部署模式配置",
			"    mode: \"main\"",
			"    main_router_ip: \"\"",
			"    # lan_iface: \"\"",
			"    ipv6_mode: \"off\"",
			"watchdog:",
			"    interval: 180",
		}, "\n") + "\n"

		outBytes := runWriteGateway(t, migrated4Space, "side", "192.168.1.1")
		outStr := string(outBytes)

		var rawParsed config.Config
		if err := yaml.Unmarshal(outBytes, &rawParsed); err != nil {
			t.Fatalf("raw yaml.Unmarshal failed (mixed indent left by install.sh):\n%s\nerr: %v", outStr, err)
		}
		if rawParsed.Gateway.Mode != "side" || rawParsed.Gateway.MainRouterIP != "192.168.1.1" || rawParsed.Gateway.IPv6Mode != "off" {
			t.Fatalf("parsed Gateway mismatch: %+v\nYAML:\n%s", rawParsed.Gateway, outStr)
		}
		if !strings.Contains(outStr, "\n    mode: \"side\"\n") || !strings.Contains(outStr, "\n    main_router_ip: \"192.168.1.1\"\n") {
			t.Fatalf("expected 4-space indent preserved for gateway keys, got:\n%s", outStr)
		}
	})

	t.Run("heals_already_mixed_2_and_4_space_gateway_block", func(t *testing.T) {
		corruptedMixed := strings.Join([]string{
			"subs:",
			"    - name: main",
			"      url: https://sub.example.com/client",
			"gateway: # (可选) 客户端网关部署模式配置",
			"  mode: \"side\"",
			"  main_router_ip: \"192.168.1.2\"",
			"    # lan_iface: \"\"",
			"    ipv6_mode: \"off\"",
			"watchdog:",
			"    interval: 180",
		}, "\n") + "\n"

		outBytes := runWriteGateway(t, corruptedMixed, "side", "192.168.1.1")
		outStr := string(outBytes)

		var rawParsed config.Config
		if err := yaml.Unmarshal(outBytes, &rawParsed); err != nil {
			t.Fatalf("expected write_gateway_config to heal mixed indentation for raw yaml.Unmarshal, got err: %v\nYAML:\n%s", err, outStr)
		}
		if rawParsed.Gateway.Mode != "side" || rawParsed.Gateway.MainRouterIP != "192.168.1.1" || rawParsed.Gateway.IPv6Mode != "off" {
			t.Fatalf("parsed Gateway mismatch: %+v", rawParsed.Gateway)
		}
	})

	t.Run("preserves_2space_indent_even_with_nested_4space_failover_enabled", func(t *testing.T) {
		twoSpace := strings.Join([]string{
			"subs:",
			"  - name: \"main\"",
			"    url: \"https://sub.example.com/client\"",
			"gateway:",
			"  mode: \"main\"",
			"  main_router_ip: \"\"",
			"  # lan_iface: \"\"",
			"  ipv6_mode: \"off\"",
			"watchdog:",
			"  interval: 180",
			"  failover:",
			"    enabled: true",
		}, "\n") + "\n"

		outBytes := runWriteGateway(t, twoSpace, "side", "192.168.1.1")
		outStr := string(outBytes)

		var rawParsed config.Config
		if err := yaml.Unmarshal(outBytes, &rawParsed); err != nil {
			t.Fatalf("raw yaml.Unmarshal failed on 2-space file: %v\nYAML:\n%s", err, outStr)
		}
		if !strings.Contains(outStr, "\n  mode: \"side\"\n") || !strings.Contains(outStr, "\n  main_router_ip: \"192.168.1.1\"\n") {
			t.Fatalf("expected 2-space indent preserved when level-1 keys use 2 spaces, got:\n%s", outStr)
		}
	})
}
