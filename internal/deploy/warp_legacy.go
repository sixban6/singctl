// 文件职责：负责遗留 fscarmen / warp-go / wg-quick 等非内置纯 Go WARP 安装产物的检测、清理、标准 systemd 服务单元重写及卸载逻辑。
//
// 架构设计原则：
//   - 依赖倒置与隔离测试：通过 LegacyWarpPurgeEnv 注入文件系统路径与 systemctl 执行器，支持全量离线单元测试且不触碰宿主机真实系统目录。
package deploy

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"singctl/internal/logger"
)

// UninstallWarp uninstalls WARP (wireproxy) and any legacy fscarmen WARP leftovers.
func UninstallWarp() error {
	logger.Info("Uninstalling WARP (wireproxy)...")
	_ = runCmd("systemctl", "stop", "wireproxy")
	_ = runCmd("systemctl", "disable", "wireproxy")
	_, _ = PurgeLegacyFscarmenWarp()
	_ = os.Remove(DefaultWireproxyService)
	_ = runCmd("systemctl", "daemon-reload")
	_ = os.Remove(DefaultWireproxyBin)
	_ = os.RemoveAll("/etc/wireproxy")
	logger.Success("WARP uninstallation completed.")
	return nil
}

// IsWindtfWireproxyBinary 检测指定路径是否为内置纯 Go 支持 [Resolve]/ResolveStrategy 的 windtf/wireproxy 二进制。
// 老旧 fscarmen 预编译版基于 upstream wireproxy，不支持 ResolveStrategy 且会导致配置解析报错崩溃。
func IsWindtfWireproxyBinary(binPath string) bool {
	info, err := os.Stat(binPath)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return false
	}
	f, err := os.Open(binPath)
	if err != nil {
		return false
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, 32*1024*1024))
	if err != nil {
		return false
	}
	return bytes.Contains(buf, []byte("ResolveStrategy"))
}

// LegacyWarpPurgeEnv 允许测试注入隔离的文件系统与 systemd 路径以验证 fscarmen 残留清理逻辑。
type LegacyWarpPurgeEnv struct {
	LegacyFiles      []string
	LegacyGlobs      []string
	LegacyDirs       []string
	UnitFiles        []string
	StopServices     []string
	StandardUnitPath string
	PrimaryBin       string
	PrimaryConf      string
	RunSystemctl     func(args ...string) error
}

func defaultLegacyWarpPurgeEnv(env *LegacyWarpPurgeEnv) LegacyWarpPurgeEnv {
	var e LegacyWarpPurgeEnv
	customFilesProvided := env != nil && (env.LegacyFiles != nil || env.LegacyGlobs != nil)
	if env != nil {
		e = *env
	}
	if !customFilesProvided {
		e.LegacyFiles = []string{
			"/usr/bin/warp",
			"/usr/local/bin/warp",
			"/usr/bin/wireproxy",
			"/usr/bin/warp-go",
			"/usr/local/bin/warp-go",
			"/etc/systemd/system/warp-go.service",
			LegacyWireproxyConf,
			"/etc/wireguard/wgcf.conf",
			"/etc/wireguard/wgcf-account.toml",
		}
		e.LegacyGlobs = []string{
			"/etc/wireguard/proxy.conf*",
			"/etc/wireguard/wgcf*",
			"/etc/wireguard/warp*",
		}
	}
	if e.LegacyDirs == nil {
		if env == nil {
			e.LegacyDirs = []string{"/opt/warp-go"}
		} else {
			e.LegacyDirs = []string{}
		}
	}
	if e.UnitFiles == nil {
		if env == nil {
			e.UnitFiles = []string{
				DefaultWireproxyService,
				"/lib/systemd/system/wireproxy.service",
				"/usr/lib/systemd/system/wireproxy.service",
			}
		} else {
			e.UnitFiles = []string{}
		}
	}
	if e.StopServices == nil {
		if env == nil {
			e.StopServices = []string{"wg-quick@wgcf", "warp-go", "warp-svc"}
		} else {
			e.StopServices = []string{}
		}
	}
	e.StandardUnitPath = cmp.Or(strings.TrimSpace(e.StandardUnitPath), DefaultWireproxyService)
	e.PrimaryBin = cmp.Or(strings.TrimSpace(e.PrimaryBin), DefaultWireproxyBin)
	e.PrimaryConf = cmp.Or(strings.TrimSpace(e.PrimaryConf), DefaultWireproxyConf)
	if e.RunSystemctl == nil {
		e.RunSystemctl = func(args ...string) error {
			return runCmd("systemctl", args...)
		}
	}
	return e
}

func isLegacyWireproxyUnitContent(content string) bool {
	return strings.Contains(content, "/usr/bin/wireproxy") || strings.Contains(content, LegacyWireproxyConf)
}

func collectLegacyFilesToCheck(e LegacyWarpPurgeEnv) []string {
	files := slices.Clone(e.LegacyFiles)
	for _, pattern := range e.LegacyGlobs {
		if matches, err := filepath.Glob(pattern); err == nil {
			for _, m := range matches {
				if !slices.Contains(files, m) {
					files = append(files, m)
				}
			}
		}
	}
	return files
}

// HasLegacyFscarmenWarp 检测宿主机是否存在旧版 fscarmen / warp-go / /etc/wireguard/proxy.conf 等非内置纯 Go WARP 残留。
func HasLegacyFscarmenWarp() bool {
	return HasLegacyFscarmenWarpWithEnv(nil)
}

func HasLegacyFscarmenWarpWithEnv(env *LegacyWarpPurgeEnv) bool {
	e := defaultLegacyWarpPurgeEnv(env)
	for _, p := range collectLegacyFilesToCheck(e) {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	for _, d := range e.LegacyDirs {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return true
		}
	}
	for _, uf := range e.UnitFiles {
		if raw, err := os.ReadFile(uf); err == nil && isLegacyWireproxyUnitContent(string(raw)) {
			return true
		}
	}
	if _, err := os.Stat(e.PrimaryBin); err == nil && !IsWindtfWireproxyBinary(e.PrimaryBin) {
		return true
	}
	return false
}

// PurgeLegacyFscarmenWarp 彻底清理旧版 fscarmen 脚本产物、旧版 /usr/bin/wireproxy 与 /etc/wireguard/proxy.conf，
// 并统一收敛至纯 Go 版本 (/usr/local/bin/wireproxy + /etc/wireproxy/wireproxy.conf)。
func PurgeLegacyFscarmenWarp() (bool, error) {
	return PurgeLegacyFscarmenWarpWithEnv(nil)
}

func PurgeLegacyFscarmenWarpWithEnv(env *LegacyWarpPurgeEnv) (bool, error) {
	e := defaultLegacyWarpPurgeEnv(env)
	changed := false

	for _, svc := range e.StopServices {
		_ = e.RunSystemctl("stop", svc)
		_ = e.RunSystemctl("disable", svc)
	}

	legacyUnitDetected := false
	for _, uf := range e.UnitFiles {
		raw, err := os.ReadFile(uf)
		if err != nil {
			continue
		}
		if isLegacyWireproxyUnitContent(string(raw)) {
			legacyUnitDetected = true
			if uf != e.StandardUnitPath {
				if rmErr := os.Remove(uf); rmErr == nil {
					changed = true
				}
			}
		}
	}
	if legacyUnitDetected {
		_ = e.RunSystemctl("stop", "wireproxy")
		if err := writeWireproxySystemdUnit(e.StandardUnitPath, e.PrimaryBin, e.PrimaryConf); err != nil {
			return changed, fmt.Errorf("重写标准 wireproxy.service 失败: %w", err)
		}
		changed = true
	}

	for _, p := range collectLegacyFilesToCheck(e) {
		if _, err := os.Stat(p); err == nil {
			if rmErr := os.Remove(p); rmErr == nil {
				changed = true
			}
		}
	}
	for _, d := range e.LegacyDirs {
		if _, err := os.Stat(d); err == nil {
			if rmErr := os.RemoveAll(d); rmErr == nil {
				changed = true
			}
		}
	}

	if _, err := os.Stat(e.PrimaryBin); err == nil && !IsWindtfWireproxyBinary(e.PrimaryBin) {
		if rmErr := os.Remove(e.PrimaryBin); rmErr == nil {
			changed = true
		}
	}

	if changed {
		_ = e.RunSystemctl("daemon-reload")
	}
	return changed, nil
}

func writeWireproxySystemdUnit(unitPath, wireproxyBin, confPath string) error {
	if dir := filepath.Dir(unitPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	serviceContent := fmt.Sprintf(`[Unit]
Description=WireProxy for WARP
After=network.target

[Service]
Type=simple
ExecStart=%s -s -c %s
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, wireproxyBin, confPath)
	return os.WriteFile(unitPath, []byte(serviceContent), 0644)
}
