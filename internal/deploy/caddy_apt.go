package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"singctl/internal/logger"
)

const (
	caddyStandaloneSystemdUnitPath = "/etc/systemd/system/caddy.service"
	caddyAptSourceListPath         = "/etc/apt/sources.list.d/caddy-stable.list"
	caddyAptKeyringPath            = "/usr/share/keyrings/caddy-stable-archive-keyring.gpg"
	caddyBinaryPath                = "/usr/bin/caddy"
	caddyDpkgDivertPath            = "/usr/bin/caddy.dpkg-dist"
	caddyDpkgInfoDir               = "/var/lib/dpkg/info"
)

// BuildStandaloneCaddyServiceUnit 返回由 singctl 独立托管（不依赖 apt/dpkg 包管理器）的 caddy.service 单元内容。
func BuildStandaloneCaddyServiceUnit() string {
	return `[Unit]
Description=Caddy (Custom build with Cloudflare DNS & Layer4, managed by singctl)
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`
}

// NeutralizeCaddyDpkgMetadata 清空 dpkg 中 caddy 包的 conffiles 记录并将 prerm/postrm 置为空操作，
// 确保后续执行 `dpkg --purge caddy` 时：
//  1. 不会触发 `deb-systemd-invoke stop caddy.service`（运行中网关 0 毫秒不中断）；
//  2. 不会删除 `/etc/caddy/Caddyfile`、`/var/lib/caddy` ACME 证书或 `caddy` 系统用户；
//  3. 不会 mask `caddy.service`。
func NeutralizeCaddyDpkgMetadata(dpkgInfoDir string) error {
	if strings.TrimSpace(dpkgInfoDir) == "" {
		return nil
	}
	if info, err := os.Stat(dpkgInfoDir); err != nil || !info.IsDir() {
		return nil
	}

	conffiles := filepath.Join(dpkgInfoDir, "caddy.conffiles")
	if _, err := os.Stat(conffiles); err == nil {
		if err := os.WriteFile(conffiles, []byte{}, 0644); err != nil {
			return fmt.Errorf("truncate %s: %w", conffiles, err)
		}
	}

	noopScript := []byte("#!/bin/sh\nexit 0\n")
	for _, ext := range []string{"prerm", "postrm"} {
		p := filepath.Join(dpkgInfoDir, "caddy."+ext)
		if _, err := os.Stat(p); err == nil {
			if err := os.WriteFile(p, noopScript, 0755); err != nil {
				return fmt.Errorf("neutralize %s: %w", p, err)
			}
		}
	}
	return nil
}

func isCaddyRegisteredInDpkg() bool {
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		return false
	}
	out, err := exec.Command("dpkg-query", "-W", "-f=${Status}", "caddy").Output()
	if err != nil {
		return false
	}
	status := strings.TrimSpace(string(out))
	return status != "" && !strings.Contains(status, "not-installed")
}

func hasLegacyCaddyAptArtifacts() bool {
	if _, err := os.Stat(caddyAptSourceListPath); err == nil {
		return true
	}
	if _, err := os.Stat(caddyAptKeyringPath); err == nil {
		return true
	}
	return isCaddyRegisteredInDpkg()
}

func ensureCaddySystemUserAndDirs() {
	if _, err := exec.LookPath("groupadd"); err == nil {
		_ = exec.Command("groupadd", "--system", "caddy").Run()
	}
	if _, err := exec.LookPath("id"); err == nil {
		if exec.Command("id", "-u", "caddy").Run() != nil {
			if _, uErr := exec.LookPath("useradd"); uErr == nil {
				_ = exec.Command(
					"useradd", "--system",
					"--gid", "caddy",
					"--create-home",
					"--home-dir", "/var/lib/caddy",
					"--shell", "/usr/sbin/nologin",
					"--comment", "Caddy web server",
					"caddy",
				).Run()
			}
		}
	}
	_ = os.MkdirAll("/etc/caddy", 0755)
	_ = os.MkdirAll("/var/lib/caddy", 0750)
	_ = exec.Command("chown", "-R", "caddy:caddy", "/var/lib/caddy").Run()
}

func ensureStandaloneCaddySystemdUnit() error {
	// 若此前被 deb-systemd-helper mask 成指向 /dev/null 的软链接，先移除软链接再写入独立单元文件
	if fi, err := os.Lstat(caddyStandaloneSystemdUnitPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(caddyStandaloneSystemdUnitPath)
	}
	unitContent := BuildStandaloneCaddyServiceUnit()
	if existing, err := os.ReadFile(caddyStandaloneSystemdUnitPath); err == nil && string(existing) == unitContent {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(caddyStandaloneSystemdUnitPath), 0755); err != nil {
		return err
	}
	tmpPath := caddyStandaloneSystemdUnitPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(unitContent), 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, caddyStandaloneSystemdUnitPath)
}

// DetachCaddyFromApt 将定制版 Caddy（含 Cloudflare DNS 与 Layer4 模块）与 Debian/Ubuntu APT/dpkg 彻底解耦：
//   - 无损保留正在运行的 `/usr/bin/caddy`、`/etc/caddy/Caddyfile` 与 `/var/lib/caddy` 证书（零停机、不断连）；
//   - 写入 `/etc/systemd/system/caddy.service` 独立服务单元；
//   - 清除 `dpkg` 中残留的旧版 `caddy` 账面记录以及 `caddy-stable.list` 第三方源，
//     彻底根除 `apt list --upgradable` 虚报更新与 `apt upgrade` 误覆盖定制二进制的风险。
func DetachCaddyFromApt() {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return
	}
	if !hasLegacyCaddyAptArtifacts() {
		// 即使无残留 APT 源，也确保独立 systemd unit 存在（若系统已部署 /usr/bin/caddy）
		if _, err := os.Stat(caddyBinaryPath); err == nil {
			_ = ensureStandaloneCaddySystemdUnit()
		}
		return
	}

	logger.Info("检测到遗留的 Caddy APT/dpkg 账面记录或第三方源，正在执行零停机独立化收口...")

	ensureCaddySystemUserAndDirs()

	// 1. 备份当前定制二进制与 Caddyfile，双保险防意外丢失
	binKeep := caddyBinaryPath + ".singctl-keep"
	if data, err := os.ReadFile(caddyBinaryPath); err == nil && len(data) > 0 {
		_ = os.WriteFile(binKeep, data, 0755)
	}
	cfPath := caddyfilePath()
	cfKeep := cfPath + ".singctl-keep"
	if data, err := os.ReadFile(cfPath); err == nil && len(data) > 0 {
		_ = os.WriteFile(cfKeep, data, 0644)
	}

	// 2. 先落盘独立 systemd 服务单元
	_ = ensureStandaloneCaddySystemdUnit()

	// 3. 若 dpkg 数据库中仍登记有 caddy 包，安全剥离账面记录且不触碰在线进程与文件
	if isCaddyRegisteredInDpkg() {
		_ = exec.Command("apt-mark", "unhold", "caddy").Run()

		diverted := false
		if _, err := exec.LookPath("dpkg-divert"); err == nil {
			// 不带 --rename：/usr/bin/caddy 原地不动，仅告知 dpkg 将包内路径映射至 .dpkg-dist
			if exec.Command("dpkg-divert", "--local", "--divert", caddyDpkgDivertPath, "--add", caddyBinaryPath).Run() == nil {
				diverted = true
			}
		}

		_ = NeutralizeCaddyDpkgMetadata(caddyDpkgInfoDir)
		_ = exec.Command("dpkg", "--purge", "caddy").Run()

		if diverted {
			_ = exec.Command("dpkg-divert", "--local", "--remove", caddyBinaryPath).Run()
		}
		_ = os.Remove(caddyDpkgDivertPath)
	}

	// 4. 校验并兜底恢复 /usr/bin/caddy 与 Caddyfile，清理临时备份
	if info, err := os.Stat(caddyBinaryPath); err != nil || info.Size() == 0 {
		if _, kErr := os.Stat(binKeep); kErr == nil {
			_ = os.Rename(binKeep, caddyBinaryPath)
			_ = os.Chmod(caddyBinaryPath, 0755)
		}
	} else {
		_ = os.Remove(binKeep)
	}

	if info, err := os.Stat(cfPath); err != nil || info.Size() == 0 {
		if _, kErr := os.Stat(cfKeep); kErr == nil {
			_ = os.Rename(cfKeep, cfPath)
			_ = os.Chmod(cfPath, 0644)
		}
	} else {
		_ = os.Remove(cfKeep)
	}

	// 5. 确保独立 systemd 单元生效并自启（不重启在线 caddy 进程）
	_ = ensureStandaloneCaddySystemdUnit()
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "enable", "caddy").Run()

	// 6. 移除 Cloudsmith 第三方源、密钥及缓存列表，刷新 APT 索引消除账面残留
	removedRepo := false
	if err := os.Remove(caddyAptSourceListPath); err == nil {
		removedRepo = true
	}
	_ = os.Remove(caddyAptKeyringPath)
	if matches, err := filepath.Glob("/var/lib/apt/lists/*caddy*"); err == nil {
		for _, m := range matches {
			_ = os.Remove(m)
			removedRepo = true
		}
	}
	if removedRepo {
		if _, err := exec.LookPath("apt-get"); err == nil {
			_ = exec.Command("apt-get", "update", "-qq").Run()
		}
	}

	logger.Success("已清理 Caddy APT/dpkg 遗留账面记录，网关现由 singctl 独立托管")
}
