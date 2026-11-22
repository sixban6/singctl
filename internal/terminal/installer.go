// 文件职责：负责 Web 终端所需的系统依赖安装、GoTTY/wstunnel 二进制下载解压及通过 servicemgr 托管守护单元。
package terminal

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"singctl/internal/common/release"
	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
)

func installDependencies() error {
	logger.Info("正在检查并安装系统依赖 (tmux, openssl, tar, wget)...")

	if isCommandAvailable("tmux") && isCommandAvailable("openssl") && isCommandAvailable("tar") && isCommandAvailable("wget") {
		logger.Success("基础依赖环境已完备。")
		return nil
	}

	if isCommandAvailable("apt-get") {
		_ = exec.Command("apt-get", "update", "-y").Run()
		cmdInstall := exec.Command("apt-get", "install", "-y", "tmux", "openssl", "tar", "wget")
		cmdInstall.Stdout = os.Stdout
		cmdInstall.Stderr = os.Stderr
		if err := cmdInstall.Run(); err != nil {
			return fmt.Errorf("apt-get 安装依赖失败: %w", err)
		}
		_ = exec.Command("apt-get", "install", "-y", "openssl-provider-legacy").Run()
	} else if isCommandAvailable("dnf") {
		cmd := exec.Command("dnf", "install", "-y", "tmux", "openssl", "tar", "wget")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("dnf 安装依赖失败: %w", err)
		}
	} else if isCommandAvailable("yum") {
		cmd := exec.Command("yum", "install", "-y", "tmux", "openssl", "tar", "wget")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("yum 安装依赖失败: %w", err)
		}
	} else if isCommandAvailable("apk") {
		cmd := exec.Command("apk", "add", "--no-cache", "tmux", "openssl", "tar", "wget")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("apk 安装依赖失败: %w", err)
		}
	} else {
		return fmt.Errorf("未识别的 Linux 包管理器 (请先手动安装 tmux, openssl, tar, wget)")
	}

	if isCommandAvailable("tmux") && isCommandAvailable("openssl") && isCommandAvailable("tar") && isCommandAvailable("wget") {
		logger.Success("基础依赖环境已安装完成。")
		return nil
	}

	return fmt.Errorf("基础依赖未完全就绪，请手动安装 tmux 与 openssl")
}

func isCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func installGoTTY(cfg *config.Config, arch string) error {
	if fi, err := os.Stat(GottyBinaryPath); err == nil && fi.Size() > 0 {
		logger.Success("GoTTY 二进制已就绪 (%s)", GottyBinaryPath)
		return nil
	}

	logger.Info("正在下载 GoTTY %s (%s)...", GottyVersion, arch)
	fileName := fmt.Sprintf("gotty_%s_linux_%s.tar.gz", GottyVersion, arch)
	url := fmt.Sprintf("https://github.com/sorenisanerd/gotty/releases/download/%s/%s", GottyVersion, fileName)
	if cfg != nil && cfg.GitHub.MirrorURL != "" {
		url = strings.TrimSuffix(cfg.GitHub.MirrorURL, "/") + "/" + url
	}

	return downloadAndExtractTarGzBinary(url, "gotty", GottyBinaryPath, "GoTTY")
}

func installWstunnel(cfg *config.Config, arch string) error {
	if fi, err := os.Stat(WstunnelBinaryPath); err == nil && fi.Size() > 0 {
		logger.Success("wstunnel 二进制已就绪 (%s)", WstunnelBinaryPath)
		return nil
	}

	logger.Info("正在下载 wstunnel %s (%s)...", WstunnelVersion, arch)
	versionNum := strings.TrimPrefix(WstunnelVersion, "v")
	fileName := fmt.Sprintf("wstunnel_%s_linux_%s.tar.gz", versionNum, arch)
	url := fmt.Sprintf("https://github.com/erebe/wstunnel/releases/download/%s/%s", WstunnelVersion, fileName)
	if cfg != nil && cfg.GitHub.MirrorURL != "" {
		url = strings.TrimSuffix(cfg.GitHub.MirrorURL, "/") + "/" + url
	}

	return downloadAndExtractTarGzBinary(url, "wstunnel", WstunnelBinaryPath, "wstunnel")
}

func downloadAndExtractTarGzBinary(url, targetBinName, destPath, label string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	if err := release.DownloadAndExtractBinary(context.Background(), client, url, "", targetBinName, destPath); err != nil {
		return fmt.Errorf("下载并安装 %s 失败: %w", label, err)
	}
	logger.Success("%s 二进制已成功安装至 %s", label, destPath)
	return nil
}

func createGottySystemdService(port int, termPath, tmuxPath string) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=GoTTY Web Terminal
After=network.target

[Service]
Type=simple
User=root
Environment="LANG=en_US.UTF-8"
Environment="TERM=xterm-256color"
WorkingDirectory=/root
ExecStart=%s -a 127.0.0.1 -p %d -w --ws-origin ".*" --path %s %s new -A -s web
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, GottyBinaryPath, port, termPath, tmuxPath)

	mgr := servicemgr.NewSystemd(nil)
	if err := mgr.InstallUnit(context.Background(), servicemgr.UnitSpec{
		Name:        "gotty",
		SystemdPath: GottyServicePath,
		SystemdBody: serviceContent,
	}); err != nil {
		return fmt.Errorf("启动 gotty.service 失败: %w", err)
	}

	logger.Success("GoTTY Systemd 守护进程已启动 (监听 127.0.0.1:%d, 挂载 tmux 会话: web)", port)
	return nil
}

func createWstunnelSystemdService(sshTunnelPort int, sshPort int) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=wstunnel SSH WebSocket Bridge
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s server --restrict-to 127.0.0.1:%d ws://127.0.0.1:%d
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, WstunnelBinaryPath, sshPort, sshTunnelPort)

	mgr := servicemgr.NewSystemd(nil)
	if err := mgr.InstallUnit(context.Background(), servicemgr.UnitSpec{
		Name:        "wstunnel",
		SystemdPath: WstunnelServicePath,
		SystemdBody: serviceContent,
	}); err != nil {
		return fmt.Errorf("启动 wstunnel.service 失败: %w", err)
	}

	logger.Success("wstunnel 守护进程已启动 (监听 127.0.0.1:%d, 转发至本地 SSH 127.0.0.1:%d)", sshTunnelPort, sshPort)
	return nil
}

func runCmd(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command execution failed (%s %v): %v, output: %s", name, arg, err, string(out))
	}
	return nil
}

// CopyFile copies src to dst with explicit permissions.
func CopyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
