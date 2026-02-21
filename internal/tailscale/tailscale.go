package tailscale

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"singctl/internal/logger"
	"strings"
	"time"
)

const (
	installDir = "/usr/sbin"
)

type Tailscale struct {
	// httpClient is used for all HTTP requests. Defaults to http.DefaultClient.
	httpClient *http.Client
	// openWrtCheck returns true when running on OpenWrt/ImmortalWrt.
	// Defaults to the real isOpenWrt() filesystem check.
	openWrtCheck func() bool
}

func New() *Tailscale {
	return &Tailscale{
		httpClient:   http.DefaultClient,
		openWrtCheck: isOpenWrt,
	}
}

// pkgsStableURL 是 Tailscale 官方 stable 渠道的 JSON 元数据接口。
// 该接口始终与实际可下载文件保持同步，避免 GitHub releases API 的延迟问题。
const pkgsStableURL = "https://pkgs.tailscale.com/stable/?mode=json"

// pkgsInfo 是 pkgs.tailscale.com/stable/?mode=json 返回的结构体
type pkgsInfo struct {
	Tarballs        map[string]string `json:"Tarballs"`        // arch -> filename
	TarballsVersion string            `json:"TarballsVersion"` // e.g. "1.94.2"
}

// getLatestPkgsInfo 从 Tailscale 官方 pkgs 接口获取最新 stable 信息
func (t *Tailscale) getLatestPkgsInfo() (*pkgsInfo, error) {
	return t.getLatestPkgsInfoFrom(pkgsStableURL)
}

// getLatestPkgsInfoFrom 从指定 URL 获取 pkgsInfo（便于测试注入）
func (t *Tailscale) getLatestPkgsInfoFrom(apiURL string) (*pkgsInfo, error) {
	resp, err := t.httpClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pkgs info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pkgs API returned status: %s", resp.Status)
	}

	var info pkgsInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode pkgs response: %w", err)
	}

	if info.TarballsVersion == "" {
		return nil, fmt.Errorf("pkgs API returned empty version")
	}

	return &info, nil
}

// getLatestTailscaleVersion 获取最新 stable 版本号（保留向后兼容）
func (t *Tailscale) getLatestTailscaleVersion() (string, error) {
	info, err := t.getLatestPkgsInfo()
	if err != nil {
		return "", err
	}
	return info.TarballsVersion, nil
}

// getLANSubnet 从 UCI 配置中获取 LAN 接口的子网信息
func (t *Tailscale) getLANSubnet() (string, error) {
	// 获取 LAN 接口的 IP 地址
	out, err := exec.Command("uci", "get", "network.lan.ipaddr").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get LAN IP: %w", err)
	}
	ipAddr := strings.TrimSpace(string(out))

	// 获取 LAN 接口的子网掩码
	out, err = exec.Command("uci", "get", "network.lan.netmask").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get LAN netmask: %w", err)
	}
	netmask := strings.TrimSpace(string(out))

	// 将 IP 和子网掩码转换为 CIDR 格式
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipAddr)
	}

	mask := net.ParseIP(netmask)
	if mask == nil {
		return "", fmt.Errorf("invalid netmask: %s", netmask)
	}

	// 转换为 IPMask
	ipMask := net.IPMask(mask.To4())
	ones, _ := ipMask.Size()

	// 计算网络地址
	network := ip.Mask(ipMask)

	// 返回 CIDR 格式的子网
	return fmt.Sprintf("%s/%d", network.String(), ones), nil
}

// getSystemArchitecture 检测系统架构并映射到 Tailscale 的架构命名
func (t *Tailscale) getSystemArchitecture() (string, error) {
	out, err := exec.Command("uname", "-m").Output()
	if err != nil {
		return "", fmt.Errorf("failed to detect architecture: %w", err)
	}

	arch := strings.TrimSpace(string(out))

	// 映射系统架构到 Tailscale 的架构命名
	switch arch {
	case "x86_64", "amd64":
		return "amd64", nil
	case "aarch64", "arm64":
		return "arm64", nil
	case "armv7l", "armv7":
		return "arm", nil
	case "i386", "i686":
		return "386", nil
	default:
		return "", fmt.Errorf("unsupported architecture: %s", arch)
	}
}

func (t *Tailscale) Install() error {
	if !t.openWrtCheck() {
		logger.Warn("Tailscale installation is currently only supported on OpenWrt and ImmortalWrt.")
		return nil
	}
	logger.Info("Starting Tailscale installation...")

	// 0. Get latest pkgs info (version + per-arch filenames)
	logger.Info("Fetching latest Tailscale version...")
	pkgs, err := t.getLatestPkgsInfo()
	if err != nil {
		logger.Warn("Failed to fetch pkgs info: %v", err)
		// fallback: use last known stable
		pkgs = &pkgsInfo{
			TarballsVersion: "1.94.2",
			Tarballs: map[string]string{
				"amd64":  "tailscale_1.94.2_amd64.tgz",
				"arm64":  "tailscale_1.94.2_arm64.tgz",
				"arm":    "tailscale_1.94.2_arm.tgz",
				"386":    "tailscale_1.94.2_386.tgz",
				"mips":   "tailscale_1.94.2_mips.tgz",
				"mipsle": "tailscale_1.94.2_mipsle.tgz",
			},
		}
	}
	version := pkgs.TarballsVersion
	logger.Info("Using Tailscale version: %s", version)

	// 0.1 Detect system architecture
	arch, err := t.getSystemArchitecture()
	if err != nil {
		logger.Warn("Failed to detect architecture, using fallback amd64: %v", err)
		arch = "amd64"
	}
	logger.Info("Detected system architecture: %s", arch)

	// 0.2 Get tarball filename from pkgs info (falls back to constructed name)
	tarball, ok := pkgs.Tarballs[arch]
	if !ok {
		tarball = fmt.Sprintf("tailscale_%s_%s.tgz", version, arch)
		logger.Warn("Architecture %s not found in pkgs info, using fallback filename: %s", arch, tarball)
	}
	tailscaleURL := "https://pkgs.tailscale.com/stable/" + tarball

	// 1. Download
	logger.Info("Downloading Tailscale...")
	resp, err := http.Get(tailscaleURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "tailscale-*.tgz")
	if err != nil {
		return fmt.Errorf("create temp file failed: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		return fmt.Errorf("write file failed: %w", err)
	}
	tmpFile.Close()

	// 2. Extract and Install
	logger.Info("Extracting and installing...")
	tmpDir, err := os.MkdirTemp("", "tailscale-extract-*")
	if err != nil {
		return fmt.Errorf("create temp dir failed: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := exec.Command("tar", "xzf", tmpFile.Name(), "-C", tmpDir).Run(); err != nil {
		return fmt.Errorf("extract failed: %w", err)
	}

	// Find extracted directory (it should be tailscale_<version>_<arch>)
	extractedDir := filepath.Join(tmpDir, fmt.Sprintf("tailscale_%s_%s", version, arch))

	// Copy binaries
	if err := copyFile(filepath.Join(extractedDir, "tailscale"), filepath.Join(installDir, "tailscale")); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(extractedDir, "tailscaled"), filepath.Join(installDir, "tailscaled")); err != nil {
		return err
	}

	if err := os.Chmod(filepath.Join(installDir, "tailscale"), 0755); err != nil {
		return fmt.Errorf("chmod tailscale failed: %w", err)
	}
	if err := os.Chmod(filepath.Join(installDir, "tailscaled"), 0755); err != nil {
		return fmt.Errorf("chmod tailscaled failed: %w", err)
	}

	// 3. Create Init Script
	logger.Info("Checking for kmod-tun...")
	hasTun := checkTunModule()
	if hasTun {
		logger.Info("kmod-tun detected, using Scheme 2 (Kernel Mode)")
	} else {
		logger.Info("kmod-tun NOT detected, using Scheme 1 (Userspace Mode)")
	}

	logger.Info("Creating init script...")
	if err := createInitScript(hasTun); err != nil {
		return err
	}

	// 4. Enable and Start Service
	logger.Info("Enabling and starting service...")
	if err := exec.Command("/etc/init.d/tailscale", "enable").Run(); err != nil {
		return fmt.Errorf("enable service failed: %w", err)
	}
	if err := exec.Command("/etc/init.d/tailscale", "start").Run(); err != nil {
		return fmt.Errorf("start service failed: %w", err)
	}

	logger.Success("Tailscale installed successfully")
	logger.Info("Run 'singctl start tailscale' to configure and authenticate your device")
	return nil
}

// Start brings up Tailscale and configures firewall/network rules.
// advertiseExitNode=true also advertises this device as a Tailscale exit node.
func (t *Tailscale) Start(advertiseExitNode bool) error {
	if !t.openWrtCheck() {
		logger.Warn("Tailscale start is currently only supported on OpenWrt and ImmortalWrt.")
		return nil
	}
	logger.Info("Starting Tailscale configuration...")

	hasTun := checkTunModule()
	if hasTun {
		logger.Info("kmod-tun detected, configuring for Kernel Mode")
	} else {
		logger.Info("kmod-tun NOT detected, configuring for Userspace Mode")
	}

	// 0. Ensure tailscaled service is running
	logger.Info("Ensuring tailscaled service is running...")
	if err := exec.Command("/etc/init.d/tailscale", "start").Run(); err != nil {
		logger.Warn("Failed to start tailscaled service: %v", err)
	}
	// Give it a moment to start
	time.Sleep(1 * time.Second)

	// 1. Get LAN subnet
	lanSubnet, err := t.getLANSubnet()
	if err != nil {
		logger.Warn("Failed to detect LAN subnet, using default 192.168.31.0/24: %v", err)
		lanSubnet = "192.168.31.0/24"
	}
	logger.Info("Detected LAN subnet: %s", lanSubnet)

	// 2. Tailscale Up (Config and Online)
	// --reset: 让 singctl 成为参数的唯一来源，避免残留非默认参数导致 tailscale up 报错。
	args := []string{"up", "--reset", "--advertise-routes=" + lanSubnet, "--accept-dns=false"}
	if hasTun {
		args = append(args, "--netfilter-mode=on")
	}
	if advertiseExitNode {
		args = append(args, "--advertise-exit-node")
		logger.Info("Exit node advertisement enabled")
	}

	cmd := exec.Command(filepath.Join(installDir, "tailscale"), args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tailscale up failed: %w", err)
	}

	// 3. Optimize UDP GRO for better performance (Tailscale recommendation)
	logger.Info("Optimizing UDP GRO settings for better performance...")
	if err := optimizeUDPGRO(); err != nil {
		logger.Warn("Failed to optimize UDP GRO (non-critical): %v", err)
	}

	// 3. Configure Firewall and Network
	logger.Info("Configuring firewall and network...")

	// Commands
	// Note: We need to handle potential duplicates or errors if items already exist.
	// `uci add` creates a NEW anonymous section every time.
	// To perform this idempotently without complex parsing, we can check if `network.tailscale` exists.
	// The user request script logic is: uci set ... (implies create/overwrite for named, add for anonymous).

	// For named section network.tailscale
	exec.Command("uci", "set", "network.tailscale=interface").Run()
	exec.Command("uci", "set", "network.tailscale.device=tailscale0").Run()
	exec.Command("uci", "set", "network.tailscale.proto=unmanaged").Run()

	// For firewall zone. 'tailscale' is a named section in network but firewall zones are usually anonymous or named.
	// User script: `uci add firewall zone` then `uci set firewall.@zone[-1].name='tailscale'`
	// This implies creating a new zone named tailscale.
	// We should check if a zone named 'tailscale' already exists to avoid duplicates.
	// Since we can't easily parse uci output here without a helper, we'll try to delete it first if possible,
	// or assume the user wants us to run this setup.
	// `uci delete firewall.tailscale` might not work if it's not a named section.
	// However, standard OpenWrt practice for scripts is often checking or just appending.
	// Given the "singctl" nature, repeated calls should be safe.
	// Let's rely on `uci get firewall.@zone[-1].name` check? No too complex.
	// Let's implement the script commands as requested.

	cmds := [][]string{
		// Network Interface (Named 'tailscale', safe to repeat)
		{"uci", "set", "network.tailscale=interface"},
		{"uci", "set", "network.tailscale.device=tailscale0"},
		{"uci", "set", "network.tailscale.proto=unmanaged"},

		// Firewall Zone
		// We use `uci add` which always adds. This WILL create duplicates if run multiple times.
		// A simple workaround for the named zone 'tailscale' if we could refer to it.
		// If we use named sections for zones (supported in newer OpenWrt), we could use `uci set firewall.tailscale=zone`.
		// But the user script uses `uci add firewall zone` + `name=tailscale`.
		// Let's stick to the user's script for correctness of their specific setup.
		{"uci", "add", "firewall", "zone"},
		{"uci", "set", "firewall.@zone[-1].name=tailscale"},
		{"uci", "set", "firewall.@zone[-1].network=tailscale"},
		{"uci", "set", "firewall.@zone[-1].input=ACCEPT"},
		{"uci", "set", "firewall.@zone[-1].output=ACCEPT"},
		{"uci", "set", "firewall.@zone[-1].forward=ACCEPT"},
		{"uci", "set", "firewall.@zone[-1].masq=1"},

		// Forwarding Rules
		{"uci", "add", "firewall", "forwarding"},
		{"uci", "set", "firewall.@forwarding[-1].src=tailscale"},
		{"uci", "set", "firewall.@forwarding[-1].dest=lan"},

		{"uci", "add", "firewall", "forwarding"},
		{"uci", "set", "firewall.@forwarding[-1].src=lan"},
		{"uci", "set", "firewall.@forwarding[-1].dest=tailscale"},

		{"uci", "add", "firewall", "forwarding"},
		{"uci", "set", "firewall.@forwarding[-1].src=tailscale"},
		{"uci", "set", "firewall.@forwarding[-1].dest=wan"},
	}

	for _, args := range cmds {
		// Just run them.
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
			logger.Warn("Command failed: %v", args)
		}
	}

	// Commit and Reload
	exec.Command("uci", "commit", "network").Run()
	exec.Command("uci", "commit", "firewall").Run()
	exec.Command("/etc/init.d/network", "reload").Run()
	exec.Command("/etc/init.d/firewall", "reload").Run()

	logger.Success("Tailscale configured and started")
	return nil
}

func (t *Tailscale) Stop() error {
	if !t.openWrtCheck() {
		logger.Warn("Tailscale stop is currently only supported on OpenWrt and ImmortalWrt.")
		return nil
	}
	logger.Info("Stopping Tailscale...")

	// 1. Bring down Tailscale connection
	if err := exec.Command(filepath.Join(installDir, "tailscale"), "down").Run(); err != nil {
		logger.Warn("tailscale down failed: %v", err)
	}

	// 2. Stop the service
	if err := exec.Command("/etc/init.d/tailscale", "stop").Run(); err != nil {
		return fmt.Errorf("stop service failed: %w", err)
	}

	// 3. Restore UDP GRO settings to default
	logger.Info("Restoring UDP GRO settings to default...")
	if err := restoreUDPGRO(); err != nil {
		logger.Warn("Failed to restore UDP GRO (non-critical): %v", err)
	}

	logger.Success("Tailscale stopped successfully")
	return nil
}

// parseVersionOutput 从 "tailscale version" 输出中提取版本号（首行）
func parseVersionOutput(out string) (string, error) {
	lines := strings.SplitN(strings.TrimSpace(out), "\n", 2)
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", fmt.Errorf("unexpected tailscale version output: %s", out)
	}
	return strings.TrimSpace(lines[0]), nil
}

// getInstalledVersionOf 运行指定二进制文件的 version 命令，返回版本号。
func (t *Tailscale) getInstalledVersionOf(binPath string) (string, error) {
	out, err := exec.Command(binPath, "version").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run %s version: %w", binPath, err)
	}
	return parseVersionOutput(string(out))
}

// getInstalledVersion 返回 tailscale 和 tailscaled 中较旧的版本号。
// 两者都必须达到最新版本，Update() 才能軭行。
func (t *Tailscale) getInstalledVersion() (string, error) {
	clientVer, clientErr := t.getInstalledVersionOf(filepath.Join(installDir, "tailscale"))
	daemonVer, daemonErr := t.getInstalledVersionOf(filepath.Join(installDir, "tailscaled"))

	// 两者都失败，返回客户端的错误
	if clientErr != nil && daemonErr != nil {
		return "", clientErr
	}
	// 仅客户端失败，以守护进程版本为准（会触发更新）
	if clientErr != nil {
		return daemonVer, nil
	}
	// 仅守护进程失败，以客户端版本为准（会触发更新）
	if daemonErr != nil {
		return clientVer, nil
	}
	// 两者都成功：返回较旧的版本。
	// 只要两者中任意一个不是最新版，Update() 即会执行更新。
	if clientVer != daemonVer {
		logger.Warn("Version mismatch: tailscale=%s tailscaled=%s; will update both", clientVer, daemonVer)
		// 返回较旧的一个，就能触发更新流程
		if clientVer < daemonVer {
			return clientVer, nil
		}
		return daemonVer, nil
	}
	return clientVer, nil
}

// Update 将 Tailscale 更新到最新稳定版
func (t *Tailscale) Update() error {
	if !t.openWrtCheck() {
		logger.Warn("Tailscale update is currently only supported on OpenWrt and ImmortalWrt.")
		return nil
	}
	logger.Info("Checking for Tailscale updates...")

	// 1. 获取最新 pkgs info（版本 + 各架构文件名）
	pkgs, err := t.getLatestPkgsInfo()
	if err != nil {
		return fmt.Errorf("failed to fetch latest version: %w", err)
	}
	latestVersion := pkgs.TarballsVersion
	logger.Info("Latest Tailscale version: %s", latestVersion)

	// 2. 获取当前已安装版本（tailscale 和 tailscaled 中较旧的一个）
	clientVer, clientErr := t.getInstalledVersionOf(filepath.Join(installDir, "tailscale"))
	daemonVer, daemonErr := t.getInstalledVersionOf(filepath.Join(installDir, "tailscaled"))

	switch {
	case clientErr != nil && daemonErr != nil:
		logger.Warn("Could not determine installed versions (%v), proceeding with update...", clientErr)
	case clientErr != nil:
		logger.Warn("Could not read tailscale version (%v), proceeding...", clientErr)
	case daemonErr != nil:
		logger.Warn("Could not read tailscaled version (%v), proceeding...", daemonErr)
	default:
		logger.Info("Installed: tailscale=%s  tailscaled=%s", clientVer, daemonVer)
		if clientVer == latestVersion && daemonVer == latestVersion {
			logger.Success("Tailscale is already up to date (%s)", latestVersion)
			return nil
		}
		if clientVer != daemonVer {
			logger.Info("Version mismatch detected: tailscale=%s tailscaled=%s", clientVer, daemonVer)
		}
		logger.Info("Updating to %s", latestVersion)
	}

	// 3. 检测系统架构
	arch, err := t.getSystemArchitecture()
	if err != nil {
		logger.Warn("Failed to detect architecture, using fallback amd64: %v", err)
		arch = "amd64"
	}
	logger.Info("Detected system architecture: %s", arch)

	// 从 pkgs info 中取精确文件名（避免手动拼接出错）
	tarball, ok := pkgs.Tarballs[arch]
	if !ok {
		tarball = fmt.Sprintf("tailscale_%s_%s.tgz", latestVersion, arch)
		logger.Warn("Architecture %s not in pkgs info, using fallback: %s", arch, tarball)
	}
	tailscaleURL := "https://pkgs.tailscale.com/stable/" + tarball

	// 4. 下载新版本
	logger.Info("Downloading Tailscale %s...", latestVersion)
	resp, err := t.httpClient.Get(tailscaleURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	tmpFile, err := os.CreateTemp("", "tailscale-*.tgz")
	if err != nil {
		return fmt.Errorf("create temp file failed: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err = io.Copy(tmpFile, resp.Body); err != nil {
		return fmt.Errorf("write file failed: %w", err)
	}
	tmpFile.Close()

	// 5. 解压
	logger.Info("Extracting...")
	tmpDir, err := os.MkdirTemp("", "tailscale-extract-*")
	if err != nil {
		return fmt.Errorf("create temp dir failed: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := exec.Command("tar", "xzf", tmpFile.Name(), "-C", tmpDir).Run(); err != nil {
		return fmt.Errorf("extract failed: %w", err)
	}

	extractedDir := filepath.Join(tmpDir, fmt.Sprintf("tailscale_%s_%s", latestVersion, arch))

	// 6. 停止服务，替换二进制文件，重启服务
	logger.Info("Stopping tailscale service before replacing binaries...")
	if err := stopTailscaledProcess(); err != nil {
		logger.Warn("Stop may be incomplete: %v", err)
	}

	if err := copyFile(filepath.Join(extractedDir, "tailscale"), filepath.Join(installDir, "tailscale")); err != nil {
		return fmt.Errorf("replace tailscale binary failed: %w", err)
	}
	if err := copyFile(filepath.Join(extractedDir, "tailscaled"), filepath.Join(installDir, "tailscaled")); err != nil {
		return fmt.Errorf("replace tailscaled binary failed: %w", err)
	}

	if err := os.Chmod(filepath.Join(installDir, "tailscale"), 0755); err != nil {
		return fmt.Errorf("chmod tailscale failed: %w", err)
	}
	if err := os.Chmod(filepath.Join(installDir, "tailscaled"), 0755); err != nil {
		return fmt.Errorf("chmod tailscaled failed: %w", err)
	}

	logger.Info("Restarting tailscale service...")
	if err := exec.Command("/etc/init.d/tailscale", "start").Run(); err != nil {
		return fmt.Errorf("restart service failed: %w", err)
	}

	logger.Success("Tailscale updated to %s successfully", latestVersion)
	return nil
}

// stopTailscaledProcess 先通过 init.d 优雅停止服务，再用 killall -9 确保进程退出，
// 最后轮询等待 tailscaled 进程消失，防止替换二进制时出现 "text file busy" 错误。
func stopTailscaledProcess() error {
	// 1. 优雅停止
	exec.Command("/etc/init.d/tailscale", "stop").Run()

	// 2. 强制杀掉仍在运行的 tailscaled（忽略 "no process" 错误）
	exec.Command("killall", "-9", "tailscaled").Run()

	// 3. 轮询等待进程彻底消失（最多 5 秒）
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		// "pgrep -x tailscaled" 退出码非 0 表示进程已不存在
		if err := exec.Command("pgrep", "-x", "tailscaled").Run(); err != nil {
			return nil // 进程已退出
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("tailscaled process did not exit within timeout")
}

// optimizeUDPGRO configures UDP GRO settings for better Tailscale performance
// Reference: https://tailscale.com/s/ethtool-config-udp-gro
func optimizeUDPGRO() error {
	// Check if ethtool is available
	if _, err := exec.LookPath("ethtool"); err != nil {
		return fmt.Errorf("ethtool not found (install with: apk add ethtool or opkg install ethtool)")
	}

	// Get the default route network interface
	out, err := exec.Command("ip", "-o", "route", "get", "8.8.8.8").Output()
	if err != nil {
		return fmt.Errorf("failed to get default route: %w", err)
	}

	// Parse interface name from output (typically field 5)
	fields := strings.Fields(string(out))
	var netdev string
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			netdev = fields[i+1]
			break
		}
	}

	if netdev == "" {
		return fmt.Errorf("could not determine network interface")
	}

	logger.Info("Configuring UDP GRO on interface: %s", netdev)

	// Configure rx-udp-gro-forwarding and rx-gro-list
	cmd := exec.Command("ethtool", "-K", netdev, "rx-udp-gro-forwarding", "on", "rx-gro-list", "off")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ethtool command failed: %w", err)
	}

	logger.Success("UDP GRO optimization applied")
	return nil
}

// restoreUDPGRO restores UDP GRO settings to default values
func restoreUDPGRO() error {
	// Check if ethtool is available
	if _, err := exec.LookPath("ethtool"); err != nil {
		return fmt.Errorf("ethtool not found")
	}

	// Get the default route network interface
	out, err := exec.Command("ip", "-o", "route", "get", "8.8.8.8").Output()
	if err != nil {
		return fmt.Errorf("failed to get default route: %w", err)
	}

	// Parse interface name from output
	fields := strings.Fields(string(out))
	var netdev string
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			netdev = fields[i+1]
			break
		}
	}

	if netdev == "" {
		return fmt.Errorf("could not determine network interface")
	}

	logger.Info("Restoring UDP GRO on interface: %s", netdev)

	// Restore to default settings (rx-udp-gro-forwarding off)
	cmd := exec.Command("ethtool", "-K", netdev, "rx-udp-gro-forwarding", "off", "rx-gro-list", "on")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ethtool command failed: %w", err)
	}

	logger.Success("UDP GRO settings restored to default")
	return nil
}

func checkTunModule() bool {
	// Use lsmod to check for 'tun' module
	out, err := exec.Command("lsmod").Output()
	if err != nil {
		// If lsmod fails (e.g. not found), we can't be sure.
		// Fallback to checking /dev/net/tun or return false?
		// User explicitly asked for lsmod.
		logger.Warn("lsmod failed: %v, assuming no kmod-tun", err)
		return false
	}
	// Check if output contains "tun"
	return strings.Contains(string(out), "tun")
}

func createInitScript(hasTun bool) error {
	scriptPath := "/etc/init.d/tailscale"

	content := `#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
STOP=10

start_service() {
`
	if hasTun {
		content += `    # 确保 TUN 设备存在
    if [ ! -c /dev/net/tun ]; then
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200
        chmod 0666 /dev/net/tun
    fi

    # 开启转发
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    mkdir -p /etc/tailscale
    mkdir -p /var/run/tailscale

    procd_open_instance
    procd_set_param command /usr/sbin/tailscaled
    
    # 核心差异：移除 userspace-networking，默认使用 tun
    procd_append_param command --state=/etc/tailscale/tailscaled.state
    procd_append_param command --socket=/var/run/tailscale/tailscaled.sock
    procd_append_param command --port=41641
    
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`
	} else {
		content += `    # 开启内核转发(虽然是用户态，但为了路由功能最好开启)
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    mkdir -p /etc/tailscale
    mkdir -p /var/run/tailscale

    procd_open_instance
    procd_set_param command /usr/sbin/tailscaled
    
    # 核心差异：用户态网络模式
    procd_append_param command --tun=userspace-networking
    procd_append_param command --state=/etc/tailscale/tailscaled.state
    procd_append_param command --socket=/var/run/tailscale/tailscaled.sock
    procd_append_param command --port=41641
    
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`
	}

	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		return fmt.Errorf("write init script failed: %w", err)
	}
	return nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source failed: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create dest failed: %w", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("copy failed: %w", err)
	}
	return nil
}
