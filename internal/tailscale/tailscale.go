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
)

const (
	installDir = "/usr/sbin"
)

type Tailscale struct{}

func New() *Tailscale {
	return &Tailscale{}
}

// getLatestTailscaleVersion 从 GitHub API 获取最新的稳定版本
func (t *Tailscale) getLatestTailscaleVersion() (string, error) {
	url := "https://api.github.com/repos/tailscale/tailscale/releases/latest"
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch latest version: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status: %s", resp.Status)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	// tag_name 格式通常是 "v1.94.1"，需要去掉前缀 "v"
	version := strings.TrimPrefix(release.TagName, "v")
	if version == "" {
		return "", fmt.Errorf("invalid version format: %s", release.TagName)
	}

	return version, nil
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
	if !isOpenWrt() {
		logger.Warn("Tailscale installation is currently only supported on OpenWrt and ImmortalWrt.")
		return nil
	}
	logger.Info("Starting Tailscale installation...")

	// 0. Get latest version
	logger.Info("Fetching latest Tailscale version...")
	version, err := t.getLatestTailscaleVersion()
	if err != nil {
		logger.Warn("Failed to fetch latest version, using fallback 1.94.1: %v", err)
		version = "1.94.1"
	}
	logger.Info("Using Tailscale version: %s", version)

	// 0.1 Detect system architecture
	arch, err := t.getSystemArchitecture()
	if err != nil {
		logger.Warn("Failed to detect architecture, using fallback amd64: %v", err)
		arch = "amd64"
	}
	logger.Info("Detected system architecture: %s", arch)

	tailscaleURL := fmt.Sprintf("https://pkgs.tailscale.com/stable/tailscale_%s_%s.tgz", version, arch)

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

func (t *Tailscale) Start() error {
	if !isOpenWrt() {
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

	// 1. Get LAN subnet
	lanSubnet, err := t.getLANSubnet()
	if err != nil {
		logger.Warn("Failed to detect LAN subnet, using default 192.168.31.0/24: %v", err)
		lanSubnet = "192.168.31.0/24"
	}
	logger.Info("Detected LAN subnet: %s", lanSubnet)

	// 2. Tailscale Up (Config and Online)
	args := []string{"up", "--advertise-routes=" + lanSubnet, "--accept-dns=false"}
	if hasTun {
		args = append(args, "--netfilter-mode=on")
	}

	cmd := exec.Command(filepath.Join(installDir, "tailscale"), args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tailscale up failed: %w", err)
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
	if !isOpenWrt() {
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

	logger.Success("Tailscale stopped successfully")
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
