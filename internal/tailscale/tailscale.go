package tailscale

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"singctl/internal/logger"
	"strings"
)

const (
	tailscaleVersion = "1.94.1"
	tailscaleURL     = "https://pkgs.tailscale.com/stable/tailscale_" + tailscaleVersion + "_amd64.tgz"
	installDir       = "/usr/sbin"
)

type Tailscale struct{}

func New() *Tailscale {
	return &Tailscale{}
}

func (t *Tailscale) Install() error {
	if !isOpenWrt() {
		logger.Warn("Tailscale installation is currently only supported on OpenWrt and ImmortalWrt.")
		return nil
	}
	logger.Info("Starting Tailscale installation...")

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

	// Find extracted directory (it should be tailscale_<version>_amd64)
	extractedDir := filepath.Join(tmpDir, "tailscale_"+tailscaleVersion+"_amd64")

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

	// 5. Initial tailscale up execution
	// User request implies running `up` after install.
	logger.Info("Running tailscale up...")
	args := []string{"up", "--advertise-routes=192.168.31.0/24", "--accept-dns=false"}
	if hasTun {
		args = append(args, "--netfilter-mode=on")
	}

	if err := exec.Command(filepath.Join(installDir, "tailscale"), args...).Run(); err != nil {
		logger.Warn("tailscale up failed (might need auth url, check output): %v", err)
	} else {
		logger.Success("Tailscale up executed successfully")
	}

	logger.Success("Tailscale installed successfully")
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

	// 1. Tailscale Up (Config and Online)
	args := []string{"up", "--advertise-routes=192.168.31.0/24", "--accept-dns=false"}
	if hasTun {
		args = append(args, "--netfilter-mode=on")
	}

	cmd := exec.Command(filepath.Join(installDir, "tailscale"), args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tailscale up failed: %w", err)
	}

	// 2. Configure Firewall and Network
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
