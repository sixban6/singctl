package constant

import (
	"os"
	"path/filepath"
	"runtime"
)

var (
	// Sing-box paths
	SingBoxInstallDir     string
	SingBoxConfigDir      string
	SingBoxConfigFile     string
	SingBoxSystemdService string
	SingBoxNftablesFile   string

	// Tailscale paths
	TailscaleSystemdService string
	TailscaleInitdScript    string
	TailscaleStateDir       string

	// Firewall
	FirewallSystemdService string
	FirewallInitdScript    string

	// Sub-store
	SubStoreDir  string
	SubStoreFile string
)

func init() {
	if runtime.GOOS == "linux" {
		SingBoxConfigDir = "/etc/sing-box"
		SingBoxConfigFile = "/etc/sing-box/config.json"
		SingBoxSystemdService = "/etc/systemd/system/sing-box.service"
		SingBoxNftablesFile = "/etc/sing-box/sec_block.nft"

		TailscaleSystemdService = "/etc/systemd/system/tailscaled.service"
		TailscaleInitdScript = "/etc/init.d/tailscale"
		TailscaleStateDir = "/etc/tailscale"

		FirewallSystemdService = "/etc/systemd/system/singctl-firewall.service"
		FirewallInitdScript = "/etc/init.d/singctl-firewall"

		SubStoreDir = "/etc/sub-store"
		SubStoreFile = "/etc/sub-store/sub-store.json"
	} else if runtime.GOOS == "windows" {
		SingBoxInstallDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "sing-box", "sing-box.exe")
		SingBoxConfigDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "sing-box")
		SingBoxConfigFile = filepath.Join(SingBoxConfigDir, "config.json")
	} else if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		SingBoxInstallDir = "/usr/local/bin/sing-box"
		SingBoxConfigDir = filepath.Join(home, "Documents")
		SingBoxConfigFile = filepath.Join(SingBoxConfigDir, "sing-box-config.json")
	}

	// Dynamic linux check for SingBoxInstallDir
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/etc/openwrt_release"); err == nil {
			SingBoxInstallDir = "/usr/bin/sing-box"
		} else if _, err := os.Stat("/etc/openwrt_version"); err == nil {
			SingBoxInstallDir = "/usr/bin/sing-box"
		} else {
			SingBoxInstallDir = "/usr/local/bin/sing-box"
		}
	}
}
