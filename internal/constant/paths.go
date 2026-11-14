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
	SingBoxWorkConfigFile string
	SingBoxBasicLogFile   string
	SingBoxSimpleLogFile  string
	SingBoxSystemdService string
	SingBoxNftablesFile   string

	// Tailscale paths
	TailscaleSystemdService string
	TailscaleInitdScript    string
	TailscaleStateDir       string

	// Firewall
	FirewallSystemdService string
	FirewallInitdScript    string

	// Sub-store / Native SubHub
	SubStoreDir          string
	SubStoreFile         string
	SubHubSystemdService string
	SubHubInitdScript    string

	// AdGuard Home (Client Local Anti-Hijack DNS)
	AdGuardInstallPath    string
	AdGuardConfigDir      string
	AdGuardConfigFile     string
	AdGuardWorkDir        string
	AdGuardSystemdService string
	AdGuardInitdScript    string

	// Mask site
	MaskSiteDir string

	// mTLS Vault & Caddy runtime projection
	SingctlMtlsDir  string
	CaddyConfigDir  string
	CaddyMtlsDir    string
	CaddyMtlsCACert string
)

func init() {
	if runtime.GOOS == "linux" {
		SingBoxConfigDir = "/etc/sing-box"
		SingBoxConfigFile = "/etc/sing-box/config.json"
		SingBoxWorkConfigFile = "/tmp/sing-box-work/config.json"
		SingBoxBasicLogFile = "/tmp/sing-box-basic.log"
		SingBoxSimpleLogFile = "/tmp/sing-box-simple.log"
		SingBoxSystemdService = "/etc/systemd/system/sing-box.service"
		SingBoxNftablesFile = "/etc/sing-box/sec_block.nft"

		TailscaleSystemdService = "/etc/systemd/system/tailscaled.service"
		TailscaleInitdScript = "/etc/init.d/tailscale"
		TailscaleStateDir = "/etc/tailscale"

		FirewallSystemdService = "/etc/systemd/system/singctl-firewall.service"
		FirewallInitdScript = "/etc/init.d/singctl-firewall"

		SubStoreDir = "/etc/sub-store"
		SubStoreFile = "/etc/sub-store/sub-store.json"
		SubHubSystemdService = "/etc/systemd/system/singctl-sub.service"
		SubHubInitdScript = "/etc/init.d/singctl-sub"
		AdGuardConfigDir = "/etc/AdGuardHome"
		AdGuardConfigFile = "/etc/AdGuardHome/AdGuardHome.yaml"
		AdGuardWorkDir = "/etc/AdGuardHome"
		AdGuardSystemdService = "/etc/systemd/system/AdGuardHome.service"
		AdGuardInitdScript = "/etc/init.d/AdGuardHome"
		MaskSiteDir = "/var/www/mask-site"
		SingctlMtlsDir = "/etc/singctl/mtls"
		CaddyConfigDir = "/etc/caddy"
		CaddyMtlsDir = "/etc/caddy/mtls"
	} else if runtime.GOOS == "windows" {
		SingBoxInstallDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "sing-box", "sing-box.exe")
		SingBoxConfigDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "sing-box")
		SingBoxConfigFile = filepath.Join(SingBoxConfigDir, "config.json")
		SubStoreDir = filepath.Join(os.TempDir(), "singctl-sub-store")
		SubStoreFile = filepath.Join(SubStoreDir, "sub-store.json")
		AdGuardInstallPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "AdGuardHome", "AdGuardHome.exe")
		AdGuardConfigDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "AdGuardHome")
		AdGuardConfigFile = filepath.Join(AdGuardConfigDir, "AdGuardHome.yaml")
		AdGuardWorkDir = AdGuardConfigDir
		SingctlMtlsDir = filepath.Join(os.TempDir(), "singctl-mtls-vault")
		CaddyConfigDir = filepath.Join(os.TempDir(), "singctl-caddy")
		CaddyMtlsDir = filepath.Join(CaddyConfigDir, "mtls")
	} else if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		SingBoxInstallDir = "/usr/local/bin/sing-box"
		SingBoxConfigDir = filepath.Join(home, "Documents")
		SingBoxConfigFile = filepath.Join(SingBoxConfigDir, "sing-box-config.json")
		SubStoreDir = filepath.Join(os.TempDir(), "singctl-sub-store")
		SubStoreFile = filepath.Join(SubStoreDir, "sub-store.json")
		AdGuardInstallPath = "/usr/local/bin/AdGuardHome"
		AdGuardConfigDir = "/etc/AdGuardHome"
		AdGuardConfigFile = "/etc/AdGuardHome/AdGuardHome.yaml"
		AdGuardWorkDir = "/etc/AdGuardHome"
		MaskSiteDir = filepath.Join(os.TempDir(), "mask-site")
		SingctlMtlsDir = filepath.Join(os.TempDir(), "singctl-mtls-vault")
		CaddyConfigDir = filepath.Join(os.TempDir(), "singctl-caddy")
		CaddyMtlsDir = filepath.Join(CaddyConfigDir, "mtls")
	} else {
		SubStoreDir = filepath.Join(os.TempDir(), "singctl-sub-store")
		SubStoreFile = filepath.Join(SubStoreDir, "sub-store.json")
		AdGuardInstallPath = "/usr/local/bin/AdGuardHome"
		AdGuardConfigDir = "/etc/AdGuardHome"
		AdGuardConfigFile = "/etc/AdGuardHome/AdGuardHome.yaml"
		AdGuardWorkDir = "/etc/AdGuardHome"
		MaskSiteDir = filepath.Join(os.TempDir(), "mask-site")
		SingctlMtlsDir = filepath.Join(os.TempDir(), "singctl-mtls-vault")
		CaddyConfigDir = filepath.Join(os.TempDir(), "singctl-caddy")
		CaddyMtlsDir = filepath.Join(CaddyConfigDir, "mtls")
	}

	CaddyMtlsCACert = filepath.Join(SingctlMtlsDir, "ca.crt")

	// Dynamic linux check for SingBoxInstallDir & AdGuardInstallPath
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/etc/openwrt_release"); err == nil {
			SingBoxInstallDir = "/usr/bin/sing-box"
			AdGuardInstallPath = "/usr/bin/AdGuardHome"
		} else if _, err := os.Stat("/etc/openwrt_version"); err == nil {
			SingBoxInstallDir = "/usr/bin/sing-box"
			AdGuardInstallPath = "/usr/bin/AdGuardHome"
		} else {
			SingBoxInstallDir = "/usr/local/bin/sing-box"
			AdGuardInstallPath = "/usr/local/bin/AdGuardHome"
		}
	}
}
