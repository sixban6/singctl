package deploy

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
)

// UninstallCaddy uninstalls Caddy and removes its configuration
func UninstallCaddy() error {
	logger.Info("Uninstalling Caddy...")
	if err := runEmbeddedScript("uninstall_caddy.sh"); err != nil {
		return fmt.Errorf("caddy uninstallation failed: %w", err)
	}
	_ = runCmd("apt-mark", "unhold", "caddy")
	logger.Success("Caddy uninstallation completed.")
	return nil
}

// RestartCaddy restarts the caddy systemd service
func RestartCaddy() error {
	logger.Info("Restarting Caddy service...")
	_ = runCmd("systemctl", "daemon-reload")
	if err := runCmd("systemctl", "enable", "--now", "caddy"); err != nil {
		return fmt.Errorf("failed to enable caddy: %w", err)
	}
	if err := runCmd("systemctl", "restart", "caddy"); err != nil {
		return fmt.Errorf("failed to restart caddy: %w", err)
	}
	return nil
}

// RotateCloudflareToken renders Caddyfile with updated configuration and restarts Caddy
func RotateCloudflareToken(cfg *config.Config) error {
	logger.Info("Rendering and saving Caddyfile with new Cloudflare API token...")
	if err := renderCaddyfile(cfg); err != nil {
		return fmt.Errorf("failed to render Caddyfile: %w", err)
	}
	if err := RestartCaddy(); err != nil {
		return err
	}
	logger.Success("Cloudflare API token rotated and Caddy restarted successfully.")
	return nil
}

// FormatIPForCaddy formats an IP for use in Caddy addresses (wrapping IPv6 in brackets).
func FormatIPForCaddy(ip string) string {
	trimmed := strings.TrimSpace(ip)
	if strings.Contains(trimmed, ":") && !strings.HasPrefix(trimmed, "[") {
		return fmt.Sprintf("[%s]", trimmed)
	}
	return trimmed
}

// StripIPBrackets removes brackets from IPv6 address if present.
func StripIPBrackets(ip string) string {
	return strings.Trim(strings.TrimSpace(ip), "[]")
}

// DeployCaddy handles the installation and configuration of Caddy + Cloudflare DNS plugin
func DeployCaddy(cfg *config.Config) error {
	logger.Info("Starting Caddy deployment...")

	// 1. Install Caddy & Cloudflare plugin via script
	if err := installCaddy(); err != nil {
		return fmt.Errorf("caddy installation failed: %w", err)
	}

	// Auto-detect server public IP if not explicitly configured
	if cfg != nil && cfg.Server.ServerIP == "" {
		if ip := config.DiscoverPublicIP(); ip != "" {
			logger.Info("Auto-detected server public IP for ACME IP certificate: %s", ip)
			cfg.Server.ServerIP = ip
		}
	}

	// 2. Ensure mask site webroot and rich static index.html exist
	if err := os.MkdirAll(constant.MaskSiteDir, 0755); err != nil {
		return fmt.Errorf("failed to create mask site root: %w", err)
	}
	maskHTML, err := templateFiles.ReadFile("templates/mask_index.html")
	if err == nil {
		if err := os.WriteFile(filepath.Join(constant.MaskSiteDir, "index.html"), maskHTML, 0644); err != nil {
			logger.Warn("Failed to write mask site index.html: %v", err)
		}
	}

	// Also ensure legacy /var/www/html exists
	_ = os.MkdirAll("/var/www/html", 0755)

	// 3. Render and save Caddyfile
	logger.Info("Rendering and saving Caddyfile...")
	if err := renderCaddyfile(cfg); err != nil {
		return err
	}

	// 4. Restart Caddy
	if err := RestartCaddy(); err != nil {
		return err
	}

	logger.Success("Caddy deployment completed successfully.")
	return nil
}

func installCaddy() error {
	return runEmbeddedScript("install_caddy.sh")
}

// PreviewCaddyfile renders the Caddyfile template with cfg and returns the result as a string.
// It is exported for use in tests.
func PreviewCaddyfile(cfg *config.Config) (string, error) {
	tmplData, err := templateFiles.ReadFile("templates/caddyfile.tpl")
	if err != nil {
		return "", fmt.Errorf("could not read embedded Caddyfile template: %w", err)
	}

	t, err := template.New("caddyfile").Parse(string(tmplData))
	if err != nil {
		return "", fmt.Errorf("failed to parse caddyfile template: %w", err)
	}

	tuicPort := 443
	anytlsPort := 443
	if cfg != nil {
		if cfg.Server.TuicPort > 0 {
			tuicPort = cfg.Server.TuicPort
		}
		if cfg.Server.AnyTLSPort > 0 {
			anytlsPort = cfg.Server.AnyTLSPort
		}
	}

	type tmplContext struct {
		NodeDomain        string
		SubstoreDomain    string
		TuicDomain        string
		CFDNSKey          string
		Sni               string
		TuicPort          int
		AnyTLSPort        int
		SSKey             string
		ServerIP          string
		ServerIPFormatted string
	}

	nodeDomain := ""
	substoreDomain := ""
	tuicDomain := ""
	cfDNSKey := ""
	sni := ""
	serverIPRaw := ""
	if cfg != nil {
		nodeDomain = cfg.Server.GetNodeDomain()
		substoreDomain = cfg.Server.GetSubstoreDomain()
		tuicDomain = cfg.Server.GetTuicDomain()
		cfDNSKey = cfg.Server.CFDNSKey
		sni = cfg.Server.Sni
		serverIPRaw = cfg.Server.ServerIP
	}

	ssKey := ""
	keyFile := filepath.Join(constant.SubStoreDir, "key")
	if keyBytes, err := os.ReadFile(keyFile); err == nil {
		ssKey = strings.TrimSpace(string(keyBytes))
	}

	ctx := tmplContext{
		NodeDomain:        nodeDomain,
		SubstoreDomain:    substoreDomain,
		TuicDomain:        tuicDomain,
		CFDNSKey:          cfDNSKey,
		Sni:               sni,
		TuicPort:          tuicPort,
		AnyTLSPort:        anytlsPort,
		SSKey:             ssKey,
		ServerIP:          StripIPBrackets(serverIPRaw),
		ServerIPFormatted: FormatIPForCaddy(serverIPRaw),
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("failed to execute caddyfile template: %w", err)
	}
	return buf.String(), nil
}

func renderCaddyfile(cfg *config.Config) error {
	content, err := PreviewCaddyfile(cfg)
	if err != nil {
		return err
	}

	// Ensure Caddy config directory exists
	if err := os.MkdirAll("/etc/caddy", 0755); err != nil {
		return err
	}

	caddyfilePath := "/etc/caddy/Caddyfile"
	if err := os.WriteFile(caddyfilePath, []byte(content), 0640); err != nil {
		return err
	}
	return secureCaddyfile(caddyfilePath)
}

func secureCaddyfile(path string) error {
	gid, err := lookupCaddyGID()
	if err != nil {
		return err
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return fmt.Errorf("set ownership root:caddy for %s failed: %w", path, err)
	}
	return ensureFilePermissions(path, 0640)
}

func lookupCaddyGID() (int, error) {
	if u, err := user.Lookup("caddy"); err == nil {
		gid, convErr := strconv.Atoi(u.Gid)
		if convErr == nil {
			return gid, nil
		}
	}
	g, err := user.LookupGroup("caddy")
	if err != nil {
		return 0, fmt.Errorf("lookup caddy user/group failed: %w", err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("parse caddy gid %q failed: %w", g.Gid, err)
	}
	return gid, nil
}
