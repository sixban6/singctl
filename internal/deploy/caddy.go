package deploy

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"text/template"

	"singctl/internal/config"
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

// DeployCaddy handles the installation and configuration of Caddy + Cloudflare DNS plugin
func DeployCaddy(cfg *config.Config) error {
	logger.Info("Starting Caddy deployment...")

	// 1. Install Caddy & Cloudflare plugin via script
	if err := installCaddy(); err != nil {
		return fmt.Errorf("caddy installation failed: %w", err)
	}

	// 2. Ensure basic webroot exists
	if err := os.MkdirAll("/var/www/html", 0755); err != nil {
		return fmt.Errorf("failed to create web root: %w", err)
	}
	// Create empty index.html
	if _, err := os.Stat("/var/www/html/index.html"); os.IsNotExist(err) {
		if err := os.WriteFile("/var/www/html/index.html", []byte("OK"), 0644); err != nil {
			return fmt.Errorf("failed to create dummy index.html: %w", err)
		}
	}

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

	tuicPort := 8448
	anytlsPort := 8444
	if cfg != nil {
		if cfg.Server.TuicPort > 0 {
			tuicPort = cfg.Server.TuicPort
		}
		if cfg.Server.AnyTLSPort > 0 {
			anytlsPort = cfg.Server.AnyTLSPort
		}
	}

	type tmplContext struct {
		SBDomain   string
		CFDNSKey   string
		Sni        string
		TuicPort   int
		AnyTLSPort int
	}
	ctx := tmplContext{
		SBDomain:   cfg.Server.SBDomain,
		CFDNSKey:   cfg.Server.CFDNSKey,
		Sni:        cfg.Server.Sni,
		TuicPort:   tuicPort,
		AnyTLSPort: anytlsPort,
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
