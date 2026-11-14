package deploy

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy/masksite"
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

// SyncCaddyfile checks if Caddy is installed, renders Caddyfile with current cfg, and reloads Caddy only if changed or inactive.
func SyncCaddyfile(cfg *config.Config) error {
	targetPath := caddyfilePath()
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return nil
	}
	effectiveCfg := prepareRuntimeCaddyConfig(cfg)
	content, err := PreviewCaddyfile(effectiveCfg)
	if err != nil {
		return fmt.Errorf("failed to render Caddyfile: %w", err)
	}
	existing, rErr := os.ReadFile(targetPath)
	changed := rErr != nil || string(existing) != content
	var (
		prev    []byte
		hadPrev bool
	)
	if changed {
		prev, hadPrev, err = writeCaddyfileAtomically(targetPath, content)
		if err != nil {
			return err
		}
	}
	if !changed && runCmd("systemctl", "is-active", "--quiet", "caddy") == nil {
		return nil
	}
	if err := runCmd("systemctl", "reload", "caddy"); err != nil {
		if rErr := RestartCaddy(); rErr != nil {
			if changed && hadPrev {
				rollbackCaddyfile(targetPath, prev, hadPrev)
			}
			return rErr
		}
	}
	return nil
}

// RotateCloudflareToken renders Caddyfile with updated configuration and restarts Caddy
func RotateCloudflareToken(cfg *config.Config) error {
	logger.Info("Rendering and saving Caddyfile with new Cloudflare API token...")
	prev, hadPrev, err := renderCaddyfileWithBackup(cfg)
	if err != nil {
		return fmt.Errorf("failed to render Caddyfile: %w", err)
	}
	if err := RestartCaddy(); err != nil {
		rollbackCaddyfile(caddyfilePath(), prev, hadPrev)
		return err
	}
	logger.Success("Cloudflare API token rotated and Caddy restarted successfully.")
	return nil
}

// RegenerateMaskSite creates and writes a brand new randomized camouflage site to constant.MaskSiteDir.
func RegenerateMaskSite() (*masksite.SiteMeta, error) {
	logger.Info("Generating new randomized camouflage blog...")
	meta, err := masksite.GenerateAndWrite(constant.MaskSiteDir)
	if err != nil {
		return nil, fmt.Errorf("failed to regenerate mask site: %w", err)
	}
	logger.Success("Generated unique camouflage blog: '%s' by %s (%s)", meta.BlogTitle, meta.AuthorName, meta.Category)
	return meta, nil
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

	// Auto-detect server public IP if not explicitly configured (only when using standard port 443,
	// since shared-IP NAT VPSs on custom ports do not own port 80/443 for IP ACME HTTP-01/TLS-ALPN-01 challenges)
	if cfg != nil && cfg.Server.ServerIP == "" && cfg.Server.GetHy2Port() == 443 && cfg.Server.GetVlessPort() == 443 {
		if ip := config.DiscoverPublicIP(); ip != "" {
			logger.Info("Auto-detected server public IP for ACME IP certificate: %s", ip)
			cfg.Server.ServerIP = ip
		}
	}

	// 2. Ensure mask site webroot and rich dynamic camouflage blog exist
	if err := os.MkdirAll(constant.MaskSiteDir, 0755); err != nil {
		return fmt.Errorf("failed to create mask site root: %w", err)
	}
	indexPath := filepath.Join(constant.MaskSiteDir, "index.html")
	needRegen := false
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		needRegen = true
	} else if data, err := os.ReadFile(indexPath); err == nil {
		// Automatically replace tiny placeholder stubs (e.g. "<html><body>ok</body></html>")
		// or the old static hardcoded template with a unique randomized blog.
		contentStr := strings.TrimSpace(string(data))
		if len(contentStr) < 512 || strings.Contains(contentStr, "Alex Chen") || strings.Contains(contentStr, "DevNotes | Systems, Architecture") {
			needRegen = true
		}
	}

	if needRegen {
		logger.Info("Generating randomized camouflage fallback blog for Caddy...")
		meta, err := masksite.GenerateAndWrite(constant.MaskSiteDir)
		if err != nil {
			logger.Warn("Failed to generate random camouflage site: %v, falling back to embedded template", err)
			maskHTML, rErr := TemplateFiles.ReadFile("templates/mask_index.html")
			if rErr == nil {
				_ = os.WriteFile(indexPath, maskHTML, 0644)
			}
		} else {
			logger.Success("Camouflage fallback blog ready: '%s' by %s (%s)", meta.BlogTitle, meta.AuthorName, meta.Category)
		}
	}

	// Also ensure legacy /var/www/html exists
	_ = os.MkdirAll("/var/www/html", 0755)

	// 3. Render and save Caddyfile
	logger.Info("Rendering and saving Caddyfile...")
	prev, hadPrev, err := renderCaddyfileWithBackup(cfg)
	if err != nil {
		return err
	}

	// 4. Restart Caddy
	if err := RestartCaddy(); err != nil {
		rollbackCaddyfile(caddyfilePath(), prev, hadPrev)
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
	tmplData, err := TemplateFiles.ReadFile("templates/caddyfile.tpl")
	if err != nil {
		return "", fmt.Errorf("could not read embedded Caddyfile template: %w", err)
	}

	t, err := template.New("caddyfile").Parse(string(tmplData))
	if err != nil {
		return "", fmt.Errorf("failed to parse caddyfile template: %w", err)
	}

	hy2Port := 443
	vlessPort := 443

	type tmplContext struct {
		NodeDomain        string
		SubstoreDomain    string
		CFDNSKey          string
		Sni               string
		Hy2Port           int
		VlessPort         int
		SSKey             string
		ServerIP          string
		ServerIPFormatted string
		TerminalPath      string
		TerminalPort      int
		SSHTunnelPath     string
		SSHTunnelPort     int
		MtlsCA            string
		AdminPath         string
		AdminPort         int
		AdminGatewayToken string
		ACMEEmail         string
	}

	nodeDomain := ""
	substoreDomain := ""
	cfDNSKey := ""
	sni := ""
	serverIPRaw := ""
	terminalPath := ""
	terminalPort := 18080
	sshTunnelPath := ""
	sshTunnelPort := 18081
	mtlsCA := ""
	adminPath := ""
	adminPort := 8092
	if cfg != nil {
		hy2Port = cfg.Server.GetHy2Port()
		vlessPort = cfg.Server.GetVlessPort()
		nodeDomain = cfg.Server.GetNodeDomain()
		substoreDomain = cfg.Server.GetSubstoreDomain()
		if substoreDomain == "" {
			substoreDomain = nodeDomain
		}
		cfDNSKey = cfg.Server.CFDNSKey
		sni = cfg.Server.Sni
		serverIPRaw = cfg.Server.ServerIP

		if cfg.Server.WebAdmin.Enabled || cfg.Server.WebAdmin.Path != "" {
			adminPath = cfg.Server.GetWebAdminPath()
			adminPort = cfg.Server.GetWebAdminPort()
		}

		if cfg.Server.WebTerminal.Enabled {
			terminalPath = strings.TrimSpace(cfg.Server.WebTerminal.Path)
			if terminalPath != "" && !strings.HasPrefix(terminalPath, "/") {
				terminalPath = "/" + terminalPath
			}
			terminalPath = strings.TrimSuffix(terminalPath, "/")

			if cfg.Server.WebTerminal.Port > 0 {
				terminalPort = cfg.Server.WebTerminal.Port
			}

			sshTunnelPath = strings.TrimSpace(cfg.Server.WebTerminal.SSHTunnelPath)
			if sshTunnelPath == "" {
				sshTunnelPath = "/ssh-ws"
			}
			if !strings.HasPrefix(sshTunnelPath, "/") {
				sshTunnelPath = "/" + sshTunnelPath
			}
			sshTunnelPath = strings.TrimSuffix(sshTunnelPath, "/")

			if cfg.Server.WebTerminal.SSHTunnelPort > 0 {
				sshTunnelPort = cfg.Server.WebTerminal.SSHTunnelPort
			}

			mtlsCA = strings.TrimSpace(cfg.Server.WebTerminal.MtlsCA)
			if mtlsCA == "" {
				mtlsCA = "/etc/caddy/mtls/ca.crt"
			}
		}
	}

	ssKey := ""
	keyFile := filepath.Join(constant.SubStoreDir, "key")
	if keyBytes, err := os.ReadFile(keyFile); err == nil {
		ssKey = strings.TrimSpace(string(keyBytes))
	}

	domainForEmail := substoreDomain
	if domainForEmail == "" {
		domainForEmail = nodeDomain
	}
	acmeEmail := "admin@example.com"
	if domainForEmail != "" {
		parts := strings.Split(strings.TrimSpace(domainForEmail), ".")
		if len(parts) >= 2 {
			acmeEmail = "admin@" + strings.Join(parts[len(parts)-2:], ".")
		} else {
			acmeEmail = "admin@" + domainForEmail
		}
	}

	ctx := tmplContext{
		NodeDomain:        nodeDomain,
		SubstoreDomain:    substoreDomain,
		CFDNSKey:          cfDNSKey,
		Sni:               sni,
		Hy2Port:           hy2Port,
		VlessPort:         vlessPort,
		SSKey:             ssKey,
		ServerIP:          StripIPBrackets(serverIPRaw),
		ServerIPFormatted: FormatIPForCaddy(serverIPRaw),
		TerminalPath:      terminalPath,
		TerminalPort:      terminalPort,
		SSHTunnelPath:     sshTunnelPath,
		SSHTunnelPort:     sshTunnelPort,
		MtlsCA:            mtlsCA,
		AdminPath:         adminPath,
		AdminPort:         adminPort,
		AdminGatewayToken: config.DeriveGatewayToken(adminPath),
		ACMEEmail:         acmeEmail,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("failed to execute caddyfile template: %w", err)
	}
	return buf.String(), nil
}

func caddyfilePath() string {
	return filepath.Join(caddyConfigDir(), "Caddyfile")
}

// prepareRuntimeCaddyConfig resolves/heals the mTLS trust_pool CA before disk write and degrades
// cleanly if the CA file is absent on disk, keeping PreviewCaddyfile itself 100% pure.
func prepareRuntimeCaddyConfig(cfg *config.Config) *config.Config {
	if cfg == nil || !cfg.Server.WebTerminal.Enabled {
		return cfg
	}
	resolvedCA, ready, err := EnsureCaddyMtlsTrustPool(cfg.Server.WebTerminal.MtlsCA)
	if err != nil || !ready {
		logger.Warn("检测到 web_terminal 已启用但 mTLS 根证书 (%s) 缺失，已临时跳过 Web 终端路由以保障 Caddy 网关正常运行；请执行 'singctl sr term install' 补齐证书", resolvedCA)
		effective := *cfg
		effective.Server.WebTerminal.Enabled = false
		return &effective
	}
	if strings.TrimSpace(cfg.Server.WebTerminal.MtlsCA) == "" && resolvedCA != "" {
		effective := *cfg
		effective.Server.WebTerminal.MtlsCA = resolvedCA
		return &effective
	}
	return cfg
}

func renderCaddyfile(cfg *config.Config) error {
	_, _, err := renderCaddyfileWithBackup(cfg)
	return err
}

func renderCaddyfileWithBackup(cfg *config.Config) (prev []byte, hadPrev bool, err error) {
	effectiveCfg := prepareRuntimeCaddyConfig(cfg)
	content, err := PreviewCaddyfile(effectiveCfg)
	if err != nil {
		return nil, false, err
	}
	return writeCaddyfileAtomically(caddyfilePath(), content)
}

func writeCaddyfileAtomically(targetPath, content string) (prev []byte, hadPrev bool, err error) {
	if existing, rErr := os.ReadFile(targetPath); rErr == nil {
		prev = existing
		hadPrev = true
	}

	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return prev, hadPrev, err
	}

	if hadPrev {
		bakPath := targetPath + ".bak"
		if wErr := writeFileAtomicWithMode(bakPath, prev, 0640); wErr == nil {
			_ = applyCaddyfileOwnership(bakPath)
		}
	}

	tmp, err := os.CreateTemp(dir, ".Caddyfile.tmp.*")
	if err != nil {
		return prev, hadPrev, err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0640); err != nil {
		_ = tmp.Close()
		return prev, hadPrev, err
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return prev, hadPrev, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return prev, hadPrev, err
	}
	if err := tmp.Close(); err != nil {
		return prev, hadPrev, err
	}
	if err := applyCaddyfileOwnership(tmpPath); err != nil {
		return prev, hadPrev, err
	}

	if caddyBin, lookErr := exec.LookPath("caddy"); lookErr == nil {
		if out, vErr := exec.Command(caddyBin, "validate", "--config", tmpPath, "--adapter", "caddyfile").CombinedOutput(); vErr != nil {
			return prev, hadPrev, fmt.Errorf("caddyfile validate failed: %s (%w)", strings.TrimSpace(string(out)), vErr)
		}
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		return prev, hadPrev, err
	}
	cleanup = false
	if err := applyCaddyfileOwnership(targetPath); err != nil {
		return prev, hadPrev, err
	}
	return prev, hadPrev, nil
}

func rollbackCaddyfile(targetPath string, prev []byte, hadPrev bool) {
	if !hadPrev {
		return
	}
	logger.Warn("Caddy 启动或重载失败，正在自动回滚上一份有效 Caddyfile...")
	if err := writeFileAtomicWithMode(targetPath, prev, 0640); err == nil {
		_ = applyCaddyfileOwnership(targetPath)
		_ = RestartCaddy()
	}
}

func applyCaddyfileOwnership(path string) error {
	if os.Geteuid() == 0 {
		if _, err := lookupCaddyGID(); err == nil {
			return secureCaddyfile(path)
		}
	}
	return ensureFilePermissions(path, 0640)
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
