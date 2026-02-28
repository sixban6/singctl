package deploy

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

// getCaddyCertPath waits and finds the actual cert path Caddy generated (Let's Encrypt or ZeroSSL)
func getCaddyCertPath(domain string) (string, string) {
	basePath := "/var/lib/caddy/.local/share/caddy/certificates"

	logger.Info("Waiting for Caddy to generate certificates for %s...", domain)
	for i := 0; i < 30; i++ {
		dirs, err := os.ReadDir(basePath)
		if err == nil {
			for _, d := range dirs {
				if !d.IsDir() {
					continue
				}
				crtPath := filepath.Join(basePath, d.Name(), domain, domain+".crt")
				keyPath := filepath.Join(basePath, d.Name(), domain, domain+".key")
				if _, err := os.Stat(crtPath); err == nil {
					if _, err := os.Stat(keyPath); err == nil {
						logger.Success("Found certificate at %s", crtPath)
						return crtPath, keyPath
					}
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

	logger.Warn("Timeout waiting for Caddy certs, using Let's Encrypt fallback path")
	return filepath.Join(basePath, "acme-v02.api.letsencrypt.org-directory", domain, domain+".crt"),
		filepath.Join(basePath, "acme-v02.api.letsencrypt.org-directory", domain, domain+".key")
}

// DeploySingbox handles sing-box installation, config rendering, and outputs URL
func DeploySingbox(cfg *config.Config) error {
	logger.Info("Starting Sing-box Server deployment...")

	// 1. Install or update Sing-box by reusing the internal installation logic
	logger.Info("Installing/Updating sing-box core...")
	sb := singbox.New(cfg)
	if err := sb.Install(); err != nil {
		return fmt.Errorf("failed to install sing-box: %w", err)
	}

	// 2. Generate a new UUID
	logger.Info("Generating new UUID for Hysteria2 and VLESS...")
	uuidCmd := exec.Command("sing-box", "generate", "uuid")
	out, err := uuidCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate sing-box uuid: %w", err)
	}
	hyUUID := strings.TrimSpace(string(out))

	// Generate Reality Keypair
	logger.Info("Generating VLESS Reality Keypair...")
	keyCmd := exec.Command("sing-box", "generate", "reality-keypair")
	keyOut, err := keyCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate reality keypair: %w", err)
	}
	var privateKey, publicKey string
	for _, line := range strings.Split(string(keyOut), "\n") {
		if strings.HasPrefix(line, "PrivateKey: ") {
			privateKey = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey: "))
		} else if strings.HasPrefix(line, "PublicKey: ") {
			publicKey = strings.TrimSpace(strings.TrimPrefix(line, "PublicKey: "))
		}
	}

	logger.Info("Generating VLESS Reality Short ID...")
	sidCmd := exec.Command("sing-box", "generate", "rand", "8", "--hex")
	sidOut, err := sidCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate short id: %w", err)
	}
	shortID := strings.TrimSpace(string(sidOut))

	// 3. Render and save config.json
	logger.Info("Rendering and saving sing-box config.json...")
	crt, key := getCaddyCertPath(cfg.Server.SBDomain)
	if err := renderSingboxConfig(cfg, hyUUID, crt, key, privateKey, shortID); err != nil {
		return err
	}

	// 4. Enable and restart sing-box service
	logger.Info("Restarting sing-box service...")
	// Force daemon-reload
	_ = runCmd("systemctl", "daemon-reload")

	if err := runCmd("systemctl", "enable", "--now", "sing-box"); err != nil {
		return fmt.Errorf("failed to enable sing-box service: %w", err)
	}
	if err := runCmd("systemctl", "restart", "sing-box"); err != nil {
		return fmt.Errorf("failed to restart sing-box service: %w", err)
	}

	// 5. Print high-visibility output
	shareLinkHy2 := fmt.Sprintf("hysteria2://%s@%s:52021/?sni=%s&alpn=h3&insecure=0#Hysteria2-Node", hyUUID, cfg.Server.SBDomain, cfg.Server.SBDomain)
	shareLinkVless := fmt.Sprintf("vless://%s@%s:8443?type=tcp&security=reality&pbk=%s&fp=chrome&sni=www.microsoft.com&sid=%s&flow=xtls-rprx-vision#VLESS-Reality-Node", hyUUID, cfg.Server.SBDomain, publicKey, shortID)

	logger.Success("Sing-box Server deployed successfully!")
	fmt.Println("\n========================================================")
	fmt.Println("🚀 Hysteria2 Access Link (Copy to your client):")
	fmt.Printf("%s\n", shareLinkHy2)
	fmt.Println("\n🚀 VLESS Reality Access Link (Copy to your client):")
	fmt.Printf("%s\n", shareLinkVless)
	fmt.Println("========================================================")

	return nil
}

func renderSingboxConfig(cfg *config.Config, hyUUID, crtPath, keyPath, privKey, shortID string) error {
	tmplData, err := templateFiles.ReadFile("templates/server_config.json")
	if err != nil {
		return fmt.Errorf("could not read embedded sing-box template: %w", err)
	}

	t, err := template.New("singbox_config").Parse(string(tmplData))
	if err != nil {
		return fmt.Errorf("failed to parse sing-box template: %w", err)
	}

	type tmplContext struct {
		HyUUID            string
		SBDomain          string
		CertPath          string
		KeyPath           string
		RealityPrivateKey string
		RealityShortID    string
	}
	ctx := tmplContext{
		HyUUID:            hyUUID,
		SBDomain:          cfg.Server.SBDomain,
		CertPath:          crtPath,
		KeyPath:           keyPath,
		RealityPrivateKey: privKey,
		RealityShortID:    shortID,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return fmt.Errorf("failed to execute sing-box template: %w", err)
	}

	if err := os.MkdirAll("/etc/sing-box", 0755); err != nil {
		return err
	}

	return os.WriteFile("/etc/sing-box/config.json", buf.Bytes(), 0644)
}
