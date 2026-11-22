// 文件职责：负责服务端 sing-box 实例安装、ACME 证书发现自愈、配置模板渲染与服务生命周期编排。
package deploy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/singbox"
	"singctl/internal/telemetry"
)

type SingBoxServer struct {
	crtPath string
	keyPath string

	hyUUID     string
	privateKey string
	publicKey  string
	shortID    string
	cfg        *config.Config
	ConfigFile string

	hy2Tag         string
	vrTag          string
	ShareLinkHy2   string
	ShareLinkVless string
}

func NewSingBoxServer(cfg *config.Config) (*SingBoxServer, error) {
	sbs := &SingBoxServer{cfg: cfg}
	if err := sbs.init(); err != nil {
		return nil, err
	}
	return sbs, nil
}

func (sbs *SingBoxServer) init() error {
	_ = sbs.LoadExistingCredentials()

	sbs.initCaddyCertPath()
	if err := sbs.initVRParams(); err != nil {
		return fmt.Errorf("failed to initialize VR parameters: %w", err)
	}
	sbs.initTag()
	sbs.updateShareLinks()
	return nil
}

func (sbs *SingBoxServer) initTag() {
	tagPrefix := ""
	if sbs.cfg != nil {
		tagPrefix = sbs.cfg.Server.GetNodeTag()
	}
	if tagPrefix == "" {
		tagPrefix = "node"
	}
	sbs.hy2Tag = fmt.Sprintf("sec_%s_hy2", tagPrefix)
	sbs.vrTag = fmt.Sprintf("sec_%s_vr", tagPrefix)
}

func (sbs *SingBoxServer) HyUUID() string    { return sbs.hyUUID }
func (sbs *SingBoxServer) PublicKey() string { return sbs.publicKey }
func (sbs *SingBoxServer) ShortID() string   { return sbs.shortID }
func (sbs *SingBoxServer) Hy2Tag() string    { return sbs.hy2Tag }
func (sbs *SingBoxServer) VrTag() string     { return sbs.vrTag }

func (sbs *SingBoxServer) Hy2Port() int {
	if sbs != nil && sbs.cfg != nil {
		return sbs.cfg.Server.GetHy2Port()
	}
	return 443
}

func (sbs *SingBoxServer) VlessPort() int {
	if sbs != nil && sbs.cfg != nil {
		return sbs.cfg.Server.GetVlessPort()
	}
	return 443
}

// IsValidPublicACMECert verifies that the certificate file exists, is a valid X.509 PEM certificate,
// has not expired, and is not issued by Caddy's internal self-signed CA ("Caddy Local Authority").
func IsValidPublicACMECert(crtPath string) bool {
	data, err := os.ReadFile(crtPath)
	if err != nil || len(data) == 0 {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if time.Now().After(cert.NotAfter) {
		return false
	}
	issuerCN := strings.ToLower(cert.Issuer.CommonName)
	issuerOrg := strings.ToLower(strings.Join(cert.Issuer.Organization, " "))
	if strings.Contains(issuerCN, "caddy local") || strings.Contains(issuerOrg, "caddy local") {
		return false
	}
	return cert.Issuer.String() != cert.Subject.String()
}

// LookupValidCaddyCert locates a valid, non-self-signed ACME certificate and key for domain under Caddy's storage.
func LookupValidCaddyCert(domain string) (string, string) {
	return lookupCaddyCert(domain)
}

func lookupCaddyCert(domain string) (string, string) {
	basePath := "/var/lib/caddy/.local/share/caddy/certificates"
	if _, err := os.Stat("/var/lib/caddy"); os.IsNotExist(err) {
		return "", ""
	}

	parts := strings.Split(domain, ".")
	var wildcardNames []string
	if len(parts) >= 2 {
		wildcardNames = append(wildcardNames, "wildcard_."+strings.Join(parts[1:], "."))
	}

	dirs, err := os.ReadDir(basePath)
	if err != nil {
		return "", ""
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		dirNameLower := strings.ToLower(d.Name())
		if dirNameLower == "local" || dirNameLower == "pki" {
			continue
		}
		crtPath := filepath.Join(basePath, d.Name(), domain, domain+".crt")
		keyPath := filepath.Join(basePath, d.Name(), domain, domain+".key")
		if _, err := os.Stat(crtPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil && IsValidPublicACMECert(crtPath) {
				return crtPath, keyPath
			}
		}

		for _, wName := range wildcardNames {
			wCrt := filepath.Join(basePath, d.Name(), wName, wName+".crt")
			wKey := filepath.Join(basePath, d.Name(), wName, wName+".key")
			if _, err := os.Stat(wCrt); err == nil {
				if _, err := os.Stat(wKey); err == nil && IsValidPublicACMECert(wCrt) {
					return wCrt, wKey
				}
			}
		}
	}
	return "", ""
}

func findCaddyCertForDomain(domain string) (string, string) {
	basePath := "/var/lib/caddy/.local/share/caddy/certificates"
	fallbackCrt := filepath.Join(basePath, "acme-v02.api.letsencrypt.org-directory", domain, domain+".crt")
	fallbackKey := filepath.Join(basePath, "acme-v02.api.letsencrypt.org-directory", domain, domain+".key")

	if _, err := os.Stat("/var/lib/caddy"); os.IsNotExist(err) {
		return fallbackCrt, fallbackKey
	}

	if crt, key := lookupCaddyCert(domain); crt != "" {
		return crt, key
	}

	logger.Info("Waiting for Caddy to generate public ACME certificates for %s...", domain)
	for range 60 {
		time.Sleep(1 * time.Second)
		if crt, key := lookupCaddyCert(domain); crt != "" {
			logger.Success("Found valid ACME certificate at %s", crt)
			return crt, key
		}
	}
	return fallbackCrt, fallbackKey
}

// SyncHysteria2CertIfNeeded inspects /etc/sing-box/config.json and heals the Hysteria2 certificate_path
// if it points to a deleted/expired/local self-signed cert while a valid Caddy ACME cert is available.
func SyncHysteria2CertIfNeeded(cfg *config.Config) (bool, string, error) {
	cfgFile := constant.SingBoxConfigFile
	rawBytes, err := os.ReadFile(cfgFile)
	if err != nil {
		return false, "", nil
	}

	var doc map[string]any
	if err := json.Unmarshal(rawBytes, &doc); err != nil {
		return false, "", nil
	}

	inbounds, ok := doc["inbounds"].([]any)
	if !ok {
		return false, "", nil
	}

	domain := ""
	if cfg != nil {
		domain = cfg.Server.GetNodeDomain()
	}

	changed := false
	var healMsg string
	for _, ibAny := range inbounds {
		ib, ok := ibAny.(map[string]any)
		if !ok || ib["type"] != "hysteria2" {
			continue
		}
		tlsObj, ok := ib["tls"].(map[string]any)
		if !ok {
			continue
		}
		curCrt, _ := tlsObj["certificate_path"].(string)
		if domain == "" && curCrt != "" {
			domain = filepath.Base(filepath.Dir(curCrt))
		}
		if domain == "" {
			continue
		}

		validCrt, validKey := lookupCaddyCert(domain)
		if validCrt == "" || validKey == "" {
			continue
		}

		if curCrt != validCrt || !IsValidPublicACMECert(curCrt) {
			tlsObj["certificate_path"] = validCrt
			tlsObj["key_path"] = validKey
			changed = true
			healMsg = fmt.Sprintf("Hysteria2 证书路径已自动修复同步至有效 ACME 证书 (%s)", domain)
		}
		if _, hasMasq := ib["masquerade"]; !hasMasq {
			if st, err := os.Stat("/var/www/mask-site"); err == nil && st.IsDir() {
				ib["masquerade"] = "file:///var/www/mask-site"
				changed = true
				if healMsg == "" {
					healMsg = "已为 Hysteria2 补齐 HTTP/3 静态伪装站回落配置 (masquerade)"
				}
			}
		}
	}

	if !changed {
		return false, "", nil
	}

	outBytes, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return false, "", err
	}

	tmpPath := cfgFile + ".tmp"
	if err := os.WriteFile(tmpPath, outBytes, 0600); err != nil {
		return false, "", err
	}
	_ = os.Chmod(tmpPath, 0600)

	sbBin := constant.SingBoxInstallDir
	if _, err := os.Stat(sbBin); err == nil {
		if out, cErr := exec.Command(sbBin, "check", "-c", tmpPath).CombinedOutput(); cErr != nil {
			_ = os.Remove(tmpPath)
			return false, "", fmt.Errorf("sing-box check failed: %s", strings.TrimSpace(string(out)))
		}
	}

	if err := os.Rename(tmpPath, cfgFile); err != nil {
		_ = os.Remove(tmpPath)
		return false, "", err
	}
	_ = os.Chmod(cfgFile, 0600)
	_ = serviceMgr().Restart(context.Background(), "sing-box")
	return true, healMsg, nil
}

func (sbs *SingBoxServer) initCaddyCertPath() {
	nodeDomain := sbs.cfg.Server.GetNodeDomain()
	sbs.crtPath, sbs.keyPath = findCaddyCertForDomain(nodeDomain)
}

func (sbs *SingBoxServer) RefreshCaddyCertPath() {
	sbs.initCaddyCertPath()
}

func (sbs *SingBoxServer) SetConfig(cfg *config.Config) {
	if cfg != nil {
		sbs.cfg = cfg
		sbs.updateShareLinks()
	}
}

const singboxServiceContentTemplate = `[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run -c %s
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
`

func (sbs *SingBoxServer) ensureSystemdService() error {
	servicePath := constant.SingBoxSystemdService
	expectedContent := fmt.Sprintf(singboxServiceContentTemplate, constant.SingBoxInstallDir, constant.SingBoxConfigFile)
	shouldWrite := false

	if existing, err := os.ReadFile(servicePath); os.IsNotExist(err) {
		logger.Info("sing-box.service not found, creating it...")
		shouldWrite = true
	} else if err != nil {
		return fmt.Errorf("failed to check service file state: %w", err)
	} else if string(existing) != expectedContent {
		logger.Info("sing-box.service content is outdated, updating it...")
		shouldWrite = true
	}

	if shouldWrite {
		if err := os.WriteFile(servicePath, []byte(expectedContent), 0644); err != nil {
			return fmt.Errorf("failed to write sing-box.service: %w", err)
		}
		logger.Info("Reloading systemd daemon...")
		if err := serviceMgr().DaemonReload(context.Background()); err != nil {
			return fmt.Errorf("failed to daemon-reload: %w", err)
		}
		logger.Success("sing-box.service is ready at %s", servicePath)
	}
	return nil
}

func (sbs *SingBoxServer) DeploySingbox() error {
	logger.Info("Starting Sing-box Server deployment...")
	logger.Info("Installing/Updating sing-box core...")
	sb := singbox.New(sbs.cfg)
	if err := sb.Install(); err != nil {
		return fmt.Errorf("failed to install sing-box: %w", err)
	}
	logger.Info("Rendering and saving sing-box config.json...")
	if err := sbs.renderSingboxConfig(); err != nil {
		return fmt.Errorf("failed to render config: %w", err)
	}
	if err := sbs.ensureSystemdService(); err != nil {
		return err
	}
	logger.Info("Restarting sing-box service...")
	ctx := context.Background()
	if err := serviceMgr().Enable(ctx, "sing-box"); err != nil {
		return fmt.Errorf("failed to enable sing-box service: %w", err)
	}
	if err := serviceMgr().Restart(ctx, "sing-box"); err != nil {
		return fmt.Errorf("failed to restart sing-box service: %w", err)
	}
	sbs.updateShareLinks()
	sbs.ShowLoginInfo()
	return nil
}

func (sbs *SingBoxServer) RegenerateCredentials() error {
	sbs.hyUUID = ""
	sbs.privateKey = ""
	sbs.publicKey = ""
	sbs.shortID = ""
	if err := sbs.initVRParams(); err != nil {
		return err
	}
	sbs.updateShareLinks()
	return nil
}

func (sbs *SingBoxServer) ResetCredentials() error {
	logger.Info("Resetting sing-box server credentials...")
	if _, err := os.Stat(constant.SingBoxInstallDir); os.IsNotExist(err) {
		logger.Info("sing-box binary not found, installing...")
		sb := singbox.New(sbs.cfg)
		if err := sb.Install(); err != nil {
			return fmt.Errorf("failed to install sing-box: %w", err)
		}
	}
	if err := sbs.RegenerateCredentials(); err != nil {
		return fmt.Errorf("failed to regenerate credentials: %w", err)
	}
	logger.Info("Rendering and saving new sing-box config.json...")
	if err := sbs.renderSingboxConfig(); err != nil {
		return fmt.Errorf("failed to render config: %w", err)
	}
	if err := sbs.ensureSystemdService(); err != nil {
		return err
	}
	logger.Info("Restarting sing-box service...")
	ctx := context.Background()
	if err := serviceMgr().Enable(ctx, "sing-box"); err != nil {
		return fmt.Errorf("failed to enable sing-box service: %w", err)
	}
	if err := serviceMgr().Restart(ctx, "sing-box"); err != nil {
		return fmt.Errorf("failed to restart sing-box service: %w", err)
	}
	sbs.ShowLoginInfo()
	return nil
}

func (sbs *SingBoxServer) ShowLoginInfo() {
	logger.Success("Sing-box 服务端核心部署完成！")
	fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
	fmt.Println("│               🚀 服务端节点分享与客户端导入                │")
	fmt.Println("└────────────────────────────────────────────────────────────┘")
	fmt.Printf("\n【1】Hysteria 2 节点 (端口: %d / QUIC UDP)\n", sbs.Hy2Port())
	fmt.Printf("• 分享链接: %s\n", sbs.ShareLinkHy2)
	fmt.Printf("\n【2】VLESS Reality 节点 (端口: %d / TCP Reality)\n", sbs.VlessPort())
	fmt.Printf("• 分享链接: %s\n", sbs.ShareLinkVless)
	fmt.Println("────────────────────────────────────────────────────────────")
	fmt.Println()
}

func (sbs *SingBoxServer) PreviewServerConfig() (string, error) {
	tmplData, err := TemplateFiles.ReadFile("templates/server_config.json")
	if err != nil {
		return "", fmt.Errorf("could not read embedded sing-box template: %w", err)
	}

	t, err := template.New("singbox_config").Parse(string(tmplData))
	if err != nil {
		return "", fmt.Errorf("failed to parse sing-box template: %w", err)
	}

	type tmplContext struct {
		HyUUID                 string
		SBDomain               string
		CertPath               string
		KeyPath                string
		RealityPrivateKey      string
		RealityShortID         string
		Sni                    string
		RealityHandshakeServer string
		RealityHandshakePort   int
		TelemetrySecret        string
	}
	cfgDir := constant.SingBoxConfigDir
	if sbs.ConfigFile != "" {
		cfgDir = filepath.Dir(sbs.ConfigFile)
	}
	telemetrySecret, _ := telemetry.EnsureSecret(cfgDir)
	sbDomain := sbs.cfg.Server.GetNodeDomain()
	sni := sbs.cfg.Server.Sni
	handshakeServer := sni
	handshakePort := 443
	if sbDomain != "" && strings.EqualFold(strings.TrimSpace(sni), strings.TrimSpace(sbDomain)) {
		handshakeServer = "127.0.0.1"
		handshakePort = 9443
	}
	ctx := tmplContext{
		HyUUID:                 sbs.hyUUID,
		SBDomain:               sbDomain,
		CertPath:               sbs.crtPath,
		KeyPath:                sbs.keyPath,
		RealityPrivateKey:      sbs.privateKey,
		RealityShortID:         sbs.shortID,
		Sni:                    sni,
		RealityHandshakeServer: handshakeServer,
		RealityHandshakePort:   handshakePort,
		TelemetrySecret:        telemetrySecret,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("failed to execute sing-box template: %w", err)
	}
	rendered := buf.String()
	if handshakePort != 443 {
		patched, patchErr := setRealityHandshakePort(rendered, handshakePort)
		if patchErr != nil {
			return "", fmt.Errorf("failed to apply reality handshake port: %w", patchErr)
		}
		rendered = patched
	}
	if sbs.cfg != nil {
		if compiled, applyErr := ApplyWarpRoutingWithProtectedDomains([]byte(rendered), sbs.cfg.Server.WarpRouting, CollectServerProtectedDomains(sbs.cfg)); applyErr == nil {
			rendered = string(compiled)
		}
	}
	return rendered, nil
}

func (sbs *SingBoxServer) renderSingboxConfig() error {
	content, err := sbs.PreviewServerConfig()
	if err != nil {
		return fmt.Errorf("failed to render config: %w", err)
	}
	if err := os.MkdirAll(constant.SingBoxConfigDir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(constant.SingBoxConfigFile, []byte(content), 0600); err != nil {
		return err
	}
	return ensureFilePermissions(constant.SingBoxConfigFile, 0600)
}

func UninstallSingbox() error {
	logger.Info("Uninstalling sing-box server...")
	_ = serviceMgr().RemoveUnit(context.Background(), servicemgrUnitSpec("sing-box", constant.SingBoxSystemdService))
	exe := constant.SingBoxInstallDir
	if err := os.Remove(exe); err != nil && !os.IsNotExist(err) {
		logger.Warn("Failed to remove sing-box executable: %v", err)
	}
	if err := os.RemoveAll(constant.SingBoxConfigDir); err != nil {
		logger.Warn("Failed to remove sing-box config directory: %v", err)
	}
	logger.Success("Sing-box uninstallation completed.")
	return nil
}
