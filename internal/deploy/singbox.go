package deploy

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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
	// Try loading existing deployed credentials first to prevent redundant regeneration
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

func (sbs *SingBoxServer) updateShareLinks() {
	nodeDomain := sbs.cfg.Server.GetNodeDomain()
	hy2Port := sbs.Hy2Port()
	vlessPort := sbs.VlessPort()
	sbs.ShareLinkHy2 = fmt.Sprintf("hysteria2://%s@%s:%d/?sni=%s&alpn=h3&insecure=0#%s", sbs.hyUUID, nodeDomain, hy2Port, nodeDomain, sbs.hy2Tag)
	sbs.ShareLinkVless = fmt.Sprintf("vless://%s@%s:%d?type=tcp&encryption=none&security=reality&pbk=%s&fp=chrome&sni=%s&sid=%s&flow=xtls-rprx-vision#%s", sbs.hyUUID, nodeDomain, vlessPort, sbs.publicKey, sbs.cfg.Server.Sni, sbs.shortID, sbs.vrTag)
}

// HyUUID returns the Hysteria2 password / VLESS UUID.
func (sbs *SingBoxServer) HyUUID() string {
	return sbs.hyUUID
}

// PublicKey returns the VLESS Reality public key.
func (sbs *SingBoxServer) PublicKey() string {
	return sbs.publicKey
}

// ShortID returns the VLESS Reality short ID.
func (sbs *SingBoxServer) ShortID() string {
	return sbs.shortID
}

// Hy2Tag returns the Hysteria 2 tag.
func (sbs *SingBoxServer) Hy2Tag() string {
	return sbs.hy2Tag
}

// VrTag returns the VLESS Reality tag.
func (sbs *SingBoxServer) VrTag() string {
	return sbs.vrTag
}

// Hy2Port returns the external Hysteria 2 UDP port (defaults to 443; configurable via server.hy2_port).
func (sbs *SingBoxServer) Hy2Port() int {
	if sbs != nil && sbs.cfg != nil {
		return sbs.cfg.Server.GetHy2Port()
	}
	return 443
}

// VlessPort returns the external VLESS Reality TCP port (defaults to 443; configurable via server.vless_port).
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
	now := time.Now()
	if now.After(cert.NotAfter) {
		return false
	}
	issuerCN := strings.ToLower(cert.Issuer.CommonName)
	issuerOrg := strings.ToLower(strings.Join(cert.Issuer.Organization, " "))
	if strings.Contains(issuerCN, "caddy local") || strings.Contains(issuerOrg, "caddy local") {
		return false
	}
	if cert.Issuer.String() == cert.Subject.String() {
		return false
	}
	return true
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
		// Never select Caddy's internal self-signed local CA directory for public Hysteria2 nodes
		if dirNameLower == "local" || dirNameLower == "pki" {
			continue
		}
		// 1. Direct domain cert match
		crtPath := filepath.Join(basePath, d.Name(), domain, domain+".crt")
		keyPath := filepath.Join(basePath, d.Name(), domain, domain+".key")
		if _, err := os.Stat(crtPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil && IsValidPublicACMECert(crtPath) {
				return crtPath, keyPath
			}
		}

		// 2. Wildcard cert fallback (e.g. wildcard_.example.com)
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

	// 1. Immediate check: if certs already exist, return instantly without logging wait
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

		needsCertFix := curCrt != validCrt || !IsValidPublicACMECert(curCrt)
		if needsCertFix {
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
	_ = exec.Command("systemctl", "restart", "sing-box").Run()
	return true, healMsg, nil
}

// initCaddyCertPath finds or waits for the actual cert path Caddy generated (Let's Encrypt or ZeroSSL)
func (sbs *SingBoxServer) initCaddyCertPath() {
	nodeDomain := sbs.cfg.Server.GetNodeDomain()
	sbs.crtPath, sbs.keyPath = findCaddyCertForDomain(nodeDomain)
}

// RefreshCaddyCertPath re-resolves the Caddy TLS certificate path after Caddy deployment/renewal
// without clearing already loaded credentials.
func (sbs *SingBoxServer) RefreshCaddyCertPath() {
	sbs.initCaddyCertPath()
}

// SetConfig updates the underlying config reference on an already-initialized SingBoxServer instance.
func (sbs *SingBoxServer) SetConfig(cfg *config.Config) {
	if cfg != nil {
		sbs.cfg = cfg
		sbs.updateShareLinks()
	}
}
func (sbs *SingBoxServer) initVRParams() error {
	// If credentials were already loaded (e.g. via LoadExistingCredentials), skip generation.
	if sbs.hyUUID != "" {
		if sbs.publicKey == "" && sbs.privateKey != "" {
			pub, err := deriveRealityPublicKey(sbs.privateKey)
			if err != nil {
				return fmt.Errorf("failed to derive reality public key from existing private key: %w", err)
			}
			sbs.publicKey = pub
		}
		return nil
	}

	// 2. Generate a new UUID
	logger.Info("Generating new UUID for Hysteria2 and VLESS...")
	uuid, err := generateUUIDv4()
	if err != nil {
		return fmt.Errorf("failed to generate uuid: %w", err)
	}
	sbs.hyUUID = uuid

	// Generate Reality Keypair
	logger.Info("Generating VLESS Reality Keypair...")
	privateKey, publicKey, err := generateRealityKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate reality keypair locally: %w", err)
	}
	sbs.privateKey = privateKey
	sbs.publicKey = publicKey

	logger.Info("Generating VLESS Reality Short ID...")
	shortID, err := generateHexRandom(8)
	if err != nil {
		return fmt.Errorf("failed to generate short id: %w", err)
	}
	sbs.shortID = shortID
	return nil
}

func generateUUIDv4() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// RFC 4122 version 4 UUID
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func generateRealityKeypair() (privateKey string, publicKey string, err error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privateKey = base64.RawURLEncoding.EncodeToString(priv.Bytes())
	publicKey = base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	return privateKey, publicKey, nil
}

func deriveRealityPublicKey(privateKey string) (string, error) {
	privBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil {
		return "", err
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func generateHexRandom(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DeploySingbox handles sing-box installation, config rendering, and outputs URL

// 定义标准的服务文件内容 (请根据你的实际二进制路径和配置文件路径调整 ExecStart)
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

// 检查并创建 service 文件的辅助方法
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
		if err := runCmd("systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("failed to daemon-reload: %w", err)
		}
		logger.Success("sing-box.service is ready at %s", servicePath)
	}

	return nil
}

// 修复后的主部署逻辑
func (sbs *SingBoxServer) DeploySingbox() error {
	logger.Info("Starting Sing-box Server deployment...")

	// 1. Install or update Sing-box core
	logger.Info("Installing/Updating sing-box core...")
	sb := singbox.New(sbs.cfg)
	if err := sb.Install(); err != nil {
		return fmt.Errorf("failed to install sing-box: %w", err)
	}

	// 2. Render and save config.json
	logger.Info("Rendering and saving sing-box config.json...")
	if err := sbs.renderSingboxConfig(); err != nil {
		return fmt.Errorf("failed to render config: %w", err)
	}

	// 3. 检查并创建 systemd 服务 (新增的拦截逻辑)
	if err := sbs.ensureSystemdService(); err != nil {
		return err
	}

	// 4. Enable and restart sing-box service (使用 restart 确保加载新配置)
	logger.Info("Restarting sing-box service...")

	if err := runCmd("systemctl", "enable", "sing-box"); err != nil {
		return fmt.Errorf("failed to enable sing-box service: %w", err)
	}
	if err := runCmd("systemctl", "restart", "sing-box"); err != nil {
		return fmt.Errorf("failed to restart sing-box service: %w", err)
	}
	sbs.updateShareLinks()
	sbs.ShowLoginInfo()
	return nil
}

// RegenerateCredentials forces generation of fresh credentials and updates share links.
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

// ResetCredentials regenerates credentials, renders configuration, and restarts sing-box.
func (sbs *SingBoxServer) ResetCredentials() error {
	logger.Info("Resetting sing-box server credentials...")

	// 1. Check if sing-box is installed; install if missing
	if _, err := os.Stat(constant.SingBoxInstallDir); os.IsNotExist(err) {
		logger.Info("sing-box binary not found, installing...")
		sb := singbox.New(sbs.cfg)
		if err := sb.Install(); err != nil {
			return fmt.Errorf("failed to install sing-box: %w", err)
		}
	}

	// 2. Regenerate credentials and share links
	if err := sbs.RegenerateCredentials(); err != nil {
		return fmt.Errorf("failed to regenerate credentials: %w", err)
	}

	// 3. Render and save config.json
	logger.Info("Rendering and saving new sing-box config.json...")
	if err := sbs.renderSingboxConfig(); err != nil {
		return fmt.Errorf("failed to render config: %w", err)
	}

	// 4. Ensure systemd service exists and is up to date
	if err := sbs.ensureSystemdService(); err != nil {
		return err
	}

	// 5. Restart sing-box service
	logger.Info("Restarting sing-box service...")
	if err := runCmd("systemctl", "enable", "sing-box"); err != nil {
		return fmt.Errorf("failed to enable sing-box service: %w", err)
	}
	if err := runCmd("systemctl", "restart", "sing-box"); err != nil {
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

	// 1. Hysteria 2
	fmt.Printf("\n【1】Hysteria 2 节点 (端口: %d / QUIC UDP)\n", sbs.Hy2Port())
	fmt.Printf("• 分享链接: %s\n", sbs.ShareLinkHy2)

	// 2. VLESS Reality
	fmt.Printf("\n【2】VLESS Reality 节点 (端口: %d / TCP Reality)\n", sbs.VlessPort())
	fmt.Printf("• 分享链接: %s\n", sbs.ShareLinkVless)
	fmt.Println("────────────────────────────────────────────────────────────")
	fmt.Println()
}

// PreviewServerConfig renders the sing-box server config template and returns it as a string.
// It is exported for use in tests.
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
		// Reality 自偷模式 (当 SNI 与节点自身域名一致，如 NAT 443 域名分流场景)：
		// 指向本地 Caddy 9443 真实 ACME 证书端点，避免连接自身 :443 形成 Layer4 转发死循环。
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
		rendered = strings.Replace(
			rendered,
			fmt.Sprintf("\"server\": %q,\n            \"server_port\": 443", handshakeServer),
			fmt.Sprintf("\"server\": %q,\n            \"server_port\": %d", handshakeServer, handshakePort),
			1,
		)
	}
	if sbs.cfg != nil && !sbs.cfg.Server.WarpRouting.IsEmpty() {
		if compiled, applyErr := ApplyWarpRoutingToServerConfigJSON([]byte(rendered), sbs.cfg.Server.WarpRouting); applyErr == nil {
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

func (sbs *SingBoxServer) getConfigFile() string {
	if sbs.ConfigFile != "" {
		return sbs.ConfigFile
	}
	return constant.SingBoxConfigFile
}

// LoadExistingCredentials reads the deployed sing-box config and populates
// sbs with the existing uuid, private_key and short_id, and updates share links
// so that SNI updates or node syncs accurately reflect deployed credentials.
func (sbs *SingBoxServer) LoadExistingCredentials() error {
	configFile := sbs.getConfigFile()
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("read existing config: %w", err)
	}

	var raw struct {
		Inbounds []struct {
			Type  string `json:"type"`
			Users []struct {
				UUID string `json:"uuid"`
			} `json:"users"`
			TLS struct {
				ServerName string `json:"server_name"`
				Reality    struct {
					PrivateKey string   `json:"private_key"`
					ShortID    []string `json:"short_id"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse existing config: %w", err)
	}

	for _, inbound := range raw.Inbounds {
		if len(inbound.Users) > 0 && inbound.Users[0].UUID != "" {
			sbs.hyUUID = inbound.Users[0].UUID
			if inbound.TLS.ServerName != "" && sbs.cfg != nil && sbs.cfg.Server.Sni == "" {
				sbs.cfg.Server.Sni = inbound.TLS.ServerName
			}
			sbs.privateKey = inbound.TLS.Reality.PrivateKey
			if sbs.privateKey != "" {
				pub, err := deriveRealityPublicKey(sbs.privateKey)
				if err != nil {
					return fmt.Errorf("derive public key from existing private key: %w", err)
				}
				sbs.publicKey = pub
			}
			if len(inbound.TLS.Reality.ShortID) > 0 {
				sbs.shortID = inbound.TLS.Reality.ShortID[0]
			}
			sbs.updateShareLinks()
			logger.Info("Loaded existing credentials from %s", configFile)
			return nil
		}
	}
	return fmt.Errorf("no credentials found in existing sing-box config")
}

// UninstallServer uninstalls sing-box from the server
func UninstallSingbox() error {
	logger.Info("Uninstalling sing-box server...")

	// Stop and disable service
	_ = exec.Command("systemctl", "stop", "sing-box").Run()
	_ = exec.Command("systemctl", "disable", "sing-box").Run()

	// Remove service file
	if err := os.Remove(constant.SingBoxSystemdService); err != nil && !os.IsNotExist(err) {
		logger.Warn("Failed to remove sing-box.service: %v", err)
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()

	// Remove executable
	exe := constant.SingBoxInstallDir
	if err := os.Remove(exe); err != nil && !os.IsNotExist(err) {
		logger.Warn("Failed to remove sing-box executable: %v", err)
	}

	// Remove configs
	if err := os.RemoveAll(constant.SingBoxConfigDir); err != nil {
		logger.Warn("Failed to remove sing-box config directory: %v", err)
	}

	logger.Success("Sing-box uninstallation completed.")
	return nil
}
