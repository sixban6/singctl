package deploy

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
)

type SingBoxServer struct {
	crtPath string
	keyPath string

	hyUUID     string
	privateKey string
	publicKey  string
	shortID    string
	cfg        *config.Config

	hy2Tag         string
	vrTag          string
	ShareLinkHy2   string
	ShareLinkVless string
}

func NewSingBoxServer(cfg *config.Config) *SingBoxServer {
	sbs := &SingBoxServer{cfg: cfg}
	sbs.init()
	return sbs
}

func (sbs *SingBoxServer) init() {
	sbs.initCaddyCertPath()
	err := sbs.initVRParams()
	if err != nil {
		logger.Error("failed to initialize VR parameters: %v", err)
		os.Exit(-1)
	}
	sbs.initTag()
}

func (sbs *SingBoxServer) initTag() {
	suffix, _, _ := strings.Cut(sbs.cfg.Server.SBDomain, ".")
	sbs.hy2Tag = fmt.Sprintf("sec_%s_hy2", suffix)
	sbs.vrTag = fmt.Sprintf("sec_%s_vr", suffix)
}

// getCaddyCertPath waits and finds the actual cert path Caddy generated (Let's Encrypt or ZeroSSL)
func (sbs *SingBoxServer) initCaddyCertPath() {
	basePath := "/var/lib/caddy/.local/share/caddy/certificates"

	logger.Info("Waiting for Caddy to generate certificates for %s...", sbs.cfg.Server.SBDomain)

	// 最多重试 30 次，每次间隔 1 秒
	for range 30 {
		dirs, err := os.ReadDir(basePath)
		if err == nil {
			for _, d := range dirs {
				if !d.IsDir() {
					continue
				}
				crtPath := filepath.Join(basePath, d.Name(), sbs.cfg.Server.SBDomain, sbs.cfg.Server.SBDomain+".crt")
				keyPath := filepath.Join(basePath, d.Name(), sbs.cfg.Server.SBDomain, sbs.cfg.Server.SBDomain+".key")

				if _, err := os.Stat(crtPath); err == nil {
					if _, err := os.Stat(keyPath); err == nil {
						logger.Success("Found certificate at %s", crtPath)
						sbs.crtPath = crtPath
						sbs.keyPath = keyPath
						// 修复关键：找到证书后，立刻结束函数，不再继续等待
						return
					}
				}
			}
		}
		// 没找到，休息 1 秒后再进下一次循环
		time.Sleep(1 * time.Second)
	}

	// 只有当 30 次循环都跑完还没 `return` 时，才会走到这里（真正触发超时）
	logger.Warn("Timeout waiting for Caddy certs, using Let's Encrypt fallback path")
	sbs.crtPath = filepath.Join(basePath, "acme-v02.api.letsencrypt.org-directory", sbs.cfg.Server.SBDomain, sbs.cfg.Server.SBDomain+".crt")
	sbs.keyPath = filepath.Join(basePath, "acme-v02.api.letsencrypt.org-directory", sbs.cfg.Server.SBDomain, sbs.cfg.Server.SBDomain+".key")
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
const singboxServiceContent = `[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c %s
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

	// 1. 检查文件是否存在
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		logger.Info("sing-box.service not found, creating it...")

		// 2. 写入服务文件
		svcContent := fmt.Sprintf(singboxServiceContent, constant.SingBoxConfigFile)
		if err := os.WriteFile(servicePath, []byte(svcContent), 0644); err != nil {
			return fmt.Errorf("failed to write sing-box.service: %w", err)
		}

		// 3. 重新加载 systemd 守护进程以识别新服务
		logger.Info("Reloading systemd daemon...")
		if err := runCmd("systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("failed to daemon-reload: %w", err)
		}

		logger.Success("Successfully created sing-box.service")
	} else if err != nil {
		return fmt.Errorf("failed to check service file state: %w", err)
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
	sbs.ShareLinkHy2 = fmt.Sprintf("hysteria2://%s@%s/?sni=%s&alpn=h3&insecure=0#%s", sbs.hyUUID, sbs.cfg.Server.SBDomain, sbs.cfg.Server.SBDomain, sbs.hy2Tag)
	sbs.ShareLinkVless = fmt.Sprintf("vless://%s@%s:443?type=tcp&encryption=none&security=reality&pbk=%s&fp=chrome&sni=%s&sid=%s&flow=xtls-rprx-vision#%s", sbs.hyUUID, sbs.cfg.Server.SBDomain, sbs.publicKey, sbs.cfg.Server.Sni, sbs.shortID, sbs.vrTag)
	sbs.ShowLoginInfo()
	return nil
}

func (sbs *SingBoxServer) ShowLoginInfo() {

	// 5. Print high-visibility output

	logger.Success("Sing-box Server deployed successfully!")
	fmt.Println("\n========================================================")
	fmt.Println("🚀 Hysteria2 Access Link (Copy to your client):")
	fmt.Printf("%s\n", sbs.ShareLinkHy2)
	fmt.Println("\n🚀 VLESS Reality Access Link (Copy to your client):")
	fmt.Printf("%s\n", sbs.ShareLinkVless)
	fmt.Println("========================================================")
}

// PreviewServerConfig renders the sing-box server config template and returns it as a string.
// It is exported for use in tests.
func (sbs *SingBoxServer) PreviewServerConfig() (string, error) {
	tmplData, err := templateFiles.ReadFile("templates/server_config.json")
	if err != nil {
		return "", fmt.Errorf("could not read embedded sing-box template: %w", err)
	}

	t, err := template.New("singbox_config").Parse(string(tmplData))
	if err != nil {
		return "", fmt.Errorf("failed to parse sing-box template: %w", err)
	}

	type tmplContext struct {
		HyUUID            string
		SBDomain          string
		CertPath          string
		KeyPath           string
		RealityPrivateKey string
		RealityShortID    string
		Sni               string
	}
	ctx := tmplContext{
		HyUUID:            sbs.hyUUID,
		SBDomain:          sbs.cfg.Server.SBDomain,
		CertPath:          sbs.crtPath,
		KeyPath:           sbs.keyPath,
		RealityPrivateKey: sbs.privateKey,
		RealityShortID:    sbs.shortID,
		Sni:               sbs.cfg.Server.Sni,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("failed to execute sing-box template: %w", err)
	}
	return buf.String(), nil
}

func (sbs *SingBoxServer) renderSingboxConfig() error {
	content, err := sbs.PreviewServerConfig()
	if err != nil {
		return fmt.Errorf("failed to render config: %w", err)
	}

	if err := os.MkdirAll(constant.SingBoxConfigDir, 0755); err != nil {
		return err
	}

	return os.WriteFile(constant.SingBoxConfigFile, []byte(content), 0644)
}

// LoadExistingCredentials reads the deployed sing-box config and populates
// sbs with the existing uuid, private_key and short_id so that SNI updates
// do not regenerate credentials.
func (sbs *SingBoxServer) LoadExistingCredentials() error {
	data, err := os.ReadFile(constant.SingBoxConfigFile)
	if err != nil {
		return fmt.Errorf("read existing config: %w", err)
	}

	var raw struct {
		Inbounds []struct {
			Users []struct {
				UUID string `json:"uuid"`
			} `json:"users"`
			TLS struct {
				Reality struct {
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
			logger.Info("Loaded existing credentials from %s", constant.SingBoxConfigFile)
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
