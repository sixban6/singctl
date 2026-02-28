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
	"singctl/internal/fileutil"
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
		logger.Info("Init VR Protocol Params Failed")
		return
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
	for i := 0; i < 30; i++ {
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

	// 2. Generate a new UUID
	logger.Info("Generating new UUID for Hysteria2 and VLESS...")
	uuidCmd := exec.Command("sing-box", "generate", "uuid")
	out, err := uuidCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate sing-box uuid: %w", err)
	}
	sbs.hyUUID = strings.TrimSpace(string(out))

	// Generate Reality Keypair
	logger.Info("Generating VLESS Reality Keypair...")
	keyCmd := exec.Command("sing-box", "generate", "reality-keypair")
	keyOut, err := keyCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate reality keypair: %w", err)
	}
	for _, line := range strings.Split(string(keyOut), "\n") {
		if strings.HasPrefix(line, "PrivateKey: ") {
			sbs.privateKey = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey: "))
		} else if strings.HasPrefix(line, "PublicKey: ") {
			sbs.publicKey = strings.TrimSpace(strings.TrimPrefix(line, "PublicKey: "))
		}
	}

	logger.Info("Generating VLESS Reality Short ID...")
	sidCmd := exec.Command("sing-box", "generate", "rand", "8", "--hex")
	sidOut, err := sidCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate short id: %w", err)
	}
	sbs.shortID = strings.TrimSpace(string(sidOut))
	return nil
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
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
`

// 检查并创建 service 文件的辅助方法
func (sbs *SingBoxServer) ensureSystemdService() error {
	servicePath := "/etc/systemd/system/sing-box.service"

	// 1. 检查文件是否存在
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		logger.Info("sing-box.service not found, creating it...")

		// 2. 写入服务文件
		if err := os.WriteFile(servicePath, []byte(singboxServiceContent), 0644); err != nil {
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
	sbs.ShareLinkVless = fmt.Sprintf("vless://%s@%s:443?type=tcp&encryption=none&security=reality&pbk=%s&fp=chrome&sni=www.microsoft.com&sid=%s&flow=xtls-rprx-vision#%s", sbs.hyUUID, sbs.cfg.Server.SBDomain, sbs.publicKey, sbs.shortID, sbs.vrTag)
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

func (sbs *SingBoxServer) renderSingboxConfig() error {
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
		HyUUID:            sbs.hyUUID,
		SBDomain:          sbs.cfg.Server.SBDomain,
		CertPath:          sbs.crtPath,
		KeyPath:           sbs.keyPath,
		RealityPrivateKey: sbs.privateKey,
		RealityShortID:    sbs.shortID,
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

// UninstallServer uninstalls sing-box from the server
func UninstallSingbox() error {
	logger.Info("Uninstalling sing-box server...")

	// Stop and disable service
	_ = exec.Command("systemctl", "stop", "sing-box").Run()
	_ = exec.Command("systemctl", "disable", "sing-box").Run()

	// Remove service file
	if err := os.Remove("/etc/systemd/system/sing-box.service"); err != nil && !os.IsNotExist(err) {
		logger.Warn("Failed to remove sing-box.service: %v", err)
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()

	// Remove executable
	exe := fileutil.GetSingBoxInstallDir()
	if err := os.Remove(exe); err != nil && !os.IsNotExist(err) {
		logger.Warn("Failed to remove sing-box executable: %v", err)
	}

	// Remove configs
	if err := os.RemoveAll(filepath.Dir(fileutil.GetSingboxConfigPath())); err != nil {
		logger.Warn("Failed to remove sing-box config directory: %v", err)
	}

	logger.Success("Sing-box uninstallation completed.")
	return nil
}
