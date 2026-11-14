package terminal

import (
	"archive/tar"
	"cmp"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"
)

const (
	DefaultTerminalPort  = 18080
	DefaultSSHTunnelPort = 18081
	DefaultSSHTunnelPath = "/ssh-ws"
	DefaultMtlsCADir     = "/etc/caddy/mtls"
	DefaultMtlsCACert    = "/etc/caddy/mtls/ca.crt"
	DefaultClientP12     = "/etc/caddy/mtls/client.p12"
	DefaultClientCrt     = "/etc/caddy/mtls/client.crt"
	DefaultClientKey     = "/etc/caddy/mtls/client.key"
	GottyVersion         = "v1.5.0"
	GottyBinaryPath      = "/usr/local/bin/gotty"
	GottyServicePath     = "/etc/systemd/system/gotty.service"
	WstunnelVersion      = "v11.1.0"
	WstunnelBinaryPath   = "/usr/local/bin/wstunnel"
	WstunnelServicePath  = "/etc/systemd/system/wstunnel.service"
)

// InstallOptions contains options for terminal deployment
type InstallOptions struct {
	Path            string
	Port            int
	Password        string
	Force           bool
	SkipCaddyDeploy bool // 由 sr install / sr ri all 在 DeployCaddy 前置调用时置为 true，避免重复跑 DeployCaddy
}

// InstallResult contains deployment details
type InstallResult struct {
	URL           string
	Domain        string
	Path          string
	Port          int
	SSHTunnelPath string
	SSHTunnelPort int
	SSHPort       int
	Password      string
	P12Path       string
	P12Base64     string
	ClientCrtPath string
	ClientKeyPath string
	NodeTag       string
}

// StatusResult contains terminal status information
type StatusResult struct {
	Enabled         bool
	ServiceActive   bool // GoTTY Web Terminal
	WstunnelActive  bool // wstunnel Native SSH
	Domain          string
	Path            string
	Port            int
	SSHTunnelPath   string
	SSHTunnelPort   int
	SSHPort         int
	URL             string
	P12Exists       bool
	P12Path         string
	ClientCrtExists bool
	ClientCrtPath   string
	ClientKeyPath   string
	Password        string
	NodeTag         string
}

// GenerateRandomHex generates random hex characters
func GenerateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateRandomPassword generates a friendly secure alphanumeric password
func GenerateRandomPassword(length int) string {
	const charset = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, length)
	randBytes := make([]byte, length)
	_, _ = rand.Read(randBytes)
	for i := range b {
		b[i] = charset[int(randBytes[i])%len(charset)]
	}
	return string(b)
}

// Install installs and configures GoTTY + Tmux + mTLS
func Install(cfg *config.Config, configPath string, opts InstallOptions) (*InstallResult, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("Web 终端服务端仅支持在 Linux 系统上运行 (当前为: %s)", runtime.GOOS)
	}

	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return nil, fmt.Errorf("不支持的 CPU 架构: %s (仅支持 amd64 与 arm64)", arch)
	}

	// 1. 规范化参数
	termPath := strings.TrimSpace(opts.Path)
	if termPath == "" {
		if cfg != nil && cfg.Server.WebTerminal.Path != "" {
			termPath = cfg.Server.WebTerminal.Path
		} else {
			termPath = fmt.Sprintf("/term-%s", GenerateRandomHex(4))
		}
	}
	if !strings.HasPrefix(termPath, "/") {
		termPath = "/" + termPath
	}
	termPath = strings.TrimSuffix(termPath, "/")

	port := opts.Port
	if port <= 0 {
		if cfg != nil && cfg.Server.WebTerminal.Port > 0 {
			port = cfg.Server.WebTerminal.Port
		} else {
			port = DefaultTerminalPort
		}
	}

	forceCert := opts.Force
	password := strings.TrimSpace(opts.Password)
	if password != "" {
		if cfg == nil || cfg.Server.WebTerminal.Password != password {
			forceCert = true
		}
	} else {
		if cfg != nil && cfg.Server.WebTerminal.Password != "" {
			password = cfg.Server.WebTerminal.Password
		} else {
			password = GenerateRandomPassword(10)
			if _, ok := resolveMtlsArtifact("client.p12", DefaultClientP12); ok {
				forceCert = true
			}
		}
	}

	domain := ""
	if cfg != nil {
		domain = cfg.Server.GetNodeDomain()
		if domain == "" {
			domain = cfg.Server.GetSubstoreDomain()
		}
	}
	if domain == "" {
		return nil, fmt.Errorf("未在配置中找到有效域名 (node_domain 或 substore_domain)，请先在 %s 中配置域名", configPath)
	}

	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Info("🚀 正在安装与配置 GoTTY + Tmux + mTLS 双向认证 Web 终端...")
	logger.Info("═══════════════════════════════════════════════════════════")

	// 2. 安装系统依赖 (tmux, openssl, tar, wget)
	if err := installDependencies(); err != nil {
		return nil, fmt.Errorf("安装基础依赖失败: %w", err)
	}

	// 3. 安装 GoTTY 二进制
	if err := installGoTTY(cfg, arch); err != nil {
		return nil, fmt.Errorf("安装 GoTTY 二进制失败: %w", err)
	}

	// 4. 生成 mTLS 根证书与客户端证书
	if err := generateMTLSCertificates(password, forceCert); err != nil {
		return nil, fmt.Errorf("生成 mTLS 双向认证证书失败: %w", err)
	}

	// 5. 配置并启动 GoTTY Systemd 守护进程
	tmuxPath, err := exec.LookPath("tmux")
	if err != nil {
		tmuxPath = "/usr/bin/tmux"
	}
	if err := createGottySystemdService(port, termPath, tmuxPath); err != nil {
		return nil, fmt.Errorf("创建 GoTTY Systemd 服务失败: %w", err)
	}

	// 6. 安装并配置 wstunnel (Native SSH over WSS)，保留已配置的端口/路径
	sshPort := resolveWebTerminalSSHPort(cfg, DetectSSHPort)
	sshTunnelPort := DefaultSSHTunnelPort
	if cfg != nil && cfg.Server.WebTerminal.SSHTunnelPort > 0 {
		sshTunnelPort = cfg.Server.WebTerminal.SSHTunnelPort
	}
	sshTunnelPath := DefaultSSHTunnelPath
	if cfg != nil && strings.TrimSpace(cfg.Server.WebTerminal.SSHTunnelPath) != "" {
		sshTunnelPath = strings.TrimSpace(cfg.Server.WebTerminal.SSHTunnelPath)
	}
	mtlsCA := cmp.Or(deploy.DefaultCaddyMtlsCACertPath(), DefaultMtlsCACert)
	if cfg != nil && strings.TrimSpace(cfg.Server.WebTerminal.MtlsCA) != "" {
		mtlsCA = strings.TrimSpace(cfg.Server.WebTerminal.MtlsCA)
	}
	_, _, _ = deploy.EnsureCaddyMtlsTrustPool(mtlsCA)

	if err := installWstunnel(cfg, arch); err != nil {
		logger.Warn("安装 wstunnel 失败 (Native SSH 穿透可能不可用): %v", err)
	} else {
		if err := createWstunnelSystemdService(sshTunnelPort, sshPort); err != nil {
			logger.Warn("启动 wstunnel 守护进程失败: %v", err)
		}
	}

	// 7. 更新 singctl.yaml 配置
	if cfg != nil {
		cfg.Server.WebTerminal = config.WebTerminalConfig{
			Enabled:       true,
			Port:          port,
			Path:          termPath,
			MtlsCA:        mtlsCA,
			Password:      password,
			SSHTunnelPort: sshTunnelPort,
			SSHTunnelPath: sshTunnelPath,
			SSHPort:       sshPort,
		}
		if err := config.Save(configPath, cfg); err != nil {
			logger.Warn("保存 singctl.yaml 失败: %v", err)
		} else {
			logger.Success("已更新 Web 终端与 SSH 穿透配置至 %s", configPath)
		}
	}

	// 8. 渲染 Caddyfile 并平滑重载 Caddy (sr install 前置准备场景可通过 SkipCaddyDeploy 跳过重复部署)
	if !opts.SkipCaddyDeploy {
		logger.Info("正在更新 Caddyfile 并重载 Caddy 路由...")
		if err := deploy.DeployCaddy(cfg); err != nil {
			return nil, fmt.Errorf("更新 Caddy 配置失败: %w", err)
		}
	}

	// 9. 读取客户端证书 client.p12 并编码为 Base64
	p12Path, _ := resolveMtlsArtifact("client.p12", DefaultClientP12)
	crtPath, _ := resolveMtlsArtifact("client.crt", DefaultClientCrt)
	keyPath, _ := resolveMtlsArtifact("client.key", DefaultClientKey)

	var p12Base64 string
	if p12Bytes, err := os.ReadFile(p12Path); err == nil {
		p12Base64 = base64.StdEncoding.EncodeToString(p12Bytes)
	}

	nodeTag := "node"
	if cfg != nil {
		nodeTag = cfg.Server.GetNodeTag()
	}
	if nodeTag == "" {
		nodeTag = "node"
	}

	fullURL := fmt.Sprintf("https://%s%s/", domain, termPath)
	res := &InstallResult{
		URL:           fullURL,
		Domain:        domain,
		Path:          termPath,
		Port:          port,
		SSHTunnelPath: sshTunnelPath,
		SSHTunnelPort: sshTunnelPort,
		SSHPort:       sshPort,
		Password:      password,
		P12Path:       p12Path,
		P12Base64:     p12Base64,
		ClientCrtPath: crtPath,
		ClientKeyPath: keyPath,
		NodeTag:       nodeTag,
	}

	return res, nil
}

// Uninstall stops GoTTY, removes service and cleans up certificates
func Uninstall(cfg *config.Config, configPath string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("Web 终端操作仅支持在 Linux 系统上运行")
	}

	logger.Info("正在停止并禁用 GoTTY 与 wstunnel 服务...")
	_ = exec.Command("systemctl", "stop", "gotty").Run()
	_ = exec.Command("systemctl", "disable", "gotty").Run()
	_ = os.Remove(GottyServicePath)
	_ = exec.Command("systemctl", "stop", "wstunnel").Run()
	_ = exec.Command("systemctl", "disable", "wstunnel").Run()
	_ = os.Remove(WstunnelServicePath)
	_ = exec.Command("systemctl", "daemon-reload").Run()

	logger.Info("正在清理 mTLS 证书目录...")
	if err := deploy.RemoveMtlsAll(); err != nil {
		logger.Warn("清理 mTLS 证书警告: %v", err)
	}

	if cfg != nil {
		cfg.Server.WebTerminal.Enabled = false
		if err := config.Save(configPath, cfg); err != nil {
			logger.Warn("更新配置失败: %v", err)
		}
		logger.Info("正在更新 Caddyfile 并移除 Web 终端与 SSH 穿透路由...")
		if err := deploy.DeployCaddy(cfg); err != nil {
			logger.Warn("重载 Caddy 失败: %v", err)
		}
	}

	logger.Success("GoTTY Web 终端、wstunnel SSH 穿透服务与 mTLS 证书已彻底卸载。")
	return nil
}

// Status checks the status of Web Terminal
func Status(cfg *config.Config) (*StatusResult, error) {
	p12Path, p12Exists := resolveMtlsArtifact("client.p12", DefaultClientP12)
	crtPath, crtExists := resolveMtlsArtifact("client.crt", DefaultClientCrt)
	keyPath, _ := resolveMtlsArtifact("client.key", DefaultClientKey)

	res := &StatusResult{
		P12Path:         p12Path,
		P12Exists:       p12Exists,
		ClientCrtPath:   crtPath,
		ClientCrtExists: crtExists,
		ClientKeyPath:   keyPath,
		SSHTunnelPath:   DefaultSSHTunnelPath,
		SSHTunnelPort:   DefaultSSHTunnelPort,
		SSHPort:         22,
		NodeTag:         "node",
	}

	if cfg != nil {
		if tag := cfg.Server.GetNodeTag(); tag != "" {
			res.NodeTag = tag
		}
		res.Enabled = cfg.Server.WebTerminal.Enabled
		res.Path = cfg.Server.WebTerminal.Path
		res.Port = cfg.Server.WebTerminal.Port
		res.Password = cfg.Server.WebTerminal.Password
		if cfg.Server.WebTerminal.SSHTunnelPath != "" {
			res.SSHTunnelPath = cfg.Server.WebTerminal.SSHTunnelPath
		}
		if cfg.Server.WebTerminal.SSHTunnelPort > 0 {
			res.SSHTunnelPort = cfg.Server.WebTerminal.SSHTunnelPort
		}
		res.SSHPort = resolveWebTerminalSSHPort(cfg, DetectSSHPort)
		domain := cfg.Server.GetNodeDomain()
		if domain == "" {
			domain = cfg.Server.GetSubstoreDomain()
		}
		res.Domain = domain
		if res.Domain != "" && res.Path != "" {
			res.URL = fmt.Sprintf("https://%s%s/", res.Domain, res.Path)
		}
	} else {
		res.SSHPort = DetectSSHPort()
	}

	if runtime.GOOS == "linux" {
		out, err := exec.Command("systemctl", "is-active", "gotty").Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			res.ServiceActive = true
		}
		outWs, errWs := exec.Command("systemctl", "is-active", "wstunnel").Output()
		if errWs == nil && strings.TrimSpace(string(outWs)) == "active" {
			res.WstunnelActive = true
		}
	}

	return res, nil
}

// ExportCert reads the client.p12 certificate file and returns base64 string
func ExportCert() (string, error) {
	p12Path, ok := resolveMtlsArtifact("client.p12", DefaultClientP12)
	if !ok {
		return "", fmt.Errorf("客户端证书文件 %s 不存在，请先执行 singctl term install", p12Path)
	}
	bytes, err := os.ReadFile(p12Path)
	if err != nil {
		return "", fmt.Errorf("读取证书失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func resolveMtlsArtifact(name, legacyPath string) (string, bool) {
	vaultPath := deploy.VaultMtlsFilePath(name)
	if info, err := os.Stat(vaultPath); err == nil && !info.IsDir() && info.Size() > 0 {
		return vaultPath, true
	}
	if legacyPath != "" {
		if info, err := os.Stat(legacyPath); err == nil && !info.IsDir() && info.Size() > 0 {
			return legacyPath, true
		}
	}
	return vaultPath, false
}

func installDependencies() error {
	logger.Info("正在检查并安装系统依赖 (tmux, openssl, tar, wget)...")

	// 1. 如果基础依赖都已经安装，直接放行
	if isCommandAvailable("tmux") && isCommandAvailable("openssl") && isCommandAvailable("tar") && isCommandAvailable("wget") {
		logger.Success("基础依赖环境已完备。")
		return nil
	}

	// 2. 根据系统包管理器安装基础依赖
	if isCommandAvailable("apt-get") {
		_ = exec.Command("apt-get", "update", "-y").Run()
		cmdInstall := exec.Command("apt-get", "install", "-y", "tmux", "openssl", "tar", "wget")
		cmdInstall.Stdout = os.Stdout
		cmdInstall.Stderr = os.Stderr
		if err := cmdInstall.Run(); err != nil {
			return fmt.Errorf("apt-get 安装依赖失败: %w", err)
		}
		// 可选安装 openssl-provider-legacy (部分系统无此独立包，忽略错误)
		_ = exec.Command("apt-get", "install", "-y", "openssl-provider-legacy").Run()
	} else if isCommandAvailable("dnf") {
		cmd := exec.Command("dnf", "install", "-y", "tmux", "openssl", "tar", "wget")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("dnf 安装依赖失败: %w", err)
		}
	} else if isCommandAvailable("yum") {
		cmd := exec.Command("yum", "install", "-y", "tmux", "openssl", "tar", "wget")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("yum 安装依赖失败: %w", err)
		}
	} else if isCommandAvailable("apk") {
		cmd := exec.Command("apk", "add", "--no-cache", "tmux", "openssl", "tar", "wget")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("apk 安装依赖失败: %w", err)
		}
	} else {
		return fmt.Errorf("未识别的 Linux 包管理器 (请先手动安装 tmux, openssl, tar, wget)")
	}

	// 3. 再次校验关键依赖
	if isCommandAvailable("tmux") && isCommandAvailable("openssl") && isCommandAvailable("tar") && isCommandAvailable("wget") {
		logger.Success("基础依赖环境已安装完成。")
		return nil
	}

	return fmt.Errorf("基础依赖未完全就绪，请手动安装 tmux 与 openssl")
}

func isCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func installGoTTY(cfg *config.Config, arch string) error {
	if fi, err := os.Stat(GottyBinaryPath); err == nil && fi.Size() > 0 {
		logger.Success("GoTTY 二进制已就绪 (%s)", GottyBinaryPath)
		return nil
	}

	logger.Info("正在下载 GoTTY %s (%s)...", GottyVersion, arch)
	fileName := fmt.Sprintf("gotty_%s_linux_%s.tar.gz", GottyVersion, arch)
	url := fmt.Sprintf("https://github.com/sorenisanerd/gotty/releases/download/%s/%s", GottyVersion, fileName)
	if cfg != nil && cfg.GitHub.MirrorURL != "" {
		url = strings.TrimSuffix(cfg.GitHub.MirrorURL, "/") + "/" + url
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("下载 GoTTY 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 GoTTY 返回状态码 %d", resp.StatusCode)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("解压 gzip 失败: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取 tar 失败: %w", err)
		}

		if header.Name == "gotty" || filepath.Base(header.Name) == "gotty" {
			tmpBinary := GottyBinaryPath + ".tmp"
			outFile, err := os.OpenFile(tmpBinary, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("写入临时 gotty 二进制失败: %w", err)
			}
			_, copyErr := io.Copy(outFile, tarReader)
			outFile.Close()
			if copyErr != nil {
				_ = os.Remove(tmpBinary)
				return fmt.Errorf("保存 gotty 失败: %w", copyErr)
			}
			_ = os.Chmod(tmpBinary, 0755)
			if err := os.Rename(tmpBinary, GottyBinaryPath); err != nil {
				_ = os.Remove(GottyBinaryPath)
				if err := os.Rename(tmpBinary, GottyBinaryPath); err != nil {
					return fmt.Errorf("安装 gotty 二进制失败: %w", err)
				}
			}
			logger.Success("GoTTY 二进制已成功安装至 %s", GottyBinaryPath)
			return nil
		}
	}

	return fmt.Errorf("在下载包中未找到 gotty 可执行文件")
}

func generateMTLSCertificates(password string, force bool) error {
	if err := deploy.MigrateLegacyCaddyMtlsToVault(); err != nil {
		return err
	}

	vaultP12 := deploy.VaultMtlsFilePath("client.p12")
	vaultCA := deploy.VaultMtlsFilePath("ca.crt")
	if !force {
		p12Info, pErr := os.Stat(vaultP12)
		caInfo, cErr := os.Stat(vaultCA)
		if pErr == nil && p12Info.Size() > 0 && cErr == nil && caInfo.Size() > 0 {
			if _, _, err := deploy.EnsureCaddyMtlsTrustPool(""); err != nil {
				return err
			}
			logger.Success("检测到已有 mTLS 证书，复用现有证书 (如需重建可加 --force)")
			return nil
		}
	}

	logger.Info("正在生成 10 年期 mTLS 双向认证证书 (兼容 macOS 与现代浏览器)...")

	// 临时工作目录
	tmpDir, err := os.MkdirTemp("", "singctl-mtls-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	caKey := filepath.Join(tmpDir, "ca.key")
	caCrt := filepath.Join(tmpDir, "ca.crt")
	clientKey := filepath.Join(tmpDir, "client.key")
	clientCsr := filepath.Join(tmpDir, "client.csr")
	clientExt := filepath.Join(tmpDir, "client.ext")
	clientCrt := filepath.Join(tmpDir, "client.crt")
	clientP12 := filepath.Join(tmpDir, "client.p12")

	// 1. 生成自签名根证书 CA
	if err := runCmd("openssl", "genrsa", "-out", caKey, "4096"); err != nil {
		return fmt.Errorf("生成 CA 私钥失败: %w", err)
	}
	if err := runCmd("openssl", "req", "-x509", "-new", "-nodes", "-key", caKey,
		"-sha256", "-days", "3650", "-subj", "/O=PersonalOps/CN=OpsRootCA", "-out", caCrt); err != nil {
		return fmt.Errorf("生成 CA 证书失败: %w", err)
	}

	// 2. 生成客户端私钥与 CSR
	if err := runCmd("openssl", "genrsa", "-out", clientKey, "2048"); err != nil {
		return fmt.Errorf("生成客户端私钥失败: %w", err)
	}
	if err := runCmd("openssl", "req", "-new", "-key", clientKey,
		"-subj", "/O=PersonalOps/CN=AdminClient", "-out", clientCsr); err != nil {
		return fmt.Errorf("生成客户端 CSR 失败: %w", err)
	}

	// 3. 写入 client.ext 扩展属性 (clientAuth)
	extContent := `basicConstraints = CA:FALSE
nsCertType = client
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
`
	if err := os.WriteFile(clientExt, []byte(extContent), 0644); err != nil {
		return fmt.Errorf("写入 client.ext 失败: %w", err)
	}

	// 4. 用 CA 签发客户端证书
	if err := runCmd("openssl", "x509", "-req", "-in", clientCsr, "-CA", caCrt,
		"-CAkey", caKey, "-CAcreateserial", "-out", clientCrt, "-days", "3650",
		"-sha256", "-extfile", clientExt); err != nil {
		return fmt.Errorf("签发客户端证书失败: %w", err)
	}

	// 5. 打包为客户端用的 .p12 文件 (多重兼容策略：确保 macOS Keychain、Windows 与现代浏览器无缝导入)
	var exportErr error
	// 策略 1: 显式指定 macOS 原生支持的 3DES/SHA1 算法 (兼容性最强，防止 RC2 或现代 AES 在 macOS 钥匙串报错)
	p12AlgoArgs := []string{
		"pkcs12", "-export",
		"-keypbe", "PBE-SHA1-3DES",
		"-certpbe", "PBE-SHA1-3DES",
		"-macalg", "sha1",
		"-out", clientP12,
		"-inkey", clientKey,
		"-in", clientCrt,
		"-certfile", caCrt,
		"-passout", fmt.Sprintf("pass:%s", password),
	}
	exportErr = runCmd("openssl", p12AlgoArgs...)

	// 策略 2: 标准 OpenSSL 3.x -legacy 模式
	if exportErr != nil {
		p12Args := []string{
			"pkcs12", "-export", "-legacy",
			"-out", clientP12,
			"-inkey", clientKey,
			"-in", clientCrt,
			"-certfile", caCrt,
			"-passout", fmt.Sprintf("pass:%s", password),
		}
		exportErr = runCmd("openssl", p12Args...)
	}

	// 策略 3: 显式加载 default 与 legacy provider
	if exportErr != nil {
		p12ProviderArgs := []string{
			"pkcs12", "-export",
			"-provider", "default", "-provider", "legacy",
			"-out", clientP12,
			"-inkey", clientKey,
			"-in", clientCrt,
			"-certfile", caCrt,
			"-passout", fmt.Sprintf("pass:%s", password),
		}
		exportErr = runCmd("openssl", p12ProviderArgs...)
	}

	// 策略 4: 如果为 OpenSSL 1.1 或以上参数皆不支持，尝试原生模式
	if exportErr != nil {
		p12FallbackArgs := []string{
			"pkcs12", "-export",
			"-out", clientP12,
			"-inkey", clientKey,
			"-in", clientCrt,
			"-certfile", caCrt,
			"-passout", fmt.Sprintf("pass:%s", password),
		}
		if err2 := runCmd("openssl", p12FallbackArgs...); err2 != nil {
			return fmt.Errorf("打包 PKCS#12 客户端证书失败: %w", exportErr)
		}
	}

	// 6. 将全套凭据存入持久化 0700/0600 主库，并只读投射公钥 ca.crt 给 Caddy
	bundle := make(map[string][]byte, 4)
	for _, spec := range []struct {
		name string
		src  string
		req  bool
	}{
		{"ca.crt", caCrt, true},
		{"client.p12", clientP12, true},
		{"client.crt", clientCrt, false},
		{"client.key", clientKey, false},
	} {
		data, rErr := os.ReadFile(spec.src)
		if rErr != nil {
			if spec.req {
				return fmt.Errorf("读取生成的 %s 失败: %w", spec.name, rErr)
			}
			continue
		}
		bundle[spec.name] = data
	}

	if err := deploy.SaveMtlsBundleToVault(bundle); err != nil {
		return fmt.Errorf("保存 mTLS 证书至主库失败: %w", err)
	}
	if _, _, err := deploy.EnsureCaddyMtlsTrustPool(""); err != nil {
		return fmt.Errorf("投射 Caddy ca.crt 失败: %w", err)
	}

	logger.Success("mTLS 证书生成成功：主库 %s 与 Caddy 只读 ca.crt 已就绪。", deploy.MtlsVaultDir())
	return nil
}

func createGottySystemdService(port int, termPath, tmuxPath string) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=GoTTY Web Terminal
After=network.target

[Service]
Type=simple
User=root
Environment="LANG=en_US.UTF-8"
Environment="TERM=xterm-256color"
WorkingDirectory=/root
ExecStart=%s -a 127.0.0.1 -p %d -w --ws-origin ".*" --path %s %s new -A -s web
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, GottyBinaryPath, port, termPath, tmuxPath)

	if err := os.WriteFile(GottyServicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("写入 gotty.service 失败: %w", err)
	}

	_ = runCmd("systemctl", "daemon-reload")
	if err := runCmd("systemctl", "enable", "--now", "gotty"); err != nil {
		return fmt.Errorf("启动 gotty.service 失败: %w", err)
	}
	_ = runCmd("systemctl", "restart", "gotty")

	logger.Success("GoTTY Systemd 守护进程已启动 (监听 127.0.0.1:%d, 挂载 tmux 会话: web)", port)
	return nil
}

func runCmd(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command execution failed (%s %v): %v, output: %s", name, arg, err, string(out))
	}
	return nil
}

func CopyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// DetectSSHPort tries to detect the SSH daemon port on the server
// DetectSSHPort resolves the effective SSH listening port, preferring hardened drop-in configs over default port 22.
func DetectSSHPort() int {
	return detectSSHPortFrom(os.Getenv("SSH_CONNECTION"), "/etc/ssh/sshd_config.d/*.conf", "/etc/ssh/sshd_config")
}

func resolveWebTerminalSSHPort(cfg *config.Config, detector func() int) int {
	if cfg != nil && cfg.Server.WebTerminal.SSHPort > 0 {
		return cfg.Server.WebTerminal.SSHPort
	}
	if detector != nil {
		if p := detector(); p > 0 {
			return p
		}
	}
	return 22
}

func detectSSHPortFrom(envConn, configDGlob, mainConfigPath string) int {
	fallbackPort := 0

	// 1. 优先扫描 /etc/ssh/sshd_config.d/*.conf (如 00-singctl-hardening.conf 中的非 22 端口)
	if configDGlob != "" {
		matches, _ := filepath.Glob(configDGlob)
		slices.Sort(matches)
		for _, match := range matches {
			for _, p := range scanSSHDConfigPorts(match) {
				if p != 22 {
					return p
				}
				if fallbackPort == 0 {
					fallbackPort = p
				}
			}
		}
	}

	// 2. 检查当前会话环境变量 SSH_CONNECTION ("client_ip client_port server_ip server_port")
	if conn := strings.TrimSpace(envConn); conn != "" {
		parts := strings.Fields(conn)
		if len(parts) >= 4 {
			if p, err := strconv.Atoi(parts[3]); err == nil && p > 0 && p <= 65535 {
				return p
			}
		}
	}

	// 3. 回退检查主配置文件 /etc/ssh/sshd_config
	if mainConfigPath != "" {
		for _, p := range scanSSHDConfigPorts(mainConfigPath) {
			if p != 22 {
				return p
			}
			if fallbackPort == 0 {
				fallbackPort = p
			}
		}
	}

	if fallbackPort > 0 {
		return fallbackPort
	}
	return 22
}

func scanSSHDConfigPorts(path string) []int {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var ports []int
	for line := range strings.SplitSeq(string(data), "\n") {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "port") {
			continue
		}
		for _, rawPort := range fields[1:] {
			if p, pErr := strconv.Atoi(rawPort); pErr == nil && p > 0 && p <= 65535 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

func installWstunnel(cfg *config.Config, arch string) error {
	if fi, err := os.Stat(WstunnelBinaryPath); err == nil && fi.Size() > 0 {
		logger.Success("wstunnel 二进制已就绪 (%s)", WstunnelBinaryPath)
		return nil
	}

	logger.Info("正在下载 wstunnel %s (%s)...", WstunnelVersion, arch)
	versionNum := strings.TrimPrefix(WstunnelVersion, "v")
	fileName := fmt.Sprintf("wstunnel_%s_linux_%s.tar.gz", versionNum, arch)
	url := fmt.Sprintf("https://github.com/erebe/wstunnel/releases/download/%s/%s", WstunnelVersion, fileName)
	if cfg != nil && cfg.GitHub.MirrorURL != "" {
		url = strings.TrimSuffix(cfg.GitHub.MirrorURL, "/") + "/" + url
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("下载 wstunnel 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 wstunnel 返回状态码 %d", resp.StatusCode)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("解压 gzip 失败: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取 tar 失败: %w", err)
		}

		if header.Name == "wstunnel" || filepath.Base(header.Name) == "wstunnel" {
			tmpBinary := WstunnelBinaryPath + ".tmp"
			outFile, err := os.OpenFile(tmpBinary, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("写入临时 wstunnel 失败: %w", err)
			}
			_, copyErr := io.Copy(outFile, tarReader)
			outFile.Close()
			if copyErr != nil {
				_ = os.Remove(tmpBinary)
				return fmt.Errorf("保存 wstunnel 失败: %w", copyErr)
			}
			_ = os.Chmod(tmpBinary, 0755)
			if err := os.Rename(tmpBinary, WstunnelBinaryPath); err != nil {
				_ = os.Remove(WstunnelBinaryPath)
				if err := os.Rename(tmpBinary, WstunnelBinaryPath); err != nil {
					return fmt.Errorf("更新 wstunnel 二进制失败: %w", err)
				}
			}
			logger.Success("wstunnel 二进制已成功安装至 %s", WstunnelBinaryPath)
			return nil
		}
	}

	return fmt.Errorf("在下载包中未找到 wstunnel 可执行文件")
}

func createWstunnelSystemdService(sshTunnelPort int, sshPort int) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=wstunnel SSH WebSocket Bridge
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s server --restrict-to 127.0.0.1:%d ws://127.0.0.1:%d
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, WstunnelBinaryPath, sshPort, sshTunnelPort)

	if err := os.WriteFile(WstunnelServicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("写入 wstunnel.service 失败: %w", err)
	}

	_ = runCmd("systemctl", "daemon-reload")
	if err := runCmd("systemctl", "enable", "--now", "wstunnel"); err != nil {
		return fmt.Errorf("启动 wstunnel.service 失败: %w", err)
	}
	_ = runCmd("systemctl", "restart", "wstunnel")

	logger.Success("wstunnel 守护进程已启动 (监听 127.0.0.1:%d, 转发至本地 SSH 127.0.0.1:%d)", sshTunnelPort, sshPort)
	return nil
}
