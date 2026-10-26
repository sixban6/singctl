package terminal

import (
	"archive/tar"
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
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"
)

const (
	DefaultTerminalPort = 18080
	DefaultMtlsCADir    = "/etc/caddy/mtls"
	DefaultMtlsCACert   = "/etc/caddy/mtls/ca.crt"
	DefaultClientP12    = "/etc/caddy/mtls/client.p12"
	GottyVersion        = "v1.5.0"
	GottyBinaryPath     = "/usr/local/bin/gotty"
	GottyServicePath    = "/etc/systemd/system/gotty.service"
)

// InstallOptions contains options for terminal deployment
type InstallOptions struct {
	Path     string
	Port     int
	Password string
	Force    bool
}

// InstallResult contains deployment details
type InstallResult struct {
	URL       string
	Domain    string
	Path      string
	Port      int
	Password  string
	P12Path   string
	P12Base64 string
}

// StatusResult contains terminal status information
type StatusResult struct {
	Enabled       bool
	ServiceActive bool
	Domain        string
	Path          string
	Port          int
	URL           string
	P12Exists     bool
	P12Path       string
	Password      string
}

// GenerateRandomHex generates random hex characters
func GenerateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateRandomPassword generates a friendly secure password
func GenerateRandomPassword(length int) string {
	const charset = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*"
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

	password := strings.TrimSpace(opts.Password)
	if password == "" {
		if cfg != nil && cfg.Server.WebTerminal.Password != "" {
			password = cfg.Server.WebTerminal.Password
		} else {
			password = GenerateRandomPassword(10)
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
	if err := installGoTTY(cfg, arch, opts.Force); err != nil {
		return nil, fmt.Errorf("安装 GoTTY 二进制失败: %w", err)
	}

	// 4. 生成 mTLS 根证书与客户端证书
	if err := generateMTLSCertificates(password, opts.Force); err != nil {
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

	// 6. 更新 singctl.yaml 配置
	if cfg != nil {
		cfg.Server.WebTerminal = config.WebTerminalConfig{
			Enabled:  true,
			Port:     port,
			Path:     termPath,
			MtlsCA:   DefaultMtlsCACert,
			Password: password,
		}
		if err := config.Save(configPath, cfg); err != nil {
			logger.Warn("保存 singctl.yaml 失败: %v", err)
		} else {
			logger.Success("已更新 Web 终端配置至 %s", configPath)
		}
	}

	// 7. 渲染 Caddyfile 并平滑重载 Caddy
	logger.Info("正在更新 Caddyfile 并重载 Caddy 路由...")
	if err := deploy.DeployCaddy(cfg); err != nil {
		return nil, fmt.Errorf("更新 Caddy 配置失败: %w", err)
	}

	// 8. 读取客户端证书 client.p12 并编码为 Base64
	var p12Base64 string
	if p12Bytes, err := os.ReadFile(DefaultClientP12); err == nil {
		p12Base64 = base64.StdEncoding.EncodeToString(p12Bytes)
	}

	fullURL := fmt.Sprintf("https://%s%s/", domain, termPath)
	res := &InstallResult{
		URL:       fullURL,
		Domain:    domain,
		Path:      termPath,
		Port:      port,
		Password:  password,
		P12Path:   DefaultClientP12,
		P12Base64: p12Base64,
	}

	return res, nil
}

// Uninstall stops GoTTY, removes service and cleans up certificates
func Uninstall(cfg *config.Config, configPath string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("Web 终端操作仅支持在 Linux 系统上运行")
	}

	logger.Info("正在停止并禁用 GoTTY 服务...")
	_ = exec.Command("systemctl", "stop", "gotty").Run()
	_ = exec.Command("systemctl", "disable", "gotty").Run()
	_ = os.Remove(GottyServicePath)
	_ = exec.Command("systemctl", "daemon-reload").Run()

	logger.Info("正在清理 mTLS 证书目录...")
	_ = os.RemoveAll(DefaultMtlsCADir)

	if cfg != nil {
		cfg.Server.WebTerminal.Enabled = false
		if err := config.Save(configPath, cfg); err != nil {
			logger.Warn("更新配置失败: %v", err)
		}
		logger.Info("正在更新 Caddyfile 并移除 Web 终端路由...")
		if err := deploy.DeployCaddy(cfg); err != nil {
			logger.Warn("重载 Caddy 失败: %v", err)
		}
	}

	logger.Success("GoTTY Web 终端与 mTLS 证书已彻底卸载。")
	return nil
}

// Status checks the status of Web Terminal
func Status(cfg *config.Config) (*StatusResult, error) {
	res := &StatusResult{
		P12Path: DefaultClientP12,
	}

	if cfg != nil {
		res.Enabled = cfg.Server.WebTerminal.Enabled
		res.Path = cfg.Server.WebTerminal.Path
		res.Port = cfg.Server.WebTerminal.Port
		res.Password = cfg.Server.WebTerminal.Password
		domain := cfg.Server.GetNodeDomain()
		if domain == "" {
			domain = cfg.Server.GetSubstoreDomain()
		}
		res.Domain = domain
		if res.Domain != "" && res.Path != "" {
			res.URL = fmt.Sprintf("https://%s%s/", res.Domain, res.Path)
		}
	}

	if _, err := os.Stat(DefaultClientP12); err == nil {
		res.P12Exists = true
	}

	if runtime.GOOS == "linux" {
		out, err := exec.Command("systemctl", "is-active", "gotty").Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			res.ServiceActive = true
		}
	}

	return res, nil
}

// ExportCert reads the client.p12 certificate file and returns base64 string
func ExportCert() (string, error) {
	if _, err := os.Stat(DefaultClientP12); err != nil {
		return "", fmt.Errorf("客户端证书文件 %s 不存在，请先执行 singctl term install", DefaultClientP12)
	}
	bytes, err := os.ReadFile(DefaultClientP12)
	if err != nil {
		return "", fmt.Errorf("读取证书失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func installDependencies() error {
	logger.Info("正在检查并安装系统依赖 (tmux, openssl, tar, wget)...")
	if isCommandAvailable("tmux") && isCommandAvailable("openssl") && isCommandAvailable("tar") && isCommandAvailable("wget") {
		logger.Success("基础依赖环境已完备。")
		return nil
	}

	if isCommandAvailable("apt-get") {
		cmd := exec.Command("apt-get", "update", "-y")
		_ = cmd.Run()
		cmd = exec.Command("apt-get", "install", "-y", "tmux", "openssl", "tar", "wget")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	} else if isCommandAvailable("dnf") {
		cmd := exec.Command("dnf", "install", "-y", "tmux", "openssl", "tar", "wget")
		return cmd.Run()
	} else if isCommandAvailable("yum") {
		cmd := exec.Command("yum", "install", "-y", "tmux", "openssl", "tar", "wget")
		return cmd.Run()
	}

	return fmt.Errorf("未识别的 Linux 包管理器 (请手动安装 tmux 与 openssl)")
}

func isCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func installGoTTY(cfg *config.Config, arch string, force bool) error {
	if _, err := os.Stat(GottyBinaryPath); err == nil && !force {
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
			outFile, err := os.OpenFile(GottyBinaryPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("写入 gotty 二进制失败: %w", err)
			}
			_, copyErr := io.Copy(outFile, tarReader)
			outFile.Close()
			if copyErr != nil {
				return fmt.Errorf("保存 gotty 失败: %w", copyErr)
			}
			logger.Success("GoTTY 二进制已成功安装至 %s", GottyBinaryPath)
			return nil
		}
	}

	return fmt.Errorf("在下载包中未找到 gotty 可执行文件")
}

func generateMTLSCertificates(password string, force bool) error {
	if err := os.MkdirAll(DefaultMtlsCADir, 0755); err != nil {
		return err
	}

	if _, err := os.Stat(DefaultClientP12); err == nil && !force {
		if _, err := os.Stat(DefaultMtlsCACert); err == nil {
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

	// 5. 打包为客户端用的 .p12 文件 (加 -legacy 确保 macOS 钥匙串兼容)
	p12Args := []string{
		"pkcs12", "-export", "-legacy",
		"-out", clientP12,
		"-inkey", clientKey,
		"-in", clientCrt,
		"-certfile", caCrt,
		"-passout", fmt.Sprintf("pass:%s", password),
	}
	if err := runCmd("openssl", p12Args...); err != nil {
		// 如果 OpenSSL 1.1 不支持 -legacy 标志，回退重试无 -legacy 形式
		p12FallbackArgs := []string{
			"pkcs12", "-export",
			"-out", clientP12,
			"-inkey", clientKey,
			"-in", clientCrt,
			"-certfile", caCrt,
			"-passout", fmt.Sprintf("pass:%s", password),
		}
		if err2 := runCmd("openssl", p12FallbackArgs...); err2 != nil {
			return fmt.Errorf("打包 PKCS#12 客户端证书失败: %w", err)
		}
	}

	// 6. 将 ca.crt 与 client.p12 复制到正式目录，私钥全部自动销毁
	if err := copyFile(caCrt, DefaultMtlsCACert, 0644); err != nil {
		return fmt.Errorf("保存 ca.crt 失败: %w", err)
	}
	if err := copyFile(clientP12, DefaultClientP12, 0600); err != nil {
		return fmt.Errorf("保存 client.p12 失败: %w", err)
	}

	logger.Success("mTLS 证书生成成功：已保留公钥 ca.crt 与客户端包 client.p12，服务器端敏感私钥已自动彻底销毁。")
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
ExecStart=%s -a 127.0.0.1 -p %d -w --path %s %s new -A -s web
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

func copyFile(src, dst string, perm os.FileMode) error {
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
