// 文件职责：提供服务端 GoTTY + Tmux + wstunnel + mTLS Web 终端的安装、卸载、运行状态检查、证书导出与 SSH 端口识别主入口。
package terminal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
)

const (
	DefaultTerminalPort  = 18080
	DefaultSSHTunnelPort = 18081
	DefaultSSHTunnelPath = "/ssh-ws"
	DefaultMtlsCADir     = "/etc/singctl/mtls"
	DefaultMtlsCACert    = "/etc/singctl/mtls/ca.crt"
	DefaultClientP12     = "/etc/singctl/mtls/client.p12"
	DefaultClientCrt     = "/etc/singctl/mtls/client.crt"
	DefaultClientKey     = "/etc/singctl/mtls/client.key"
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
	sshPort := ResolveWebTerminalSSHPort(cfg, DetectSSHPort)
	sshTunnelPort := DefaultSSHTunnelPort
	if cfg != nil && cfg.Server.WebTerminal.SSHTunnelPort > 0 {
		sshTunnelPort = cfg.Server.WebTerminal.SSHTunnelPort
	}
	sshTunnelPath := DefaultSSHTunnelPath
	if cfg != nil && strings.TrimSpace(cfg.Server.WebTerminal.SSHTunnelPath) != "" {
		sshTunnelPath = strings.TrimSpace(cfg.Server.WebTerminal.SSHTunnelPath)
	}
	rawMtlsCA := ""
	if cfg != nil {
		rawMtlsCA = cfg.Server.WebTerminal.MtlsCA
	}
	mtlsCA := deploy.NormalizeMtlsCAPath(rawMtlsCA)
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
	return &InstallResult{
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
	}, nil
}

// Uninstall stops GoTTY, removes service and cleans up certificates
func Uninstall(cfg *config.Config, configPath string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("Web 终端操作仅支持在 Linux 系统上运行")
	}

	logger.Info("正在停止并禁用 GoTTY 与 wstunnel 服务...")
	mgr := servicemgr.NewSystemd(nil)
	ctx := context.Background()
	_ = mgr.RemoveUnit(ctx, servicemgr.UnitSpec{Name: "gotty", SystemdPath: GottyServicePath})
	_ = mgr.RemoveUnit(ctx, servicemgr.UnitSpec{Name: "wstunnel", SystemdPath: WstunnelServicePath})

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
		res.SSHPort = ResolveWebTerminalSSHPort(cfg, DetectSSHPort)
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
		mgr := servicemgr.NewSystemd(nil)
		ctx := context.Background()
		res.ServiceActive = mgr.IsActive(ctx, "gotty")
		res.WstunnelActive = mgr.IsActive(ctx, "wstunnel")
	}

	return res, nil
}

// ExportCert reads the client.p12 certificate file and returns base64 string
func ExportCert() (string, error) {
	p12Path, ok := resolveMtlsArtifact("client.p12", DefaultClientP12)
	if !ok {
		return "", fmt.Errorf("客户端证书文件 %s 不存在，请先执行 singctl term install", p12Path)
	}
	raw, err := os.ReadFile(p12Path)
	if err != nil {
		return "", fmt.Errorf("读取证书失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// DetectSSHPort resolves the effective SSH listening port, preferring hardened drop-in configs over default port 22.
func DetectSSHPort() int {
	return DetectSSHPortFrom(os.Getenv("SSH_CONNECTION"), "/etc/ssh/sshd_config.d/*.conf", "/etc/ssh/sshd_config")
}

// ResolveWebTerminalSSHPort resolves the SSH port for WebTerminal, preferring explicit config over host detection.
func ResolveWebTerminalSSHPort(cfg *config.Config, detector func() int) int {
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

// DetectSSHPortFrom inspects drop-in sshd configs, SSH_CONNECTION, and main sshd_config to resolve the active SSH port.
func DetectSSHPortFrom(envConn, configDGlob, mainConfigPath string) int {
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
