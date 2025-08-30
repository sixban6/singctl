package singbox

import (
	"context"
	"fmt"
	"github.com/sixban6/ghinstall"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"singctl/internal/config"
	"singctl/internal/fileutil"
	"singctl/internal/logger"
	"singctl/internal/scripts"
	"strings"
)

// getSingBoxInstallDir 返回适合当前系统的 sing-box 安装路径
func getSingBoxInstallDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "sing-box", "sing-box.exe")
	case "linux":
		// 检查是否为 OpenWrt 系统
		if _, err := os.Stat("/etc/openwrt_release"); err == nil {
			return "/usr/bin/sing-box"
		}
		if _, err := os.Stat("/etc/openwrt_version"); err == nil {
			return "/usr/bin/sing-box"
		}
		return "/usr/local/bin/sing-box"
	default:
		// macOS等其他系统
		return "/usr/local/bin/sing-box"
	}
}

type SingBox struct {
	config          *config.Config
	configPath      string
	configGenerator *ConfigGenerator
}

func New(cfg *config.Config) *SingBox {
	var configPath string
	if runtime.GOOS == "windows" {
		configPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "sing-box", "config.json")
	} else {
		configPath = "/etc/sing-box/config.json"
	}

	return &SingBox{
		config:          cfg,
		configPath:      configPath,
		configGenerator: NewConfigGenerator(cfg),
	}
}

// SetConfigPath 设置配置文件路径（主要用于测试）
func (sb *SingBox) SetConfigPath(path string) {
	sb.configPath = path
}

// Start 启动 sing-box（调用脚本）
func (sb *SingBox) Start() error {
	// Create temporary script file
	tempDir := os.TempDir()
	var scriptPath string
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		scriptPath = filepath.Join(tempDir, "start_singbox.bat")
	} else {
		scriptPath = filepath.Join(tempDir, "start_singbox.sh")
	}

	// Write embedded script to temporary file
	if err := scripts.WriteStartScript(scriptPath); err != nil {
		return fmt.Errorf("write start script failed: %w", err)
	}
	defer os.Remove(scriptPath)

	// Execute script with appropriate command
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", scriptPath)
	} else {
		cmd = exec.Command("sh", scriptPath)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("start sing-box failed: %w", err)
	}

	logger.Success("🚀🚀🚀Sing-box started successfully")
	logger.Info("🎉🎉🎉SingBox 控制面板地址: http://%s", sb.configGenerator.GetWebUIAddress())
	return nil
}

// Stop 停止 sing-box（调用脚本）
func (sb *SingBox) Stop() error {
	// Create temporary script file
	tempDir := os.TempDir()
	var scriptPath string
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		scriptPath = filepath.Join(tempDir, "stop_singbox.bat")
	} else {
		scriptPath = filepath.Join(tempDir, "stop_singbox.sh")
	}

	// Write embedded script to temporary file
	if err := scripts.WriteStopScript(scriptPath); err != nil {
		return fmt.Errorf("write stop script failed: %w", err)
	}
	defer os.Remove(scriptPath)

	// Execute script with appropriate command
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", scriptPath)
	} else {
		cmd = exec.Command("sh", scriptPath)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("stop sing-box failed: %w", err)
	}

	logger.Success("Sing-box stopped successfully")
	return nil
}

// ValidateConfig 验证现有配置文件是否有效
func (sb *SingBox) ValidateConfig() error {
	// 检查配置文件是否存在
	if _, err := os.Stat(sb.configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", sb.configPath)
	}

	// 检查文件内容是否为空或只有空JSON
	content, err := os.ReadFile(sb.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// 检查是否为空文件或空JSON对象
	contentStr := strings.TrimSpace(string(content))
	if contentStr == "" || contentStr == "{}" || contentStr == "null" {
		return fmt.Errorf("config file is empty or contains no valid configuration")
	}

	exe := getSingBoxInstallDir()
	cmd := exec.Command(exe, "check", "-c", sb.configPath)
	// 使用 sing-box check 命令验证配置
	//cmd := exec.Command("sing-box", "check", "-c", sb.configPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	logger.Success("Config validation passed: %s", sb.configPath)
	return nil
}

// GenerateConfig 生成配置文件
func (sb *SingBox) GenerateConfig() error {
	configContent, err := sb.configGenerator.Generate()
	if err != nil {
		return fmt.Errorf("generate config failed: %w", err)
	}

	// 备份原配置文件（如果存在）
	if _, err := os.Stat(sb.configPath); err == nil {
		backupPath := fmt.Sprintf("%s_bak", sb.configPath)
		if err := os.Rename(sb.configPath, backupPath); err != nil {
			return fmt.Errorf("backup sing-box config file failed: %w", err)
		}
		logger.Success("backup sing-box config file successfully, backup path: %s", backupPath)
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(sb.configPath), 0755); err != nil {
		return fmt.Errorf("create config directory failed: %w", err)
	}

	tmp := sb.configPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(configContent), 0644); err != nil {
		return err
	}
	err = os.Rename(tmp, sb.configPath)
	if err != nil {
		return fmt.Errorf("rename config file failed: %w", err)
	}

	logger.Success("Config generated: %s", sb.configPath)
	return nil
}

// Install 安装 sing-box
func (sb *SingBox) Install() error {
	return sb.installOrUpdate(getSingBoxInstallDir())
}

// installOrUpdate 安装或更新 sing-box
func (sb *SingBox) installOrUpdate(targetPath string) error {
	ctx := context.Background()

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "singbox-install-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	// 生成 8 位十六进制随机后缀
	//b := make([]byte, 4)
	//rand.Read(b)
	//suffix := fmt.Sprintf("%08x", b)
	//tempDir := fmt.Sprintf("./singbox-install-%s", suffix)
	//if err := os.MkdirAll(tempDir, 0755); err != nil {
	//	return fmt.Errorf("create temp dir: %w", err)
	//}

	defer os.RemoveAll(tempDir)

	// 使用 ghinstall 配置下载到临时目录
	cfg := &ghinstall.Config{
		Github: []ghinstall.Repo{
			{
				URL:       "https://github.com/SagerNet/sing-box",
				OutputDir: tempDir,
			},
		},
		MirrorURL: sb.config.GitHub.MirrorURL,
	}
	// 2. 使用自定义过滤器
	filter := ghinstall.CustomFilter(func(assets []ghinstall.Asset) (*ghinstall.Asset, error) {
		for _, asset := range assets {
			if sb.selectSingBoxAsset(asset.Name) {
				return &asset, nil
			}
		}
		return nil, fmt.Errorf("no suitable asset found for OS: %s", runtime.GOOS)
	})
	if err := ghinstall.InstallWithConfigAndFilter(ctx, cfg, filter); err != nil {
		return fmt.Errorf("install sing-box failed: %w", err)
	}

	// 找到下载的新执行文件
	newExe, err := fileutil.FindExecutable(tempDir, "sing-box")
	if err != nil {
		return fmt.Errorf("new executable not found in downloaded package: %w", err)
	}

	// 安装或替换文件
	if err := fileutil.InstallOrReplace(newExe, targetPath); err != nil {
		return fmt.Errorf("install or replace failed: %w", err)
	}

	logger.Success("Sing-box installed successfully")
	return nil
}

// selectSingBoxAsset 选择合适的sing-box资产
func (sb *SingBox) selectSingBoxAsset(assetName string) bool {
	name := strings.ToLower(assetName)

	// 排除不需要的文件
	excludePatterns := []string{
		"dsym",    // Debug symbols (macOS)
		"sfm",     // SFM GUI client (macOS)
		".deb",    // Debian packages
		".rpm",    // RPM packages
		"android", // macOS binaries (if not on macOS)
	}

	for _, pattern := range excludePatterns {
		if strings.Contains(name, pattern) {
			// Allow darwin only on macOS
			if pattern == "darwin" && runtime.GOOS == "darwin" {
				continue
			}
			// Allow windows only on Windows
			if pattern == "windows" && runtime.GOOS == "windows" {
				continue
			}
			return false
		}
	}
	// 必须包含Linux（除非在其他平台）
	if runtime.GOOS == "darwin" && !strings.Contains(name, "darwin") {
		return false
	}

	// 必须包含Linux（除非在其他平台）
	if runtime.GOOS == "windows" && !strings.Contains(name, "windows") {
		return false
	}

	// 必须包含Linux（除非在其他平台）
	if runtime.GOOS == "linux" && !strings.Contains(name, "linux") {
		return false
	}

	// 必须包含正确的架构
	arch := runtime.GOARCH
	if arch == "amd64" {
		// Accept both amd64 and x86_64
		if !strings.Contains(name, "amd64") && !strings.Contains(name, "x86_64") {
			return false
		}
	} else if !strings.Contains(name, arch) {
		return false
	}

	// 必须是压缩包格式
	if !strings.Contains(name, ".tar.gz") && !strings.Contains(name, ".zip") {
		return false
	}

	return true
}

// Update 更新 sing-box
func (sb *SingBox) Update() error {
	return sb.installOrUpdate(getSingBoxInstallDir())
}
