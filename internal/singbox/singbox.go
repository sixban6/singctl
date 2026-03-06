package singbox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/scripts"
	"singctl/internal/util/file"
	"singctl/internal/util/github"
	"singctl/internal/util/netinfo"
	"strings"

	"github.com/sixban6/ghinstall"
)

type SingBox struct {
	config          *config.Config
	configPath      string
	configGenerator *ConfigGenerator
}

func New(cfg *config.Config) *SingBox {

	return &SingBox{
		config:          cfg,
		configPath:      constant.SingBoxConfigFile,
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

	exe := constant.SingBoxInstallDir
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
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return sb.InstallGUI()
	}
	return sb.installOrUpdate(constant.SingBoxInstallDir)
}

// InstallGUI 安装 GUI 客户端
func (sb *SingBox) InstallGUI() error {
	var downloadURL string
	if runtime.GOOS == "darwin" {
		downloadURL = constant.MacURL
	} else if runtime.GOOS == "windows" {
		downloadURL = constant.WinURL
	}

	// If URL is empty or it's the old hardcoded default, fetch dynamically
	if downloadURL == "" || strings.Contains(downloadURL, "SFM-1.13.0-rc.1-Apple.pkg") {
		logger.Info("Dynamically resolving the latest GUI client address from GitHub...")
		latestURL, err := fetchLatestGUIAsset(runtime.GOOS)
		if err != nil {
			return fmt.Errorf("failed to fetch latest GUI asset: %w", err)
		}
		downloadURL = latestURL
	}

	if downloadURL == "" {
		return fmt.Errorf("GUI download URL not configured for %s and dynamic fetch failed", runtime.GOOS)
	}

	// 优化下载逻辑：检查Google连通性
	downloadURL = netinfo.GetReachableURL(downloadURL, sb.config.GitHub.MirrorURL)

	logger.Info("Downloading GUI client from: %s", downloadURL)

	// Create temp file
	tempFile, err := os.CreateTemp("", "singbox-gui-*"+filepath.Ext(downloadURL))
	if err != nil {
		return fmt.Errorf("create temp file failed: %w", err)
	}
	defer os.Remove(tempFile.Name())

	// Download
	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		return fmt.Errorf("write to file failed: %w", err)
	}
	tempFile.Close()

	// Install
	if runtime.GOOS == "darwin" {
		if strings.HasSuffix(downloadURL, ".pkg") {
			logger.Info("Installing PKG package (requires administrator privileges)...")
			// 使用 osascript 获取管理员权限并执行静默安装
			// "do shell script ... with administrator privileges" 会弹出系统的密码输入框
			// 注意: AppleScript 中字符串内嵌引号需要转义，这里使用单引号包裹路径以简化
			script := fmt.Sprintf("installer -pkg '%s' -target /", tempFile.Name())
			cmd := exec.Command("osascript", "-e", fmt.Sprintf("do shell script \"%s\" with administrator privileges", script))
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		} else if strings.HasSuffix(downloadURL, ".dmg") {
			logger.Info("Mounting DMG...")
			// Simplified DMG handling: User might need to drag-drop manually if we just open it
			cmd := exec.Command("open", tempFile.Name())
			return cmd.Run()
		}
	} else if runtime.GOOS == "windows" {
		logger.Info("Starting installer...")
		cmd := exec.Command("cmd", "/C", "start", "", tempFile.Name())
		return cmd.Run()
	}

	return fmt.Errorf("unsupported installer format")
}

// StartGUI 启动 GUI 客户端
func (sb *SingBox) StartGUI() error {
	appName := constant.AppName

	// Mac App path check
	appPath := fmt.Sprintf("/Applications/%s.app", appName)
	if _, err := os.Stat(appPath); os.IsNotExist(err) {
		logger.Info("App %s not found in /Applications", appName)
		fmt.Print("Do you want to install it now? [Y/n]: ")
		var input string
		fmt.Scanln(&input)
		if input == "" || strings.ToLower(input) == "y" {
			if err := sb.InstallGUI(); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("app not installed")
		}
	} else {
		// App exists, just open it
		logger.Success("App found at %s", appPath)
	}

	logger.Info("Config file is located at: %s", sb.configPath)

	// 按需生成配置：仅当现有配置无效时才重新生成
	if err := sb.ValidateConfig(); err != nil {
		// 需要重新生成，先校验 subs 确保不 panic
		if err2 := sb.config.ValidateSubs(); err2 != nil {
			logger.Warn("Cannot generate config, subscription invalid: %v", err2)
		} else {
			if err := sb.GenerateConfig(); err != nil {
				logger.Warn("Failed to generate config: %v", err)
			} else {
				logger.Success("Config generated successfully.")
			}
		}
	} else {
		logger.Info("Using existing valid config")
	}

	// 启动应用,并打开配置
	if runtime.GOOS == "darwin" {

		cmd1 := exec.Command("open", "-a", appName)
		cmd2 := exec.Command("open", "-t", sb.configPath)
		// 依次执行并检查错误
		if err := cmd1.Run(); err != nil {
			return fmt.Errorf("启动应用失败: %w", err)
		}

		if err := cmd2.Run(); err != nil {
			return fmt.Errorf("打开配置失败: %w", err)
		}
		logger.Info("配置文件: %s, 请手动导入配置", sb.configPath)
	} else if runtime.GOOS == "windows" {
		// Windows logic needs path presumably, or if it's in path
		// For now simple placeholder or assume standard install location if possible
		return fmt.Errorf("windows start not fully implemented yet without known path")
	}

	return nil
}

// installOrUpdate 安装或更新 sing-box (CLI)
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

	mirror := sb.config.GitHub.MirrorURL
	if mirror == "https://github.com" {
		mirror = ""
	}

	cfg := &ghinstall.Config{
		Github: []ghinstall.Repo{
			{
				URL:       "https://github.com/SagerNet/sing-box",
				OutputDir: tempDir,
			},
		},
		MirrorURL: mirror,
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
	newExe, err := file.FindExecutable(tempDir, "sing-box")
	if err != nil {
		return fmt.Errorf("new executable not found in downloaded package: %w", err)
	}

	// 安装或替换文件
	if err := file.InstallOrReplace(newExe, targetPath); err != nil {
		return fmt.Errorf("install or replace failed: %w", err)
	}

	logger.Success("Sing-box installed successfully")
	return nil
}

// selectSingBoxAsset 选择合适的sing-box资产
// selectSingBoxAsset 选择合适的sing-box资产
func (sb *SingBox) selectSingBoxAsset(assetName string) bool {
	name := strings.ToLower(assetName)

	// 1. 排除绝对不需要的关键词（包括 glibc）
	excludePatterns := []string{
		"dsym",    // 排除 macOS Debug symbols
		"sfm",     // 排除 macOS 图形界面客户端
		".deb",    // 排除 Debian 安装包
		".rpm",    // 排除 RPM 安装包
		"android", // 排除 Android 库
		"glibc",   // 关键修复：强行排除 glibc 版本，确保在 OpenWrt 等 musl 系统上可用
	}

	for _, pattern := range excludePatterns {
		if strings.Contains(name, pattern) {
			return false
		}
	}

	// 2. 匹配操作系统
	if runtime.GOOS == "darwin" && !strings.Contains(name, "darwin") {
		return false
	}
	if runtime.GOOS == "windows" && !strings.Contains(name, "windows") {
		return false
	}
	if runtime.GOOS == "linux" && !strings.Contains(name, "linux") {
		return false
	}

	// 3. 匹配 CPU 架构
	arch := runtime.GOARCH
	if arch == "amd64" {
		// x86_64 和 amd64 是同义词
		if !strings.Contains(name, "amd64") && !strings.Contains(name, "x86_64") {
			return false
		}
	} else if arch == "arm64" {
		// arm64 和 aarch64 经常混用，最好同时兼容
		if !strings.Contains(name, "arm64") && !strings.Contains(name, "aarch64") {
			return false
		}
	} else if !strings.Contains(name, arch) {
		return false
	}

	// 4. 确保是压缩包文件
	if !strings.HasSuffix(name, ".tar.gz") && !strings.HasSuffix(name, ".zip") {
		return false
	}

	return true
}

// ParseSingBoxVersionOutput 从 "sing-box version" 的输出中提取版本号。
// 支持格式: "sing-box version 1.12.0" 或多行输出（取首行最后一个字段）。
func ParseSingBoxVersionOutput(raw string) (string, error) {
	lines := strings.SplitN(strings.TrimSpace(raw), "\n", 2)
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", fmt.Errorf("unexpected sing-box version output: %q", raw)
	}
	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) == 0 {
		return "", fmt.Errorf("unexpected sing-box version output: %q", raw)
	}
	return parts[len(parts)-1], nil
}

// getCurrentVersion 获取当前已安装 sing-box 的版本号。
func (sb *SingBox) getCurrentVersion() (string, error) {
	out, err := exec.Command(constant.SingBoxInstallDir, "version").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run sing-box version: %w", err)
	}
	return ParseSingBoxVersionOutput(string(out))
}

// fetchLatestVersion 从 GitHub API 获取 sing-box 最新稳定 Release 的版本号。
func (sb *SingBox) fetchLatestVersion() (string, error) {
	fetcher := github.NewReleaseFetcher(sb.config.GitHub.MirrorURL, nil)
	return fetcher.FetchLatestTag("SagerNet/sing-box")
}

// Update 更新 sing-box（更新前对比版本，避免无意义的重复下载）。
func (sb *SingBox) Update() error {
	logger.Info("Checking for sing-box updates...")

	// 1. 获取远端最新版本
	latestVersion, err := sb.fetchLatestVersion()
	if err != nil {
		logger.Warn("⚠️ 无法获取最新版本 (%v)，将继续尝试更新", err)
		latestVersion = "unknown"
	} else {
		logger.Info("Latest sing-box version: %s", latestVersion)
	}

	// 2. 获取当前安装版本
	currentVersion, currentErr := sb.getCurrentVersion()
	if currentErr != nil {
		logger.Warn("无法获取当前版本 (%v)，继续执行更新...", currentErr)
	} else if latestVersion != "unknown" && currentVersion == latestVersion {
		logger.Success("✅ sing-box 已是最新版本 (当前: %s)", currentVersion)
		return nil
	} else if latestVersion != "unknown" {
		logger.Info("⬆️ sing-box 更新: %s -> %s", currentVersion, latestVersion)
	} else {
		logger.Info("Updating sing-box...")
	}

	// 3. 执行实际更新
	return sb.installOrUpdate(constant.SingBoxInstallDir)
}
