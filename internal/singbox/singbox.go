// 文件职责：实现客户端 sing-box 进程启停、网关透明代理联动、核心版本下载升级与多平台包管理。
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
	"singctl/internal/common/fsx"
	"singctl/internal/common/netx"
	releasepkg "singctl/internal/common/release"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/gateway"
	"singctl/internal/logger"
	"singctl/internal/singbox/scripts"
	"strings"
	"time"
)

type SingBox struct {
	config          *config.Config
	configPath      string
	configGenerator *ConfigGenerator
	deps            InstallDeps
}

func New(cfg *config.Config) *SingBox {
	return NewWithDeps(cfg, InstallDeps{})
}

// NewWithDeps 创建支持显式注入平台、磁盘探测与发布客户端替身的 SingBox 实例（未设置字段自动回退生产默认实现）。
func NewWithDeps(cfg *config.Config, deps InstallDeps) *SingBox {
	var cg *ConfigGenerator
	if deps.HTTPClient != nil || deps.APIBase != "" {
		cg = NewOfflineConfigGenerator(cfg)
	} else {
		cg = NewConfigGenerator(cfg)
	}
	return &SingBox{
		config:          cfg,
		configPath:      constant.SingBoxConfigFile,
		configGenerator: cg,
		deps:            deps,
	}
}

// GatewayOrchestrator 抽象 Linux 主/旁路由网关拓扑规则的消费侧接口。
type GatewayOrchestrator interface {
	Apply(ctx context.Context, cfg config.GatewayConfig) error
	Teardown(ctx context.Context) error
}

// StartWithGateway 编排网关透明代理规则应用、sing-box 启动脚本执行及旁路由启动失败自动回滚。
func StartWithGateway(
	ctx context.Context,
	isLinux bool,
	gwCfg config.GatewayConfig,
	gw GatewayOrchestrator,
	runStartScript func() error,
) error {
	if isLinux {
		if err := gw.Apply(ctx, gwCfg); err != nil {
			return fmt.Errorf("apply gateway topology failed: %w", err)
		}
	}
	if err := runStartScript(); err != nil {
		if isLinux && gwCfg.IsSideRouter() {
			if tdErr := gw.Teardown(ctx); tdErr != nil {
				logger.Warn("启动 sing-box 失败后回滚旁路由规则异常: %v", tdErr)
			} else {
				logger.Warn("sing-box 启动失败，已自动回滚旁路由拦截与转发规则")
			}
		}
		return err
	}
	return nil
}

// Start 启动 sing-box（调用脚本）
func (sb *SingBox) Start() error {
	gwCfg := config.GatewayConfig{}
	if sb.config != nil {
		gwCfg = sb.config.Gateway
	}

	err := StartWithGateway(
		context.Background(),
		runtime.GOOS == "linux",
		gwCfg,
		gateway.NewController(),
		func() error {
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

			// Pre-clean old TProxy dataplane in Go before starting sing-box so stop/ujail/probe runs with direct network
			if runtime.GOOS == "linux" && os.Geteuid() == 0 {
				_ = sb.cleanupNativeDataplane(context.Background())
			}

			// Execute script with appropriate command
			totalRAM := readHostTotalRAMBytes()
			_ = EnforceLowMemoryBasicLogCap(sb.config, totalRAM, constant.SingBoxBasicLogFile)
			if runtime.GOOS == "windows" {
				cmd = exec.Command("cmd", "/C", scriptPath)
			} else {
				cmd = exec.Command("sh", scriptPath)
			}
			cmdEnv := BuildSingBoxCommandEnv(os.Environ(), sb.config, totalRAM)
			if runtime.GOOS == "linux" && os.Geteuid() == 0 {
				cmdEnv = append(cmdEnv, "SINGCTL_GO_DATAPLANE=1")
			}
			cmd.Env = cmdEnv
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			if err := cmd.Run(); err != nil {
				return fmt.Errorf("start sing-box failed: %w", err)
			}
			if runtime.GOOS == "linux" && os.Geteuid() == 0 {
				if dpErr := sb.applyNativeDataplane(context.Background()); dpErr != nil {
					return fmt.Errorf("apply go native dataplane failed: %w", dpErr)
				}
			}
			_ = EnforceLowMemoryBasicLogCap(sb.config, totalRAM, constant.SingBoxBasicLogFile)
			return nil
		},
	)
	if err != nil {
		return err
	}

	logger.Success("🚀🚀🚀Sing-box started successfully")
	logger.Info("Sing-Box 本地控制面已监听: %s (外置 Clash 面板已移除，请使用 SingCtl WebUI 原生节点控制台)", sb.configGenerator.GetWebUIAddress())
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
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		cmd.Env = append(os.Environ(), "SINGCTL_GO_DATAPLANE=1")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("stop sing-box failed: %w", err)
	}

	if runtime.GOOS == "linux" {
		if os.Geteuid() == 0 {
			_ = sb.cleanupNativeDataplane(context.Background())
		}
		_ = gateway.NewController().Teardown(context.Background())
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

	// 规则集本地化：预下载 remote 规则集并改写为本地引用，
	// 使 sing-box 启动不依赖 GitHub；下载失败自动回退/保留 remote
	pureBaseJSON := sb.localizeRuleSets(configContent)
	preserveManual := (sb.config == nil || !sb.config.IsDirectAuditMode()) &&
		(sb.config == nil || sb.config.Watchdog.ShouldPreserveManualConfig())
	configContent, preservedChanges := PrepareRegeneratedConfig(context.Background(), sb.configPath, pureBaseJSON, preserveManual)

	// 备份原配置文件（如果存在）
	if _, err := os.Stat(sb.configPath); err == nil {
		backupPath := fmt.Sprintf("%s_bak", sb.configPath)
		if err := os.Rename(sb.configPath, backupPath); err != nil {
			return fmt.Errorf("backup sing-box config file failed: %w", err)
		}
		_ = os.Chmod(backupPath, 0600)
		logger.Success("backup sing-box config file successfully, backup path: %s", backupPath)
	}

	if err := fsx.WriteAtomic0600(sb.configPath, []byte(configContent)); err != nil {
		return err
	}
	CleanupLegacyFlashCacheDB(sb.configPath, configContent)
	_ = SaveBaseSnapshot(sb.configPath, pureBaseJSON)
	if preservedChanges > 0 {
		logger.Success("🛡️ 已自动合并保留 %d 处 config.json 手动修改", preservedChanges)
	}

	logger.Success("Config generated: %s", sb.configPath)
	return nil
}

// localizeRuleSets 将生成配置中的 remote 规则集替换为本地缓存引用（离线优先，不阻塞等待网络下载）。
// 失败时返回原始内容，不影响配置生成流程。
func (sb *SingBox) localizeRuleSets(configContent string) string {
	localized, stats, err := LocalizeRuleSets(configContent, LocalizeOptions{
		MirrorURL:    sb.config.GitHub.MirrorURL,
		CacheTTL:     DefaultRuleSetCacheTTL,
		OfflineFirst: true,
	})
	if err != nil {
		logger.Warn("⚠️ 规则集本地化已跳过: %v", err)
		return configContent
	}
	if stats.Remote == 0 {
		return configContent
	}
	logger.Info("规则集本地化: 远程 %d → 本地缓存 %d, 内置快照 %d, 保留远程 %d",
		stats.Remote, stats.Cached, stats.Snapshot, stats.Kept)
	return localized
}

// Install 安装 sing-box
func (sb *SingBox) Install() error {
	goos := sb.effectiveGOOS()
	if goos == "darwin" || goos == "windows" {
		return sb.InstallGUI()
	}
	return sb.installOrUpdate(sb.effectiveTargetPath())
}

// InstallGUI 安装 GUI 客户端
func (sb *SingBox) InstallGUI() error {
	logger.Info("Dynamically resolving the latest GUI client address from GitHub...")
	downloadURL, err := fetchLatestGUIAsset(runtime.GOOS)
	if err != nil {
		return fmt.Errorf("failed to fetch latest GUI asset: %w", err)
	}
	if downloadURL == "" {
		return fmt.Errorf("GUI download URL not found for %s", runtime.GOOS)
	}

	// 优化下载逻辑：检查Google连通性
	downloadURL = netx.GetReachableURL(downloadURL, sb.config.GitHub.MirrorURL)

	logger.Info("Downloading GUI client from: %s", downloadURL)

	// Create temp file
	tempFile, err := os.CreateTemp("", "singbox-gui-*"+filepath.Ext(downloadURL))
	if err != nil {
		return fmt.Errorf("create temp file failed: %w", err)
	}
	defer os.Remove(tempFile.Name())

	// 下载（为避免弱网下永久挂起，显式使用带超时的 client）
	dlClient := &http.Client{Timeout: 10 * time.Minute}
	resp, err := dlClient.Get(downloadURL)
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
// 小内存/小闪存/lite 客户端优先从本仓库 singbox-lite-latest 滚动通道流式验签直写安装；
// 发布元数据永远从 GitHub API 直连获取（信任锚，不走镜像），压缩包支持镜像加速与 SHA256 强校验。
func (sb *SingBox) installOrUpdate(targetPath string) error {
	ctx := context.Background()
	client := sb.buildReleaseClient()

	if sb.shouldUseSingBoxLite(targetPath) {
		fallback, err := sb.tryInstallSingBoxLite(ctx, client, targetPath)
		if !fallback {
			return err
		}
	}

	// 1. 直连获取上游发布元数据（资产名、大小、下载地址；信任锚，不走镜像）
	info, err := client.FetchLatest(ctx, UpstreamSingBoxRepo)
	if err != nil {
		return fmt.Errorf("无法直连 GitHub API 获取 sing-box 发布信息（为保证供应链安全，元数据不走镜像）: %w", err)
	}

	// 2. 选择当前平台的压缩包资产
	var asset *releasepkg.Asset
	for i := range info.Assets {
		if sb.selectSingBoxAsset(info.Assets[i].Name) {
			asset = &info.Assets[i]
			break
		}
	}
	if asset == nil {
		return fmt.Errorf("no suitable asset found for OS: %s, Arch: %s", sb.effectiveGOOS(), sb.effectiveGOARCH())
	}

	// 低内存/小闪存设备即使回退到上游包也采用零 /tmp 流式直写解压
	if sb.shouldStreamDirectToTarget(targetPath, asset, false) {
		return sb.streamInstallSingBoxTarGz(ctx, client, UpstreamSingBoxRepo, info, asset, targetPath, false)
	}

	// 创建临时目录（常规大容量主机）
	tempDir, err := os.MkdirTemp(sb.deps.TempDir, "singbox-install-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// 3. 下载并解压（官方 digest 随元数据直连返回，下载内容做 sha256 强校验）
	res, err := client.Download(ctx, *asset, tempDir)
	if err != nil {
		return fmt.Errorf("download sing-box failed: %w", err)
	}
	if res.SHA256Verified {
		logger.Success("✅ sha256 校验通过，与 GitHub 官方 digest 一致 (%s)", asset.Name)
	} else if res.ViaMirror {
		logger.Warn("⚠️ sing-box 经镜像下载；官方元数据无 digest，仅按大小校验（%d 字节），无法进行加密校验", asset.Size)
	}

	extractDir := filepath.Join(tempDir, "extracted")
	if err := releasepkg.Extract(res.Path, extractDir); err != nil {
		return fmt.Errorf("extract sing-box archive failed: %w", err)
	}

	// 找到下载的新执行文件
	newExe, err := fsx.FindExecutable(extractDir, "sing-box")
	if err != nil {
		return fmt.Errorf("new executable not found in downloaded package: %w", err)
	}

	// 安装或替换文件
	if err := fsx.InstallOrReplace(newExe, targetPath); err != nil {
		return fmt.Errorf("install or replace failed: %w", err)
	}

	logger.Success("Sing-box installed successfully")
	return nil
}

// selectSingBoxAsset 选择合适的上游 SagerNet/sing-box 资产
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
	goos := sb.effectiveGOOS()
	if goos == "darwin" && !strings.Contains(name, "darwin") {
		return false
	}
	if goos == "windows" && !strings.Contains(name, "windows") {
		return false
	}
	if goos == "linux" && !strings.Contains(name, "linux") {
		return false
	}

	// 3. 匹配 CPU 架构
	arch := sb.effectiveGOARCH()
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
	if sb.deps.CurrentVersionFn != nil {
		return sb.deps.CurrentVersionFn()
	}
	out, err := exec.Command(sb.effectiveTargetPath(), "version").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run sing-box version: %w", err)
	}
	return ParseSingBoxVersionOutput(string(out))
}

// fetchLatestVersion 从 GitHub API 获取目标通道（singbox-lite-latest 或上游 SagerNet/sing-box）的最新版本号。
func (sb *SingBox) fetchLatestVersion(targetPath string) (string, error) {
	ctx := context.Background()
	client := sb.buildReleaseClient()
	if sb.shouldUseSingBoxLite(targetPath) {
		repo := sb.liteRepo()
		info, err := client.FetchTag(ctx, repo, constant.SingBoxLiteReleaseTag)
		if err == nil {
			if asset := SelectSingBoxLiteAsset(info.Assets, sb.effectiveGOARCH()); asset != nil {
				if ver, vErr := ParseSingBoxLiteAssetVersion(asset.Name); vErr == nil {
					return ver, nil
				}
			}
			logger.Warn("⚠️ sing-box-lite 通道 (%s) 暂无 linux/%s 资产，回退查询上游 %s 最新版本", constant.SingBoxLiteReleaseTag, sb.effectiveGOARCH(), UpstreamSingBoxRepo)
		} else if releasepkg.IsNotFound(err) {
			logger.Warn("⚠️ sing-box-lite 精简通道 (%s@%s) 尚未就绪 (404)，回退查询上游 %s 最新版本", repo, constant.SingBoxLiteReleaseTag, UpstreamSingBoxRepo)
		} else {
			return "", err
		}
	}
	return client.FetchLatestTag(ctx, UpstreamSingBoxRepo)
}

// Update 更新 sing-box（更新前精准对齐目标通道版本比对，避免无意义的重复下载）。
func (sb *SingBox) Update() error {
	logger.Info("Checking for sing-box updates...")
	targetPath := sb.effectiveTargetPath()

	// 1. 获取远端目标通道最新版本
	latestVersion, err := sb.fetchLatestVersion(targetPath)
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
	} else if latestVersion != "unknown" && strings.TrimPrefix(currentVersion, "v") == strings.TrimPrefix(latestVersion, "v") {
		logger.Success("✅ sing-box 已是最新版本 (当前: %s)", currentVersion)
		return nil
	} else if latestVersion != "unknown" {
		logger.Info("⬆️ sing-box 更新: %s -> %s", currentVersion, latestVersion)
	} else {
		logger.Info("Updating sing-box...")
	}

	// 3. 执行实际更新
	return sb.installOrUpdate(targetPath)
}
