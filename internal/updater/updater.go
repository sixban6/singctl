package updater

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/util/file"
	releasepkg "singctl/internal/util/release"
)

// SkipChecksumEnv 允许用户在无法直连 GitHub 时显式跳过校验（自担风险）。
const SkipChecksumEnv = "SINGCTL_SKIP_CHECKSUM"

type Updater struct {
	mirrorURL string
	repoURL   string
}

func New(mirrorURL, repoURL string) *Updater {
	if repoURL == "" {
		repoURL = "https://github.com/sixban6/singctl" // 替换为实际仓库
	}
	return &Updater{
		mirrorURL: mirrorURL,
		repoURL:   repoURL,
	}
}

func (u *Updater) UpdateSelf(configPath string, currentVersion string) error {
	logger.Info("Checking for singctl updates...")

	ctx := context.Background()

	// 1. 直连 GitHub API 获取发布元数据（tag + 资产列表，绝不经镜像，
	//    防止镜像篡改"最新版本"指向旧版或恶意资产）。
	client := releasepkg.NewClient(u.mirrorURL)
	info, err := client.FetchLatest(ctx, "sixban6/singctl")
	if err != nil {
		return fmt.Errorf("无法直连 GitHub API 获取版本信息（为保证供应链安全，元数据不走镜像）: %w", err)
	}

	// 版本检测：对比当前版本与远端最新版本
	normalizedVersion := strings.TrimPrefix(currentVersion, "v")
	latestVersion := strings.TrimPrefix(info.TagName, "v")
	if normalizedVersion != "" && normalizedVersion != "dev" {
		logger.Info("Latest singctl version: %s, current: %s", latestVersion, normalizedVersion)
		if normalizedVersion == latestVersion {
			logger.Success("✅ singctl 已是最新版本 (当前: %s)", normalizedVersion)
			return nil
		}
		logger.Info("⬆️ singctl 更新: %s -> %s", normalizedVersion, latestVersion)
	}

	// 2. 选择当前平台的压缩包资产
	var asset *releasepkg.Asset
	for i := range info.Assets {
		if u.selectSingCtlAsset(info.Assets[i].Name) {
			asset = &info.Assets[i]
			break
		}
	}
	if asset == nil {
		return fmt.Errorf("no suitable asset found for OS: %s, Arch: %s", runtime.GOOS, runtime.GOARCH)
	}

	// 3. 下载压缩包（可走镜像加速），并强制校验 sha256
	tempDir, err := os.MkdirTemp("", "singctl-update-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	archivePath, viaMirror, err := client.Download(ctx, *asset, tempDir)
	if err != nil {
		return fmt.Errorf("download new version failed: %w", err)
	}

	if err := u.verifyArchive(ctx, client, info, asset, archivePath, viaMirror); err != nil {
		return err
	}

	// 4. 解压并定位新的可执行文件
	extractDir := filepath.Join(tempDir, "extracted")
	if err := releasepkg.Extract(archivePath, extractDir); err != nil {
		return fmt.Errorf("extract archive failed: %w", err)
	}
	newExe, err := file.FindExecutable(extractDir, "singctl")
	if err != nil {
		return fmt.Errorf("new executable not found in downloaded package: %w", err)
	}

	// 5. 同步 configs 目录
	var configsSrc string
	filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() && info.Name() == "configs" {
			configsSrc = path
			return filepath.SkipDir
		}
		return nil
	})

	if configsSrc != "" && configPath != "" {
		configDir := filepath.Dir(configPath)
		logger.Info("Syncing default configurations to %s...", configDir)
		if err := file.CopyDir(configsSrc, configDir); err != nil {
			logger.Warn("Failed to sync configs directory: %v", err)
		}

		logger.Info("Migrating main configuration file...")
		// 迁移主配置文件
		templatePath := filepath.Join(configsSrc, "singctl.yaml")
		templateData, err := os.ReadFile(templatePath)
		if err != nil {
			logger.Warn("Failed to read downloaded template config %s: %v", templatePath, err)
		} else {
			if err := config.MigrateConfig(configPath, templateData); err != nil {
				logger.Warn("Failed to migrate config %s: %v", configPath, err)
			}
		}
	}

	// 6. 执行安全替换
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get current executable: %w", err)
	}
	if err := file.SafeReplace(currentExe, newExe); err != nil {
		return err
	}

	logger.Success("SingCtl updated successfully")
	logger.Info("Please restart the application to use the new version")
	return nil
}

// verifyArchive 校验下载的压缩包。
// checksums.txt 从 GitHub 直连获取（不走镜像），校验失败一律中止；
// 仅当用户显式设置 SkipChecksumEnv=1 时跳过（会打印醒目警告）。
func (u *Updater) verifyArchive(ctx context.Context, client *releasepkg.Client, info *releasepkg.Info, asset *releasepkg.Asset, archivePath string, viaMirror bool) error {
	if os.Getenv(SkipChecksumEnv) == "1" {
		logger.Warn("⚠️  %s=1 已设置，跳过 sha256 校验。镜像或网络被劫持时可能安装恶意程序，请自行承担风险！", SkipChecksumEnv)
		return nil
	}

	sums, err := client.FetchChecksums(ctx, "sixban6/singctl", info.TagName, nil, info)
	if err != nil {
		return fmt.Errorf("无法直连 GitHub 获取 checksums.txt（校验必需，不走镜像）。请检查网络后重试；确要跳过请设置 %s=1: %w", SkipChecksumEnv, err)
	}
	expected, ok := sums[asset.Name]
	if !ok {
		return fmt.Errorf("checksums.txt 中没有资产 %s 的记录，拒绝安装", asset.Name)
	}
	if err := releasepkg.VerifySHA256(archivePath, expected); err != nil {
		if viaMirror {
			return fmt.Errorf("镜像下载的安装包校验失败（可能被篡改或损坏），已中止: %w", err)
		}
		return fmt.Errorf("安装包校验失败（可能被篡改或损坏），已中止: %w", err)
	}
	logger.Success("✅ sha256 校验通过 (%s)", asset.Name)
	return nil
}

// selectSingCtlAsset 选择合适的 singctl 资源
func (u *Updater) selectSingCtlAsset(assetName string) bool {
	name := strings.ToLower(assetName)

	// 排除校验文件
	if strings.Contains(name, "checksums") {
		return false
	}

	// 必须包含 singctl
	if !strings.Contains(name, "singctl") {
		return false
	}

	// 必须包含正确的操作系统
	if !strings.Contains(name, runtime.GOOS) {
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
