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
	"singctl/internal/util/github"

	"github.com/sixban6/ghinstall"
)

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

	// 版本检测：对比当前版本与远端最新版本
	normalizedVersion := strings.TrimPrefix(currentVersion, "v")
	if normalizedVersion != "" && normalizedVersion != "dev" {
		fetcher := github.NewReleaseFetcher(u.mirrorURL, nil)
		latestVersion, err := fetcher.FetchLatestTag("sixban6/singctl")
		if err != nil {
			logger.Warn("⚠️ 无法获取最新版本 (%v)，将继续尝试更新", err)
		} else {
			logger.Info("Latest singctl version: %s, current: %s", latestVersion, normalizedVersion)
			if normalizedVersion == latestVersion {
				logger.Success("✅ singctl 已是最新版本 (当前: %s)", normalizedVersion)
				return nil
			}
			logger.Info("⬆️ singctl 更新: %s -> %s", normalizedVersion, latestVersion)
		}
	}

	ctx := context.Background()

	// 获取当前执行文件路径
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get current executable: %w", err)
	}

	// 创建临时目录下载新版本
	tempDir, err := os.MkdirTemp("", "singctl-update-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &ghinstall.Config{
		Github: []ghinstall.Repo{
			{
				URL:       u.repoURL,
				OutputDir: tempDir,
			},
		},
		MirrorURL: u.mirrorURL,
	}
	// 使用自定义过滤器匹配 singctl 资源
	filter := ghinstall.CustomFilter(func(assets []ghinstall.Asset) (*ghinstall.Asset, error) {
		for _, asset := range assets {
			if u.selectSingCtlAsset(asset.Name) {
				return &asset, nil
			}
		}
		return nil, fmt.Errorf("no suitable asset found for OS: %s", runtime.GOOS)
	})
	if err := ghinstall.InstallWithConfigAndFilter(ctx, cfg, filter); err != nil {
		return fmt.Errorf("download new version failed: %w", err)
	}

	// 找到下载的新执行文件
	newExe, err := file.FindExecutable(tempDir, "singctl")
	if err != nil {
		return fmt.Errorf("new executable not found in downloaded package: %w", err)
	}

	// 同步 configs 目录
	var configsSrc string
	filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
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

	// 执行安全替换
	if err := file.SafeReplace(currentExe, newExe); err != nil {
		return err
	}

	logger.Success("SingCtl updated successfully")
	logger.Info("Please restart the application to use the new version")
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
