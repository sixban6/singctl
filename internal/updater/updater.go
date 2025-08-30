package updater

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/sixban6/ghinstall"
	"singctl/internal/fileutil"
	"singctl/internal/logger"
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

func (u *Updater) UpdateSelf() error {
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
	newExe, err := fileutil.FindExecutable(tempDir, "singctl")
	if err != nil {
		return fmt.Errorf("new executable not found in downloaded package: %w", err)
	}

	// 执行安全替换
	if err := fileutil.SafeReplace(currentExe, newExe); err != nil {
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

