// 文件职责：负责 SingCtl 自升级版本检测、平台/Lite 资产筛选，并按宿主内存与 /tmp 空间自动分派归档升级或零 /tmp 流式直写升级。
package updater

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"singctl/internal/common/fsx"
	releasepkg "singctl/internal/common/release"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/singbox/ruleset_snapshot"
)

// SkipChecksumEnv 允许用户在无法直连 GitHub 时显式跳过校验（自担风险）。
const SkipChecksumEnv = "SINGCTL_SKIP_CHECKSUM"

// Deps 定义 Updater 可注入的外部 HTTP 与宿主机环境探测依赖（未设置字段自动回退生产默认实现）。
type Deps struct {
	APIBase           string
	DLBase            string
	HTTPClient        *http.Client
	Repo              string
	GOOS              string
	GOARCH            string
	IsLite            *bool
	ReadTotalRAMBytes func() uint64
	IsLowFlashHost    func() bool
	IsServerHost      func(configPath string) bool
	StatTmpSpace      func(path string) (sysinfo.DiskSpace, error)
	ResolveExePath    func() (string, error)
	TempDir           string
}

// Updater 封装 SingCtl 供应链安全的版本拉取、SHA256 校验与平滑二进制替换。
type Updater struct {
	mirrorURL string
	repoURL   string
	deps      Deps
}

// New 创建使用生产默认宿主依赖的 Updater。
func New(mirrorURL, repoURL string) *Updater {
	return NewWithDeps(mirrorURL, repoURL, Deps{})
}

// NewWithDeps 创建带显式依赖注入的 Updater（供离线确定性单测与特殊宿主定制）。
func NewWithDeps(mirrorURL, repoURL string, deps Deps) *Updater {
	if repoURL == "" {
		repoURL = constant.GitHubRepoURL
	}
	return &Updater{
		mirrorURL: mirrorURL,
		repoURL:   repoURL,
		deps:      deps,
	}
}

func (u *Updater) buildReleaseClient() *releasepkg.Client {
	client := releasepkg.NewClient(u.mirrorURL)
	if u.deps.APIBase != "" {
		client.APIBase = u.deps.APIBase
	}
	if u.deps.DLBase != "" {
		client.DLBase = u.deps.DLBase
	}
	if u.deps.HTTPClient != nil {
		client.HTTP = u.deps.HTTPClient
	}
	client.SkipSHA256 = os.Getenv(SkipChecksumEnv) == "1"
	return client
}

func (u *Updater) targetRepo() string {
	return cmp.Or(strings.TrimSpace(u.deps.Repo), constant.GitHubRepo)
}

func (u *Updater) targetPlatform() (goos, goarch string, isLite bool) {
	goos = cmp.Or(u.deps.GOOS, runtime.GOOS)
	goarch = cmp.Or(u.deps.GOARCH, runtime.GOARCH)
	isLite = ruleset_snapshot.IsLite
	if u.deps.IsLite != nil {
		isLite = *u.deps.IsLite
	}
	return goos, goarch, isLite
}

func (u *Updater) isLowMemoryHost() bool {
	if u.deps.ReadTotalRAMBytes != nil {
		return sysinfo.IsLowMemoryRAM(u.deps.ReadTotalRAMBytes())
	}
	return sysinfo.IsLowMemoryHost()
}

func (u *Updater) isLowFlashHost() bool {
	if u.deps.IsLowFlashHost != nil {
		return u.deps.IsLowFlashHost()
	}
	return sysinfo.IsLowFlashHost()
}

func (u *Updater) isServerHost(configPath string) bool {
	if u.deps.IsServerHost != nil {
		return u.deps.IsServerHost(configPath)
	}
	if p := strings.TrimSpace(configPath); p != "" {
		if cfg, err := config.Load(p); err == nil && cfg.HasActiveServerConfig() {
			return true
		}
	}
	// 仅在未注入测试可执行路径替身的真实 Linux 宿主机上检测服务端 systemd 单元，避免单测污染。
	if u.deps.ResolveExePath == nil && runtime.GOOS == "linux" {
		for _, unitPath := range []string{constant.SubHubSystemdService, "/etc/systemd/system/singctl-ui.service"} {
			if unitPath != "" {
				if _, err := os.Stat(unitPath); err == nil {
					return true
				}
			}
		}
	}
	return false
}

func (u *Updater) resolveLiteTarget(goos, configPath string, isLiteBuild bool) (bool, string) {
	if isLiteBuild {
		return true, ""
	}
	if goos != "linux" {
		return false, ""
	}
	if u.isServerHost(configPath) {
		return false, ""
	}
	lowFlash := u.isLowFlashHost()
	lowMem := u.isLowMemoryHost()
	switch {
	case lowFlash && lowMem:
		return true, "检测到小闪存且低内存宿主机，自动优先匹配 -lite 精简包以防撑爆 /overlay"
	case lowFlash:
		return true, "检测到小闪存宿主机（<=160MiB 总容量或 <=64MiB 可用空间），自动优先匹配 -lite 精简包以防撑爆 /overlay"
	case lowMem:
		return true, "检测到低内存宿主机，自动优先匹配 -lite 精简包以降低闪存与内存占用"
	default:
		return false, ""
	}
}

func (u *Updater) resolveCurrentExe() (string, error) {
	if u.deps.ResolveExePath != nil {
		return u.deps.ResolveExePath()
	}
	return ResolveExecutablePath()
}

// CheckLatest 直连 GitHub API 比对当前版本与最新官方 Release（不执行下载或替换）。
func (u *Updater) CheckLatest(ctx context.Context, currentVersion string) (latestVersion string, upToDate bool, err error) {
	client := u.buildReleaseClient()
	info, fErr := client.FetchLatest(ctx, u.targetRepo())
	if fErr != nil {
		return "", false, fErr
	}
	latest := strings.TrimPrefix(strings.TrimSpace(info.TagName), "v")
	cur := strings.TrimPrefix(strings.TrimSpace(currentVersion), "v")
	if cur != "" && cur != "dev" && cur == latest {
		return latest, true, nil
	}
	return latest, false, nil
}

// UpdateSelf 检查最新官方 Release 并在校验 SHA256 后安全替换当前 singctl 二进制。
func (u *Updater) UpdateSelf(configPath string, currentVersion string) error {
	logger.Info("Checking for singctl updates...")

	ctx := context.Background()
	client := u.buildReleaseClient()
	repo := u.targetRepo()

	// 1. 直连 GitHub API 获取发布元数据（绝不经镜像，防止镜像篡改最新版本指向旧版或恶意资产）。
	info, err := client.FetchLatest(ctx, repo)
	if err != nil {
		return fmt.Errorf("无法直连 GitHub API 获取版本信息（为保证供应链安全，元数据不走镜像）: %w", err)
	}

	normalizedVersion := strings.TrimPrefix(currentVersion, "v")
	latestVersion := strings.TrimPrefix(info.TagName, "v")
	if normalizedVersion != "" && normalizedVersion != "dev" {
		logger.Info("Latest singctl version: %s, current: %s", latestVersion, normalizedVersion)
		if normalizedVersion == latestVersion {
			logger.Success("✅ singctl 已是最新版本 (当前: %s)", normalizedVersion)
			return nil
		}
		logVersionTransition(normalizedVersion, latestVersion)
	}

	// 2. 选择当前平台的压缩包资产（严格区分完整版与 lite 轻量版；小闪存/低内存非服务端宿主自动启用 -lite 保护）
	goos, goarch, isLiteBuild := u.targetPlatform()
	wantLite, liteReason := u.resolveLiteTarget(goos, configPath, isLiteBuild)
	if liteReason != "" {
		logger.Info("📦 %s", liteReason)
	}
	asset := SelectSingCtlAsset(info.Assets, goos, goarch, wantLite)
	if asset == nil {
		return fmt.Errorf("no suitable asset found for OS: %s, Arch: %s (lite=%v)", goos, goarch, wantLite)
	}

	// 3. 低内存路由器或 /tmp 可用空间不足时：走零 /tmp 流式 SHA256 校验直写升级路径
	if u.shouldUseZeroTmpStreaming(asset) {
		return u.updateSelfZeroTmpStream(ctx, client, repo, info, asset, goos, configPath)
	}

	return u.updateSelfArchive(ctx, client, repo, info, asset, configPath)
}

func logVersionTransition(normalizedVersion, latestVersion string) {
	curParts := strings.Split(normalizedVersion, ".")
	latestParts := strings.Split(latestVersion, ".")
	if len(curParts) >= 2 && len(latestParts) >= 2 {
		curMajorMinor := curParts[0] + "." + curParts[1]
		latestMajorMinor := latestParts[0] + "." + latestParts[1]
		if curMajorMinor != latestMajorMinor {
			logger.Warn("🚀 检测到全新的 sing-box 大版本内核升级: %s -> %s (适配 sing-box %s.x)", normalizedVersion, latestVersion, latestMajorMinor)
			return
		}
		logger.Info("⬆️ singctl 同轨升级: %s -> %s", normalizedVersion, latestVersion)
		return
	}
	logger.Info("⬆️ singctl 更新: %s -> %s", normalizedVersion, latestVersion)
}

func (u *Updater) updateSelfArchive(
	ctx context.Context,
	client *releasepkg.Client,
	repo string,
	info *releasepkg.Info,
	asset *releasepkg.Asset,
	configPath string,
) error {
	tempDir, err := os.MkdirTemp(u.deps.TempDir, "singctl-update-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	res, err := client.Download(ctx, *asset, tempDir)
	if err != nil {
		return fmt.Errorf("download new version failed: %w", err)
	}

	if res.SHA256Verified {
		logger.Success("✅ sha256 校验通过，与 GitHub 官方 digest 一致 (%s)", asset.Name)
	} else if err := u.verifyChecksumsFile(ctx, client, repo, info, asset, res.Path, res.ViaMirror); err != nil {
		return err
	}

	extractDir := filepath.Join(tempDir, "extracted")
	if err := releasepkg.Extract(res.Path, extractDir); err != nil {
		return fmt.Errorf("extract archive failed: %w", err)
	}
	newExe, err := fsx.FindExecutable(extractDir, "singctl")
	if err != nil {
		return fmt.Errorf("new executable not found in downloaded package: %w", err)
	}

	u.syncExtractedConfigs(extractDir, newExe, configPath)

	currentExe, err := u.resolveCurrentExe()
	if err != nil {
		return fmt.Errorf("get current executable: %w", err)
	}
	if err := fsx.SafeReplace(currentExe, newExe); err != nil {
		return err
	}

	logger.Success("SingCtl updated successfully")
	logger.Info("Binary replaced on disk: %s", currentExe)
	return nil
}

func (u *Updater) syncExtractedConfigs(extractDir, newExe, configPath string) {
	if configPath == "" {
		return
	}
	var configsSrc string
	_ = filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() && info.Name() == "configs" {
			configsSrc = path
			return filepath.SkipDir
		}
		return nil
	})
	if configsSrc == "" {
		return
	}

	configDir := filepath.Dir(configPath)
	logger.Info("Syncing default configurations to %s...", configDir)
	if err := fsx.CopyDir(configsSrc, configDir); err != nil {
		logger.Warn("Failed to sync configs directory: %v", err)
	}

	logger.Info("Migrating main configuration file...")
	templatePath := filepath.Join(configsSrc, "singctl.yaml")
	migrateCmd := exec.Command(newExe, "internal-migrate", "--config", configPath, "--template", templatePath)
	if out, err := migrateCmd.CombinedOutput(); err != nil {
		logger.Warn("New binary migrate command returned %v (%s), falling back to in-process migration", err, strings.TrimSpace(string(out)))
		templateData, rErr := os.ReadFile(templatePath)
		if rErr != nil {
			logger.Warn("Failed to read downloaded template config %s: %v", templatePath, rErr)
			return
		}
		if mErr := config.MigrateConfig(configPath, templateData); mErr != nil {
			logger.Warn("Failed to migrate config %s: %v", configPath, mErr)
		}
	} else {
		logger.Success("Main configuration migrated successfully using new version.")
	}
}

// ResolveExecutablePath 返回清洗 Linux /proc/self/exe (deleted) 与 .backup 后缀后的真实可执行文件路径。
func ResolveExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		for _, fb := range []string{"/usr/bin/singctl", "/usr/local/bin/singctl"} {
			if _, stErr := os.Stat(fb); stErr == nil {
				return fb, nil
			}
		}
		return "", err
	}
	cleaned := SanitizeExecutablePath(exe)
	if _, stErr := os.Stat(cleaned); stErr != nil {
		for _, fb := range []string{"/usr/bin/singctl", "/usr/local/bin/singctl"} {
			if _, fbErr := os.Stat(fb); fbErr == nil {
				return fb, nil
			}
		}
	}
	return cleaned, nil
}

// SanitizeExecutablePath 剥离可执行路径末尾的 ` (deleted)` 与 `.backup` 残留后缀。
func SanitizeExecutablePath(exe string) string {
	p := strings.TrimSpace(exe)
	for {
		next := strings.TrimSuffix(p, " (deleted)")
		next = strings.TrimSuffix(next, ".backup")
		if next == p {
			break
		}
		p = next
	}
	return p
}

func (u *Updater) verifyChecksumsFile(ctx context.Context, client *releasepkg.Client, repo string, info *releasepkg.Info, asset *releasepkg.Asset, archivePath string, viaMirror bool) error {
	if client.SkipSHA256 {
		logger.Warn("⚠️  %s=1 已设置，跳过 sha256 校验。镜像或网络被劫持时可能安装恶意程序，请自行承担风险！", SkipChecksumEnv)
		return nil
	}

	sums, err := client.FetchChecksums(ctx, repo, info.TagName, nil, info)
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

// SelectSingCtlAsset 根据目标系统、架构及构建变体（完整版 vs lite 轻量版）选择最合适的资产。
func SelectSingCtlAsset(assets []releasepkg.Asset, goos, goarch string, isLite bool) *releasepkg.Asset {
	var standardMatch *releasepkg.Asset
	var liteMatch *releasepkg.Asset

	for i := range assets {
		if !matchesOSAndArch(assets[i].Name, goos, goarch) {
			continue
		}
		if isLiteAssetName(assets[i].Name) {
			if liteMatch == nil {
				liteMatch = &assets[i]
			}
		} else {
			if standardMatch == nil {
				standardMatch = &assets[i]
			}
		}
	}

	if isLite {
		if liteMatch != nil {
			return liteMatch
		}
		return standardMatch
	}
	return standardMatch
}

func isLiteAssetName(assetName string) bool {
	name := strings.ToLower(assetName)
	return strings.Contains(name, "-lite.") || strings.Contains(name, "-lite-") || strings.Contains(name, "_lite.")
}

func matchesOSAndArch(assetName, goos, goarch string) bool {
	name := strings.ToLower(assetName)
	goos = strings.ToLower(goos)
	goarch = strings.ToLower(goarch)

	if strings.Contains(name, "checksums") || !strings.Contains(name, "singctl") || !strings.Contains(name, goos) {
		return false
	}
	if goarch == "amd64" {
		if !strings.Contains(name, "amd64") && !strings.Contains(name, "x86_64") {
			return false
		}
	} else if !strings.Contains(name, goarch) {
		return false
	}
	return strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".zip")
}
