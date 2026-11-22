// 文件职责：实现小内存/小闪存网关 sing-box-lite 自动通道判定、版本资产匹配与零 /tmp 流式 SHA256 直写安装。
package singbox

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"singctl/internal/common/fsx"
	"singctl/internal/common/netx"
	releasepkg "singctl/internal/common/release"
	"singctl/internal/common/sysinfo"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/singbox/ruleset_snapshot"
)

const (
	// SingBoxLiteEnv 允许通过环境变量显式开启（1/true）或关闭（0/false）sing-box-lite 精简通道。
	SingBoxLiteEnv = "SINGCTL_SINGBOX_LITE"
	// SingBoxLiteDiskThresholdBytes 目标安装目录所在分区可用空间自动启用 sing-box-lite 的阈值（120 MiB）。
	SingBoxLiteDiskThresholdBytes uint64 = 120 * 1024 * 1024
	// UpstreamSingBoxRepo 为上游官方 sing-box 发布仓库坐标。
	UpstreamSingBoxRepo = "SagerNet/sing-box"

	minTmpAvailBytesForSingBoxArchive uint64 = 96 * 1024 * 1024
)

var liteVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9A-Za-z.-]+)?$`)

// InstallDeps 定义安装/升级 sing-box 时的可选依赖注入（未设置字段自动回退生产默认实现，严禁修改全局变量）。
type InstallDeps struct {
	GOOS              string
	GOARCH            string
	IsLiteBinary      *bool
	ReadTotalRAMBytes func() uint64
	StatDiskSpace     func(path string) (sysinfo.DiskSpace, error)
	Getenv            func(key string) string
	TargetPath        string
	TempDir           string
	CurrentVersionFn  func() (string, error)
	APIBase           string
	DLBase            string
	HTTPClient        *http.Client
	DirectFirst       *bool
	LiteRepo          string
}

// ShouldUseSingBoxLite 纯策略判定当前设备是否应优先使用 sing-box-lite 精简二进制通道。
//   - 仅在 linux/amd64 与 linux/arm64 架构上生效；
//   - 支持 SINGCTL_SINGBOX_LITE=1/true 强制开启、0/false 强制关闭；
//   - 自动启用条件：当前 singctl 为 -tags lite 构建、或处于低内存模式、或目标分区可用空间 < 120 MiB。
func ShouldUseSingBoxLite(goos, goarch string, isLiteBinary bool, lowMemory bool, availDiskBytes uint64, envOverride string) bool {
	osNorm := strings.ToLower(strings.TrimSpace(goos))
	archNorm := strings.ToLower(strings.TrimSpace(goarch))
	if osNorm != "linux" || (archNorm != "amd64" && archNorm != "arm64") {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(envOverride)) {
	case "1", "true", "on", "yes":
		return true
	case "0", "false", "off", "no":
		return false
	}

	if isLiteBinary || lowMemory {
		return true
	}
	if availDiskBytes > 0 && availDiskBytes < SingBoxLiteDiskThresholdBytes {
		return true
	}
	return false
}

// SelectSingBoxLiteAsset 从 singbox-lite-latest 发布资产列表中选择匹配指定 Linux 架构的压缩包。
func SelectSingBoxLiteAsset(assets []releasepkg.Asset, goarch string) *releasepkg.Asset {
	archNorm := strings.ToLower(strings.TrimSpace(goarch))
	if archNorm != "amd64" && archNorm != "arm64" {
		return nil
	}
	suffix := "-linux-" + archNorm + "-lite.tar.gz"
	for i := range assets {
		lower := strings.ToLower(strings.TrimSpace(assets[i].Name))
		if !strings.HasPrefix(lower, "sing-box-") || !strings.HasSuffix(lower, suffix) {
			continue
		}
		if _, err := ParseSingBoxLiteAssetVersion(assets[i].Name); err == nil {
			return &assets[i]
		}
	}
	return nil
}

// ParseSingBoxLiteAssetVersion 从 sing-box-<version>-linux-<arch>-lite.tar.gz 资产名中提取版本号。
func ParseSingBoxLiteAssetVersion(assetName string) (string, error) {
	trimmed := strings.TrimSpace(assetName)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "sing-box-") {
		return "", fmt.Errorf("invalid sing-box-lite asset prefix: %q", assetName)
	}
	var suffixLen int
	switch {
	case strings.HasSuffix(lower, "-linux-amd64-lite.tar.gz"):
		suffixLen = len("-linux-amd64-lite.tar.gz")
	case strings.HasSuffix(lower, "-linux-arm64-lite.tar.gz"):
		suffixLen = len("-linux-arm64-lite.tar.gz")
	default:
		return "", fmt.Errorf("invalid sing-box-lite asset suffix: %q", assetName)
	}

	rawVer := trimmed[len("sing-box-") : len(trimmed)-suffixLen]
	rawVer = strings.TrimPrefix(rawVer, "v")
	if rawVer == "" || strings.Contains(rawVer, "..") || !liteVersionPattern.MatchString(rawVer) {
		return "", fmt.Errorf("invalid version %q in sing-box-lite asset %q", rawVer, assetName)
	}
	return rawVer, nil
}

func (sb *SingBox) effectiveGOOS() string {
	return cmp.Or(strings.TrimSpace(sb.deps.GOOS), runtime.GOOS)
}

func (sb *SingBox) effectiveGOARCH() string {
	return cmp.Or(strings.TrimSpace(sb.deps.GOARCH), runtime.GOARCH)
}

func (sb *SingBox) effectiveTargetPath() string {
	return cmp.Or(strings.TrimSpace(sb.deps.TargetPath), constant.SingBoxInstallDir)
}

func (sb *SingBox) effectiveIsLiteBinary() bool {
	if sb.deps.IsLiteBinary != nil {
		return *sb.deps.IsLiteBinary
	}
	return ruleset_snapshot.IsLite
}

func (sb *SingBox) effectiveTotalRAMBytes() uint64 {
	if sb.deps.ReadTotalRAMBytes != nil {
		return sb.deps.ReadTotalRAMBytes()
	}
	return readHostTotalRAMBytes()
}

func (sb *SingBox) effectiveAvailDiskBytes(path string) uint64 {
	statFn := sb.deps.StatDiskSpace
	if statFn == nil {
		statFn = sysinfo.Statfs
	}
	ds, err := statFn(path)
	if err != nil {
		return 0
	}
	return ds.AvailBytes
}

func (sb *SingBox) effectiveGetenv(key string) string {
	if sb.deps.Getenv != nil {
		return sb.deps.Getenv(key)
	}
	return os.Getenv(key)
}

func (sb *SingBox) mirrorURL() string {
	if sb.config == nil {
		return ""
	}
	return sb.config.GitHub.MirrorURL
}

func (sb *SingBox) liteRepo() string {
	return cmp.Or(strings.TrimSpace(sb.deps.LiteRepo), constant.GitHubRepo)
}

func (sb *SingBox) buildReleaseClient() *releasepkg.Client {
	client := releasepkg.NewClient(sb.mirrorURL())
	if sb.deps.APIBase != "" {
		client.APIBase = sb.deps.APIBase
	}
	if sb.deps.DLBase != "" {
		client.DLBase = sb.deps.DLBase
	}
	if sb.deps.HTTPClient != nil {
		client.HTTP = sb.deps.HTTPClient
	}
	if sb.deps.DirectFirst != nil {
		client.DirectFirst = *sb.deps.DirectFirst
	} else {
		client.DirectFirst = netx.CheckGoogleConnectivity()
	}
	return client
}

func (sb *SingBox) shouldUseSingBoxLite(targetPath string) bool {
	totalRAM := sb.effectiveTotalRAMBytes()
	lowMem := sb.config.EffectiveLowMemory(totalRAM)
	availDisk := sb.effectiveAvailDiskBytes(filepath.Dir(targetPath))
	return ShouldUseSingBoxLite(
		sb.effectiveGOOS(),
		sb.effectiveGOARCH(),
		sb.effectiveIsLiteBinary(),
		lowMem,
		availDisk,
		sb.effectiveGetenv(SingBoxLiteEnv),
	)
}

func (sb *SingBox) shouldStreamDirectToTarget(targetPath string, asset *releasepkg.Asset, forceStream bool) bool {
	if asset == nil {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(asset.Name))
	if !strings.HasSuffix(lower, ".tar.gz") && !strings.HasSuffix(lower, ".tgz") {
		return false
	}
	if forceStream {
		return true
	}
	totalRAM := sb.effectiveTotalRAMBytes()
	if sb.config.EffectiveLowMemory(totalRAM) {
		return true
	}
	availTarget := sb.effectiveAvailDiskBytes(filepath.Dir(targetPath))
	if availTarget > 0 && availTarget < SingBoxLiteDiskThresholdBytes {
		return true
	}
	tmpDir := cmp.Or(strings.TrimSpace(sb.deps.TempDir), os.TempDir())
	requiredTmp := minTmpAvailBytesForSingBoxArchive
	if asset.Size > 0 {
		requiredTmp = max(requiredTmp, uint64(asset.Size)*3)
	}
	availTmp := sb.effectiveAvailDiskBytes(tmpDir)
	return availTmp > 0 && availTmp < requiredTmp
}

func parseSHA256DigestField(digest string) (string, bool) {
	algo, sum, ok := strings.Cut(strings.ToLower(strings.TrimSpace(digest)), ":")
	if !ok || algo != "sha256" || len(sum) != sha256.Size*2 {
		return "", false
	}
	if _, err := hex.DecodeString(sum); err != nil {
		return "", false
	}
	return sum, true
}

func resolveAssetSHA256(
	ctx context.Context,
	client *releasepkg.Client,
	repo string,
	info *releasepkg.Info,
	asset *releasepkg.Asset,
	requireChecksum bool,
) (expectedSHA string, fromDigest bool, err error) {
	if sum, ok := parseSHA256DigestField(asset.Digest); ok {
		return sum, true, nil
	}
	sums, fetchErr := client.FetchChecksums(ctx, repo, info.TagName, nil, info)
	if fetchErr == nil {
		if sum := strings.ToLower(strings.TrimSpace(sums[asset.Name])); len(sum) == sha256.Size*2 {
			if _, decErr := hex.DecodeString(sum); decErr == nil {
				return sum, false, nil
			}
		}
	}
	if requireChecksum {
		if fetchErr != nil {
			return "", false, fmt.Errorf("无法直连 GitHub 获取 sing-box-lite 校验清单 checksums.txt: %w", fetchErr)
		}
		return "", false, fmt.Errorf("checksums.txt 中缺少资产 %s 的 SHA256 记录，拒绝未校验安装", asset.Name)
	}
	return "", false, nil
}

type downloadCandidate struct {
	url       string
	viaMirror bool
}

func buildDownloadCandidates(client *releasepkg.Client, asset *releasepkg.Asset) []downloadCandidate {
	dlBase := cmp.Or(strings.TrimSuffix(client.DLBase, "/"), "https://github.com")
	directURL := strings.TrimSpace(asset.BrowserDownloadURL)
	if directURL == "" {
		directURL = dlBase + "/" + asset.Name
	}
	mirror := strings.TrimSuffix(strings.TrimSpace(client.Mirror), "/")
	if mirror == "" {
		return []downloadCandidate{{url: directURL, viaMirror: false}}
	}
	mirrorURL := mirror + "/" + directURL
	if client.DirectFirst {
		return []downloadCandidate{
			{url: directURL, viaMirror: false},
			{url: mirrorURL, viaMirror: true},
		}
	}
	return []downloadCandidate{
		{url: mirrorURL, viaMirror: true},
		{url: directURL, viaMirror: false},
	}
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func streamExtractVerifyOnce(
	ctx context.Context,
	httpClient *http.Client,
	downloadURL string,
	binaryName string,
	stagedPath string,
	expectedSize int64,
	expectedSHA string,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}

	counter := &countingReader{r: resp.Body}
	hasher := sha256.New()
	tee := io.TeeReader(counter, hasher)

	if err := releasepkg.ExtractBinaryStream(tee, binaryName, stagedPath, releasepkg.DefaultMaxBinaryBytes); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return fmt.Errorf("drain archive trailer: %w", err)
	}

	if expectedSize > 0 && counter.n != expectedSize {
		return fmt.Errorf("archive size mismatch: got %d bytes, want %d", counter.n, expectedSize)
	}
	if expectedSHA != "" {
		actualSHA := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(actualSHA, expectedSHA) {
			return fmt.Errorf("sha256 mismatch: got %s, want %s", actualSHA, expectedSHA)
		}
	}
	return nil
}

// streamInstallSingBoxTarGz 以零 /tmp 归档落盘方式流式下载、校验整包 SHA256 并解压到 targetPath 同分区临时文件后单步原子替换。
func (sb *SingBox) streamInstallSingBoxTarGz(
	ctx context.Context,
	client *releasepkg.Client,
	repo string,
	info *releasepkg.Info,
	asset *releasepkg.Asset,
	targetPath string,
	requireChecksum bool,
) error {
	expectedSHA, fromDigest, err := resolveAssetSHA256(ctx, client, repo, info, asset, requireChecksum)
	if err != nil {
		return err
	}

	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("prepare target binary directory %s: %w", targetDir, err)
	}

	stagedTmp, err := os.CreateTemp(targetDir, ".sing-box-stream-*.tmp")
	if err != nil {
		return fmt.Errorf("create staged temp file in %s: %w", targetDir, err)
	}
	stagedPath := stagedTmp.Name()
	_ = stagedTmp.Close()
	_ = os.Remove(stagedPath)
	defer func() {
		_ = os.Remove(stagedPath)
	}()

	binName := "sing-box"
	if sb.effectiveGOOS() == "windows" {
		binName = "sing-box.exe"
	}

	logger.Info("Zero-/tmp flash streaming mode: streaming %s directly into %s (0 MB /tmp archive usage)...", asset.Name, targetDir)

	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	var lastErr error
	for _, cand := range buildDownloadCandidates(client, asset) {
		if err := streamExtractVerifyOnce(ctx, httpClient, cand.url, binName, stagedPath, asset.Size, expectedSHA); err != nil {
			_ = os.Remove(stagedPath)
			if cand.viaMirror {
				lastErr = fmt.Errorf("mirror stream %s: %w", cand.url, err)
			} else {
				lastErr = fmt.Errorf("direct stream %s: %w", cand.url, err)
			}
			continue
		}

		if expectedSHA != "" {
			if fromDigest {
				logger.Success("✅ sha256 流式校验通过，与 GitHub 官方 digest 一致 (%s)", asset.Name)
			} else {
				logger.Success("✅ sha256 流式校验通过，与官方 checksums.txt 一致 (%s)", asset.Name)
			}
		} else if cand.viaMirror {
			logger.Warn("⚠️ sing-box 经镜像流式下载；官方元数据无 digest，仅按大小校验（%d 字节）", asset.Size)
		}

		if err := atomicReplaceStagedExecutable(stagedPath, targetPath, sb.effectiveGOOS()); err != nil {
			return err
		}
		logger.Success("Sing-box installed successfully (%s -> %s)", asset.Name, targetPath)
		return nil
	}

	return fmt.Errorf("all streaming download attempts failed for %s: %w", asset.Name, lastErr)
}

func atomicReplaceStagedExecutable(stagedPath, targetPath, goos string) error {
	if err := os.Chmod(stagedPath, 0755); err != nil {
		return fmt.Errorf("chmod staged binary: %w", err)
	}
	if goos == "windows" {
		return fsx.InstallOrReplace(stagedPath, targetPath)
	}
	// POSIX 同目录 rename(2) 单步原子替换目录项：
	//   1) 无需像 SafeReplace 再额外拷贝第二份 30~86MB 临时文件，保护 40MB 小闪存 /overlay 不爆满；
	//   2) 对正在运行的旧 sing-box 进程零 ETXTBSY；
	//   3) 若 targetPath 原本是指向 /tmp 的软链接，直接原子替换为 /overlay 真实持久文件而不穿透写入 /tmp。
	if err := os.Rename(stagedPath, targetPath); err != nil {
		return fmt.Errorf("atomic rename %s -> %s: %w", stagedPath, targetPath, err)
	}
	return nil
}

// tryInstallSingBoxLite 尝试从本仓库 singbox-lite-latest 固定通道流式验签直写安装精简版 sing-box。
// 当通道尚未发布（404）或暂无对应架构产物时返回 fallback=true 以便调用方平滑回退 SagerNet/sing-box。
func (sb *SingBox) tryInstallSingBoxLite(ctx context.Context, client *releasepkg.Client, targetPath string) (fallback bool, err error) {
	repo := sb.liteRepo()
	arch := sb.effectiveGOARCH()

	info, err := client.FetchTag(ctx, repo, constant.SingBoxLiteReleaseTag)
	if err != nil {
		if releasepkg.IsNotFound(err) {
			logger.Warn("⚠️ sing-box-lite 精简通道 (%s@%s) 尚未就绪 (404)，平滑回退上游 %s", repo, constant.SingBoxLiteReleaseTag, UpstreamSingBoxRepo)
			return true, nil
		}
		return false, fmt.Errorf("无法直连 GitHub API 获取 sing-box-lite 发布信息（元数据不走镜像）: %w", err)
	}

	asset := SelectSingBoxLiteAsset(info.Assets, arch)
	if asset == nil {
		logger.Warn("⚠️ sing-box-lite 通道 (%s) 未找到 linux/%s 资产，平滑回退上游 %s", constant.SingBoxLiteReleaseTag, arch, UpstreamSingBoxRepo)
		return true, nil
	}

	ver, _ := ParseSingBoxLiteAssetVersion(asset.Name)
	logger.Info("📦 命中 sing-box-lite 小闪存/低内存精简通道: v%s (%s)", ver, asset.Name)
	if err := sb.streamInstallSingBoxTarGz(ctx, client, repo, info, asset, targetPath, true); err != nil {
		return false, err
	}
	return false, nil
}
