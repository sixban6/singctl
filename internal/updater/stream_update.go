// 文件职责：实现低内存与低 /tmp 可用空间场景下的零 /tmp 归档落盘流式 SHA256 校验直写自升级。
package updater

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
	"strings"

	"singctl/configs"
	"singctl/internal/common/fsx"
	releasepkg "singctl/internal/common/release"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/logger"
)

const minTmpAvailBytesForArchiveUpdate uint64 = 64 * 1024 * 1024

type byteCountReader struct {
	r io.Reader
	n int64
}

func (b *byteCountReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.n += int64(n)
	return n, err
}

func canStreamTarGzAsset(assetName string) bool {
	lower := strings.ToLower(strings.TrimSpace(assetName))
	return strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
}

func (u *Updater) shouldUseZeroTmpStreaming(asset *releasepkg.Asset) bool {
	if asset == nil || !canStreamTarGzAsset(asset.Name) {
		return false
	}

	if u.isLowMemoryHost() || u.isLowFlashHost() {
		return true
	}

	tmpDir := cmp.Or(u.deps.TempDir, os.TempDir())
	statFn := u.deps.StatTmpSpace
	if statFn == nil {
		statFn = sysinfo.Statfs
	}
	requiredTmp := minTmpAvailBytesForArchiveUpdate
	if asset.Size > 0 {
		requiredTmp = max(requiredTmp, uint64(asset.Size)*3)
	}
	if ds, err := statFn(tmpDir); err == nil && ds.AvailBytes > 0 && ds.AvailBytes < requiredTmp {
		return true
	}
	return false
}

func parseOfficialSHA256Digest(digest string) (string, bool) {
	algo, sum, ok := strings.Cut(strings.ToLower(strings.TrimSpace(digest)), ":")
	if !ok || algo != "sha256" || len(sum) != sha256.Size*2 {
		return "", false
	}
	return sum, true
}

func (u *Updater) resolveExpectedAssetSHA256(
	ctx context.Context,
	client *releasepkg.Client,
	repo string,
	info *releasepkg.Info,
	asset *releasepkg.Asset,
) (expected string, fromDigest bool, err error) {
	if client.SkipSHA256 {
		logger.Warn("⚠️  %s=1 已设置，跳过 sha256 校验。镜像或网络被劫持时可能安装恶意程序，请自行承担风险！", SkipChecksumEnv)
		return "", false, nil
	}
	if sum, ok := parseOfficialSHA256Digest(asset.Digest); ok {
		return sum, true, nil
	}
	sums, err := client.FetchChecksums(ctx, repo, info.TagName, nil, info)
	if err != nil {
		return "", false, fmt.Errorf("无法直连 GitHub 获取 checksums.txt（校验必需，不走镜像）。请检查网络后重试；确要跳过请设置 %s=1: %w", SkipChecksumEnv, err)
	}
	sum, ok := sums[asset.Name]
	if !ok || sum == "" {
		return "", false, fmt.Errorf("checksums.txt 中没有资产 %s 的记录，拒绝安装", asset.Name)
	}
	return strings.ToLower(strings.TrimSpace(sum)), false, nil
}

type streamCandidate struct {
	url       string
	viaMirror bool
}

func buildStreamCandidates(client *releasepkg.Client, asset *releasepkg.Asset) []streamCandidate {
	dlBase := cmp.Or(strings.TrimSuffix(client.DLBase, "/"), "https://github.com")
	directURL := strings.TrimSpace(asset.BrowserDownloadURL)
	if directURL == "" {
		directURL = dlBase + "/" + asset.Name
	}
	mirror := strings.TrimSuffix(strings.TrimSpace(client.Mirror), "/")
	if mirror == "" {
		return []streamCandidate{{url: directURL, viaMirror: false}}
	}
	mirrorURL := mirror + "/" + directURL
	if client.DirectFirst {
		return []streamCandidate{
			{url: directURL, viaMirror: false},
			{url: mirrorURL, viaMirror: true},
		}
	}
	return []streamCandidate{
		{url: mirrorURL, viaMirror: true},
		{url: directURL, viaMirror: false},
	}
}

func (u *Updater) updateSelfZeroTmpStream(
	ctx context.Context,
	client *releasepkg.Client,
	repo string,
	info *releasepkg.Info,
	asset *releasepkg.Asset,
	goos string,
	configPath string,
) error {
	currentExe, err := u.resolveCurrentExe()
	if err != nil {
		return fmt.Errorf("get current executable: %w", err)
	}
	expectedSHA, fromDigest, err := u.resolveExpectedAssetSHA256(ctx, client, repo, info, asset)
	if err != nil {
		return err
	}

	targetDir := filepath.Dir(currentExe)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("prepare target binary directory %s: %w", targetDir, err)
	}

	stagedTmp, err := os.CreateTemp(targetDir, ".singctl-stream-*.tmp")
	if err != nil {
		return fmt.Errorf("create staged temp file in %s: %w", targetDir, err)
	}
	stagedPath := stagedTmp.Name()
	_ = stagedTmp.Close()
	_ = os.Remove(stagedPath)
	defer func() {
		_ = os.Remove(stagedPath)
	}()

	binName := "singctl"
	if goos == "windows" {
		binName = "singctl.exe"
	}

	logger.Info("Low-memory / low-/tmp mode enabled: streaming %s directly to %s (0 MB /tmp archive usage)...", asset.Name, targetDir)

	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	var lastErr error
	for _, cand := range buildStreamCandidates(client, asset) {
		if err := streamExtractAndVerifyOnce(ctx, httpClient, cand.url, binName, stagedPath, asset.Size, expectedSHA); err != nil {
			_ = os.Remove(stagedPath)
			if cand.viaMirror {
				lastErr = fmt.Errorf("mirror stream %s failed: %w", cand.url, err)
			} else {
				lastErr = fmt.Errorf("direct stream %s failed: %w", cand.url, err)
			}
			continue
		}

		if expectedSHA != "" {
			if fromDigest {
				logger.Success("✅ sha256 流式校验通过，与 GitHub 官方 digest 一致 (%s)", asset.Name)
			} else {
				logger.Success("✅ sha256 流式校验通过 (%s)", asset.Name)
			}
		}

		if err := fsx.SafeReplace(currentExe, stagedPath); err != nil {
			return err
		}
		_ = os.Remove(stagedPath)

		if configPath != "" {
			if _, stErr := os.Stat(configPath); stErr == nil {
				if mErr := config.MigrateConfig(configPath, configs.ClientConfigYAML); mErr != nil {
					logger.Warn("In-process config migration warning for %s: %v", configPath, mErr)
				}
			}
		}

		logger.Success("SingCtl updated successfully (zero-/tmp streaming mode)")
		logger.Info("Binary replaced on disk: %s", currentExe)
		return nil
	}

	return fmt.Errorf("all zero-/tmp streaming download attempts failed: %w", lastErr)
}

func streamExtractAndVerifyOnce(
	ctx context.Context,
	httpClient *http.Client,
	downloadURL string,
	binName string,
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
		return fmt.Errorf("unexpected status %s", resp.Status)
	}

	counter := &byteCountReader{r: resp.Body}
	hasher := sha256.New()
	tee := io.TeeReader(counter, hasher)

	if err := releasepkg.ExtractBinaryStream(tee, binName, stagedPath, releasepkg.DefaultMaxBinaryBytes); err != nil {
		return err
	}
	// 消费归档剩余尾部字节（如 configs/* 与 gzip 校验尾），确保整包字节数与官方 SHA256 100% 完整比对。
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return fmt.Errorf("drain archive tail: %w", err)
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
