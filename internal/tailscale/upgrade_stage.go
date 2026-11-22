// 文件职责：负责 Tailscale 发布归档流式下载校验（零额外内存拷贝）、二进制解包暂存与可执行完整性验证。
package tailscale

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	releasepkg "singctl/internal/common/release"
	"strings"
	"time"
)

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// streamStageTailscaleArchive downloads, computes SHA256 on the fly, and unpacks directly into installDir/.tailscale*.new
// with zero /tmp usage. If mirror verification fails, it removes staged files and falls back automatically.
// StreamStageTailscaleArchive 流式下载、在线计算 SHA256 并直接解包至 installDir/.tailscale*.new。
func StreamStageTailscaleArchive(ctx context.Context, client *releasepkg.Client, asset releasepkg.Asset, installDir string) (combinedSymlink bool, shaVerified bool, viaMirror bool, err error) {
	return streamStageTailscaleArchive(ctx, client, asset, installDir)
}

func streamStageTailscaleArchive(ctx context.Context, client *releasepkg.Client, asset releasepkg.Asset, installDir string) (combinedSymlink bool, shaVerified bool, viaMirror bool, err error) {
	if client == nil {
		client = releasepkg.NewClient("")
	}
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return false, false, false, fmt.Errorf("create install dir: %w", err)
	}

	directURL := strings.TrimSpace(asset.BrowserDownloadURL)
	if directURL == "" {
		return false, false, false, fmt.Errorf("empty download URL for asset %s", asset.Name)
	}
	mirror := strings.TrimSpace(client.Mirror)

	type candidate struct {
		url    string
		mirror bool
	}
	var order []candidate
	if client.DirectFirst || mirror == "" {
		order = append(order, candidate{directURL, false})
		if mirror != "" {
			order = append(order, candidate{strings.TrimSuffix(mirror, "/") + "/" + directURL, true})
		}
	} else {
		order = append(order, candidate{strings.TrimSuffix(mirror, "/") + "/" + directURL, true}, candidate{directURL, false})
	}

	var expectedSHA string
	if !client.SkipSHA256 {
		if d := strings.ToLower(strings.TrimSpace(asset.Digest)); strings.HasPrefix(d, "sha256:") {
			expectedSHA = strings.TrimSpace(strings.TrimPrefix(d, "sha256:"))
		}
	}

	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 120 * time.Second}
	}

	var lastErr error
	for _, cand := range order {
		for range 2 {
			combined, verified, attemptErr := streamStageOnce(ctx, httpClient, cand.url, asset.Name, asset.Size, expectedSHA, installDir)
			if attemptErr == nil {
				return combined, verified, cand.mirror, nil
			}
			lastErr = fmt.Errorf("download from %s: %w", cand.url, attemptErr)
			removeStagedFiles(installDir)
		}
	}
	return false, false, false, fmt.Errorf("all streaming download attempts failed: %w", lastErr)
}

func streamStageOnce(ctx context.Context, httpClient *http.Client, url, assetName string, expectedSize int64, expectedSHA, installDir string) (combinedSymlink bool, shaVerified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, false, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, false, fmt.Errorf("status: %s", resp.Status)
	}

	cr := &countingReader{r: resp.Body}
	hasher := sha256.New()
	tee := io.TeeReader(cr, hasher)

	var wroteTSD, wroteTS bool
	err = releasepkg.WalkTarGzStream(tee, func(hdr *tar.Header, tr io.Reader) error {
		cleanName := filepath.ToSlash(filepath.Clean(hdr.Name))
		if strings.Contains(strings.ToLower(cleanName), "systemd") {
			return nil
		}
		base := filepath.Base(cleanName)
		if base != "tailscaled" && base != "tailscale" {
			return nil
		}

		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			dstName := stagedTailscaledName
			if base == "tailscale" {
				dstName = stagedTailscaleName
			}
			dstPath := filepath.Join(installDir, dstName)
			if err := writeStreamedExecutable(dstPath, tr, hdr.Size); err != nil {
				return fmt.Errorf("write %s: %w", dstName, err)
			}
			if base == "tailscaled" {
				wroteTSD = true
			} else {
				wroteTS = true
			}
		case tar.TypeSymlink, tar.TypeLink:
			if base == "tailscale" {
				target := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(hdr.Linkname)), "./")
				if target == "tailscaled" || filepath.Base(target) == "tailscaled" {
					combinedSymlink = true
				}
			}
		}
		return nil
	})
	if err != nil {
		return false, false, err
	}
	// Drain trailing gzip/padding bytes through tee so countingReader and sha256 see 100% of HTTP body.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return false, false, fmt.Errorf("drain archive trailer: %w", err)
	}

	if expectedSize > 0 && cr.n != expectedSize {
		return false, false, fmt.Errorf("size mismatch for %s: got %d bytes, expected %d", assetName, cr.n, expectedSize)
	}
	if expectedSHA != "" {
		gotHex := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(gotHex, expectedSHA) {
			return false, false, fmt.Errorf("sha256 mismatch for %s: got %s, expected %s", assetName, gotHex, expectedSHA)
		}
		shaVerified = true
	}

	if !wroteTSD {
		return false, false, fmt.Errorf("archive missing tailscaled executable")
	}
	if combinedSymlink {
		if wroteTS {
			_ = os.Remove(filepath.Join(installDir, stagedTailscaleName))
		}
		return true, shaVerified, nil
	}
	if !wroteTS {
		return false, false, fmt.Errorf("archive missing tailscale CLI executable")
	}
	return false, shaVerified, nil
}

func writeStreamedExecutable(dstPath string, r io.Reader, expectedSize int64) error {
	f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(f, io.LimitReader(r, maxBinaryExtractBytes))
	if copyErr == nil && expectedSize >= 0 && written != expectedSize {
		copyErr = fmt.Errorf("short tar extract: wrote %d of %d bytes", written, expectedSize)
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(dstPath)
		return copyErr
	}
	if syncErr != nil {
		_ = os.Remove(dstPath)
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(dstPath)
		return closeErr
	}
	return os.Chmod(dstPath, 0755)
}

func removeStagedFiles(installDir string) {
	_ = os.Remove(filepath.Join(installDir, stagedTailscaledName))
	_ = os.Remove(filepath.Join(installDir, stagedTailscaleName))
}

// VerifyStagedBinaries 对暂存的新版二进制执行版本自检，失败自动清理暂存文件。
func VerifyStagedBinaries(ctx context.Context, installDir string, combinedSymlink bool) (string, error) {
	return verifyStagedBinaries(ctx, installDir, combinedSymlink)
}

func verifyStagedBinaries(ctx context.Context, installDir string, combinedSymlink bool) (string, error) {
	vCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tsdNew := filepath.Join(installDir, stagedTailscaledName)
	out, err := exec.CommandContext(vCtx, tsdNew, "--version").CombinedOutput()
	if err != nil {
		removeStagedFiles(installDir)
		return "", fmt.Errorf("新版本二进制兼容预检失败 (%s --version): %w (%s)", tsdNew, err, strings.TrimSpace(string(out)))
	}
	ver, parseErr := ParseVersionOutput(string(out))
	if parseErr != nil {
		removeStagedFiles(installDir)
		return "", fmt.Errorf("新版本输出解析失败: %w", parseErr)
	}

	if !combinedSymlink {
		tsNew := filepath.Join(installDir, stagedTailscaleName)
		outCLI, err := exec.CommandContext(vCtx, tsNew, "version").CombinedOutput()
		if err != nil {
			removeStagedFiles(installDir)
			return "", fmt.Errorf("新版 CLI 兼容预检失败 (%s version): %w (%s)", tsNew, err, strings.TrimSpace(string(outCLI)))
		}
		if _, parseErr := ParseVersionOutput(string(outCLI)); parseErr != nil {
			removeStagedFiles(installDir)
			return "", fmt.Errorf("新版 CLI 输出解析失败: %w", parseErr)
		}
	}
	return ver, nil
}
