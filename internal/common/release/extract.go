// 文件职责：提供带路径穿越（Zip-Slip）防护与最大解压尺寸保护的归档全量解压及小内存流式二进制提取。
package release

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultMaxBinaryBytes 为单个流式解压可执行文件的默认大小硬上限（256 MiB），防止解压炸弹导致小内存设备 OOM。
const DefaultMaxBinaryBytes int64 = 256 << 20

// Extract 解压 .tar.gz/.tgz/.tar/.zip 到 destDir，内置严格的 Zip-Slip 路径穿越拦截与随机临时文件原子落盘。
func Extract(archive, destDir string) error {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}
	lower := strings.ToLower(archive)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return extractZip(archive, destDir)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return extractTar(archive, destDir, true)
	case strings.HasSuffix(lower, ".tar"):
		return extractTar(archive, destDir, false)
	default:
		return fmt.Errorf("unsupported archive format: %s", archive)
	}
}

// ExtractBinary 从本地 .tar.gz / .tgz 归档中安全流式提取名为 binaryName 的单个可执行文件到 destPath。
func ExtractBinary(archivePath, binaryName, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return ExtractBinaryStream(f, binaryName, destPath, DefaultMaxBinaryBytes)
}

// ExtractBinaryStream 直接从 gzip+tar 数据流中提取指定名称的可执行文件并原子写入 destPath（0755），零整包落盘、防 Zip-Slip、防超大包 OOM。
func ExtractBinaryStream(r io.Reader, binaryName, destPath string, maxBytes int64) error {
	if r == nil {
		return errors.New("nil archive stream")
	}
	targetName := strings.TrimSpace(binaryName)
	cleanDest := strings.TrimSpace(destPath)
	if targetName == "" || cleanDest == "" {
		return errors.New("binaryName and destPath must not be empty")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBinaryBytes
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		if hdr == nil {
			continue
		}
		if err := validateEntryPath(hdr.Name); err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if hdr.Name != targetName && filepath.Base(filepath.FromSlash(hdr.Name)) != targetName {
			continue
		}
		if hdr.Size > maxBytes {
			return fmt.Errorf("archive binary %s size %d exceeds limit %d", targetName, hdr.Size, maxBytes)
		}
		return writeBoundedExecutableAtomic(tr, cleanDest, maxBytes)
	}
	return fmt.Errorf("executable %s not found in archive stream", targetName)
}

// WalkTarGzStream 流式遍历 gzip+tar 归档条目（内置 Zip-Slip 路径安全校验），供多文件/软链复合流式暂存复用。
func WalkTarGzStream(r io.Reader, fn func(hdr *tar.Header, body io.Reader) error) error {
	if r == nil || fn == nil {
		return errors.New("nil stream or visitor")
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		if hdr == nil {
			continue
		}
		if err := validateEntryPath(hdr.Name); err != nil {
			return err
		}
		if err := fn(hdr, tr); err != nil {
			return err
		}
	}
	return gz.Close()
}

// DownloadAndExtractBinary 流式下载 .tar.gz 归档（支持可选镜像前缀回退直连）并直接提取指定可执行文件至 destPath。
func DownloadAndExtractBinary(ctx context.Context, httpClient *http.Client, directURL, mirrorURL, binaryName, destPath string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	directURL = strings.TrimSpace(directURL)
	mirrorURL = strings.TrimSpace(mirrorURL)
	if mirrorURL == "https://github.com" || mirrorURL == "https://github.com/" {
		mirrorURL = ""
	}

	var urls []string
	if mirrorURL != "" {
		urls = append(urls, strings.TrimSuffix(mirrorURL, "/")+"/"+directURL, directURL)
	} else {
		urls = append(urls, directURL)
	}

	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("download %s returned status %s", u, resp.Status)
			continue
		}
		extErr := ExtractBinaryStream(resp.Body, binaryName, destPath, DefaultMaxBinaryBytes)
		_ = resp.Body.Close()
		if extErr == nil {
			return nil
		}
		lastErr = fmt.Errorf("extract from %s: %w", u, extErr)
	}
	return lastErr
}

func validateEntryPath(name string) error {
	slashName := filepath.ToSlash(name)
	if strings.HasPrefix(slashName, "/") {
		return fmt.Errorf("archive entry has absolute path: %s", name)
	}
	for seg := range strings.SplitSeq(slashName, "/") {
		if seg == ".." {
			return fmt.Errorf("archive entry escapes destination dir: %s", name)
		}
	}
	cleaned := filepath.Clean(filepath.FromSlash(name))
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) || strings.HasPrefix(cleaned, string(os.PathSeparator)) {
		return fmt.Errorf("archive entry escapes destination dir: %s", name)
	}
	return nil
}

func safeJoin(destDir, name string) (string, error) {
	if err := validateEntryPath(name); err != nil {
		return "", err
	}
	cleaned := filepath.Clean(filepath.FromSlash(name))
	target := filepath.Join(destDir, cleaned)
	cleanDest := filepath.Clean(destDir)
	if target == cleanDest || !strings.HasPrefix(target, cleanDest+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive entry escapes destination dir: %s", name)
	}
	return target, nil
}

func extractZip(archive, destDir string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		target, err := safeJoin(destDir, f.Name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %s: %w", f.Name, err)
		}
		err = writeModeAtomic(rc, target, f.Mode(), DefaultMaxBinaryBytes)
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTar(archive, destDir string, gzipped bool) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()

	var tr *tar.Reader
	if gzipped {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("open gzip: %w", err)
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	} else {
		tr = tar.NewReader(f)
	}

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		target, err := safeJoin(destDir, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			mode := os.FileMode(hdr.Mode)
			if mode.Perm() == 0 {
				mode = 0644
			}
			if err := writeModeAtomic(tr, target, mode, DefaultMaxBinaryBytes); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := validateEntryPath(hdr.Linkname); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			_ = os.Symlink(hdr.Linkname, target)
		}
	}
}

func writeBoundedExecutableAtomic(r io.Reader, destPath string, maxBytes int64) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}
	return writeModeAtomic(r, destPath, 0755, maxBytes)
}

func writeModeAtomic(r io.Reader, target string, mode os.FileMode, maxBytes int64) error {
	perm := mode.Perm()
	if perm == 0 {
		perm = 0644
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".ext-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	n, copyErr := io.Copy(tmp, io.LimitReader(r, maxBytes+1))
	closeErr := tmp.Close()
	if copyErr != nil {
		return copyErr
	}
	if n > maxBytes {
		return fmt.Errorf("extracted entry %s exceeds size limit %d bytes", filepath.Base(target), maxBytes)
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	cleanup = false
	return os.Chmod(target, perm)
}
