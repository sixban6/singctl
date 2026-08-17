// Package release 提供带完整性校验的 GitHub Release 资产下载能力。
//
// 安全模型：
//   - 发布元数据（tag、资产列表、大小、checksums.txt）必须从 GitHub 直连获取，
//     绝不经过第三方镜像 —— 它们是信任锚点。
//   - 大文件（压缩包）允许通过镜像加速下载，但下载后必须校验：
//     a) 若上游发布了 checksums（如 singctl 的 checksums.txt），做 sha256 强校验；
//     b) 否则至少用直连元数据中的官方文件大小做弱校验，并向用户明确提示风险。
package release

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultAPIBase = "https://api.github.com"
	defaultDLBase  = "https://github.com"
	downloadRetry  = 2
)

// Asset 描述 GitHub Release 中的单个资产。
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	ID                 int64  `json:"id"`
	Size               int64  `json:"size"`
}

// Info 描述一次 Release 查询结果。
type Info struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Client 下载器。Mirror 仅用于加速大文件；元数据永远直连。
type Client struct {
	// APIBase GitHub API 地址（测试可覆写）。
	APIBase string
	// DLBase GitHub 发布文件下载地址前缀（测试可覆写）。
	DLBase string
	// Mirror 第三方镜像前缀，如 https://gh-proxy.com；空表示只走直连。
	Mirror string
	// HTTP 带超时的 http.Client；nil 时使用默认 60s 超时客户端。
	HTTP *http.Client
	// DirectFirst 为 true 时优先直连下载大文件（镜像作后备），否则相反。
	// 生产代码按 Google 连通性设置；测试可固定。
	DirectFirst bool
}

// NewClient 创建默认客户端。mirror 为空或 "https://github.com" 表示不使用镜像。
func NewClient(mirror string) *Client {
	if mirror == "https://github.com" {
		mirror = ""
	}
	return &Client{
		APIBase: defaultAPIBase,
		DLBase:  defaultDLBase,
		Mirror:  mirror,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) apiBase() string {
	if c.APIBase != "" {
		return strings.TrimSuffix(c.APIBase, "/")
	}
	return defaultAPIBase
}

func (c *Client) dlBase() string {
	if c.DLBase != "" {
		return strings.TrimSuffix(c.DLBase, "/")
	}
	return defaultDLBase
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// FetchLatest 直连获取最新稳定 Release 元数据（不走镜像）。
func (c *Client) FetchLatest(ctx context.Context, repo string) (*Info, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", c.apiBase(), repo)
	return c.fetchInfo(ctx, url)
}

// FetchByTag 直连获取指定 tag 的 Release 元数据（不走镜像）。
func (c *Client) FetchByTag(ctx context.Context, repo, tag string) (*Info, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/tags/%s", c.apiBase(), repo, tag)
	return c.fetchInfo(ctx, url)
}

func (c *Client) fetchInfo(ctx context.Context, url string) (*Info, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch release metadata (direct, no mirror): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status: %s (%s)", resp.Status, url)
	}

	var info Info
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode release metadata: %w", err)
	}
	if info.TagName == "" {
		return nil, fmt.Errorf("release metadata has empty tag_name (%s)", url)
	}
	return &info, nil
}

// Download 下载资产到 destDir/<asset.Name>，返回本地路径和是否经镜像下载。
// 按大小写不敏感扩展名识别压缩包，下载后：
//   - 优先直连，失败换镜像（或相反，取决于 DirectFirst）；
//   - 资产已知大小时，校验下载文件大小与官方元数据一致。
func (c *Client) Download(ctx context.Context, asset Asset, destDir string) (string, bool, error) {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", false, err
	}
	dest := filepath.Join(destDir, asset.Name)

	directURL := asset.BrowserDownloadURL
	if directURL == "" {
		directURL = fmt.Sprintf("%s/%s", c.dlBase(), asset.Name) // 测试兜底，生产路径不会走到
	}

	type candidate struct {
		url   string
		mirro bool
	}
	var order []candidate
	if c.DirectFirst || c.Mirror == "" {
		order = append(order, candidate{directURL, false})
		if c.Mirror != "" {
			order = append(order, candidate{c.mirrorURL(directURL), true})
		}
	} else {
		order = append(order, candidate{c.mirrorURL(directURL), true}, candidate{directURL, false})
	}

	var lastErr error
	for _, cand := range order {
		if err := c.downloadTo(ctx, cand.url, dest); err != nil {
			lastErr = fmt.Errorf("download from %s: %w", cand.url, err)
			continue
		}
		if asset.Size > 0 {
			info, err := os.Stat(dest)
			if err != nil {
				lastErr = err
				continue
			}
			if info.Size() != asset.Size {
				os.Remove(dest)
				lastErr = fmt.Errorf("size mismatch for %s: got %d bytes, official metadata says %d (downloaded from %s)",
					asset.Name, info.Size(), asset.Size, cand.url)
				continue
			}
		}
		return dest, cand.mirro, nil
	}
	return "", false, fmt.Errorf("all download attempts failed: %w", lastErr)
}

func (c *Client) mirrorURL(u string) string {
	return strings.TrimSuffix(c.Mirror, "/") + "/" + u
}

func (c *Client) downloadTo(ctx context.Context, url, dest string) error {
	var lastErr error
	for range downloadRetry {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := c.httpClient().Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("status: %s", resp.Status)
			continue
		}
		tmp := dest + ".part"
		f, err := os.Create(tmp)
		if err != nil {
			resp.Body.Close()
			return err
		}
		_, copyErr := io.Copy(f, resp.Body)
		closeErr := f.Close()
		resp.Body.Close()
		if copyErr != nil {
			os.Remove(tmp)
			lastErr = copyErr
			continue
		}
		if closeErr != nil {
			os.Remove(tmp)
			lastErr = closeErr
			continue
		}
		if err := os.Rename(tmp, dest); err != nil {
			return err
		}
		return nil
	}
	return lastErr
}

// FetchChecksums 直连获取并解析 checksums 类资产（不走镜像）。
// 先尝试 GitHub API 资产端点（保持在 api 域名），失败再尝试发布文件直连下载。
// asset 为 nil 时按常见命名（checksums.txt / SHA256SUMS）在 info 中查找。
func (c *Client) FetchChecksums(ctx context.Context, repo, tag string, asset *Asset, info *Info) (map[string]string, error) {
	if asset == nil && info != nil {
		for i := range info.Assets {
			n := strings.ToLower(info.Assets[i].Name)
			if n == "checksums.txt" || n == "sha256sums" || n == "sha256sums.txt" {
				asset = &info.Assets[i]
				break
			}
		}
	}
	if asset == nil {
		return nil, fmt.Errorf("no checksums asset found for %s@%s", repo, tag)
	}

	// 途径一：api.github.com 资产端点（小文件，Accept octet-stream 触发真实内容下载）
	if asset.ID > 0 {
		url := fmt.Sprintf("%s/repos/%s/releases/assets/%d", c.apiBase(), repo, asset.ID)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err == nil {
			req.Header.Set("Accept", "application/octet-stream")
			resp, err := c.httpClient().Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					data, err := io.ReadAll(resp.Body)
					if err == nil {
						return ParseChecksums(data), nil
					}
				}
			}
		}
	}

	// 途径二：github.com 发布文件直连
	url := asset.BrowserDownloadURL
	if url == "" {
		url = fmt.Sprintf("%s/%s/releases/download/%s/%s", c.dlBase(), repo, tag, asset.Name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch checksums directly from GitHub (mirrors are never used for checksums): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch checksums: status %s (%s)", resp.Status, url)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return ParseChecksums(data), nil
}

// ParseChecksums 解析 sha256sum 风格内容: "<hex>  <filename>"，支持多空格/制表符分隔及二进制模式的 * 前缀。
func ParseChecksums(data []byte) map[string]string {
	sums := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// sha256sum -b 格式为 "<hex> *<file>"，* 也可能紧贴哈希；两侧都兼容
		sum := strings.ToLower(strings.TrimPrefix(fields[0], "*"))
		// 文件名可能含空格，取哈希字段之后的所有内容
		name := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
		name = strings.TrimPrefix(name, "*")
		if name == "" {
			continue
		}
		sums[name] = sum
	}
	return sums
}

// VerifySHA256 计算 path 的 sha256 并与 expected（hex）比较。
func VerifySHA256(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, strings.TrimSpace(expected)) {
		return fmt.Errorf("sha256 mismatch for %s: got %s, want %s", filepath.Base(path), actual, expected)
	}
	return nil
}

// Extract 解压 .tar.gz/.tgz/.tar/.zip 到 destDir。带路径穿越（zip-slip）防护。
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

func safeJoin(destDir, name string) (string, error) {
	// 显式拒绝包含 .. 的条目，而不是静默归一化（更利于发现恶意构造的发布包）
	cleaned := filepath.Clean(filepath.FromSlash(name))
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) || strings.HasPrefix(cleaned, string(os.PathSeparator)) {
		return "", fmt.Errorf("archive entry escapes destination dir: %s", name)
	}
	target := filepath.Join(destDir, cleaned)
	if target == filepath.Clean(destDir) || !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) {
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
		err = writeMode(rc, target, f.Mode())
		rc.Close()
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
		if err == io.EOF {
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
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			mode := os.FileMode(hdr.Mode)
			if mode.Perm() == 0 {
				mode = 0644
			}
			if err := writeMode(tr, target, mode); err != nil {
				return err
			}
		case tar.TypeSymlink:
			_ = os.Remove(target)
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				// 符号链接失败不致命（如 Windows 无权限），跳过
				continue
			}
		default:
			// 跳过其它类型（设备文件等）
		}
	}
}

func writeMode(r io.Reader, target string, mode os.FileMode) error {
	tmp := target + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, target)
}
