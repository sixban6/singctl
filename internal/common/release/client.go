// 文件职责：提供信任锚直连 GitHub Release API 元数据查询、镜像加速资产下载及官方 SHA256 强制完整性校验。
package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// Asset 描述 GitHub Release 中的单个发布资产。
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	ID                 int64  `json:"id"`
	Size               int64  `json:"size"`
	Digest             string `json:"digest"`
}

// Info 描述一次 GitHub Release 元数据查询结果。
type Info struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Client 为带信任锚保护的 GitHub Release 客户端：元数据与校验和永远直连 APIBase，仅大体积资产允许经 Mirror 加速并强制校验。
type Client struct {
	APIBase     string
	DLBase      string
	Mirror      string
	HTTP        *http.Client
	DirectFirst bool
	SkipSHA256  bool
}

// NewClient 创建默认 Release 客户端（mirror 为空或 "https://github.com" 表示仅走直连）。
func NewClient(mirror string) *Client {
	mirror = strings.TrimSpace(mirror)
	if mirror == "https://github.com" || mirror == "https://github.com/" {
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

// StatusError 表示直连 GitHub Release API 返回了非 200 状态码。
type StatusError struct {
	StatusCode int
	Status     string
	URL        string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("github api returned status: %s (%s)", e.Status, e.URL)
}

// IsNotFound 判断错误是否为目标 Release 或 Tag 不存在（HTTP 404）。
func IsNotFound(err error) bool {
	if se, ok := errors.AsType[*StatusError](err); ok {
		return se.StatusCode == http.StatusNotFound
	}
	return false
}

// validateRepoSlug 校验 GitHub owner/repo 坐标格式，拦截空值、路径穿越与查询串注入。
func validateRepoSlug(repo string) (string, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return "", errors.New("repo must not be empty")
	}
	if strings.Contains(repo, "..") || strings.ContainsAny(repo, "\\?# \t\r\n") {
		return "", fmt.Errorf("invalid repo slug: %q", repo)
	}
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("repo must be in owner/name format: %q", repo)
	}
	return repo, nil
}

// validateTagSlug 校验 GitHub Release Tag 名称，拦截路径穿越、分隔符与查询串注入。
func validateTagSlug(tag string) (string, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" || tag == "." || strings.Contains(tag, "..") || strings.ContainsAny(tag, "/\\?# \t\r\n") {
		return "", fmt.Errorf("invalid release tag: %q", tag)
	}
	return tag, nil
}

// FetchLatest 直连获取最新稳定版 Release 元数据（绝不经镜像）。
func (c *Client) FetchLatest(ctx context.Context, repo string) (*Info, error) {
	cleanRepo, err := validateRepoSlug(repo)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/repos/%s/releases/latest", c.apiBase(), cleanRepo)
	return c.fetchInfo(ctx, url)
}

// FetchLatestTag 直连获取最新稳定版 Tag（剥离前导 "v"）。
func (c *Client) FetchLatestTag(ctx context.Context, repo string) (string, error) {
	info, err := c.FetchLatest(ctx, repo)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(strings.TrimSpace(info.TagName), "v"), nil
}

// FetchTag 直连获取指定 Tag（含 prerelease）的 Release 元数据（绝不经镜像）。
func (c *Client) FetchTag(ctx context.Context, repo, tag string) (*Info, error) {
	cleanRepo, err := validateRepoSlug(repo)
	if err != nil {
		return nil, err
	}
	cleanTag, err := validateTagSlug(tag)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/repos/%s/releases/tags/%s", c.apiBase(), cleanRepo, cleanTag)
	return c.fetchInfo(ctx, url)
}

// FetchReleases 直连获取最近 perPage 条 Release 列表（含 pre-release，绝不经镜像）。
func (c *Client) FetchReleases(ctx context.Context, repo string, perPage int) ([]Info, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return nil, errors.New("repo must not be empty")
	}
	if perPage <= 0 {
		perPage = 10
	}
	url := fmt.Sprintf("%s/repos/%s/releases?per_page=%d", c.apiBase(), repo, perPage)
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch releases list (direct, no mirror): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{StatusCode: resp.StatusCode, Status: resp.Status, URL: url}
	}
	var list []Info
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("decode releases list: %w", err)
	}
	return list, nil
}

// FindAssetURL 跨最近多个 Release 搜索第一个匹配 filter 的资产直连 URL（适用于跨 pre-release 查找 GUI 安装包）。
func (c *Client) FindAssetURL(ctx context.Context, repo string, filter func(name string) bool) (string, error) {
	if filter == nil {
		return "", errors.New("asset filter must not be nil")
	}
	releases, err := c.FetchReleases(ctx, repo, 10)
	if err != nil {
		return "", err
	}
	for _, rel := range releases {
		for _, asset := range rel.Assets {
			if filter(asset.Name) {
				return asset.BrowserDownloadURL, nil
			}
		}
	}
	return "", fmt.Errorf("no matching asset found in %s", repo)
}

func (c *Client) fetchInfo(ctx context.Context, url string) (*Info, error) {
	if ctx == nil {
		ctx = context.Background()
	}
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
		return nil, &StatusError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			URL:        url,
		}
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

// DownloadResult 描述一次资产下载与完整性校验结果。
type DownloadResult struct {
	Path           string
	ViaMirror      bool
	SHA256Verified bool
	SizeChecked    bool
}

// Download 下载资产至 destDir/<asset.Name> 并强制比对官方元数据文件大小与 SHA256 digest（失败自动切换直连/镜像）。
func (c *Client) Download(ctx context.Context, asset Asset, destDir string) (*DownloadResult, error) {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, err
	}
	dest := filepath.Join(destDir, asset.Name)

	directURL := asset.BrowserDownloadURL
	if directURL == "" {
		directURL = fmt.Sprintf("%s/%s", c.dlBase(), asset.Name)
	}
	digestHex, hasDigest := parseDigest(asset.Digest)

	type candidate struct {
		url    string
		mirror bool
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
				_ = os.Remove(dest)
				lastErr = fmt.Errorf("size mismatch for %s: got %d bytes, official metadata says %d (downloaded from %s)",
					asset.Name, info.Size(), asset.Size, cand.url)
				continue
			}
		}
		if hasDigest && !c.SkipSHA256 {
			if err := VerifySHA256(dest, digestHex); err != nil {
				_ = os.Remove(dest)
				lastErr = fmt.Errorf("sha256 mismatch for %s against official digest (downloaded from %s): %w",
					asset.Name, cand.url, err)
				continue
			}
			return &DownloadResult{Path: dest, ViaMirror: cand.mirror, SHA256Verified: true, SizeChecked: asset.Size > 0}, nil
		}
		return &DownloadResult{Path: dest, ViaMirror: cand.mirror, SHA256Verified: false, SizeChecked: asset.Size > 0}, nil
	}
	return nil, fmt.Errorf("all download attempts failed: %w", lastErr)
}

func parseDigest(d string) (string, bool) {
	d = strings.ToLower(strings.TrimSpace(d))
	algo, sum, found := strings.Cut(d, ":")
	if !found || algo != "sha256" || sum == "" {
		return "", false
	}
	return sum, true
}

func (c *Client) mirrorURL(u string) string {
	return strings.TrimSuffix(c.Mirror, "/") + "/" + u
}

func (c *Client) downloadTo(ctx context.Context, url, dest string) error {
	if ctx == nil {
		ctx = context.Background()
	}
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
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("status: %s", resp.Status)
			continue
		}
		tmp, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+".part-*")
		if err != nil {
			_ = resp.Body.Close()
			return err
		}
		tmpName := tmp.Name()
		_, copyErr := io.Copy(tmp, resp.Body)
		closeErr := tmp.Close()
		_ = resp.Body.Close()
		if copyErr != nil {
			_ = os.Remove(tmpName)
			lastErr = copyErr
			continue
		}
		if closeErr != nil {
			_ = os.Remove(tmpName)
			lastErr = closeErr
			continue
		}
		if err := os.Rename(tmpName, dest); err != nil {
			_ = os.Remove(tmpName)
			return err
		}
		return nil
	}
	return lastErr
}

// FetchChecksums 直连获取并解析 checksums.txt / SHA256SUMS 校验表（绝不走镜像）。
func (c *Client) FetchChecksums(ctx context.Context, repo, tag string, asset *Asset, info *Info) (map[string]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
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

	if asset.ID > 0 {
		url := fmt.Sprintf("%s/repos/%s/releases/assets/%d", c.apiBase(), repo, asset.ID)
		if req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil); err == nil {
			req.Header.Set("Accept", "application/octet-stream")
			if resp, err := c.httpClient().Do(req); err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					if data, err := io.ReadAll(resp.Body); err == nil {
						return ParseChecksums(data), nil
					}
				}
			}
		}
	}

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

// ParseChecksums 解析 sha256sum 风格内容（兼容二进制模式 * 前缀与带空格文件名）。
func ParseChecksums(data []byte) map[string]string {
	sums := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sum := strings.ToLower(strings.TrimPrefix(fields[0], "*"))
		name := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
		name = strings.TrimPrefix(name, "*")
		if name != "" {
			sums[name] = sum
		}
	}
	return sums
}

// VerifySHA256 计算本地文件的 SHA256 并与期望十六进制摘要比对。
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
