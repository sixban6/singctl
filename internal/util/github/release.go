package github

import (
	"encoding/json"
	"fmt"
	"net/http"
	"singctl/internal/util/netinfo"
	"strings"
)

// Release 是 GitHub Release API 的 JSON 映射。
type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset 是 GitHub Release 中的单个下载资源。
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// ReleaseFetcher 提供统一的 GitHub Release 获取接口。
type ReleaseFetcher struct {
	Mirror string       // 可选 mirror URL（如 "https://ghfast.top"）
	Client *http.Client // 可注入，默认 http.DefaultClient
}

// NewReleaseFetcher 创建新实例。
// mirror 为空或 "https://github.com" 表示不使用镜像。
// client 为 nil 时使用 http.DefaultClient。
func NewReleaseFetcher(mirror string, client *http.Client) *ReleaseFetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return &ReleaseFetcher{Mirror: mirror, Client: client}
}

// FetchLatestTag 获取指定 repo 的最新稳定 Release tag（去掉 v 前缀）。
// repo 格式: "owner/name"，例如 "SagerNet/sing-box"。
// 使用 /releases/latest 端点，仅返回稳定版（排除 pre-release）。
func (f *ReleaseFetcher) FetchLatestTag(repo string) (string, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	apiURL = f.applyMirror(apiURL)

	resp, err := f.Client.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned status: %s", resp.Status)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("decode release: %w", err)
	}
	return strings.TrimPrefix(rel.TagName, "v"), nil
}

// FindAssetURL 遍历 releases 列表，找到第一个 filter 匹配的 Asset 下载地址。
// 适用于 GUI/SFM 等需要跨 pre-release 搜索资源的场景。
func (f *ReleaseFetcher) FindAssetURL(repo string, filter func(name string) bool) (string, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=10", repo)
	apiURL = f.applyMirror(apiURL)

	resp, err := f.Client.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned status: %s", resp.Status)
	}

	var releases []Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", fmt.Errorf("decode releases: %w", err)
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

// FetchLatestTagFromURL 使用完整 URL 获取最新 tag（测试辅助方法）。
func (f *ReleaseFetcher) FetchLatestTagFromURL(fullURL string) (string, error) {
	resp, err := f.Client.Get(fullURL)
	if err != nil {
		return "", fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned status: %s", resp.Status)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("decode release: %w", err)
	}
	return strings.TrimPrefix(rel.TagName, "v"), nil
}

// FindAssetURLFromURL 使用完整 URL 查找资产（测试辅助方法）。
func (f *ReleaseFetcher) FindAssetURLFromURL(fullURL string, filter func(name string) bool) (string, error) {
	resp, err := f.Client.Get(fullURL)
	if err != nil {
		return "", fmt.Errorf("fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned status: %s", resp.Status)
	}

	var releases []Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", fmt.Errorf("decode releases: %w", err)
	}

	for _, rel := range releases {
		for _, asset := range rel.Assets {
			if filter(asset.Name) {
				return asset.BrowserDownloadURL, nil
			}
		}
	}
	return "", fmt.Errorf("no matching asset found")
}

// applyMirror 统一 Mirror 处理逻辑。
func (f *ReleaseFetcher) applyMirror(apiURL string) string {
	if f.Mirror == "" || f.Mirror == "https://github.com" {
		return apiURL
	}
	return netinfo.GetReachableURL(apiURL, f.Mirror)
}
