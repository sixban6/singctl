package deploy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/common/release"
	"singctl/internal/component"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

func newDeployReleaseClient(cfg *config.Config) *release.Client {
	c := release.NewClient(getMirrorURL(cfg))
	if ReleaseClient != nil {
		c.HTTP = ReleaseClient
	}
	return c
}

// UpgradeResult represents the outcome of a component upgrade.
type UpgradeResult struct {
	Component   string `json:"component"`
	DisplayName string `json:"displayName"`
	OldVersion  string `json:"oldVersion"`
	NewVersion  string `json:"newVersion"`
	Message     string `json:"message"`
	Updated     bool   `json:"updated"`
}

// CheckUpdateResult represents the inspection of latest remote version vs local version.
type CheckUpdateResult struct {
	Component      string `json:"component"`
	DisplayName    string `json:"displayName"`
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	HasUpdate      bool   `json:"hasUpdate"`
	Message        string `json:"message"`
}

// cleanVersion normalizes version string by removing 'v' prefix and trimming whitespace.
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	return v
}

// isNewerVersion returns true if remoteVer is strictly greater than localVer.
func IsNewerVersion(localVer, remoteVer string) bool {
	l := cleanVersion(localVer)
	r := cleanVersion(remoteVer)
	if l == "" || r == "" || l == r {
		return false
	}

	lParts := strings.Split(l, ".")
	rParts := strings.Split(r, ".")
	maxLen := max(len(lParts), len(rParts))

	for i := range maxLen {
		var lNum, rNum int
		if i < len(lParts) {
			var sub string
			for _, ch := range lParts[i] {
				if ch >= '0' && ch <= '9' {
					sub += string(ch)
				} else {
					break
				}
			}
			if sub != "" {
				fmt.Sscanf(sub, "%d", &lNum)
			}
		}
		if i < len(rParts) {
			var sub string
			for _, ch := range rParts[i] {
				if ch >= '0' && ch <= '9' {
					sub += string(ch)
				} else {
					break
				}
			}
			if sub != "" {
				fmt.Sscanf(sub, "%d", &rNum)
			}
		}

		if rNum > lNum {
			return true
		} else if rNum < lNum {
			return false
		}
	}

	return false
}

func upgradeResultToInfo(r *UpgradeResult) *component.UpgradeInfo {
	if r == nil {
		return nil
	}
	return &component.UpgradeInfo{
		Component:   r.Component,
		DisplayName: r.DisplayName,
		OldVersion:  r.OldVersion,
		NewVersion:  r.NewVersion,
		Message:     r.Message,
		Updated:     r.Updated,
	}
}

func infoToUpgradeResult(info *component.UpgradeInfo) *UpgradeResult {
	if info == nil {
		return nil
	}
	return &UpgradeResult{
		Component:   info.Component,
		DisplayName: info.DisplayName,
		OldVersion:  info.OldVersion,
		NewVersion:  info.NewVersion,
		Message:     info.Message,
		Updated:     info.Updated,
	}
}

// CheckComponentUpdate inspects if an external component (singbox, caddy, warp, singctl) has a newer version upstream.
func CheckComponentUpdate(target string, cfg *config.Config) (*CheckUpdateResult, error) {
	norm := strings.ToLower(strings.TrimSpace(target))
	if norm == "singctl" || norm == "subhub" || norm == "substore" {
		fetcher := newDeployReleaseClient(cfg)
		curr := cleanVersion(GetInstalledSubhubVersion())
		tag, err := fetcher.FetchLatestTag(context.Background(), constant.GitHubRepo)
		latest := cleanVersion(tag)
		if err != nil || latest == "" {
			latest = curr
		}
		hasUp := IsNewerVersion(curr, latest)
		msg := fmt.Sprintf("SingCtl 主程序与 SubHub 已是最新版本 (v%s)", curr)
		if hasUp {
			msg = fmt.Sprintf("发现 SingCtl 新版本: v%s (当前: v%s)", latest, curr)
		}
		return &CheckUpdateResult{
			Component:      "singctl",
			DisplayName:    "SingCtl 主程序 (WebUI + SubHub)",
			CurrentVersion: curr,
			LatestVersion:  latest,
			HasUpdate:      hasUp,
			Message:        msg,
		}, nil
	}

	comp, err := ServerRegistry().Resolve(target)
	if err == nil {
		if up, ok := comp.(component.Upgradable); ok {
			info, checkErr := up.CheckUpdate(cfg)
			if checkErr != nil {
				return nil, checkErr
			}
			return &CheckUpdateResult{
				Component:      info.Component,
				DisplayName:    info.DisplayName,
				CurrentVersion: info.CurrentVersion,
				LatestVersion:  info.LatestVersion,
				HasUpdate:      info.HasUpdate,
				Message:        info.Message,
			}, nil
		}
	}

	return nil, fmt.Errorf("未知的服务组件: %s (支持: singctl, singbox, caddy, warp)", target)
}

// UpgradeSingbox updates sing-box to the latest version and restarts its service.
func UpgradeSingbox(cfg *config.Config) (*UpgradeResult, error) {
	oldVer := GetInstalledSingBoxVersion()
	logger.Info("Starting sing-box core upgrade (current: %s)...", oldVer)

	fetcher := newDeployReleaseClient(cfg)
	latestTag, _ := fetcher.FetchLatestTag(context.Background(), "SagerNet/sing-box")
	latest := cleanVersion(latestTag)
	if latest != "" && !IsNewerVersion(oldVer, latest) {
		logger.Success("sing-box 已是最新版本 (%s)，无需重复更新", oldVer)
		return &UpgradeResult{
			Component:   "singbox",
			DisplayName: "sing-box 代理核心",
			OldVersion:  oldVer,
			NewVersion:  oldVer,
			Message:     fmt.Sprintf("sing-box 当前已是最新版本 (v%s)，无需重复更新", oldVer),
			Updated:     false,
		}, nil
	}

	sb := singbox.New(cfg)
	if err := sb.Update(); err != nil {
		logger.Warn("sb.Update encountered issue, trying direct Install: %v", err)
		if iErr := sb.Install(); iErr != nil {
			return nil, fmt.Errorf("sing-box upgrade failed: %w", iErr)
		}
	}

	_ = serviceMgr().Restart(context.Background(), "sing-box")
	newVer := GetInstalledSingBoxVersion()

	return &UpgradeResult{
		Component:   "singbox",
		DisplayName: "sing-box 代理核心",
		OldVersion:  oldVer,
		NewVersion:  newVer,
		Message:     fmt.Sprintf("sing-box 已成功平滑更新 (当前版本: %s)", newVer),
		Updated:     true,
	}, nil
}

// UpgradeCaddy atomically replaces Caddy (with Cloudflare DNS & layer4) and restarts the service.
func UpgradeCaddy(cfg *config.Config) (*UpgradeResult, error) {
	oldVer := GetInstalledCaddyVersion()
	logger.Info("Starting Caddy gateway upgrade (current: %s)...", oldVer)

	fetcher := newDeployReleaseClient(cfg)
	latestTag, _ := fetcher.FetchLatestTag(context.Background(), "caddyserver/caddy")
	latest := cleanVersion(latestTag)
	if latest != "" && !IsNewerVersion(oldVer, latest) {
		logger.Success("Caddy 已是最新版本 (%s)，无需重复更新", oldVer)
		return &UpgradeResult{
			Component:   "caddy",
			DisplayName: "Caddy 网关",
			OldVersion:  oldVer,
			NewVersion:  oldVer,
			Message:     fmt.Sprintf("Caddy 当前已是最新版本 (v%s)，无需重复更新", oldVer),
			Updated:     false,
		}, nil
	}

	arch := runtime.GOARCH
	caddyTar := fmt.Sprintf("caddy-custom-linux-%s.tar.gz", arch)
	downloadURL := fmt.Sprintf("%s/releases/latest/download/%s", constant.GitHubRepoURL, caddyTar)
	if cfg != nil && cfg.GitHub.MirrorURL != "" {
		downloadURL = fmt.Sprintf("%s/%s", strings.TrimRight(cfg.GitHub.MirrorURL, "/"), downloadURL)
	}

	tmpDir, err := os.MkdirTemp("", "caddy-upgrade-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, caddyTar)
	if err := downloadToFile(downloadURL, archivePath); err != nil {
		return nil, err
	}

	extractedCaddy := filepath.Join(tmpDir, "caddy")
	if err := release.ExtractBinary(archivePath, "caddy", extractedCaddy); err != nil {
		return nil, fmt.Errorf("failed to extract caddy: %w", err)
	}

	if err := fsx.SafeReplace("/usr/bin/caddy", extractedCaddy); err != nil {
		return nil, fmt.Errorf("failed to replace /usr/bin/caddy: %w", err)
	}
	if _, err := os.Stat("/usr/local/bin/caddy"); err == nil {
		_ = fsx.SafeReplace("/usr/local/bin/caddy", extractedCaddy)
	}
	DetachCaddyFromApt()
	_ = serviceMgr().Restart(context.Background(), "caddy")

	newVer := GetInstalledCaddyVersion()
	return &UpgradeResult{
		Component:   "caddy",
		DisplayName: "Caddy 网关",
		OldVersion:  oldVer,
		NewVersion:  newVer,
		Message:     fmt.Sprintf("Caddy 已成功平滑更新 (当前版本: %s)", newVer),
		Updated:     true,
	}, nil
}

// UpgradeWarp atomically replaces wireproxy with the latest version and restarts the service.
func UpgradeWarp(cfg *config.Config) (*UpgradeResult, error) {
	_, _ = PurgeLegacyFscarmenWarp()

	oldVer := GetInstalledWarpVersion()
	logger.Info("Starting WARP (wireproxy) upgrade (current: %s)...", oldVer)

	arch := runtime.GOARCH
	wireproxyTar := fmt.Sprintf("wireproxy_linux_%s.tar.gz", arch)
	fetcher := newDeployReleaseClient(cfg)
	latestTag, err := fetcher.FetchLatestTag(context.Background(), "windtf/wireproxy")
	if err != nil {
		latestTag = "latest"
	}
	latest := cleanVersion(latestTag)
	if IsWindtfWireproxyBinary(DefaultWireproxyBin) && latest != "" && latest != "latest" && !IsNewerVersion(oldVer, latest) {
		logger.Success("WARP (wireproxy) 已是最新版本 (%s)，无需重复更新", oldVer)
		return &UpgradeResult{
			Component:   "warp",
			DisplayName: "WARP (wireproxy)",
			OldVersion:  oldVer,
			NewVersion:  oldVer,
			Message:     fmt.Sprintf("WARP (wireproxy) 当前已是最新版本 (v%s)，无需重复更新", oldVer),
			Updated:     false,
		}, nil
	}

	downloadURL := fmt.Sprintf("https://github.com/windtf/wireproxy/releases/download/%s/%s", latestTag, wireproxyTar)
	if latestTag == "latest" {
		downloadURL = fmt.Sprintf("https://github.com/windtf/wireproxy/releases/latest/download/%s", wireproxyTar)
	}
	if cfg != nil && cfg.GitHub.MirrorURL != "" {
		downloadURL = fmt.Sprintf("%s/%s", strings.TrimRight(cfg.GitHub.MirrorURL, "/"), downloadURL)
	}

	tmpDir, err := os.MkdirTemp("", "wireproxy-upgrade-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, wireproxyTar)
	if err := downloadToFile(downloadURL, archivePath); err != nil {
		return nil, err
	}

	extractedWP := filepath.Join(tmpDir, "wireproxy")
	if err := release.ExtractBinary(archivePath, "wireproxy", extractedWP); err != nil {
		return nil, fmt.Errorf("failed to extract wireproxy: %w", err)
	}

	if err := fsx.SafeReplace(DefaultWireproxyBin, extractedWP); err != nil {
		return nil, fmt.Errorf("failed to replace %s: %w", DefaultWireproxyBin, err)
	}
	_ = serviceMgr().Restart(context.Background(), "wireproxy")

	newVer := GetInstalledWarpVersion()
	return &UpgradeResult{
		Component:   "warp",
		DisplayName: "WARP (wireproxy)",
		OldVersion:  oldVer,
		NewVersion:  newVer,
		Message:     fmt.Sprintf("WARP (wireproxy) 已成功平滑更新 (当前版本: %s)", newVer),
		Updated:     true,
	}, nil
}

// UpgradeComponent coordinates the upgrade of the specified external service or all registered upgradable services.
func UpgradeComponent(target string, cfg *config.Config) ([]*UpgradeResult, error) {
	if strings.EqualFold(strings.TrimSpace(target), "all") {
		var results []*UpgradeResult
		var errs []string
		for _, comp := range ServerRegistry().All() {
			up, ok := comp.(component.Upgradable)
			if !ok {
				continue
			}
			info, err := up.Upgrade(cfg)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", comp.DisplayName(), err))
			} else if info != nil {
				results = append(results, infoToUpgradeResult(info))
			}
		}
		if len(errs) > 0 && len(results) == 0 {
			return nil, fmt.Errorf("全量更新失败: %s", strings.Join(errs, "; "))
		}
		return results, nil
	}

	comp, err := ServerRegistry().Resolve(target)
	if err == nil {
		if up, ok := comp.(component.Upgradable); ok {
			info, upErr := up.Upgrade(cfg)
			if upErr != nil {
				return nil, upErr
			}
			return []*UpgradeResult{infoToUpgradeResult(info)}, nil
		}
	}
	return nil, fmt.Errorf("未知的服务组件: %s (支持: singbox, caddy, warp, all)", target)
}

func downloadToFile(url, destPath string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s failed with status %d", url, resp.StatusCode)
	}

	outFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer outFile.Close()
	_, err = io.Copy(outFile, resp.Body)
	return err
}
