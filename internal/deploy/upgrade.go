package deploy

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/singbox"
	"singctl/internal/updater"
	"singctl/internal/util/github"
)

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
func isNewerVersion(localVer, remoteVer string) bool {
	l := cleanVersion(localVer)
	r := cleanVersion(remoteVer)
	if l == "" || r == "" {
		return false
	}
	if l == r {
		return false
	}

	lParts := strings.Split(l, ".")
	rParts := strings.Split(r, ".")
	maxLen := len(lParts)
	if len(rParts) > maxLen {
		maxLen = len(rParts)
	}

	for i := 0; i < maxLen; i++ {
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

// CheckComponentUpdate inspects if a component has a newer version available upstream.
func CheckComponentUpdate(target string, cfg *config.Config) (*CheckUpdateResult, error) {
	fetcher := github.NewReleaseFetcher(getMirrorURL(cfg), ReleaseClient)

	switch strings.ToLower(target) {
	case "singbox", "sb", "sing-box":
		curr := GetInstalledSingBoxVersion()
		tag, err := fetcher.FetchLatestTag("SagerNet/sing-box")
		latest := cleanVersion(tag)
		if err != nil || latest == "" {
			latest = curr
		}
		hasUp := isNewerVersion(curr, latest)
		msg := fmt.Sprintf("sing-box 已是最新版本 (v%s)", curr)
		if hasUp {
			msg = fmt.Sprintf("发现 sing-box 新版本: v%s (当前: v%s)", latest, curr)
		}
		return &CheckUpdateResult{
			Component:      "singbox",
			DisplayName:    "sing-box 代理核心",
			CurrentVersion: curr,
			LatestVersion:  latest,
			HasUpdate:      hasUp,
			Message:        msg,
		}, nil

	case "caddy":
		curr := GetInstalledCaddyVersion()
		tag, err := fetcher.FetchLatestTag("caddyserver/caddy")
		latest := cleanVersion(tag)
		if err != nil || latest == "" {
			latest = curr
		}
		hasUp := isNewerVersion(curr, latest)
		msg := fmt.Sprintf("Caddy 已是最新版本 (v%s)", curr)
		if hasUp {
			msg = fmt.Sprintf("发现 Caddy 新版本: v%s (当前: v%s)", latest, curr)
		}
		return &CheckUpdateResult{
			Component:      "caddy",
			DisplayName:    "Caddy 网关",
			CurrentVersion: curr,
			LatestVersion:  latest,
			HasUpdate:      hasUp,
			Message:        msg,
		}, nil

	case "substore", "ss", "sub-store", "subhub":
		curr := GetInstalledSubstoreVersion()
		tag, err := fetcher.FetchLatestTag("sixban6/singctl")
		latest := cleanVersion(tag)
		if err != nil || latest == "" {
			latest = curr
		}
		hasUp := isNewerVersion(curr, latest)
		msg := fmt.Sprintf("SubHub 订阅引擎已是最新版本 (v%s)", curr)
		if hasUp {
			msg = fmt.Sprintf("发现 SubHub 订阅引擎新版本: v%s (当前: v%s)", latest, curr)
		}
		return &CheckUpdateResult{
			Component:      "substore",
			DisplayName:    "SubHub 订阅引擎",
			CurrentVersion: curr,
			LatestVersion:  latest,
			HasUpdate:      hasUp,
			Message:        msg,
		}, nil

	case "warp", "wireproxy":
		curr := GetInstalledWarpVersion()
		tag, err := fetcher.FetchLatestTag("windtf/wireproxy")
		latest := cleanVersion(tag)
		if err != nil || latest == "" {
			latest = curr
		}
		hasUp := isNewerVersion(curr, latest)
		msg := fmt.Sprintf("WARP (wireproxy) 已是最新版本 (v%s)", curr)
		if hasUp {
			msg = fmt.Sprintf("发现 WARP (wireproxy) 新版本: v%s (当前: v%s)", latest, curr)
		}
		return &CheckUpdateResult{
			Component:      "warp",
			DisplayName:    "WARP 出口",
			CurrentVersion: curr,
			LatestVersion:  latest,
			HasUpdate:      hasUp,
			Message:        msg,
		}, nil

	default:
		return nil, fmt.Errorf("未知的服务组件: %s", target)
	}
}

// UpgradeSingbox updates sing-box to the latest version and restarts its service.
func UpgradeSingbox(cfg *config.Config) (*UpgradeResult, error) {
	oldVer := GetInstalledSingBoxVersion()
	logger.Info("Starting sing-box core upgrade (current: %s)...", oldVer)

	fetcher := github.NewReleaseFetcher(getMirrorURL(cfg), ReleaseClient)
	latestTag, _ := fetcher.FetchLatestTag("SagerNet/sing-box")
	latest := cleanVersion(latestTag)
	if latest != "" && !isNewerVersion(oldVer, latest) {
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

	_ = runCmd("systemctl", "restart", "sing-box")
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

// UpgradeCaddy updates Caddy (with Cloudflare DNS & layer4) and restarts the service.
func UpgradeCaddy(cfg *config.Config) (*UpgradeResult, error) {
	oldVer := GetInstalledCaddyVersion()
	logger.Info("Starting Caddy gateway upgrade (current: %s)...", oldVer)

	fetcher := github.NewReleaseFetcher(getMirrorURL(cfg), ReleaseClient)
	latestTag, _ := fetcher.FetchLatestTag("caddyserver/caddy")
	latest := cleanVersion(latestTag)
	if latest != "" && !isNewerVersion(oldVer, latest) {
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
	downloadURL := fmt.Sprintf("https://github.com/sixban6/singctl/releases/latest/download/%s", caddyTar)
	if cfg != nil && cfg.GitHub.MirrorURL != "" {
		downloadURL = fmt.Sprintf("%s/%s", strings.TrimRight(cfg.GitHub.MirrorURL, "/"), downloadURL)
	}

	tmpDir, err := os.MkdirTemp("", "caddy-upgrade-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, caddyTar)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s failed with status %d", downloadURL, resp.StatusCode)
	}

	outFile, err := os.Create(archivePath)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(outFile, resp.Body); err != nil {
		outFile.Close()
		return nil, err
	}
	outFile.Close()

	// Extract caddy binary from archive
	extractedCaddy := filepath.Join(tmpDir, "caddy")
	if err := extractFileFromTarGz(archivePath, "caddy", extractedCaddy); err != nil {
		return nil, fmt.Errorf("failed to extract caddy: %w", err)
	}

	_ = runCmd("systemctl", "stop", "caddy")
	_ = runCmd("install", "-m", "0755", extractedCaddy, "/usr/bin/caddy")
	if _, err := os.Stat("/usr/local/bin/caddy"); err == nil {
		_ = runCmd("install", "-m", "0755", extractedCaddy, "/usr/local/bin/caddy")
	}
	_ = runCmd("apt-mark", "hold", "caddy")
	_ = runCmd("systemctl", "restart", "caddy")

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

// UpgradeSubstore upgrades the SingCtl binary if a newer release is available,
// cleans up any legacy Docker sub-store container, and restarts singctl-sub.service.
func UpgradeSubstore(cfg *config.Config) (*UpgradeResult, error) {
	oldVer := GetInstalledSubstoreVersion()
	logger.Info("Starting native SubHub subscription engine upgrade (current: %s)...", oldVer)

	fetcher := github.NewReleaseFetcher(getMirrorURL(cfg), ReleaseClient)
	latestTag, _ := fetcher.FetchLatestTag("sixban6/singctl")
	latest := cleanVersion(latestTag)
	if latest != "" && isNewerVersion(oldVer, latest) {
		up := updater.New(getMirrorURL(cfg), "")
		if err := up.UpdateSelf("/etc/singctl/singctl.yaml", oldVer); err != nil {
			logger.Warn("singctl self-update warning during SubHub upgrade: %v", err)
		}
	}

	sbt := NewSubstore(cfg, "")
	if err := sbt.DeploySubstore(); err != nil {
		return nil, fmt.Errorf("subhub redeploy failed: %w", err)
	}

	newVer := GetInstalledSubstoreVersion()
	updated := oldVer != newVer
	msg := fmt.Sprintf("SubHub 原生订阅引擎已就绪 (当前版本: v%s)", newVer)
	if updated {
		msg = fmt.Sprintf("SubHub 原生订阅引擎已成功更新 (v%s -> v%s)", oldVer, newVer)
	}
	return &UpgradeResult{
		Component:   "substore",
		DisplayName: "SubHub 订阅引擎",
		OldVersion:  oldVer,
		NewVersion:  newVer,
		Message:     msg,
		Updated:     updated,
	}, nil
}

// UpgradeWarp updates wireproxy to latest version and restarts the service.
func UpgradeWarp(cfg *config.Config) (*UpgradeResult, error) {
	oldVer := GetInstalledWarpVersion()
	logger.Info("Starting WARP (wireproxy) upgrade (current: %s)...", oldVer)

	arch := runtime.GOARCH
	wireproxyTar := fmt.Sprintf("wireproxy_linux_%s.tar.gz", arch)
	fetcher := github.NewReleaseFetcher(getMirrorURL(cfg), ReleaseClient)
	latestTag, err := fetcher.FetchLatestTag("windtf/wireproxy")
	if err != nil {
		latestTag = "latest"
	}
	latest := cleanVersion(latestTag)
	if latest != "" && latest != "latest" && !isNewerVersion(oldVer, latest) {
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
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s failed with status %d", downloadURL, resp.StatusCode)
	}

	outFile, err := os.Create(archivePath)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(outFile, resp.Body); err != nil {
		outFile.Close()
		return nil, err
	}
	outFile.Close()

	extractedWP := filepath.Join(tmpDir, "wireproxy")
	if err := extractFileFromTarGz(archivePath, "wireproxy", extractedWP); err != nil {
		return nil, fmt.Errorf("failed to extract wireproxy: %w", err)
	}

	_ = runCmd("systemctl", "stop", "wireproxy")
	targetDest := "/usr/local/bin/wireproxy"
	if _, err := os.Stat("/usr/bin/wireproxy"); err == nil {
		targetDest = "/usr/bin/wireproxy"
	}
	_ = runCmd("install", "-m", "0755", extractedWP, targetDest)
	_ = runCmd("systemctl", "restart", "wireproxy")

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

// UpgradeComponent coordinates the upgrade of the specified service or all services.
func UpgradeComponent(target string, cfg *config.Config) ([]*UpgradeResult, error) {
	switch strings.ToLower(target) {
	case "singbox", "sb", "sing-box":
		res, err := UpgradeSingbox(cfg)
		if err != nil {
			return nil, err
		}
		return []*UpgradeResult{res}, nil

	case "caddy":
		res, err := UpgradeCaddy(cfg)
		if err != nil {
			return nil, err
		}
		return []*UpgradeResult{res}, nil

	case "substore", "ss", "sub-store", "subhub":
		res, err := UpgradeSubstore(cfg)
		if err != nil {
			return nil, err
		}
		return []*UpgradeResult{res}, nil

	case "warp", "wireproxy":
		res, err := UpgradeWarp(cfg)
		if err != nil {
			return nil, err
		}
		return []*UpgradeResult{res}, nil

	case "all":
		var results []*UpgradeResult
		var errs []string

		if res, err := UpgradeSingbox(cfg); err != nil {
			errs = append(errs, fmt.Sprintf("sing-box: %v", err))
		} else {
			results = append(results, res)
		}

		if res, err := UpgradeCaddy(cfg); err != nil {
			errs = append(errs, fmt.Sprintf("Caddy: %v", err))
		} else {
			results = append(results, res)
		}

		if res, err := UpgradeSubstore(cfg); err != nil {
			errs = append(errs, fmt.Sprintf("Sub-Store: %v", err))
		} else {
			results = append(results, res)
		}

		if res, err := UpgradeWarp(cfg); err != nil {
			errs = append(errs, fmt.Sprintf("WARP: %v", err))
		} else {
			results = append(results, res)
		}

		if len(errs) > 0 && len(results) == 0 {
			return nil, fmt.Errorf("全量更新失败: %s", strings.Join(errs, "; "))
		}
		return results, nil

	default:
		return nil, fmt.Errorf("未知的服务组件: %s (支持: singbox, caddy, substore, warp, all)", target)
	}
}

func extractFileFromTarGz(tarGzPath, targetFileName, destPath string) error {
	f, err := os.Open(tarGzPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		baseName := filepath.Base(hdr.Name)
		if baseName == targetFileName && (hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA) {
			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return err
			}
			defer out.Close()
			_, err = io.Copy(out, tr)
			return err
		}
	}
	return fmt.Errorf("file %s not found in %s", targetFileName, tarGzPath)
}
