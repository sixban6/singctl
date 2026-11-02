package deploy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/singbox"
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

// UpgradeSingbox updates sing-box to the latest version and restarts its service.
func UpgradeSingbox(cfg *config.Config) (*UpgradeResult, error) {
	oldVer := GetInstalledSingBoxVersion()
	logger.Info("Starting sing-box core upgrade (current: %s)...", oldVer)

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

// UpgradeSubstore pulls the latest xream/sub-store docker image and recreates the container.
func UpgradeSubstore(cfg *config.Config) (*UpgradeResult, error) {
	oldVer := GetInstalledSubstoreVersion()
	logger.Info("Starting Sub-Store upgrade (current: %s)...", oldVer)

	logger.Info("Pulling latest xream/sub-store docker image...")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "pull", "xream/sub-store:latest")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("docker pull failed: %v (output: %s)", err, string(out))
	}

	sbt := NewSubstore(cfg, "")
	if err := sbt.DeploySubstore(); err != nil {
		return nil, fmt.Errorf("sub-store redeploy failed: %w", err)
	}

	newVer := GetInstalledSubstoreVersion()
	return &UpgradeResult{
		Component:   "substore",
		DisplayName: "Sub-Store 订阅中心",
		OldVersion:  oldVer,
		NewVersion:  newVer,
		Message:     fmt.Sprintf("Sub-Store 容器已成功更新至最新镜像 (%s)", newVer),
		Updated:     true,
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

	case "substore", "ss", "sub-store":
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
