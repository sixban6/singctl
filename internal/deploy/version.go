package deploy

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/singbox"
	"singctl/internal/util/github"
)

// ReleaseClient is an optional HTTP client used for fetching GitHub releases (useful for testing).
var ReleaseClient *http.Client

// ComponentVersionInfo holds the version and update status of a server component.
type ComponentVersionInfo struct {
	Name           string // Component identifier: singbox, caddy, substore, warp
	DisplayName    string // Human-readable name
	CurrentVersion string // Currently installed version (or status)
	LatestVersion  string // Latest available version
	HasUpdate      bool   // True if an update is available or component is not installed
	Installed      bool   // True if component is currently installed
	Error          error  // Any error encountered during check
}

// NormalizeVersion trims leading/trailing whitespace and removes any leading "v" prefix.
func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	return v
}

// ParseCaddyVersion extracts the version number from `caddy version` output.
func ParseCaddyVersion(raw string) (string, error) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", fmt.Errorf("unexpected caddy version output: %q", raw)
	}
	fields := strings.Fields(lines[0])
	if len(fields) == 0 {
		return "", fmt.Errorf("unexpected caddy version output: %q", raw)
	}
	for _, f := range fields {
		clean := strings.TrimPrefix(f, "v")
		if len(clean) > 0 && clean[0] >= '0' && clean[0] <= '9' && strings.Contains(clean, ".") {
			return clean, nil
		}
	}
	return strings.TrimPrefix(fields[0], "v"), nil
}

// ParseWireproxyVersion extracts the version number from `wireproxy --version` output.
func ParseWireproxyVersion(raw string) (string, error) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", fmt.Errorf("unexpected wireproxy version output: %q", raw)
	}
	fields := strings.Fields(lines[0])
	if len(fields) == 0 {
		return "", fmt.Errorf("unexpected wireproxy version output: %q", raw)
	}
	for i := len(fields) - 1; i >= 0; i-- {
		clean := strings.TrimPrefix(fields[i], "v")
		if len(clean) > 0 && clean[0] >= '0' && clean[0] <= '9' && strings.Contains(clean, ".") {
			return clean, nil
		}
	}
	return strings.TrimPrefix(fields[len(fields)-1], "v"), nil
}

func shortDigest(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func getMirrorURL(cfg *config.Config) string {
	if cfg != nil && cfg.GitHub.MirrorURL != "" {
		return cfg.GitHub.MirrorURL
	}
	return ""
}

// CheckSingBoxVersion checks the installed sing-box version against the latest GitHub release.
func CheckSingBoxVersion(cfg *config.Config) (*ComponentVersionInfo, error) {
	info := &ComponentVersionInfo{
		Name:        "singbox",
		DisplayName: "sing-box",
	}

	binPath := constant.SingBoxInstallDir
	if _, err := os.Stat(binPath); err != nil {
		if path, err := exec.LookPath("sing-box"); err == nil {
			binPath = path
		} else {
			binPath = ""
		}
	}

	if binPath != "" {
		out, err := exec.Command(binPath, "version").Output()
		if err == nil {
			ver, err := singbox.ParseSingBoxVersionOutput(string(out))
			if err == nil {
				info.Installed = true
				info.CurrentVersion = ver
			}
		}
	}

	if !info.Installed {
		info.CurrentVersion = "未安装"
	}

	fetcher := github.NewReleaseFetcher(getMirrorURL(cfg), ReleaseClient)
	latestTag, err := fetcher.FetchLatestTag("SagerNet/sing-box")
	if err != nil {
		info.Error = fmt.Errorf("fetch latest sing-box version failed: %w", err)
		info.LatestVersion = "unknown"
		if !info.Installed {
			info.HasUpdate = true
		}
		return info, info.Error
	}
	info.LatestVersion = latestTag

	if !info.Installed {
		info.HasUpdate = true
	} else {
		info.HasUpdate = (NormalizeVersion(info.CurrentVersion) != NormalizeVersion(info.LatestVersion))
	}

	return info, nil
}

// CheckCaddyVersion checks the installed Caddy version against the latest GitHub release.
func CheckCaddyVersion(cfg *config.Config) (*ComponentVersionInfo, error) {
	info := &ComponentVersionInfo{
		Name:        "caddy",
		DisplayName: "Caddy",
	}

	binPath := ""
	for _, p := range []string{"/usr/bin/caddy", "/usr/local/bin/caddy"} {
		if _, err := os.Stat(p); err == nil {
			binPath = p
			break
		}
	}
	if binPath == "" {
		if path, err := exec.LookPath("caddy"); err == nil {
			binPath = path
		}
	}

	if binPath != "" {
		out, err := exec.Command(binPath, "version").Output()
		if err == nil {
			ver, err := ParseCaddyVersion(string(out))
			if err == nil {
				info.Installed = true
				info.CurrentVersion = ver
			}
		}
	}

	if !info.Installed {
		info.CurrentVersion = "未安装"
	}

	fetcher := github.NewReleaseFetcher(getMirrorURL(cfg), ReleaseClient)
	latestTag, err := fetcher.FetchLatestTag("caddyserver/caddy")
	if err != nil {
		info.Error = fmt.Errorf("fetch latest caddy version failed: %w", err)
		info.LatestVersion = "unknown"
		if !info.Installed {
			info.HasUpdate = true
		}
		return info, info.Error
	}
	info.LatestVersion = latestTag

	if !info.Installed {
		info.HasUpdate = true
	} else {
		info.HasUpdate = (NormalizeVersion(info.CurrentVersion) != NormalizeVersion(info.LatestVersion))
	}

	return info, nil
}

// CheckWarpVersion checks the installed WARP (wireproxy) version against the latest GitHub release.
func CheckWarpVersion(cfg *config.Config) (*ComponentVersionInfo, error) {
	info := &ComponentVersionInfo{
		Name:        "warp",
		DisplayName: "WARP (wireproxy)",
	}

	binPath := ""
	for _, p := range []string{"/usr/local/bin/wireproxy", "/usr/bin/wireproxy"} {
		if _, err := os.Stat(p); err == nil {
			binPath = p
			break
		}
	}
	if binPath == "" {
		if path, err := exec.LookPath("wireproxy"); err == nil {
			binPath = path
		}
	}

	if binPath != "" {
		// try --version first, then -v
		out, err := exec.Command(binPath, "--version").Output()
		if err != nil {
			out, err = exec.Command(binPath, "-v").Output()
		}
		if err == nil {
			ver, err := ParseWireproxyVersion(string(out))
			if err == nil {
				info.Installed = true
				info.CurrentVersion = ver
			}
		}
	}

	if !info.Installed {
		info.CurrentVersion = "未安装"
	}

	fetcher := github.NewReleaseFetcher(getMirrorURL(cfg), ReleaseClient)
	latestTag, err := fetcher.FetchLatestTag("windtf/wireproxy")
	if err != nil {
		info.Error = fmt.Errorf("fetch latest wireproxy version failed: %w", err)
		info.LatestVersion = "unknown"
		if !info.Installed {
			info.HasUpdate = true
		}
		return info, info.Error
	}
	info.LatestVersion = latestTag

	if !info.Installed {
		info.HasUpdate = true
	} else {
		info.HasUpdate = (NormalizeVersion(info.CurrentVersion) != NormalizeVersion(info.LatestVersion))
	}

	return info, nil
}

// CheckSubstoreVersion checks the sub-store docker container image against the latest image.
func CheckSubstoreVersion(cfg *config.Config) (*ComponentVersionInfo, error) {
	info := &ComponentVersionInfo{
		Name:        "substore",
		DisplayName: "Sub-Store",
	}

	if _, err := exec.LookPath("docker"); err != nil {
		info.Installed = false
		info.CurrentVersion = "未安装"
		info.LatestVersion = "latest"
		info.HasUpdate = true
		return info, nil
	}

	// Check if sub-store container exists
	out, err := exec.Command("docker", "inspect", "--format={{.Image}}", "sub-store").Output()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		info.Installed = false
		info.CurrentVersion = "未运行"
		info.LatestVersion = "latest"
		info.HasUpdate = true
		return info, nil
	}

	containerImageID := strings.TrimSpace(string(out))
	info.Installed = true
	info.CurrentVersion = shortDigest(containerImageID)

	// Check remote latest image via docker pull with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_ = exec.CommandContext(ctx, "docker", "pull", "xream/sub-store").Run()

	outLatest, err := exec.Command("docker", "inspect", "--format={{.Id}}", "xream/sub-store:latest").Output()
	if err != nil || len(strings.TrimSpace(string(outLatest))) == 0 {
		info.LatestVersion = info.CurrentVersion
		info.HasUpdate = false
		return info, nil
	}

	latestImageID := strings.TrimSpace(string(outLatest))
	info.LatestVersion = shortDigest(latestImageID)
	info.HasUpdate = (containerImageID != latestImageID)

	return info, nil
}

// CheckComponentVersion checks the version of a single component.
func CheckComponentVersion(cfg *config.Config, target string) (*ComponentVersionInfo, error) {
	switch target {
	case "singbox":
		return CheckSingBoxVersion(cfg)
	case "caddy":
		return CheckCaddyVersion(cfg)
	case "substore":
		return CheckSubstoreVersion(cfg)
	case "warp":
		return CheckWarpVersion(cfg)
	default:
		return nil, fmt.Errorf("unknown target: %s", target)
	}
}

// CheckAllComponentVersions checks versions of all four server components.
func CheckAllComponentVersions(cfg *config.Config) ([]*ComponentVersionInfo, error) {
	targets := []string{"singbox", "caddy", "substore", "warp"}
	var results []*ComponentVersionInfo

	for _, target := range targets {
		info, err := CheckComponentVersion(cfg, target)
		if err != nil {
			logger.Warn("检查 %s 版本时遇到问题: %v", target, err)
			if info == nil {
				info = &ComponentVersionInfo{
					Name:        target,
					DisplayName: target,
					Error:       err,
					HasUpdate:   true,
				}
			}
		}
		results = append(results, info)
	}

	return results, nil
}
