package deploy

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
)

// ReleaseClient is an optional HTTP client used for fetching GitHub releases (useful for testing).
var ReleaseClient *http.Client

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

// GetInstalledSingBoxVersion returns the locally installed sing-box version.
func GetInstalledSingBoxVersion() string {
	binPath := constant.SingBoxInstallDir
	if _, err := os.Stat(binPath); err != nil {
		if path, err := exec.LookPath("sing-box"); err == nil {
			binPath = path
		} else {
			return ""
		}
	}
	out, err := exec.Command(binPath, "version").Output()
	if err != nil {
		return ""
	}
	ver, err := singbox.ParseSingBoxVersionOutput(string(out))
	if err != nil {
		return ""
	}
	return ver
}

// GetInstalledCaddyVersion returns the locally installed Caddy version.
func GetInstalledCaddyVersion() string {
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
		} else {
			return ""
		}
	}
	out, err := exec.Command(binPath, "version").Output()
	if err != nil {
		return ""
	}
	ver, err := ParseCaddyVersion(string(out))
	if err != nil {
		return ""
	}
	return ver
}

// GetInstalledWarpVersion returns the locally installed wireproxy version.
func GetInstalledWarpVersion() string {
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
		} else {
			return ""
		}
	}
	out, err := exec.Command(binPath, "--version").Output()
	if err != nil {
		out, err = exec.Command(binPath, "-v").Output()
	}
	if err != nil {
		return ""
	}
	ver, err := ParseWireproxyVersion(string(out))
	if err != nil {
		return ""
	}
	return ver
}

// GetInstalledSubhubVersion returns the running SubHub version from local port 3001, falling back to the on-disk singctl binary version.
func GetInstalledSubhubVersion() string {
	client := http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get("http://127.0.0.1:3001/")
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		html := string(buf[:n])
		if idx := strings.Index(html, `name="version" content="`); idx != -1 {
			start := idx + len(`name="version" content="`)
			if end := strings.Index(html[start:], `"`); end != -1 {
				return NormalizeVersion(html[start : start+end])
			}
		}
	}
	return GetDiskSingctlVersion()
}

// GetDiskSingctlVersion returns the version reported by the on-disk singctl binary.
func GetDiskSingctlVersion() string {
	for _, p := range []string{"/usr/local/bin/singctl", "/usr/bin/singctl"} {
		if _, err := os.Stat(p); err == nil {
			if out, err := exec.Command(p, "version").CombinedOutput(); err == nil {
				for line := range strings.SplitSeq(string(out), "\n") {
					if idx := strings.Index(line, "SingCtl v"); idx != -1 {
						fields := strings.Fields(line[idx:])
						if len(fields) >= 2 {
							return NormalizeVersion(fields[1])
						}
					}
				}
			}
		}
	}
	return ""
}

// GetCoreServiceVersions collects the currently installed versions of all core services.
func GetCoreServiceVersions() map[string]string {
	return map[string]string{
		"singbox": GetInstalledSingBoxVersion(),
		"caddy":   GetInstalledCaddyVersion(),
		"subhub":  GetInstalledSubhubVersion(),
		"warp":    GetInstalledWarpVersion(),
	}
}

func getMirrorURL(cfg *config.Config) string {
	if cfg != nil && cfg.GitHub.MirrorURL != "" {
		return cfg.GitHub.MirrorURL
	}
	return ""
}
