package singbox

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

// fetchLatestGUIAsset dynamically fetches the latest GUI client URL based on the OS.
// It iterates through the most recent releases to find the correct asset format.
func fetchLatestGUIAsset(goos string) (string, error) {
	resp, err := http.Get("https://api.github.com/repos/SagerNet/sing-box/releases")
	if err != nil {
		return "", fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned status: %s", resp.Status)
	}

	var releases []githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", fmt.Errorf("failed to decode releases response: %w", err)
	}

	targetExt := ""
	prefix := ""

	if goos == "darwin" {
		prefix = "SFM-"
		targetExt = "-Apple.pkg"
	} else if goos == "windows" {
		prefix = "sing-box-"
		targetExt = "-windows-amd64.zip"
	} else {
		return "", fmt.Errorf("unsupported OS for GUI: %s", goos)
	}

	for _, rel := range releases {
		for _, asset := range rel.Assets {
			if strings.HasPrefix(asset.Name, prefix) && strings.HasSuffix(asset.Name, targetExt) {
				return asset.BrowserDownloadURL, nil
			}
		}
	}

	return "", fmt.Errorf("no matching GUI asset found for %s", goos)
}
