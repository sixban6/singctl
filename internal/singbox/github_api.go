package singbox

import (
	"fmt"
	"strings"

	"singctl/internal/util/github"
)

// fetchLatestGUIAsset dynamically fetches the latest GUI client URL based on the OS.
// It iterates through the most recent releases to find the correct asset format.
func fetchLatestGUIAsset(goos string) (string, error) {
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

	fetcher := github.NewReleaseFetcher("", nil)
	return fetcher.FindAssetURL("SagerNet/sing-box", func(name string) bool {
		return strings.HasPrefix(name, prefix) && strings.HasSuffix(name, targetExt)
	})
}
