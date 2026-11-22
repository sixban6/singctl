// 文件职责：动态查询 SagerNet/sing-box 最新桌面端图形客户端（macOS SFM / Windows ZIP）资产下载地址。
package singbox

import (
	"context"
	"fmt"
	"strings"

	"singctl/internal/common/release"
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

	return release.NewClient("").FindAssetURL(context.Background(), "SagerNet/sing-box", func(name string) bool {
		return strings.HasPrefix(name, prefix) && strings.HasSuffix(name, targetExt)
	})
}
