package netinfo

import (
	"net/http"
	"singctl/internal/logger"
	"strings"
	"time"
)

func GetReachableURL(downloadURL string, mirrorURL string) string {
	// 优化下载逻辑：检查Google连通性
	if !checkGoogleConnectivity() {
		logger.Info("Google is not accessible, using mirror for download...")
		if mirrorURL != "" {
			if !strings.HasSuffix(mirrorURL, "/") {
				mirrorURL += "/"
			}
			downloadURL = mirrorURL + downloadURL
		}
	} else {
		logger.Info("Google is accessible, downloading directly...")
	}
	return downloadURL
}

// checkGoogleConnectivity 检查是否能访问Google
func checkGoogleConnectivity() bool {
	client := http.Client{
		Timeout: 3 * time.Second,
	}
	// 尝试访问 google.com
	resp, err := client.Head("https://www.google.com")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}
