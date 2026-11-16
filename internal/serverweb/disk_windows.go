//go:build windows

package serverweb

func getRootDiskUsage() (usedStr, totalStr, pctStr string, ok bool) {
	return "", "", "", false
}
