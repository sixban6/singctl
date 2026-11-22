// 文件职责：提供服务端根分区磁盘用量展示辅助，底层委托 common/sysinfo。
package serverweb

import (
	"fmt"

	"singctl/internal/common/sysinfo"
)

func getRootDiskUsage() (usedStr, totalStr, pctStr string, ok bool) {
	ds, err := sysinfo.Statfs("/")
	if err != nil || ds.TotalBytes == 0 {
		return "", "", "", false
	}
	return sysinfo.FormatDiskBytes(ds.UsedBytes), sysinfo.FormatDiskBytes(ds.TotalBytes), fmt.Sprintf("%d%%", ds.UsedPercent), true
}
