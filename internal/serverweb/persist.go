package serverweb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// writeAtomicFile0600 原子写入 0600 权限的持久化状态文件（严禁在持内存锁期间调用）。
func writeAtomicFile0600(filePath string, data []byte) error {
	if strings.TrimSpace(filePath) == "" {
		return nil
	}
	dir := filepath.Dir(filePath)
	_ = os.MkdirAll(dir, 0700)

	tmp := fmt.Sprintf("%s.%d.tmp", filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0600)
	if err := os.Rename(tmp, filePath); err != nil {
		_ = os.Remove(tmp)
		if wErr := os.WriteFile(filePath, data, 0600); wErr != nil {
			return wErr
		}
		_ = os.Chmod(filePath, 0600)
	}
	return nil
}

// cleanupStaleServerWebTmpFiles 清理因磁盘阻塞或进程异常重启遗留的 .serverweb_*.tmp 僵尸临时文件。
func cleanupStaleServerWebTmpFiles(dir string) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".serverweb_*.tmp"))
	if err != nil {
		return
	}
	now := time.Now()
	for _, p := range matches {
		st, sErr := os.Stat(p)
		if sErr != nil || st.IsDir() {
			continue
		}
		age := now.Sub(st.ModTime())
		if age > 2*time.Minute || (st.Size() == 0 && age > 10*time.Second) {
			_ = os.Remove(p)
		}
	}
}
