package file

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"singctl/internal/logger"
)

// SafeReplace 安全替换文件（处理正在运行的程序）
// SafeReplace 安全替换文件（支持 Windows 正在运行的程序）
func SafeReplace(currentFile, newFile string) error {
	if runtime.GOOS == "windows" {
		// Windows 下先尝试删除旧的 .old 文件，再重命名当前文件为 .old
		oldPath := currentFile + ".old"
		_ = os.Remove(oldPath) // 忽略错误，可能不存在

		if err := os.Rename(currentFile, oldPath); err != nil {
			return fmt.Errorf("backup current file on Windows: %w", err)
		}

		// 复制新文件
		if err := CopyFile(newFile, currentFile); err != nil {
			// 恢复备份
			_ = os.Rename(oldPath, currentFile)
			return fmt.Errorf("copy new file on Windows: %w", err)
		}

		// 设置权限
		if err := os.Chmod(currentFile, 0755); err != nil {
			return fmt.Errorf("set executable permissions on Windows: %w", err)
		}

		// 不删除 .old，重启后自动清理
		return nil
	}

	// 非 Windows 平台：先在同目录原子落盘 staging 副本并赋予 0755，再执行备份与原子 rename，
	// 消除磁盘写满或断电导致目标可执行文件半截损坏或触发 ETXTBSY 的窗口。
	dir := filepath.Dir(currentFile)
	stagedTmp, err := os.CreateTemp(dir, "."+filepath.Base(currentFile)+".stage-*")
	if err != nil {
		return fmt.Errorf("create staged executable: %w", err)
	}
	stagedPath := stagedTmp.Name()
	cleanupStage := true
	defer func() {
		if cleanupStage {
			_ = os.Remove(stagedPath)
		}
	}()

	srcFile, err := os.Open(newFile)
	if err != nil {
		_ = stagedTmp.Close()
		return fmt.Errorf("open new file: %w", err)
	}
	_, copyErr := io.Copy(stagedTmp, srcFile)
	_ = srcFile.Close()
	closeErr := stagedTmp.Close()
	if copyErr != nil {
		return fmt.Errorf("stage new file: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close staged file: %w", closeErr)
	}
	if err := os.Chmod(stagedPath, 0755); err != nil {
		return fmt.Errorf("set executable permissions: %w", err)
	}

	backupPath := currentFile + ".backup"
	_ = os.Remove(backupPath)
	if err := os.Rename(currentFile, backupPath); err != nil {
		return fmt.Errorf("backup current file: %w", err)
	}

	if err := os.Rename(stagedPath, currentFile); err != nil {
		_ = os.Rename(backupPath, currentFile) // 恢复备份
		return fmt.Errorf("atomic replace file: %w", err)
	}
	cleanupStage = false
	_ = os.Remove(backupPath)
	return nil
}

// CopyFile 复制文件
func CopyFile(src, dst string) error {
	// 确保目标目录存在
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// CopyDir recursively copies a directory tree, creating destination directories if they don't exist
func CopyDir(src string, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("source is not a directory")
	}

	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := CopyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			// Skip overwriting existing files or copying configs over
			if _, err := os.Stat(dstPath); os.IsNotExist(err) {
				if err := CopyFile(srcPath, dstPath); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// FindExecutable 在目录中查找可执行文件
func FindExecutable(dir string, namePattern string) (string, error) {
	return findExecutableRecursive(dir, namePattern, 0)
}

// findExecutableRecursive 递归查找可执行文件
func findExecutableRecursive(dir string, namePattern string, depth int) (string, error) {
	// 限制递归深度，避免无限递归
	if depth > 3 {
		logger.Warn("Search depth exceeded at: %s", dir)
		return "", fmt.Errorf("search depth exceeded")
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		logger.Error("Failed to read directory %s: %v", dir, err)
		return "", fmt.Errorf("read directory: %w", err)
	}

	if depth == 0 {
		logger.Info("Looking for executable '%s' in directory: %s", namePattern, dir)
	}

	// 优先在当前目录查找精确匹配
	candidates := []string{
		filepath.Join(dir, namePattern),
		filepath.Join(dir, namePattern+".exe"), // Windows
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			logger.Info("Found exact match: %s", candidate)
			// 确保有执行权限
			if err := os.Chmod(candidate, 0755); err == nil {
				logger.Success("Successfully set executable permissions")
				return candidate, nil
			} else {
				logger.Error("Failed to set executable permissions: %v", err)
			}
		}
	}

	// 在当前目录查找包含模式的文件
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filePath := filepath.Join(dir, file.Name())

		// 检查是否包含指定字符串
		if strings.Contains(strings.ToLower(file.Name()), strings.ToLower(namePattern)) {
			logger.Info("Found pattern match: %s", filePath)
			// 找到匹配的文件，先设置执行权限再返回
			if err := os.Chmod(filePath, 0755); err == nil {
				logger.Success("Successfully set executable permissions")
				return filePath, nil
			} else {
				logger.Error("Failed to set executable permissions: %v", err)
			}
		}
	}

	// 递归搜索子目录
	for _, file := range files {
		if file.IsDir() {
			subDir := filepath.Join(dir, file.Name())
			logger.Info("Searching subdirectory: %s", file.Name())
			if result, err := findExecutableRecursive(subDir, namePattern, depth+1); err == nil {
				return result, nil
			}
		}
	}

	if depth == 0 {
		logger.Error("No executable file found matching pattern: %s", namePattern)
	}
	return "", fmt.Errorf("no executable file found matching pattern: %s", namePattern)
}

// InstallOrReplace 安装或替换文件
// 如果目标文件存在则安全替换，不存在则直接复制
func InstallOrReplace(newFile, targetFile string) error {
	// 确保目标目录存在
	if err := os.MkdirAll(filepath.Dir(targetFile), 0755); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}

	if _, err := os.Stat(targetFile); err == nil {
		return SafeReplace(targetFile, newFile)
	} else {
		if err := CopyFile(newFile, targetFile); err != nil {
			return fmt.Errorf("copy file: %w", err)
		}
		if err := os.Chmod(targetFile, 0755); err != nil {
			return fmt.Errorf("set executable permissions: %w", err)
		}
	}
	return nil
}

// MaskSubscriptionURL 对订阅URL进行脱敏处理（剥离 userinfo 凭据、隐藏公网 IP 段并保持合法 UTF-8）。
func MaskSubscriptionURL(rawURL string) string {
	if rawURL == "" {
		return "未配置"
	}

	schemeIdx := strings.Index(rawURL, "://")
	if schemeIdx < 0 {
		return "***"
	}

	scheme := rawURL[:schemeIdx+3]
	remaining := rawURL[schemeIdx+3:]
	if remaining == "" {
		return "***"
	}

	authority := remaining
	for _, sep := range []byte{'/', '?', '#'} {
		if idx := strings.IndexByte(authority, sep); idx >= 0 {
			authority = authority[:idx]
		}
	}
	// 剥离 user:password@ 认证信息，严防凭据泄漏
	if atIdx := strings.LastIndexByte(authority, '@'); atIdx >= 0 {
		authority = authority[atIdx+1:]
	}
	if authority == "" {
		return "***"
	}

	host := authority
	portSuffix := ""
	if h, p, err := net.SplitHostPort(authority); err == nil && h != "" {
		host = h
		portSuffix = ":" + p
	}
	hostClean := strings.Trim(host, "[]")

	// 若主机为 IP 地址，强制脱敏后段字节
	if ip := net.ParseIP(hostClean); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			parts := strings.Split(v4.String(), ".")
			return scheme + parts[0] + ".***.***.***" + portSuffix + "/***"
		}
		return scheme + "[***]" + portSuffix + "/***"
	}

	// 域名脱敏：按 Unicode rune 切片保留首字符和顶级域名，防止截断多字节 UTF-8
	domainParts := strings.Split(hostClean, ".")
	if len(domainParts) >= 2 {
		runes := []rune(domainParts[0])
		if len(runes) > 1 {
			domainParts[0] = string(runes[0]) + strings.Repeat("*", len(runes)-1)
		}
		return scheme + strings.Join(domainParts, ".") + portSuffix + "/***"
	}

	runes := []rune(hostClean)
	if len(runes) > 1 {
		return scheme + string(runes[0]) + strings.Repeat("*", len(runes)-1) + portSuffix + "/***"
	}
	return scheme + "***" + portSuffix + "/***"
}

// WriteAtomic 在目标同目录下创建随机唯一临时文件、显式锁定权限并原子替换目标路径，
// 防止并发写入互相踩踏或进程中断留下半截损坏配置。
func WriteAtomic(targetPath string, data []byte, perm os.FileMode) error {
	cleanPath := strings.TrimSpace(targetPath)
	if cleanPath == "" {
		return fmt.Errorf("empty target file path")
	}
	if perm == 0 {
		perm = 0600
	}
	dir := filepath.Dir(cleanPath)
	if dir != "" && dir != "." {
		dirPerm := os.FileMode(0755)
		if perm&0077 == 0 {
			dirPerm = 0700
		}
		if err := os.MkdirAll(dir, dirPerm); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(cleanPath)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, cleanPath); err != nil {
		return err
	}
	cleanup = false
	return os.Chmod(cleanPath, perm)
}

// WriteAtomic0600 以强制 0600 敏感凭据权限原子写入目标文件。
func WriteAtomic0600(targetPath string, data []byte) error {
	return WriteAtomic(targetPath, data, 0600)
}
