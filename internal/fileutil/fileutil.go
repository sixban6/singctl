package fileutil

import (
	"fmt"
	"io"
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

	// 非 Windows 平台，使用 .backup 机制
	backupPath := currentFile + ".backup"
	if err := os.Rename(currentFile, backupPath); err != nil {
		return fmt.Errorf("backup current file: %w", err)
	}

	if err := CopyFile(newFile, currentFile); err != nil {
		_ = os.Rename(backupPath, currentFile) // 恢复备份
		return fmt.Errorf("copy new file: %w", err)
	}

	if err := os.Chmod(currentFile, 0755); err != nil {
		return fmt.Errorf("set executable permissions: %w", err)
	}

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
