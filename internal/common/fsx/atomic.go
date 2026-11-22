// 文件职责：提供零日志耦合的随机临时文件 0600 原子写入、可执行文件安全替换、目录复制与递归查找。
package fsx

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// WriteAtomic 在目标同目录下创建随机唯一临时文件、显式锁定权限并原子替换目标路径。
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

// CopyFile 复制文件并确保目标父目录已创建。
func CopyFile(src, dst string) error {
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

// CopyDir 递归复制目录树（跳过 .go 嵌入源码且不覆盖已存在的用户配置文件）。
func CopyDir(src, dst string) error {
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
			continue
		}
		if strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if _, err := os.Stat(dstPath); os.IsNotExist(err) {
			if err := CopyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// SafeReplace 安全原子替换磁盘上可能正在运行的可执行二进制（防止 ETXTBSY 与断电半截损坏）。
func SafeReplace(currentFile, newFile string) error {
	if runtime.GOOS == "windows" {
		oldPath := currentFile + ".old"
		_ = os.Remove(oldPath)
		if err := os.Rename(currentFile, oldPath); err != nil {
			return fmt.Errorf("backup current file on Windows: %w", err)
		}
		if err := CopyFile(newFile, currentFile); err != nil {
			_ = os.Rename(oldPath, currentFile)
			return fmt.Errorf("copy new file on Windows: %w", err)
		}
		if err := os.Chmod(currentFile, 0755); err != nil {
			return fmt.Errorf("set executable permissions on Windows: %w", err)
		}
		return nil
	}

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
		_ = os.Rename(backupPath, currentFile)
		return fmt.Errorf("atomic replace file: %w", err)
	}
	cleanupStage = false
	_ = os.Remove(backupPath)
	return nil
}

// InstallOrReplace 安装新可执行文件或安全替换现有目标文件。
func InstallOrReplace(newFile, targetFile string) error {
	if err := os.MkdirAll(filepath.Dir(targetFile), 0755); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}
	if _, err := os.Stat(targetFile); err == nil {
		return SafeReplace(targetFile, newFile)
	}
	if err := CopyFile(newFile, targetFile); err != nil {
		return fmt.Errorf("copy file: %w", err)
	}
	if err := os.Chmod(targetFile, 0755); err != nil {
		return fmt.Errorf("set executable permissions: %w", err)
	}
	return nil
}

// FindExecutable 在解压目录中递归（深度 <= 3）定位匹配的可执行文件并赋予 0755 权限。
func FindExecutable(dir, namePattern string) (string, error) {
	return findExecutableRecursive(dir, namePattern, 0)
}

func findExecutableRecursive(dir, namePattern string, depth int) (string, error) {
	if depth > 3 {
		return "", fmt.Errorf("search depth exceeded at %s", dir)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read directory: %w", err)
	}

	for _, candidate := range []string{
		filepath.Join(dir, namePattern),
		filepath.Join(dir, namePattern+".exe"),
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			if err := os.Chmod(candidate, 0755); err == nil {
				return candidate, nil
			}
		}
	}

	lowerPattern := strings.ToLower(namePattern)
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if strings.Contains(strings.ToLower(f.Name()), lowerPattern) {
			p := filepath.Join(dir, f.Name())
			if err := os.Chmod(p, 0755); err == nil {
				return p, nil
			}
		}
	}

	for _, f := range files {
		if f.IsDir() {
			if res, err := findExecutableRecursive(filepath.Join(dir, f.Name()), namePattern, depth+1); err == nil {
				return res, nil
			}
		}
	}
	return "", fmt.Errorf("no executable file found matching pattern: %s", namePattern)
}
