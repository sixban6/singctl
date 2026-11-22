// 文件职责：提供定长尾部保留的原子日志截断与受控追加打开能力，防止长期运行撑爆小内存路由器 /tmp tmpfs。
package fsx

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CapFileTail 当目标文件大小超过 maxBytes 时，仅流式定位读取末尾一半最新内容并原子重写截断（maxBytes <= 0 或文件不存在时直接返回 nil）。
func CapFileTail(path string, maxBytes int64) error {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return fmt.Errorf("empty file path")
	}
	if maxBytes <= 0 {
		return nil
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", cleanPath)
	}
	size := info.Size()
	if size <= maxBytes {
		return nil
	}

	keepBytes := max(maxBytes/2, 1)
	offset := max(size-keepBytes, 0)

	f, err := os.Open(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			return err
		}
	}
	tail, readErr := io.ReadAll(io.LimitReader(f, keepBytes))
	_ = f.Close()
	if readErr != nil {
		return readErr
	}

	perm := info.Mode().Perm()
	if perm == 0 {
		perm = 0600
	}
	return WriteAtomic(cleanPath, tail, perm)
}

// OpenCappedAppendFile 在追加打开文件前按 maxBytes 执行尾部截断保护，并确保目录与文件权限收敛。
func OpenCappedAppendFile(path string, maxBytes int64, perm os.FileMode) (*os.File, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, fmt.Errorf("empty file path")
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
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	if err := CapFileTail(cleanPath, maxBytes); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, perm)
	if err != nil {
		return nil, err
	}
	_ = f.Chmod(perm)
	return f, nil
}
