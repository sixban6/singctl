// 文件职责：提供带 0600 离线预检、自动备份轮转与健康探测失败自动回滚的事务化配置落盘原语 CommitVerified。
package fsx

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// CommitOptions 定义两阶段零断网配置切换事务参数。
type CommitOptions struct {
	TargetPath string
	Data       []byte
	Perm       os.FileMode                   // 为 0 时默认强制 0600
	KeepBackup int                           // 保留带时间戳历史备份份数（<=0 表示不额外保留历史轮转文件）
	Verify     func(stagedPath string) error // 替换前离线语法校验钩子（如 sing-box check）
	PostApply  func() error                  // 原子替换后重载/连通性探测钩子；返回非 nil 时自动恢复原文件
}

// CommitVerified 执行「0600 随机暂存 -> Verify 预校验 -> 0600 备份 -> 原子 Rename -> PostApply 失败自动回滚」完整闭环。
func CommitVerified(opts CommitOptions) error {
	cleanPath := strings.TrimSpace(opts.TargetPath)
	if cleanPath == "" {
		return fmt.Errorf("empty target file path")
	}
	perm := opts.Perm
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

	staged, err := os.CreateTemp(dir, "."+filepath.Base(cleanPath)+".stage-*")
	if err != nil {
		return fmt.Errorf("create staged config: %w", err)
	}
	stagedPath := staged.Name()
	cleanupStaged := true
	defer func() {
		if cleanupStaged {
			_ = os.Remove(stagedPath)
		}
	}()

	if err := staged.Chmod(perm); err != nil {
		_ = staged.Close()
		return err
	}
	if _, err := staged.Write(opts.Data); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}

	if opts.Verify != nil {
		if err := opts.Verify(stagedPath); err != nil {
			return fmt.Errorf("verify staged file failed: %w", err)
		}
	}

	prevBytes, prevReadErr := os.ReadFile(cleanPath)
	hadPrev := prevReadErr == nil
	if hadPrev {
		if opts.KeepBackup > 0 {
			_, _ = BackupAndPrune(cleanPath, opts.KeepBackup)
		} else {
			_ = WriteAtomic0600(cleanPath+".bak", prevBytes)
		}
	}

	if err := os.Rename(stagedPath, cleanPath); err != nil {
		return fmt.Errorf("atomic rename %s: %w", cleanPath, err)
	}
	cleanupStaged = false
	_ = os.Chmod(cleanPath, perm)

	if opts.PostApply != nil {
		if applyErr := opts.PostApply(); applyErr != nil {
			if hadPrev {
				_ = WriteAtomic(cleanPath, prevBytes, perm)
			} else {
				_ = os.Remove(cleanPath)
			}
			return fmt.Errorf("post-apply check failed (rolled back %s): %w", filepath.Base(cleanPath), applyErr)
		}
	}
	return nil
}

// BackupAndPrune 为已存在的目标文件生成 0600 时间戳备份副本，并仅保留最新的 keep 份备份。
func BackupAndPrune(targetPath string, keep int) (string, error) {
	cleanPath := strings.TrimSpace(targetPath)
	if cleanPath == "" {
		return "", fmt.Errorf("empty backup target path")
	}
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	bakPath := fmt.Sprintf("%s.backup.%d", cleanPath, time.Now().UnixNano())
	if err := WriteAtomic0600(bakPath, raw); err != nil {
		return "", err
	}
	if keep > 0 {
		matches, gErr := filepath.Glob(cleanPath + ".backup.*")
		if gErr == nil && len(matches) > keep {
			slices.Sort(matches)
			for _, old := range matches[:len(matches)-keep] {
				_ = os.Remove(old)
			}
		}
	}
	return bakPath, nil
}
