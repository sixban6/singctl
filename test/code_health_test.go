package test

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestCodebaseHygiene_NoWeeds 守护仓库整洁度：拦截遗留系统垃圾文件与重复 UI 组件回潮。
func TestCodebaseHygiene_NoWeeds(t *testing.T) {
	root := filepath.Clean("..")

	var junkFiles []string
	var toastFiles []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := d.Name()
		if d.IsDir() {
			switch name {
			case ".git", "node_modules", "dist", "build", "vendor", ".agent":
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		if name == ".DS_Store" || strings.HasSuffix(name, ".orig") || strings.HasSuffix(name, ".rej") {
			junkFiles = append(junkFiles, rel)
		}
		if name == "Toast.tsx" && rel != "web/src/ui/Toast.tsx" {
			toastFiles = append(toastFiles, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo root: %v", err)
	}

	if len(junkFiles) > 0 {
		t.Fatalf("detected workspace junk files that must be removed: %v", junkFiles)
	}
	if len(toastFiles) > 0 {
		t.Fatalf("detected duplicate Toast.tsx outside web/src/ui/Toast.tsx: %v", toastFiles)
	}
}
