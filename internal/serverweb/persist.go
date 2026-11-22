// 文件职责：桥接服务端状态异步快照合并落盘与残留临时文件清理，核心原语委托 common/fsx。
package serverweb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"singctl/internal/common/fsx"
)

const (
	defaultPersistFastWait  = 25 * time.Millisecond
	defaultPersistFlushWait = 500 * time.Millisecond
)

func tryRunSingleFlight(flag *atomic.Bool, timeout time.Duration, fn func(context.Context)) {
	fsx.TrySingleFlight(flag, timeout, fn)
}

type asyncSnapshotWriter struct {
	*fsx.AsyncSnapshotWriter
}

func newAsyncSnapshotWriter(filePath string, writeFn func(string, []byte) error) *asyncSnapshotWriter {
	if writeFn == nil {
		writeFn = writeAtomicFile0600
	}
	return &asyncSnapshotWriter{
		AsyncSnapshotWriter: fsx.NewAsyncSnapshotWriter(filePath, writeFn),
	}
}

func (w *asyncSnapshotWriter) setWriteFunc(fn func(string, []byte) error) {
	if w != nil && w.AsyncSnapshotWriter != nil {
		w.SetWriteFunc(fn)
	}
}

func writeAtomicFile0600(filePath string, data []byte) error {
	if strings.TrimSpace(filePath) == "" {
		return nil
	}
	return fsx.WriteAtomic0600(filePath, data)
}

// CleanupStaleServerWebTmpFiles 清理异常中断遗留的过期 .serverweb_*.tmp 临时文件。
func CleanupStaleServerWebTmpFiles(dir string) {
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
