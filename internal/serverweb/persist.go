package serverweb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultPersistFastWait  = 25 * time.Millisecond
	defaultPersistFlushWait = 500 * time.Millisecond
)

// asyncSnapshotWriter 单协程合并异步落盘器：
//   - 磁盘健康时（<25ms）等待原子写完成即返回，保证重启/测试强一致；
//   - 磁盘发生内核 D 状态或慢 I/O 阻塞时，调用方最多等待 maxWait（后续请求若检测到写盘已超时则 0ms 立即返回），
//     绝不阻塞登录、注销、审计或后台巡检协程，待磁盘恢复后自动合并写入最新序号快照。
type asyncSnapshotWriter struct {
	filePath string

	mu             sync.Mutex
	writeFn        func(string, []byte) error
	latestData     []byte
	latestSeq      uint64
	writtenSeq     uint64
	workerRunning  bool
	writeStartedAt time.Time
	closed         bool
	waiters        map[uint64][]chan struct{}
}

func newAsyncSnapshotWriter(filePath string, writeFn func(string, []byte) error) *asyncSnapshotWriter {
	if writeFn == nil {
		writeFn = writeAtomicFile0600
	}
	return &asyncSnapshotWriter{
		filePath: strings.TrimSpace(filePath),
		writeFn:  writeFn,
		waiters:  make(map[uint64][]chan struct{}),
	}
}

func (w *asyncSnapshotWriter) setWriteFunc(fn func(string, []byte) error) {
	if w == nil || fn == nil {
		return
	}
	w.mu.Lock()
	w.writeFn = fn
	w.mu.Unlock()
}

func (w *asyncSnapshotWriter) Submit(data []byte, seq uint64, maxWait time.Duration) {
	if w == nil || w.filePath == "" || len(data) == 0 || seq == 0 {
		return
	}

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	if seq > w.latestSeq {
		w.latestSeq = seq
		w.latestData = data
	}
	if w.writtenSeq >= seq {
		w.mu.Unlock()
		return
	}

	// 若后台写协程已处于慢盘阻塞态（耗时已达上限），直接 0ms 返回并在内存合并最新快照
	alreadyStalled := w.workerRunning && !w.writeStartedAt.IsZero() && maxWait > 0 && time.Since(w.writeStartedAt) >= maxWait
	var waitCh chan struct{}
	if maxWait > 0 && !alreadyStalled {
		waitCh = make(chan struct{})
		w.waiters[seq] = append(w.waiters[seq], waitCh)
	}
	if !w.workerRunning {
		w.workerRunning = true
		go w.runWorker()
	}
	w.mu.Unlock()

	if waitCh == nil {
		return
	}
	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	select {
	case <-waitCh:
	case <-timer.C:
	}
}

func (w *asyncSnapshotWriter) Flush(timeout time.Duration) {
	if w == nil || w.filePath == "" {
		return
	}
	if timeout <= 0 {
		timeout = defaultPersistFlushWait
	}

	w.mu.Lock()
	targetSeq := w.latestSeq
	if targetSeq == 0 || (w.writtenSeq >= targetSeq && !w.workerRunning) {
		w.mu.Unlock()
		return
	}
	waitCh := make(chan struct{})
	w.waiters[targetSeq] = append(w.waiters[targetSeq], waitCh)
	if !w.workerRunning && w.writtenSeq < targetSeq && !w.closed {
		w.workerRunning = true
		go w.runWorker()
	}
	w.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-waitCh:
	case <-timer.C:
	}
}

func (w *asyncSnapshotWriter) Close(timeout time.Duration) {
	if w == nil {
		return
	}
	w.Flush(timeout)
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
}

func (w *asyncSnapshotWriter) notifyUpToLocked(seq uint64) {
	for s, chans := range w.waiters {
		if s <= seq {
			for _, ch := range chans {
				close(ch)
			}
			delete(w.waiters, s)
		}
	}
}

func (w *asyncSnapshotWriter) runWorker() {
	for {
		w.mu.Lock()
		if w.closed || w.latestSeq <= w.writtenSeq || len(w.latestData) == 0 {
			w.workerRunning = false
			w.writeStartedAt = time.Time{}
			w.notifyUpToLocked(w.latestSeq)
			w.mu.Unlock()
			return
		}
		seq := w.latestSeq
		data := w.latestData
		fn := w.writeFn
		w.writeStartedAt = time.Now()
		w.mu.Unlock()

		err := fn(w.filePath, data)

		w.mu.Lock()
		w.writeStartedAt = time.Time{}
		if err == nil {
			if seq > w.writtenSeq {
				w.writtenSeq = seq
			}
			w.notifyUpToLocked(seq)
			w.mu.Unlock()
			continue
		}
		// 写盘报错（如只读目录）时唤醒本轮等待者并退出循环，避免死循环空转
		w.notifyUpToLocked(seq)
		if w.latestSeq <= seq {
			w.workerRunning = false
			w.mu.Unlock()
			return
		}
		w.mu.Unlock()
	}
}

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
