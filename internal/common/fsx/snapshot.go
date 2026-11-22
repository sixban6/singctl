// 文件职责：提供无锁后台单飞执行辅助 TrySingleFlight 与防慢盘 D 状态阻塞的单协程异步快照合并落盘器 AsyncSnapshotWriter。
package fsx

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultFlushTimeout = 500 * time.Millisecond

// TrySingleFlight 以 CAS 无锁单飞方式在后台执行有界任务；已有同类任务运行时直接跳过，零协程堆积。
func TrySingleFlight(flag *atomic.Bool, timeout time.Duration, fn func(context.Context)) {
	if flag == nil || fn == nil || !flag.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer flag.Store(false)
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		fn(ctx)
	}()
}

// AsyncSnapshotWriter 为单协程序号合并异步落盘器：
// 磁盘正常时（< maxWait）同步等待落盘完成即返回；遇到慢盘阻塞时最多等待 maxWait 即释放调用方并在后台合并最新快照。
type AsyncSnapshotWriter struct {
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

// NewAsyncSnapshotWriter 创建绑定指定文件路径的异步快照落盘器（writeFn 为 nil 时默认使用 WriteAtomic0600）。
func NewAsyncSnapshotWriter(filePath string, writeFn func(string, []byte) error) *AsyncSnapshotWriter {
	if writeFn == nil {
		writeFn = WriteAtomic0600
	}
	return &AsyncSnapshotWriter{
		filePath: strings.TrimSpace(filePath),
		writeFn:  writeFn,
		waiters:  make(map[uint64][]chan struct{}),
	}
}

// SetWriteFunc 允许测试注入慢盘或失败桩替换底层写文件实现。
func (w *AsyncSnapshotWriter) SetWriteFunc(fn func(string, []byte) error) {
	if w == nil || fn == nil {
		return
	}
	w.mu.Lock()
	w.writeFn = fn
	w.mu.Unlock()
}

// Submit 提交指定单调递增序号的快照字节，最多等待 maxWait。
func (w *AsyncSnapshotWriter) Submit(data []byte, seq uint64, maxWait time.Duration) {
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

// Flush 等待当前最新待写序号落盘完成或到达 timeout 上限。
func (w *AsyncSnapshotWriter) Flush(timeout time.Duration) {
	if w == nil || w.filePath == "" {
		return
	}
	if timeout <= 0 {
		timeout = defaultFlushTimeout
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

// Close 刷盘并标记落盘器关闭，拒绝后续新写入。
func (w *AsyncSnapshotWriter) Close(timeout time.Duration) {
	if w == nil {
		return
	}
	w.Flush(timeout)
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
}

func (w *AsyncSnapshotWriter) notifyUpToLocked(seq uint64) {
	for s, chans := range w.waiters {
		if s <= seq {
			for _, ch := range chans {
				close(ch)
			}
			delete(w.waiters, s)
		}
	}
}

func (w *AsyncSnapshotWriter) runWorker() {
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
		w.notifyUpToLocked(seq)
		if w.latestSeq <= seq {
			w.workerRunning = false
			w.mu.Unlock()
			return
		}
		w.mu.Unlock()
	}
}
