//go:build !windows

// 文件职责：在 Unix 平台上验证 proc 包的安全 FIFO 就绪管道握手（syscall.Fstat 防误关非 FIFO 普通文件描述符）。
package proc_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"singctl/internal/common/proc"
)

func TestNotifyReadyPipe_NeverClosesNonFIFOFileDescriptor(t *testing.T) {
	// 1. Regular file FD MUST NOT be written to or closed by NotifyReadyPipe!
	regPath := filepath.Join(t.TempDir(), "regular.txt")
	regFile, err := os.OpenFile(regPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer regFile.Close()

	proc.NotifyReadyPipe(int(regFile.Fd()))
	proc.NotifyReadyPipeResult(int(regFile.Fd()), false)

	// Verify regFile FD is still open and valid (Fstat succeeds and size is 0)
	var st syscall.Stat_t
	if err := syscall.Fstat(int(regFile.Fd()), &st); err != nil {
		t.Fatalf("NotifyReadyPipe closed a non-FIFO regular file descriptor: %v", err)
	}
	if st.Size != 0 {
		t.Fatalf("NotifyReadyPipe wrote %d bytes to regular file", st.Size)
	}

	// Invalid negative FD must be safe no-op
	proc.NotifyReadyPipe(-1)
	proc.NotifyReadyPipe(999999)

	// 2. Real pipe FD writes ready byte 1 and unblocks WaitReadyPipe
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	go proc.NotifyReadyPipe(int(w.Fd()))
	if err := proc.WaitReadyPipe(r, 2*time.Second); err != nil {
		t.Fatalf("WaitReadyPipe failed on valid FIFO signal: %v", err)
	}

	// 3. Closed write-end without ready byte returns ErrChildExited
	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	_ = w2.Close()
	if err := proc.WaitReadyPipe(r2, time.Second); !errors.Is(err, proc.ErrChildExited) {
		t.Fatalf("expected ErrChildExited on immediate pipe EOF, got %v", err)
	}

	// 4. NotifyReadyPipeResult(fd, false) sends failure byte 0 -> ErrChildExited
	r3, w3, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r3.Close()
	go proc.NotifyReadyPipeResult(int(w3.Fd()), false)
	if err := proc.WaitReadyPipe(r3, time.Second); !errors.Is(err, proc.ErrChildExited) {
		t.Fatalf("expected ErrChildExited on byte 0, got %v", err)
	}

	// 5. Timeout when child hangs without signaling
	r4, w4, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r4.Close()
	defer w4.Close()
	if err := proc.WaitReadyPipe(r4, 40*time.Millisecond); err == nil || errors.Is(err, proc.ErrChildExited) {
		t.Fatalf("expected timeout error, got %v", err)
	}
}
