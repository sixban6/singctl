package file

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestWriteAtomic_ConcurrentSafetyAndPermissions(t *testing.T) {
	if err := WriteAtomic("", []byte("x"), 0600); err == nil {
		t.Fatal("expected error for empty target path")
	}

	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "nested", "secret.json")

	var wg sync.WaitGroup
	payloads := make([][]byte, 16)
	for i := range 16 {
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 512)
		wg.Add(1)
		go func(data []byte) {
			defer wg.Done()
			if err := WriteAtomic0600(secretPath, data); err != nil {
				t.Errorf("concurrent WriteAtomic0600 failed: %v", err)
			}
		}(payloads[i])
	}
	wg.Wait()

	got, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read final file: %v", err)
	}
	matched := false
	for _, p := range payloads {
		if bytes.Equal(got, p) {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("final file content corrupted under concurrent writes (len=%d)", len(got))
	}

	st, err := os.Stat(secretPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 mode on secret file, got %v (err=%v)", st, err)
	}

	entries, err := os.ReadDir(filepath.Dir(secretPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "secret.json" {
		t.Fatalf("expected zero leftover temp files in dir, got %v", entries)
	}

	pubPath := filepath.Join(tmpDir, "manifest.json")
	if err := WriteAtomic(pubPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("WriteAtomic 0644 failed: %v", err)
	}
	pubSt, err := os.Stat(pubPath)
	if err != nil || pubSt.Mode().Perm() != 0644 {
		t.Fatalf("expected 0644 mode on public manifest, got %v (err=%v)", pubSt, err)
	}
}
