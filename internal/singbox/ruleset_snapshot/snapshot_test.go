package ruleset_snapshot

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func pickLargestSnapshotTag(t testing.TB, snap *Snapshot) string {
	t.Helper()
	var bestTag string
	var bestSize int64
	for _, tag := range snap.Tags() {
		if e, ok := snap.manifest.Entries[tag]; ok && e.Size > bestSize {
			bestSize = e.Size
			bestTag = tag
		}
	}
	if bestTag == "" {
		t.Fatal("expected non-empty embedded snapshot manifest")
	}
	return bestTag
}

func TestSnapshot_ExtractAndExtractToFile(t *testing.T) {
	snap := Load()
	tag := pickLargestSnapshotTag(t, snap)

	wantBytes, err := snap.Extract(tag)
	if err != nil {
		t.Fatalf("Extract(%q) failed: %v", tag, err)
	}
	if len(wantBytes) == 0 {
		t.Fatalf("Extract(%q) returned empty payload", tag)
	}

	destPath := filepath.Join(t.TempDir(), "nested", "rule.srs")
	if err := snap.ExtractToFile(tag, destPath, 0640); err != nil {
		t.Fatalf("ExtractToFile(%q) failed: %v", tag, err)
	}
	gotBytes, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) failed: %v", destPath, err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("ExtractToFile byte mismatch: got len=%d want len=%d", len(gotBytes), len(wantBytes))
	}
	info, err := os.Stat(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("expected file mode 0640, got %#o", info.Mode().Perm())
	}

	missingPath := filepath.Join(t.TempDir(), "should-not-exist.srs")
	if err := snap.ExtractToFile("nonexistent-ruleset-tag-xyz", missingPath, 0644); err == nil {
		t.Fatal("expected error for unknown ruleset tag")
	}
	if _, err := os.Stat(missingPath); !os.IsNotExist(err) {
		t.Fatalf("expected missing destPath on error, got stat err=%v", err)
	}
}

func BenchmarkSnapshot_Extract(b *testing.B) {
	snap := Load()
	tag := pickLargestSnapshotTag(b, snap)
	b.ReportAllocs()
	for b.Loop() {
		raw, err := snap.Extract(tag)
		if err != nil || len(raw) == 0 {
			b.Fatalf("Extract failed: err=%v len=%d", err, len(raw))
		}
	}
}

func BenchmarkSnapshot_ExtractToFile(b *testing.B) {
	snap := Load()
	tag := pickLargestSnapshotTag(b, snap)
	destPath := filepath.Join(b.TempDir(), "bench.srs")
	b.ReportAllocs()
	for b.Loop() {
		if err := snap.ExtractToFile(tag, destPath, 0644); err != nil {
			b.Fatalf("ExtractToFile failed: %v", err)
		}
	}
}
