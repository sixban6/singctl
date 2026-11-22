// 文件职责：验证规则集快照在标准完整构建（!lite）与轻量构建（lite）下的清单契约、流式解压校验及回退行为。
package ruleset_snapshot_test

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"singctl/internal/singbox/ruleset_snapshot"
)

func pickLargestSnapshotTag(t testing.TB, snap *ruleset_snapshot.Snapshot) string {
	t.Helper()
	var bestTag string
	var bestSize int64
	for _, tag := range snap.Tags() {
		if sz, ok := snap.EntrySize(tag); ok && sz > bestSize {
			bestSize = sz
			bestTag = tag
		}
	}
	if bestTag == "" {
		t.Fatal("expected non-empty embedded snapshot manifest")
	}
	return bestTag
}

func TestSnapshot_LoadConcurrencyAndBuildVariantContract(t *testing.T) {
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			snap := ruleset_snapshot.Load()
			if snap == nil {
				t.Errorf("Load() returned nil")
			}
		})
	}
	wg.Wait()

	snap := ruleset_snapshot.Load()
	if ruleset_snapshot.IsLite {
		if snap.Count() != 0 {
			t.Fatalf("expected 0 embedded rulesets in lite build, got %d", snap.Count())
		}
		if snap.GeneratedAt() != "" {
			t.Fatalf("expected empty GeneratedAt in lite build, got %q", snap.GeneratedAt())
		}
		if len(snap.Tags()) != 0 {
			t.Fatalf("expected empty Tags() in lite build, got %v", snap.Tags())
		}
		if _, _, _, ok := snap.Lookup("geoip-cn", "https://example.com/geoip-cn.srs"); ok {
			t.Fatal("expected Lookup=false in lite build")
		}
		if sz, ok := snap.EntrySize("geoip-cn"); ok || sz != 0 {
			t.Fatalf("expected EntrySize=(0,false) in lite build, got (%d,%v)", sz, ok)
		}
		if _, err := snap.Extract("geoip-cn"); err == nil {
			t.Fatal("expected Extract to return error in lite build")
		}
		missingDest := filepath.Join(t.TempDir(), "lite-missing.srs")
		if err := snap.ExtractToFile("geoip-cn", missingDest, 0644); err == nil {
			t.Fatal("expected ExtractToFile to return error in lite build")
		}
		if _, err := os.Stat(missingDest); !os.IsNotExist(err) {
			t.Fatalf("expected no file created on lite ExtractToFile failure, got %v", err)
		}
		return
	}

	if snap.Count() == 0 {
		t.Fatal("expected non-zero snapshot entries in full (!lite) build")
	}
	tag := pickLargestSnapshotTag(t, snap)
	if matched, url, format, ok := snap.Lookup(tag, ""); !ok || matched != tag || url == "" || format == "" {
		t.Fatalf("Lookup(%q) = (%q, %q, %q, %v)", tag, matched, url, format, ok)
	}

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
	if ruleset_snapshot.IsLite {
		b.Skip("skipping embedded ruleset benchmark in lite build")
	}
	snap := ruleset_snapshot.Load()
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
	if ruleset_snapshot.IsLite {
		b.Skip("skipping embedded ruleset benchmark in lite build")
	}
	snap := ruleset_snapshot.Load()
	tag := pickLargestSnapshotTag(b, snap)
	destPath := filepath.Join(b.TempDir(), "bench.srs")
	b.ReportAllocs()
	for b.Loop() {
		if err := snap.ExtractToFile(tag, destPath, 0644); err != nil {
			b.Fatalf("ExtractToFile failed: %v", err)
		}
	}
}
