package webui

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWebUIServer_ConfigStoreSnapshotAndWriteThrough(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
subs:
  - name: "sub-one"
    url: "https://sub.example.com/1"
hy2:
  up: 21
  down: 200
`), 0600); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{
		ConfigPath:              cfgPath,
		SkipAdGuardProbeForTest: true,
	})
	if srv.cfgStore == nil {
		t.Fatal("expected webui Server cfgStore to be initialized")
	}

	snap1, err := srv.loadConfigSnapshot()
	if err != nil {
		t.Fatalf("loadConfigSnapshot failed: %v", err)
	}
	if snap1.Hy2.Up != 21 {
		t.Fatalf("expected initial Hy2.Up=21, got %d", snap1.Hy2.Up)
	}
	rev1 := srv.cfgStore.Revision()

	// Unchanged disk file returns exact cached snapshot pointer without bumping revision.
	snap2 := srv.readConfigOrEmpty()
	if snap2 != snap1 || srv.cfgStore.Revision() != rev1 {
		t.Fatalf("expected immutable snapshot reuse when file unchanged")
	}

	// saveConfig atomically saves and publishes updated snapshot immediately.
	next := snap2.Clone()
	next.Hy2.Up = 66
	if err := srv.saveConfig(next); err != nil {
		t.Fatalf("saveConfig failed: %v", err)
	}
	if srv.cfgStore.Revision() <= rev1 {
		t.Fatalf("expected revision bump after saveConfig, got %d <= %d", srv.cfgStore.Revision(), rev1)
	}
	if got := srv.readConfigOrEmpty().Hy2.Up; got != 66 {
		t.Fatalf("expected immediate read-through Hy2.Up=66, got %d", got)
	}
}
