package tailscale

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallTailscaleBinaries_CombinedSymlinkAndSeparateDual(t *testing.T) {
	// Case 1: Combined ARM64 layout where extracted tailscale is a symlink to tailscaled.
	srcCombined := t.TempDir()
	dstCombined := t.TempDir()

	tsdSrc := filepath.Join(srcCombined, "tailscaled")
	tsSrc := filepath.Join(srcCombined, "tailscale")
	if err := os.WriteFile(tsdSrc, []byte("combined-elf-binary"), 0755); err != nil {
		t.Fatalf("write tailscaled src: %v", err)
	}
	if err := os.Symlink("tailscaled", tsSrc); err != nil {
		t.Fatalf("create tailscale symlink: %v", err)
	}
	// Pre-seed an older regular file at dst/tailscale to ensure upgrade replaces it atomically with symlink.
	if err := os.WriteFile(filepath.Join(dstCombined, "tailscale"), []byte("old-standalone-cli"), 0755); err != nil {
		t.Fatalf("seed old cli: %v", err)
	}

	if err := installTailscaleBinaries(tsSrc, tsdSrc, dstCombined); err != nil {
		t.Fatalf("installTailscaleBinaries (combined) failed: %v", err)
	}

	installedTSD, err := os.ReadFile(filepath.Join(dstCombined, "tailscaled"))
	if err != nil || string(installedTSD) != "combined-elf-binary" {
		t.Fatalf("unexpected tailscaled content: %q err=%v", string(installedTSD), err)
	}
	linfo, err := os.Lstat(filepath.Join(dstCombined, "tailscale"))
	if err != nil || linfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected installed tailscale to be a symlink, mode=%v err=%v", linfo, err)
	}
	linkTarget, err := os.Readlink(filepath.Join(dstCombined, "tailscale"))
	if err != nil || linkTarget != "tailscaled" {
		t.Fatalf("expected symlink target 'tailscaled', got %q err=%v", linkTarget, err)
	}

	// Case 2: Standard dual-binary layout (e.g. amd64) installs both regular files independently.
	srcDual := t.TempDir()
	dstDual := t.TempDir()
	dualTSD := filepath.Join(srcDual, "tailscaled")
	dualTS := filepath.Join(srcDual, "tailscale")
	if err := os.WriteFile(dualTSD, []byte("amd64-daemon"), 0755); err != nil {
		t.Fatalf("write dual daemon: %v", err)
	}
	if err := os.WriteFile(dualTS, []byte("amd64-cli"), 0755); err != nil {
		t.Fatalf("write dual cli: %v", err)
	}

	if err := installTailscaleBinaries(dualTS, dualTSD, dstDual); err != nil {
		t.Fatalf("installTailscaleBinaries (dual) failed: %v", err)
	}

	cliInfo, err := os.Lstat(filepath.Join(dstDual, "tailscale"))
	if err != nil || cliInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("expected regular file for dual cli, got mode=%v err=%v", cliInfo, err)
	}
	gotCLI, _ := os.ReadFile(filepath.Join(dstDual, "tailscale"))
	gotDaemon, _ := os.ReadFile(filepath.Join(dstDual, "tailscaled"))
	if string(gotCLI) != "amd64-cli" || string(gotDaemon) != "amd64-daemon" {
		t.Fatalf("unexpected dual binary contents: cli=%q daemon=%q", string(gotCLI), string(gotDaemon))
	}
}
