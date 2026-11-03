package updater

import (
	"testing"

	releasepkg "singctl/internal/util/release"
)

func TestSelectSingCtlAsset_StandardNeverPicksLite(t *testing.T) {
	// Intentionally put -lite BEFORE standard in the asset slice (reproducing alphabetical order bug)
	assets := []releasepkg.Asset{
		{Name: "checksums.txt"},
		{Name: "caddy-cloudflare-l4-linux-amd64.tar.gz"},
		{Name: "singctl-linux-amd64-lite.tar.gz"},
		{Name: "singctl-linux-amd64.tar.gz"},
		{Name: "singctl-linux-arm64-lite.tar.gz"},
		{Name: "singctl-linux-arm64.tar.gz"},
		{Name: "singctl-darwin-arm64.tar.gz"},
		{Name: "singctl-darwin-amd64.tar.gz"},
		{Name: "singctl-windows-amd64.zip"},
		{Name: "singctl-windows-arm64.zip"},
	}

	stdLinux := SelectSingCtlAsset(assets, "linux", "amd64", false)
	if stdLinux == nil || stdLinux.Name != "singctl-linux-amd64.tar.gz" {
		t.Fatalf("standard build must pick singctl-linux-amd64.tar.gz, got %+v", stdLinux)
	}

	liteLinux := SelectSingCtlAsset(assets, "linux", "amd64", true)
	if liteLinux == nil || liteLinux.Name != "singctl-linux-amd64-lite.tar.gz" {
		t.Fatalf("lite build must pick singctl-linux-amd64-lite.tar.gz, got %+v", liteLinux)
	}

	// Platforms without a dedicated -lite asset fall back to standard cleanly when isLite=true
	darwinFallback := SelectSingCtlAsset(assets, "darwin", "arm64", true)
	if darwinFallback == nil || darwinFallback.Name != "singctl-darwin-arm64.tar.gz" {
		t.Fatalf("lite build on darwin should fall back to standard asset, got %+v", darwinFallback)
	}

	winAsset := SelectSingCtlAsset(assets, "windows", "amd64", false)
	if winAsset == nil || winAsset.Name != "singctl-windows-amd64.zip" {
		t.Fatalf("windows amd64 should pick singctl-windows-amd64.zip, got %+v", winAsset)
	}
}
