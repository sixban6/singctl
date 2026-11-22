// 文件职责：验证 updater 可执行路径规范化（清理 (deleted) 与 .backup 后缀）及标准版/Lite 版发布资产选择边界。
package updater_test

import (
	"testing"

	"singctl/internal/common/release"
	"singctl/internal/updater"
)

func TestSanitizeExecutablePath_And_AssetMatching(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/usr/bin/singctl (deleted)", "/usr/bin/singctl"},
		{"/usr/local/bin/singctl.backup", "/usr/local/bin/singctl"},
		{"/usr/local/bin/singctl.backup.backup (deleted)", "/usr/local/bin/singctl"},
		{"  /usr/bin/singctl  ", "/usr/bin/singctl"},
	}
	for _, tc := range cases {
		if got := updater.SanitizeExecutablePath(tc.in); got != tc.want {
			t.Errorf("SanitizeExecutablePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if _, err := updater.ResolveExecutablePath(); err != nil {
		t.Fatalf("ResolveExecutablePath failed: %v", err)
	}

	assets := []release.Asset{
		{Name: "checksums.txt"},
		{Name: "singctl-linux-amd64.deb"},
		{Name: "singctl-linux-amd64-lite.tar.gz"},
		{Name: "singctl-linux-x86_64.tar.gz"},
	}
	std := updater.SelectSingCtlAsset(assets, "linux", "amd64", false)
	if std == nil || std.Name != "singctl-linux-x86_64.tar.gz" {
		t.Fatalf("expected standard x86_64 tar.gz asset (excluding checksums, .deb, and -lite), got %+v", std)
	}
	lite := updater.SelectSingCtlAsset(assets, "linux", "amd64", true)
	if lite == nil || lite.Name != "singctl-linux-amd64-lite.tar.gz" {
		t.Fatalf("expected -lite.tar.gz asset when isLite=true, got %+v", lite)
	}
	onlyNonArchive := []release.Asset{
		{Name: "checksums.txt"},
		{Name: "singctl-linux-amd64.deb"},
	}
	if got := updater.SelectSingCtlAsset(onlyNonArchive, "linux", "amd64", false); got != nil {
		t.Fatalf("expected checksums.txt and .deb to be excluded, got %+v", got)
	}
}
