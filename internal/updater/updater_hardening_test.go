package updater

import (
	"testing"
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
		if got := SanitizeExecutablePath(tc.in); got != tc.want {
			t.Errorf("SanitizeExecutablePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if _, err := ResolveExecutablePath(); err != nil {
		t.Fatalf("ResolveExecutablePath failed: %v", err)
	}

	if !matchesOSAndArch("singctl-linux-x86_64.tar.gz", "linux", "amd64") {
		t.Fatal("expected x86_64 archive to match amd64")
	}
	if matchesOSAndArch("checksums.txt", "linux", "amd64") {
		t.Fatal("expected checksums.txt to be excluded")
	}
	if matchesOSAndArch("singctl-linux-amd64.deb", "linux", "amd64") {
		t.Fatal("expected non-tar.gz/zip archive to be excluded")
	}
	if !isLiteAssetName("singctl-linux-amd64-lite.tar.gz") {
		t.Fatal("expected -lite.tar.gz to be recognized as lite asset")
	}
}
