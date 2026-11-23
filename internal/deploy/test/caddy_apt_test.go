// 文件职责：验证 Caddy 独立 systemd 服务单元生成与 dpkg 元数据脱钩防 apt 误删逻辑。
package deploy_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
)

func TestBuildStandaloneCaddyServiceUnit(t *testing.T) {
	unit := deploy.BuildStandaloneCaddyServiceUnit()
	for _, want := range []string{
		"Type=notify",
		"User=caddy",
		"Group=caddy",
		"ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile",
		"ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force",
		"ProtectSystem=full",
		"AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("standalone caddy.service missing %q:\n%s", want, unit)
		}
	}
}

func TestNeutralizeCaddyDpkgMetadata(t *testing.T) {
	infoDir := t.TempDir()
	conffiles := filepath.Join(infoDir, "caddy.conffiles")
	prerm := filepath.Join(infoDir, "caddy.prerm")
	postrm := filepath.Join(infoDir, "caddy.postrm")

	if err := os.WriteFile(conffiles, []byte("/etc/caddy/Caddyfile\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prerm, []byte("#!/bin/sh\ndeb-systemd-invoke stop caddy.service\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(postrm, []byte("#!/bin/sh\nuserdel -r caddy\nrm -rf /var/lib/caddy /etc/caddy\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := deploy.NeutralizeCaddyDpkgMetadata(infoDir); err != nil {
		t.Fatalf("NeutralizeCaddyDpkgMetadata failed: %v", err)
	}

	confBytes, err := os.ReadFile(conffiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(confBytes) != 0 {
		t.Fatalf("expected caddy.conffiles to be truncated to 0 bytes, got %q", string(confBytes))
	}

	for _, p := range []string{prerm, postrm} {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != "#!/bin/sh\nexit 0\n" {
			t.Fatalf("unexpected neutralized script %s: %q", p, string(raw))
		}
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0111 == 0 {
			t.Fatalf("expected %s to remain executable, mode=%v", p, st.Mode())
		}
	}
}

func TestCaddyCustomDownloadURLs_AndInstallScriptChannel(t *testing.T) {
	directRolling := constant.GitHubRepoURL + "/releases/download/" + constant.CaddyReleaseTag + "/caddy-custom-linux-amd64.tar.gz"
	directLegacy := constant.GitHubRepoURL + "/releases/latest/download/caddy-custom-linux-amd64.tar.gz"

	cases := []struct {
		name string
		cfg  *config.Config
		arch string
		want []string
	}{
		{
			name: "no_mirror_amd64",
			cfg:  nil,
			arch: "amd64",
			want: []string{directRolling, directLegacy},
		},
		{
			name: "with_mirror_trailing_slash_amd64",
			cfg:  &config.Config{GitHub: config.GitHubConfig{MirrorURL: "https://mirror.example.com/"}},
			arch: "amd64",
			want: []string{
				"https://mirror.example.com/" + directRolling,
				directRolling,
				"https://mirror.example.com/" + directLegacy,
				directLegacy,
			},
		},
		{
			name: "arm64_without_mirror",
			cfg:  &config.Config{},
			arch: "arm64",
			want: []string{
				constant.GitHubRepoURL + "/releases/download/" + constant.CaddyReleaseTag + "/caddy-custom-linux-arm64.tar.gz",
				constant.GitHubRepoURL + "/releases/latest/download/caddy-custom-linux-arm64.tar.gz",
			},
		},
		{
			name: "unsupported_arch_returns_nil",
			cfg:  &config.Config{},
			arch: "mipsle",
			want: nil,
		},
		{
			name: "empty_arch_returns_nil",
			cfg:  nil,
			arch: "",
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deploy.CaddyCustomDownloadURLs(tc.cfg, tc.arch)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("CaddyCustomDownloadURLs(%q) = %v, want %v", tc.arch, got, tc.want)
			}
		})
	}

	scriptBytes, err := os.ReadFile(filepath.Join("..", "scripts", "install_caddy.sh"))
	if err != nil {
		t.Fatalf("read install_caddy.sh: %v", err)
	}
	script := string(scriptBytes)
	wantChannel := "/releases/download/" + constant.CaddyReleaseTag + "/${CADDY_TAR}"
	if !strings.Contains(script, wantChannel) {
		t.Fatalf("expected install_caddy.sh to download from rolling tag %q", wantChannel)
	}
	if strings.Contains(script, "/releases/latest/download/${CADDY_TAR}") {
		t.Fatalf("install_caddy.sh should no longer point directly to singctl /releases/latest for caddy")
	}
}
