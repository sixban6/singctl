package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildStandaloneCaddyServiceUnit(t *testing.T) {
	unit := BuildStandaloneCaddyServiceUnit()
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

	if err := NeutralizeCaddyDpkgMetadata(infoDir); err != nil {
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
