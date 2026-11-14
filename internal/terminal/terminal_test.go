package terminal

import (
	"os"
	"path/filepath"
	"testing"

	"singctl/internal/config"
)

func TestDetectSSHPortFrom(t *testing.T) {
	t.Run("prefers hardened drop-in over default port 22 and comments", func(t *testing.T) {
		tmp := t.TempDir()
		dropIn := filepath.Join(tmp, "00-singctl-hardening.conf")
		if err := os.WriteFile(dropIn, []byte("# Port 9999\nPort 22\nPort 2222 # hardened\n"), 0644); err != nil {
			t.Fatal(err)
		}
		mainCfg := filepath.Join(tmp, "sshd_config")
		if err := os.WriteFile(mainCfg, []byte("Port 22\n"), 0644); err != nil {
			t.Fatal(err)
		}

		got := detectSSHPortFrom("", filepath.Join(tmp, "*.conf"), mainCfg)
		if got != 2222 {
			t.Fatalf("expected port 2222 from drop-in, got %d", got)
		}
	})

	t.Run("falls back to SSH_CONNECTION when drop-in only uses port 22", func(t *testing.T) {
		tmp := t.TempDir()
		dropIn := filepath.Join(tmp, "10-default.conf")
		if err := os.WriteFile(dropIn, []byte("Port 22\n"), 0644); err != nil {
			t.Fatal(err)
		}

		got := detectSSHPortFrom("192.0.2.10 54321 198.51.100.1 2222", filepath.Join(tmp, "*.conf"), "")
		if got != 2222 {
			t.Fatalf("expected port 2222 from SSH_CONNECTION, got %d", got)
		}
	})

	t.Run("uses main sshd_config when drop-in and SSH_CONNECTION absent", func(t *testing.T) {
		tmp := t.TempDir()
		mainCfg := filepath.Join(tmp, "sshd_config")
		if err := os.WriteFile(mainCfg, []byte("#Port 22\nPort 2022\n"), 0644); err != nil {
			t.Fatal(err)
		}

		got := detectSSHPortFrom("", filepath.Join(tmp, "*.conf"), mainCfg)
		if got != 2022 {
			t.Fatalf("expected port 2022 from main sshd_config, got %d", got)
		}
	})

	t.Run("defaults cleanly to 22 when no sources specify a port", func(t *testing.T) {
		tmp := t.TempDir()
		got := detectSSHPortFrom("", filepath.Join(tmp, "*.conf"), filepath.Join(tmp, "missing_sshd_config"))
		if got != 22 {
			t.Fatalf("expected fallback port 22, got %d", got)
		}
	})
}

func TestResolveWebTerminalSSHPort(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			WebTerminal: config.WebTerminalConfig{SSHPort: 2222},
		},
	}
	if got := resolveWebTerminalSSHPort(cfg, func() int { return 22 }); got != 2222 {
		t.Fatalf("expected existing SSHPort 2222 preserved, got %d", got)
	}

	emptyCfg := &config.Config{}
	if got := resolveWebTerminalSSHPort(emptyCfg, func() int { return 2200 }); got != 2200 {
		t.Fatalf("expected detector port 2200 when config SSHPort unset, got %d", got)
	}

	if got := resolveWebTerminalSSHPort(nil, func() int { return 0 }); got != 22 {
		t.Fatalf("expected default port 22, got %d", got)
	}
}
