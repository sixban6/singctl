package terminal

import (
	"os"
	"path/filepath"
	"testing"

	"singctl/internal/config"
)

func TestGenerateRandomHex(t *testing.T) {
	h1 := GenerateRandomHex(4)
	h2 := GenerateRandomHex(4)
	if len(h1) != 8 {
		t.Errorf("expected 8 chars, got %d (%s)", len(h1), h1)
	}
	if h1 == h2 {
		t.Errorf("expected random hex strings to differ: %s vs %s", h1, h2)
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	p1 := GenerateRandomPassword(12)
	p2 := GenerateRandomPassword(12)
	if len(p1) != 12 {
		t.Errorf("expected 12 chars, got %d (%s)", len(p1), p1)
	}
	if p1 == p2 {
		t.Errorf("expected random passwords to differ: %s vs %s", p1, p2)
	}
}

func TestStatus_ConfigParsed(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain: "node.example.com",
			NodeTag:    "los",
			WebTerminal: config.WebTerminalConfig{
				Enabled:  true,
				Port:     18080,
				Path:     "/ops-shell-abc",
				Password: "secret-pass-123",
			},
		},
	}

	st, err := Status(cfg)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}

	if !st.Enabled {
		t.Errorf("expected Enabled true")
	}
	if st.URL != "https://node.example.com/ops-shell-abc/" {
		t.Errorf("unexpected URL: %s", st.URL)
	}
	if st.Password != "secret-pass-123" {
		t.Errorf("unexpected Password: %s", st.Password)
	}
	if st.NodeTag != "los" {
		t.Errorf("expected NodeTag los, got %s", st.NodeTag)
	}
}

func TestExportCert_NotFound(t *testing.T) {
	// Point to a non-existent file
	_, err := ExportCert()
	if err == nil {
		t.Errorf("expected error when client.p12 does not exist, got nil")
	}
}

func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "src.txt")
	dst := filepath.Join(tmpDir, "dst.txt")

	_ = os.WriteFile(src, []byte("hello world"), 0644)
	if err := copyFile(src, dst, 0644); err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}

	data, _ := os.ReadFile(dst)
	if string(data) != "hello world" {
		t.Errorf("unexpected content: %s", string(data))
	}
}
