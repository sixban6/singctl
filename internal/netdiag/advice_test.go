package netdiag

import (
	"os"
	"strings"
	"testing"
	"time"

	"singctl/internal/config"
)

func TestGenerateAdvice_Protocol(t *testing.T) {
	// 0% loss, low jitter -> VLESS-Reality
	cleanPing := &PingResult{
		LossRate:     0.0,
		Jitter:       5 * time.Millisecond,
		QualityLevel: QualityExcellent,
	}
	adv := GenerateAdvice(nil, cleanPing, nil, false)
	if adv.RecommendedProtocol != ProtocolVLESSReality {
		t.Errorf("expected VLESS-Reality for clean route, got %s", adv.RecommendedProtocol)
	}

	// 15% loss -> Hysteria 2
	lossyPing := &PingResult{
		LossRate:     15.0,
		Jitter:       60 * time.Millisecond,
		QualityLevel: QualitySevere,
	}
	adv = GenerateAdvice(nil, lossyPing, nil, false)
	if adv.RecommendedProtocol != ProtocolHysteria2 {
		t.Errorf("expected Hysteria 2 for lossy route, got %s", adv.RecommendedProtocol)
	}
	if adv.SuggestedHy2Down > 100 {
		t.Errorf("expected conservative hy2.down for severe loss, got %d", adv.SuggestedHy2Down)
	}
}

func TestApplyHy2Config_PreservesComments(t *testing.T) {
	rawYaml := `# Main configuration
subs:
  - name: "main" # primary sub
    url: "https://example.com"

# Bandwidth settings for Hysteria 2
hy2:
  up: 10 # upload speed
  down: 100 # download speed
`
	tmpFile, err := os.CreateTemp("", "singctl_test_hy2_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if err := os.WriteFile(tmpFile.Name(), []byte(rawYaml), 0600); err != nil {
		t.Fatal(err)
	}

	// Apply updated bandwidth
	if err := ApplyHy2Config(tmpFile.Name(), 35, 250); err != nil {
		t.Fatalf("ApplyHy2Config failed: %v", err)
	}

	// Read updated file
	updatedData, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	content := string(updatedData)
	if !strings.Contains(content, "up: 35") {
		t.Errorf("expected up: 35 in updated file, got:\n%s", content)
	}
	if !strings.Contains(content, "down: 250") {
		t.Errorf("expected down: 250 in updated file, got:\n%s", content)
	}
	// Verify comments preserved
	if !strings.Contains(content, "# Bandwidth settings for Hysteria 2") {
		t.Errorf("expected comment preserved, got:\n%s", content)
	}

	// Load via config.Load to ensure valid parsing
	cfg, err := config.Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if cfg.Hy2.Up != 35 || cfg.Hy2.Down != 250 {
		t.Errorf("expected Hy2 {35, 250}, got %+v", cfg.Hy2)
	}
}

func TestGetCarrierBuyingGuide(t *testing.T) {
	guide := GetCarrierBuyingGuide()
	if !strings.Contains(guide, "中国电信") || !strings.Contains(guide, "CN2 GIA") {
		t.Errorf("guide missing key elements: %s", guide)
	}
}
