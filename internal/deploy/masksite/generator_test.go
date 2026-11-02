package masksite

import (
	"os"
	"strings"
	"testing"
)

func TestGenerateSite(t *testing.T) {
	html, meta, err := GenerateSite()
	if err != nil {
		t.Fatalf("GenerateSite failed: %v", err)
	}

	if html == "" {
		t.Fatalf("Expected non-empty HTML")
	}
	if meta.BlogTitle == "" {
		t.Errorf("Expected non-empty BlogTitle")
	}
	if meta.AuthorName == "" {
		t.Errorf("Expected non-empty AuthorName")
	}
	if meta.Category == "" {
		t.Errorf("Expected non-empty Category")
	}
	if len(meta.Articles) < 3 {
		t.Errorf("Expected at least 3 articles, got %d", len(meta.Articles))
	}

	if !strings.Contains(html, meta.BlogTitle) {
		t.Errorf("HTML should contain blog title %q", meta.BlogTitle)
	}
	if !strings.Contains(html, meta.AuthorName) {
		t.Errorf("HTML should contain author name %q", meta.AuthorName)
	}
	if !strings.Contains(html, "modal-overlay") {
		t.Errorf("HTML should contain modal overlay reader")
	}
	if !strings.Contains(html, "data-theme") {
		t.Errorf("HTML should contain theme toggle")
	}
}

func TestGenerateAndWrite(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "masksite-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	meta, err := GenerateAndWrite(tmpDir)
	if err != nil {
		t.Fatalf("GenerateAndWrite failed: %v", err)
	}

	indexPath := tmpDir + "/index.html"
	content, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("Failed to read index.html: %v", err)
	}

	if !strings.Contains(string(content), meta.BlogTitle) {
		t.Errorf("index.html should contain blog title")
	}

	existingMeta := ReadExistingMeta(tmpDir)
	if existingMeta == "" || !strings.Contains(existingMeta, meta.BlogTitle) {
		t.Errorf("mask_meta.json should contain blog title")
	}
}

func TestHighEntropy(t *testing.T) {
	titles := make(map[string]bool)
	for i := 0; i < 10; i++ {
		_, meta, err := GenerateSite()
		if err != nil {
			t.Fatalf("GenerateSite failed at iteration %d: %v", i, err)
		}
		titles[meta.BlogTitle+"-"+meta.AuthorName] = true
	}
	// Across 10 generations, we should definitely have multiple unique combinations
	if len(titles) < 3 {
		t.Errorf("Expected high diversity, but only got %d unique combinations across 10 generations", len(titles))
	}
}
