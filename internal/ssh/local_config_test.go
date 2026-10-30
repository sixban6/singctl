package ssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalConfigManager_SyncAndClean(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config")

	// Pre-populate with existing user config
	userOriginalConfig := `
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/github_key
`
	if err := os.WriteFile(configPath, []byte(userOriginalConfig), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	mgr := NewLocalConfigManager(configPath)

	hosts := []*Host{
		{
			Name:       "node-a",
			IP:         "10.0.0.1",
			User:       "root",
			TargetPort: 2222,
			PrivateKey: "/path/to/key",
		},
		{
			Name:       "node-b",
			IP:         "10.0.0.2",
			User:       "ubuntu",
			TargetPort: 22222,
			PrivateKey: "/path/to/key2",
		},
	}

	// 1. Sync hosts
	if err := mgr.SyncHosts(hosts); err != nil {
		t.Fatalf("SyncHosts failed: %v", err)
	}

	// Check content contains both github.com and managed hosts
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "Host github.com") {
		t.Errorf("Expected original github.com entry to be preserved")
	}
	if !strings.Contains(content, "Host node-a") || !strings.Contains(content, "Port 2222") {
		t.Errorf("Expected node-a to be present with Port 2222")
	}
	if !strings.Contains(content, "Host node-b") || !strings.Contains(content, "Port 22222") {
		t.Errorf("Expected node-b to be present with Port 22222")
	}

	// 2. List managed hosts
	list, err := mgr.ListManagedHosts()
	if err != nil {
		t.Fatalf("ListManagedHosts failed: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("Expected 2 managed hosts, got %d", len(list))
	}

	// 3. Update node-a's port and sync again (In-place update check)
	hosts[0].TargetPort = 22224
	if err := mgr.SyncHosts(hosts); err != nil {
		t.Fatalf("Second SyncHosts failed: %v", err)
	}

	updatedData, _ := os.ReadFile(configPath)
	updatedContent := string(updatedData)
	if !strings.Contains(updatedContent, "Port 22224") {
		t.Errorf("Expected updated Port 22224 for node-a")
	}
	// Verify no duplicates
	if strings.Count(updatedContent, "Host node-a") != 1 {
		t.Errorf("Expected exactly one 'Host node-a', found multiple occurrences")
	}

	// 4. Clean only node-a
	cleanedCount, err := mgr.CleanManagedHosts("node-a")
	if err != nil || cleanedCount != 1 {
		t.Fatalf("Expected 1 host cleaned, got %d, err: %v", cleanedCount, err)
	}

	cleanedData, _ := os.ReadFile(configPath)
	cleanedContent := string(cleanedData)
	if strings.Contains(cleanedContent, "Host node-a") {
		t.Errorf("Expected node-a to be removed")
	}
	if !strings.Contains(cleanedContent, "Host node-b") {
		t.Errorf("Expected node-b to still remain")
	}
	if !strings.Contains(cleanedContent, "Host github.com") {
		t.Errorf("Expected original github.com to still remain")
	}

	// 5. Clean all
	cleanedAllCount, err := mgr.CleanManagedHosts("")
	if err != nil || cleanedAllCount != 1 {
		t.Fatalf("Expected 1 host cleaned, got %d, err: %v", cleanedAllCount, err)
	}
	finalData, _ := os.ReadFile(configPath)
	finalContent := string(finalData)
	if strings.Contains(finalContent, "BEGIN SINGCTL MANAGED HOST") {
		t.Errorf("Expected all singctl blocks to be cleaned")
	}
	if !strings.Contains(finalContent, "Host github.com") {
		t.Errorf("Expected original github.com to remain after all clean")
	}
}
