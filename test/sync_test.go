package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/cmd"
	"singctl/internal/config"
	"singctl/internal/deploy"
)

// TestSyncServerCmd_Registered verifies that the sync subcommand is registered with aliases ss and sync-substore.
func TestSyncServerCmd_Registered(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	if serverCmd == nil {
		t.Fatal("expected NewServerCmd to return non-nil")
	}

	var syncCmdFound bool
	for _, sub := range serverCmd.Commands() {
		if sub.Name() == "sync" {
			syncCmdFound = true
			expectedAliases := []string{"ss", "sync-substore"}
			for _, expected := range expectedAliases {
				hasAlias := false
				for _, alias := range sub.Aliases {
					if alias == expected {
						hasAlias = true
						break
					}
				}
				if !hasAlias {
					t.Errorf("expected alias %s not found in %v", expected, sub.Aliases)
				}
			}

			// Bilingual check
			if !strings.Contains(sub.Short, "/") {
				t.Errorf("expected bilingual Short description containing '/', got: %q", sub.Short)
			}
			break
		}
	}
	if !syncCmdFound {
		t.Error("expected 'sync' subcommand to be registered in server command")
	}
}

// TestSyncServerCmd_RestartFlag verifies that the --restart / -r flag is present and defaults to true.
func TestSyncServerCmd_RestartFlag(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	syncCmd := cmd.NewSyncServerCmd(configPath)
	flag := syncCmd.Flags().Lookup("restart")
	if flag == nil {
		t.Fatal("expected 'restart' flag on sync command")
	}
	if flag.Shorthand != "r" {
		t.Errorf("expected shorthand 'r' for restart flag, got %q", flag.Shorthand)
	}
	if flag.DefValue != "true" {
		t.Errorf("expected default value 'true' for restart flag, got %q", flag.DefValue)
	}
}

// TestSyncServerCmd_InvalidTarget verifies that sync rejects unknown targets.
func TestSyncServerCmd_InvalidTarget(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	syncCmd := cmd.NewSyncServerCmd(configPath)
	syncCmd.SetArgs([]string{"invalid_target"})
	err := syncCmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown target, got nil")
	}
	if !strings.Contains(err.Error(), "unknown target") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestSync_LoadExistingCredentialsAndSyncSubstore verifies end-to-end credential loading and substore writing.
func TestSync_LoadExistingCredentialsAndSyncSubstore(t *testing.T) {
	tempDir := t.TempDir()
	sbConfigFile := filepath.Join(tempDir, "config.json")
	substoreFile := filepath.Join(tempDir, "sub-store.json")

	// Mock deployed sing-box config with specific UUID, private_key, short_id
	const testUUID = "11111111-2222-3333-4444-555555555555"
	const testPrivKey = "uLpIe_G30f3L8v5F0T3C8W7N2M1K4H6B9Z0X5V2P1E8"
	const testShortID = "abcd1234ef567890"

	mockSingBoxConfig := `{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "listen_port": 8443,
      "users": [
        {
          "uuid": "` + testUUID + `",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "swdist.apple.com",
        "reality": {
          "enabled": true,
          "private_key": "` + testPrivKey + `",
          "short_id": [
            "` + testShortID + `"
          ]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "HYSTERIA2",
      "listen": "127.0.0.1",
      "listen_port": 52021,
      "users": [
        {
          "password": "` + testUUID + `"
        }
      ]
    }
  ]
}`
	if err := os.WriteFile(sbConfigFile, []byte(mockSingBoxConfig), 0644); err != nil {
		t.Fatalf("failed to write mock sing-box config: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "ssr.example.com",
			Sni:      "swdist.apple.com",
		},
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}
	sbs.ConfigFile = sbConfigFile

	// 1. Load existing credentials
	if err := sbs.LoadExistingCredentials(); err != nil {
		t.Fatalf("LoadExistingCredentials failed: %v", err)
	}

	// 2. Verify share links were updated to reflect the loaded credentials
	if !strings.Contains(sbs.ShareLinkHy2, testUUID) {
		t.Errorf("ShareLinkHy2 does not contain expected UUID: %s", sbs.ShareLinkHy2)
	}
	if !strings.Contains(sbs.ShareLinkVless, testUUID) {
		t.Errorf("ShareLinkVless does not contain expected UUID: %s", sbs.ShareLinkVless)
	}
	if !strings.Contains(sbs.ShareLinkVless, testShortID) {
		t.Errorf("ShareLinkVless does not contain expected short ID: %s", sbs.ShareLinkVless)
	}
	if !strings.Contains(sbs.ShareLinkTuic, testUUID) {
		t.Errorf("ShareLinkTuic does not contain expected UUID: %s", sbs.ShareLinkTuic)
	}

	// 3. Sync to Sub-Store config
	sbt := deploy.NewSubstore(cfg, "")
	sbt.SubstorePath = substoreFile
	sbt.SkipRestart = true

	if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
		t.Fatalf("UpdateSubstoreConfig failed: %v", err)
	}

	// 4. Read back substore json and verify contents
	data, err := os.ReadFile(substoreFile)
	if err != nil {
		t.Fatalf("failed to read substore file: %v", err)
	}

	var substoreMap map[string]interface{}
	if err := json.Unmarshal(data, &substoreMap); err != nil {
		t.Fatalf("failed to parse substore json: %v", err)
	}

	subs, ok := substoreMap["subs"].([]interface{})
	if !ok || len(subs) == 0 {
		t.Fatalf("expected non-empty subs in substore json")
	}

	var foundHy2, foundVless, foundTuic bool
	for _, s := range subs {
		subObj, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := subObj["name"].(string)
		content, _ := subObj["content"].(string)

		if name == "auto_generated_hy2" {
			foundHy2 = true
			if !strings.Contains(content, testUUID) {
				t.Errorf("auto_generated_hy2 missing UUID in content: %s", content)
			}
		}
		if name == "auto_generated_vless" {
			foundVless = true
			if !strings.Contains(content, testUUID) {
				t.Errorf("auto_generated_vless missing UUID in content: %s", content)
			}
			if !strings.Contains(content, testShortID) {
				t.Errorf("auto_generated_vless missing ShortID in content: %s", content)
			}
		}
		if name == "auto_generated_tuic" {
			foundTuic = true
			if !strings.Contains(content, testUUID) {
				t.Errorf("auto_generated_tuic missing UUID in content: %s", content)
			}
		}
	}

	if !foundHy2 {
		t.Error("expected auto_generated_hy2 in substore subs")
	}
	if !foundVless {
		t.Error("expected auto_generated_vless in substore subs")
	}
	if !foundTuic {
		t.Error("expected auto_generated_tuic in substore subs")
	}
}

// TestSync_PreserveOtherNodesWhenSyncingCurrentVPS verifies that syncing a VPS only overwrites
// the current VPS's node information and preserves other VPS nodes in Sub-Store.
func TestSync_PreserveOtherNodesWhenSyncingCurrentVPS(t *testing.T) {
	tempDir := t.TempDir()
	substoreFile := filepath.Join(tempDir, "sub-store.json")

	// Pre-populate sub-store.json with an existing node from VPS-A
	const vpsA_Domain = "vps-a.example.com"
	const vpsA_Hy2 = "hysteria2://vps-a-uuid@" + vpsA_Domain + "/?sni=" + vpsA_Domain + "&alpn=h3&insecure=0#sec_vps-a_hy2"
	const vpsA_Vless = "vless://vps-a-uuid@" + vpsA_Domain + ":443?type=tcp&security=reality&sni=swdist.apple.com#sec_vps-a_vr"
	const vpsA_Tuic = "tuic://vps-a-uuid:vps-a-uuid@tuic." + vpsA_Domain + ":443/?sni=tuic." + vpsA_Domain + "&alpn=h3&congestion_control=bbr#sec_vps-a_tuic"

	initialSubstore := map[string]interface{}{
		"subs": []interface{}{
			map[string]interface{}{
				"name":        "auto_generated_hy2",
				"displayName": "Hysteria2 Auto",
				"content":     vpsA_Hy2,
			},
			map[string]interface{}{
				"name":        "auto_generated_vless",
				"displayName": "VLESS Reality Auto",
				"content":     vpsA_Vless,
			},
			map[string]interface{}{
				"name":        "auto_generated_tuic",
				"displayName": "TUIC Auto",
				"content":     vpsA_Tuic,
			},
		},
		"collections": []interface{}{
			map[string]interface{}{
				"name":          "all",
				"subscriptions": []interface{}{"auto_generated_hy2", "auto_generated_vless", "auto_generated_tuic"},
			},
		},
	}
	initialData, err := json.Marshal(initialSubstore)
	if err != nil {
		t.Fatalf("failed to marshal initial substore: %v", err)
	}
	if err := os.WriteFile(substoreFile, initialData, 0644); err != nil {
		t.Fatalf("failed to write initial substore: %v", err)
	}

	// Now sync VPS-B (the current VPS)
	cfgB := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "vps-b.example.com",
			Sni:      "swdist.apple.com",
		},
	}
	sbsB, err := deploy.NewSingBoxServer(cfgB)
	if err != nil {
		t.Fatalf("NewSingBoxServer for VPS-B failed: %v", err)
	}

	sbtB := deploy.NewSubstore(cfgB, "")
	sbtB.SubstorePath = substoreFile
	sbtB.SkipRestart = true

	if err := sbtB.UpdateSubstoreConfig(sbsB); err != nil {
		t.Fatalf("UpdateSubstoreConfig for VPS-B failed: %v", err)
	}

	// Verify both VPS-A and VPS-B exist
	dataB, err := os.ReadFile(substoreFile)
	if err != nil {
		t.Fatalf("failed to read substore after VPS-B sync: %v", err)
	}
	var resB struct {
		Subs []struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"subs"`
	}
	if err := json.Unmarshal(dataB, &resB); err != nil {
		t.Fatalf("failed to parse substore after VPS-B sync: %v", err)
	}

	for _, sub := range resB.Subs {
		lines := strings.Split(sub.Content, "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 lines in %s, got %d: %q", sub.Name, len(lines), sub.Content)
		}
		if lines[0] != vpsA_Hy2 && lines[0] != vpsA_Vless && lines[0] != vpsA_Tuic {
			t.Errorf("expected line 0 to preserve VPS-A node, got %q", lines[0])
		}
		if sub.Name == "auto_generated_hy2" && lines[1] != sbsB.ShareLinkHy2 {
			t.Errorf("expected line 1 to be VPS-B hy2 %q, got %q", sbsB.ShareLinkHy2, lines[1])
		}
		if sub.Name == "auto_generated_vless" && lines[1] != sbsB.ShareLinkVless {
			t.Errorf("expected line 1 to be VPS-B vless %q, got %q", sbsB.ShareLinkVless, lines[1])
		}
		if sub.Name == "auto_generated_tuic" && lines[1] != sbsB.ShareLinkTuic {
			t.Errorf("expected line 1 to be VPS-B tuic %q, got %q", sbsB.ShareLinkTuic, lines[1])
		}
	}

	// Now re-sync VPS-B with regenerated credentials (testing overwrite of current VPS only)
	if err := sbsB.RegenerateCredentials(); err != nil {
		t.Fatalf("RegenerateCredentials for VPS-B failed: %v", err)
	}
	if err := sbtB.UpdateSubstoreConfig(sbsB); err != nil {
		t.Fatalf("second UpdateSubstoreConfig for VPS-B failed: %v", err)
	}

	dataB2, err := os.ReadFile(substoreFile)
	if err != nil {
		t.Fatalf("failed to read substore after second sync: %v", err)
	}
	if err := json.Unmarshal(dataB2, &resB); err != nil {
		t.Fatalf("failed to parse substore after second sync: %v", err)
	}

	for _, sub := range resB.Subs {
		lines := strings.Split(sub.Content, "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 lines in %s after second sync, got %d", sub.Name, len(lines))
		}
		// VPS-A MUST still be preserved!
		if lines[0] != vpsA_Hy2 && lines[0] != vpsA_Vless && lines[0] != vpsA_Tuic {
			t.Errorf("VPS-A node was overwritten! line 0: %q", lines[0])
		}
		// VPS-B MUST be updated to the new credentials
		if sub.Name == "auto_generated_hy2" && lines[1] != sbsB.ShareLinkHy2 {
			t.Errorf("VPS-B hy2 was not updated! line 1: %q, expected: %q", lines[1], sbsB.ShareLinkHy2)
		}
		if sub.Name == "auto_generated_vless" && lines[1] != sbsB.ShareLinkVless {
			t.Errorf("VPS-B vless was not updated! line 1: %q, expected: %q", lines[1], sbsB.ShareLinkVless)
		}
		if sub.Name == "auto_generated_tuic" && lines[1] != sbsB.ShareLinkTuic {
			t.Errorf("VPS-B tuic was not updated! line 1: %q, expected: %q", lines[1], sbsB.ShareLinkTuic)
		}
	}
}

// TestInfoServerCmd_Registered verifies that the info subcommand is registered in server command.
func TestInfoServerCmd_Registered(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	if serverCmd == nil {
		t.Fatal("expected NewServerCmd to return non-nil")
	}

	found := false
	for _, sub := range serverCmd.Commands() {
		if sub.Name() == "info" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'info' subcommand to be registered in server command")
	}
}
