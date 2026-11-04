package fleet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/subhub"
)

func TestFleetLifecycleAndSubHubAutoSync(t *testing.T) {
	tmpDir := t.TempDir()
	fleetPath := filepath.Join(tmpDir, "fleet.yaml")
	fleetStore := NewStore(fleetPath)
	subStore := subhub.NewStore(filepath.Join(tmpDir, "sub-store"), "")

	// Reject dangerous hostnames (SSH option injection defense)
	if _, err := fleetStore.Upsert(UpsertInput{
		ID:       "bad",
		Host:     "-oProxyCommand=evil",
		AuthType: AuthSSHAlias,
	}); err == nil {
		t.Fatal("expected leading '-' host/alias to be rejected")
	}

	node, err := fleetStore.Upsert(UpsertInput{
		ID:         "us-lax",
		Name:       "美西洛杉矶",
		Host:       "203.0.113.10",
		Port:       2222,
		User:       "root",
		AuthType:   AuthInlineKey,
		PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\ntestkey\n-----END OPENSSH PRIVATE KEY-----",
	})
	if err != nil {
		t.Fatalf("Upsert fleet node failed: %v", err)
	}

	// Verify human-readable YAML format + 0600 permissions
	rawYAML, err := os.ReadFile(fleetPath)
	if err != nil {
		t.Fatalf("read fleet.yaml failed: %v", err)
	}
	if !strings.Contains(string(rawYAML), "auth_type: inline_key") || !strings.Contains(string(rawYAML), "id: us-lax") {
		t.Fatalf("expected human-readable fleet.yaml content, got:\n%s", string(rawYAML))
	}
	st, err := os.Stat(fleetPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected fleet.yaml mode 0600, got %v", st.Mode().Perm())
	}

	// Ensure PublicView strips sensitive key paths & passwords
	pub := node.PublicView()
	if !pub.HasCredential || pub.KeyPath != "" || pub.Password != "" {
		t.Fatalf("PublicView leaked credentials: %+v", pub)
	}

	remoteSubDoc, _ := json.Marshal(map[string]any{
		"subs": []map[string]any{
			{
				"name":    "auto_generated_hy2",
				"content": "hysteria2://pass-lax@lax.example.com:443?sni=lax.example.com#LAX-HY2",
			},
			{
				"name":    "auto_generated_vless",
				"content": "vless://11111111-1111-1111-1111-111111111111@lax.example.com:443?encryption=none&security=reality&sni=swdist.apple.com&pbk=7abc8def9ghi0jkl1mno2pqr3stu4vwx5yz6ABC7DEF&sid=1a2b3c4d#LAX-Reality",
			},
		},
	})
	b64Doc := base64.StdEncoding.EncodeToString(remoteSubDoc)

	mgr := NewManager(fleetStore, subStore)
	mgr.Runner = func(ctx context.Context, n Node, script string) (string, int, error) {
		switch {
		case strings.Contains(script, "SINGCTL_SUB_B64="):
			return "SINGCTL_VER=SingCtl v1.14.32\nSINGCTL_LOAD=0.08 0.05 0.01\nSINGCTL_MEM=36.5\nSINGCTL_CC=bbr\nSINGCTL_SUB_B64=" + b64Doc + "\n", 42, nil
		case strings.Contains(script, "singctl sr doctor"):
			return "体检时间: 2026-11-04 | 综合健康指数: 100 / 100\n[✓] 一切正常", 38, nil
		default:
			return "OK", 35, nil
		}
	}

	ctx := t.Context()
	syncRes := mgr.SyncNode(ctx, "us-lax")
	if !syncRes.Success || syncRes.SyncedNodes != 2 || syncRes.SingctlVersion != "v1.14.32" {
		t.Fatalf("unexpected SyncNode result: %+v", syncRes)
	}

	bundle, err := subStore.ResolveCollection(ctx, "all")
	if err != nil {
		t.Fatalf("ResolveCollection failed: %v", err)
	}
	if len(bundle.Nodes) != 2 {
		t.Fatalf("expected 2 nodes synced into Master SubHub, got %d", len(bundle.Nodes))
	}

	docResults, err := mgr.RunAcross(ctx, "doctor", nil)
	if err != nil || len(docResults) != 1 || docResults[0].DoctorScore != 100 {
		t.Fatalf("unexpected fleet doctor result: %+v err=%v", docResults, err)
	}

	if err := mgr.RemoveNode("us-lax"); err != nil {
		t.Fatalf("RemoveNode failed: %v", err)
	}
	sources, _ := subStore.ListSources()
	for _, s := range sources {
		if s.Name == "fleet_us-lax" {
			t.Fatal("expected fleet_us-lax to be removed from SubHub when fleet node is deleted")
		}
	}
}

func TestLegacyFleetJSONAutoMigration(t *testing.T) {
	tmpDir := t.TempDir()
	legacyJSON := filepath.Join(tmpDir, "fleet.json")
	targetYAML := filepath.Join(tmpDir, "fleet.yaml")

	legacyContent := `{
  "version": "1",
  "nodes": [
    {
      "id": "san",
      "name": "美西圣何塞-RN1",
      "host": "198.51.100.20",
      "port": 2222,
      "user": "root",
      "authType": "key_file",
      "keyPath": "/etc/singctl/fleet_keys/master_ed25519",
      "enabled": true,
      "online": true,
      "latencyMs": 13,
      "singctlVersion": "v1.14.32",
      "doctorScore": 100,
      "syncedNodes": 2,
      "protocols": ["hy2", "vless_reality"]
    }
  ]
}`
	if err := os.WriteFile(legacyJSON, []byte(legacyContent), 0600); err != nil {
		t.Fatalf("write legacy fleet.json failed: %v", err)
	}

	store := NewStore(targetYAML)
	nodes, err := store.List()
	if err != nil || len(nodes) != 1 {
		t.Fatalf("expected 1 migrated node, got %d (err=%v)", len(nodes), err)
	}
	n := nodes[0]
	if n.ID != "san" || n.AuthType != AuthKeyFile || n.Port != 2222 || n.DoctorScore != 100 || n.SyncedNodes != 2 {
		t.Fatalf("legacy camelCase fields lost during migration: %+v", n)
	}
	if _, err := os.Stat(targetYAML); err != nil {
		t.Fatalf("expected fleet.yaml to be created: %v", err)
	}
	if _, err := os.Stat(legacyJSON); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected legacy fleet.json to be removed after migration")
	}
}

func TestBootstrapNodeSSHHardeningAndRollback(t *testing.T) {
	tmpDir := t.TempDir()
	fleetPath := filepath.Join(tmpDir, "fleet.yaml")
	fleetStore := NewStore(fleetPath)
	subStore := subhub.NewStore(filepath.Join(tmpDir, "sub-store"), "")

	remoteSubDoc, _ := json.Marshal(map[string]any{
		"subs": []map[string]any{
			{
				"name":    "auto_generated_hy2",
				"content": "hysteria2://pass-jp@jp.example.com:443?sni=jp.example.com#JP-HY2",
			},
		},
	})
	b64Doc := base64.StdEncoding.EncodeToString(remoteSubDoc)

	mgr := NewManager(fleetStore, subStore)

	// Case 1: Cloud firewall blocks port 2222 -> external verify fails -> auto-rollback triggered, server NOT locked out!
	rollbackCalled := false
	mgr.Runner = func(ctx context.Context, n Node, script string) (string, int, error) {
		if strings.Contains(script, "SINGCTL_FLEET_SSH_VERIFIED") {
			return "", 0, errors.New("dial tcp 203.0.113.88:2222: i/o timeout")
		}
		if strings.Contains(script, "PasswordAuthentication yes") {
			rollbackCalled = true
		}
		return "OK", 20, nil
	}

	ctx := t.Context()
	failRes, err := mgr.BootstrapNode(ctx, BootstrapInput{
		UpsertInput: UpsertInput{
			ID:       "jp-blocked",
			Name:     "日本东京",
			Host:     "203.0.113.88",
			Port:     22,
			User:     "root",
			Password: "InitialRootPassword!",
		},
		NodeDomain: "jp.example.com",
		CFDNSKey:   "cf-test-token",
	})
	if err != nil {
		t.Fatalf("unexpected error return: %v", err)
	}
	if failRes.Success || !rollbackCalled {
		t.Fatalf("expected bootstrap failure with automatic sshd rollback, got res=%+v rollback=%v", failRes, rollbackCalled)
	}

	// Case 2: Happy path -> port 22 + password converges to 2222 + master_ed25519 key, password wiped from fleet.yaml!
	var sawDualPort, sawVerify2222, sawFinalize2222, sawInstallOn2222 bool
	mgr.Runner = func(ctx context.Context, n Node, script string) (string, int, error) {
		switch {
		case strings.Contains(script, "PasswordAuthentication no"):
			if n.Port != 2222 || n.AuthType != AuthKeyFile {
				t.Fatalf("finalize stage expected port 2222 + key_file, got %+v", n)
			}
			sawFinalize2222 = true
			return "OK", 18, nil
		case strings.Contains(script, "Port 22\nPort 2222"):
			if n.Port != 22 || n.AuthType != AuthPassword {
				t.Fatalf("stage 1 expected initial port 22 + password, got %+v", n)
			}
			sawDualPort = true
			return "OK", 25, nil
		case strings.Contains(script, "SINGCTL_FLEET_SSH_VERIFIED"):
			if n.Port != 2222 || n.AuthType != AuthKeyFile || n.Password != "" {
				t.Fatalf("verify stage expected port 2222 + key_file + empty password, got %+v", n)
			}
			sawVerify2222 = true
			return "SINGCTL_FLEET_SSH_VERIFIED\n", 18, nil
		case strings.Contains(script, "singctl sr install"):
			if n.Port != 2222 || n.AuthType != AuthKeyFile || n.Password != "" {
				t.Fatalf("install stage expected hardened 2222 key_file node, got %+v", n)
			}
			sawInstallOn2222 = true
			return "OK", 22, nil
		case strings.Contains(script, "SINGCTL_SUB_B64="):
			return "SINGCTL_VER=SingCtl v1.14.33\nSINGCTL_LOAD=0.05 0.03 0.01\nSINGCTL_MEM=28.0\nSINGCTL_CC=bbr\nSINGCTL_SUB_B64=" + b64Doc + "\n", 18, nil
		default:
			return "OK", 18, nil
		}
	}

	okRes, err := mgr.BootstrapNode(ctx, BootstrapInput{
		UpsertInput: UpsertInput{
			ID:       "jp",
			Name:     "日本东京",
			Host:     "203.0.113.99",
			Port:     22,
			User:     "root",
			Password: "InitialSecretRootPassword!",
		},
		NodeDomain:          "jp.example.com",
		CFDNSKey:            "cf-test-token",
		ExtraAuthorizedKeys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+H8W1t2aB3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r operator-mac",
	})
	if err != nil || !okRes.Success || okRes.SyncedNodes != 1 {
		t.Fatalf("expected full bootstrap success, got res=%+v err=%v", okRes, err)
	}
	if !sawDualPort || !sawVerify2222 || !sawFinalize2222 || !sawInstallOn2222 {
		t.Fatalf("missing expected SSH hardening stages: dual=%v verify=%v finalize=%v install=%v",
			sawDualPort, sawVerify2222, sawFinalize2222, sawInstallOn2222)
	}

	rawFleet, _ := os.ReadFile(fleetPath)
	if strings.Contains(string(rawFleet), "InitialSecretRootPassword!") {
		t.Fatalf("SECURITY FAILURE: plaintext bootstrap password leaked into fleet.yaml:\n%s", string(rawFleet))
	}
	savedNode, ok, _ := fleetStore.Get("jp")
	if !ok || savedNode.Port != 2222 || savedNode.AuthType != AuthKeyFile || savedNode.Password != "" {
		t.Fatalf("expected saved node on port 2222 + key_file with wiped password, got %+v", savedNode)
	}
}
