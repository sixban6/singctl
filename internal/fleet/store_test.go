package fleet

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFleetStore_TableDrivenBoundaries(t *testing.T) {
	t.Run("legacy_json_migration_and_malformed_rejection", func(t *testing.T) {
		tmpDir := t.TempDir()
		legacyJSON := filepath.Join(tmpDir, "fleet.json")
		yamlPath := filepath.Join(tmpDir, "fleet.yaml")

		seed := `{
			"version": "1",
			"nodes": [
				{"id": "jp1", "name": "Tokyo", "host": "198.51.100.10", "port": 22, "user": "root", "authType": "password", "password": "test-password", "enabled": true}
			]
		}`
		if err := os.WriteFile(legacyJSON, []byte(seed), 0644); err != nil {
			t.Fatal(err)
		}

		store := NewStore(yamlPath)
		nodes, err := store.ListPublic()
		if err != nil {
			t.Fatalf("ListPublic failed: %v", err)
		}
		if len(nodes) != 1 || nodes[0].ID != "jp1" || !nodes[0].HasCredential || nodes[0].Password != "" {
			t.Fatalf("unexpected migrated public node: %+v", nodes)
		}

		// legacy file must have been removed after yaml migration, and fleet.yaml must be 0600
		if _, err := os.Stat(legacyJSON); !os.IsNotExist(err) {
			t.Fatalf("expected legacy fleet.json removed, stat err=%v", err)
		}
		fi, err := os.Stat(yamlPath)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("expected fleet.yaml mode 0600, got %v (err=%v)", fi.Mode().Perm(), err)
		}

		if _, err := parseFleetBytes([]byte(":\n  - [corrupt"), yamlPath); err == nil {
			t.Fatalf("expected corrupt YAML error")
		}
		if empty, err := parseFleetBytes([]byte("  \n"), yamlPath); err != nil || len(empty) != 0 {
			t.Fatalf("expected empty bytes to return empty slice, got len=%d err=%v", len(empty), err)
		}
	})

	t.Run("host_injection_and_invalid_auth_boundaries", func(t *testing.T) {
		store := NewStore(filepath.Join(t.TempDir(), "fleet.yaml"))

		invalidInputs := []UpsertInput{
			{ID: "bad node!", Host: "198.51.100.1"},
			{ID: "us1", Host: "-oProxyCommand=evil"},
			{ID: "us1", Host: "198.51.100.1;rm -rf /"},
			{ID: "us1", Host: "198.51.100.1", User: "root`id`"},
			{ID: "us1", Host: "198.51.100.1", AuthType: AuthInlineKey}, // missing PrivateKey
			{ID: "us1", Host: "198.51.100.1", AuthType: AuthPassword},  // missing Password
			{ID: "us1", Host: "198.51.100.1", AuthType: "kerberos"},    // unsupported auth type
		}
		for i, in := range invalidInputs {
			if _, err := store.Upsert(in); err == nil {
				t.Errorf("case[%d] expected Upsert error for %+v, got nil", i, in)
			}
		}
	})

	t.Run("all_auth_strategies_0600_and_custom_registry_extension", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewStore(filepath.Join(tmpDir, "fleet.yaml"))

		// 1. inline_key writes 0700 dir + 0600 .pem and PublicView masks KeyPath
		nInline, err := store.Upsert(UpsertInput{
			ID:         "n1",
			Host:       "198.51.100.11",
			AuthType:   AuthInlineKey,
			PrivateKey: "MOCK-SSH-CREDENTIAL-MATERIAL-FOR-UNIT-TEST",
		})
		if err != nil {
			t.Fatalf("inline_key Upsert failed: %v", err)
		}
		keyFI, err := os.Stat(nInline.KeyPath)
		if err != nil || keyFI.Mode().Perm() != 0600 {
			t.Fatalf("expected key file 0600, got %v (err=%v)", keyFI.Mode().Perm(), err)
		}
		dirFI, err := os.Stat(store.KeysDir)
		if err != nil || dirFI.Mode().Perm() != 0700 {
			t.Fatalf("expected KeysDir 0700, got %v (err=%v)", dirFI.Mode().Perm(), err)
		}
		if pub := nInline.PublicView(); pub.KeyPath != "" || !pub.HasCredential {
			t.Fatalf("expected PublicView to mask inline KeyPath, got %+v", pub)
		}

		// 2. ssh_alias, key_file, password
		if _, err := store.Upsert(UpsertInput{ID: "n2", SSHAlias: "vps-sg", AuthType: AuthSSHAlias}); err != nil {
			t.Fatalf("ssh_alias Upsert failed: %v", err)
		}
		if _, err := store.Upsert(UpsertInput{ID: "n3", Host: "node3.example.com", AuthType: AuthKeyFile, KeyPath: "/tmp/test_id_ed25519"}); err != nil {
			t.Fatalf("key_file Upsert failed: %v", err)
		}
		nPass, err := store.Upsert(UpsertInput{ID: "n4", Host: "203.0.113.44", AuthType: AuthPassword, Password: "test-password"})
		if err != nil {
			t.Fatalf("password Upsert failed: %v", err)
		}
		if pub := nPass.PublicView(); pub.Password != "" || !pub.HasCredential {
			t.Fatalf("expected PublicView to redact password, got %+v", pub)
		}

		// 3. Custom authCredentialApplier override (OCP)
		var target Node
		parsed, err := NormalizeUpsertInput(UpsertInput{ID: "n5", Host: "node5.example.com", AuthType: "custom_sso"})
		if err != nil {
			t.Fatal(err)
		}
		customRan := false
		err = applyAuthCredentialWithRegistry(store, parsed.ID, UpsertInput{}, parsed, &target, map[string]authCredentialApplier{
			"custom_sso": func(_ *Store, _ string, _ UpsertInput, p Node, dst *Node) error {
				customRan = true
				dst.Host = p.Host
				dst.SSHAlias = "sso-alias"
				return nil
			},
		})
		if err != nil || !customRan || target.SSHAlias != "sso-alias" {
			t.Fatalf("custom applier override failed: err=%v ran=%v target=%+v", err, customRan, target)
		}

		// 4. Delete inline_key shreds .pem
		if err := store.Delete("n1"); err != nil {
			t.Fatalf("Delete failed: %v", err)
		}
		if _, err := os.Stat(nInline.KeyPath); !os.IsNotExist(err) {
			t.Fatalf("expected deleted node pem removed, stat err=%v", err)
		}
	})

	t.Run("probe_coalescing_idempotency_and_concurrent_race", func(t *testing.T) {
		store := NewStore(filepath.Join(t.TempDir(), "fleet.yaml"))
		if _, err := store.Upsert(UpsertInput{ID: "hk1", Host: "198.51.100.99", AuthType: AuthPassword, Password: "test-password"}); err != nil {
			t.Fatal(err)
		}

		// Coalesced probe update still surfaces immediately via memory overlay on List()
		_, err := store.UpdateProbeRuntimeState("hk1", func(n *Node) {
			n.Online = true
			n.LatencyMs = 42
			n.LastProbeAt = "2026-11-21T10:00:00Z"
		}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		got, ok, err := store.Get("hk1")
		if err != nil || !ok || got.LatencyMs != 42 || !got.Online {
			t.Fatalf("unexpected Get after probe: ok=%v err=%v node=%+v", ok, err, got)
		}

		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = store.ListPublic()
				_, _ = store.UpdateProbeRuntimeState("hk1", func(n *Node) {
					n.LatencyMs = 35
					n.LastProbeAt = time.Now().UTC().Format(time.RFC3339)
				}, time.Hour)
			}()
		}
		wg.Wait()
	})
}
