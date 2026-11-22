// 文件职责：覆盖 Fleet 节点清单迁移、主机防注入校验、四类 SSH 凭据 0600 落盘与并发探针节流表驱动单测。
package fleet_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"singctl/internal/fleet"
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

		store := fleet.NewStore(yamlPath)
		nodes, err := store.ListPublic()
		if err != nil {
			t.Fatalf("ListPublic failed: %v", err)
		}
		if len(nodes) != 1 || nodes[0].ID != "jp1" || !nodes[0].HasCredential || nodes[0].Password != "" {
			t.Fatalf("unexpected migrated public node: %+v", nodes)
		}

		if _, err := os.Stat(legacyJSON); !os.IsNotExist(err) {
			t.Fatalf("expected legacy fleet.json removed, stat err=%v", err)
		}
		fi, err := os.Stat(yamlPath)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("expected fleet.yaml mode 0600, got %v (err=%v)", fi.Mode().Perm(), err)
		}

		if _, err := fleet.ParseFleetBytes([]byte(":\n  - [corrupt"), yamlPath); err == nil {
			t.Fatalf("expected corrupt YAML error")
		}
		if empty, err := fleet.ParseFleetBytes([]byte("  \n"), yamlPath); err != nil || len(empty) != 0 {
			t.Fatalf("expected empty bytes to return empty slice, got len=%d err=%v", len(empty), err)
		}
	})

	t.Run("host_injection_and_invalid_auth_boundaries", func(t *testing.T) {
		store := fleet.NewStore(filepath.Join(t.TempDir(), "fleet.yaml"))

		invalidInputs := []fleet.UpsertInput{
			{ID: "bad node!", Host: "198.51.100.1"},
			{ID: "us1", Host: "-oProxyCommand=evil"},
			{ID: "us1", Host: "198.51.100.1;rm -rf /"},
			{ID: "us1", Host: "198.51.100.1", User: "root`id`"},
			{ID: "us1", Host: "198.51.100.1", AuthType: fleet.AuthInlineKey},
			{ID: "us1", Host: "198.51.100.1", AuthType: fleet.AuthPassword},
			{ID: "us1", Host: "198.51.100.1", AuthType: "kerberos"},
		}
		for i, in := range invalidInputs {
			if _, err := store.Upsert(in); err == nil {
				t.Errorf("case[%d] expected Upsert error for %+v, got nil", i, in)
			}
		}
	})

	t.Run("all_auth_strategies_0600_and_custom_registry_extension", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := fleet.NewStore(filepath.Join(tmpDir, "fleet.yaml"))

		nInline, err := store.Upsert(fleet.UpsertInput{
			ID:         "n1",
			Host:       "198.51.100.11",
			AuthType:   fleet.AuthInlineKey,
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

		if _, err := store.Upsert(fleet.UpsertInput{ID: "n2", SSHAlias: "vps-sg", AuthType: fleet.AuthSSHAlias}); err != nil {
			t.Fatalf("ssh_alias Upsert failed: %v", err)
		}
		if _, err := store.Upsert(fleet.UpsertInput{ID: "n3", Host: "node3.example.com", AuthType: fleet.AuthKeyFile, KeyPath: "/tmp/test_id_ed25519"}); err != nil {
			t.Fatalf("key_file Upsert failed: %v", err)
		}
		nPass, err := store.Upsert(fleet.UpsertInput{ID: "n4", Host: "203.0.113.44", AuthType: fleet.AuthPassword, Password: "test-password"})
		if err != nil {
			t.Fatalf("password Upsert failed: %v", err)
		}
		if pub := nPass.PublicView(); pub.Password != "" || !pub.HasCredential {
			t.Fatalf("expected PublicView to redact password, got %+v", pub)
		}

		var target fleet.Node
		parsed, err := fleet.NormalizeUpsertInput(fleet.UpsertInput{ID: "n5", Host: "node5.example.com", AuthType: "custom_sso"})
		if err != nil {
			t.Fatal(err)
		}
		customRan := false
		err = fleet.ApplyAuthCredentialWithRegistry(store, parsed.ID, fleet.UpsertInput{}, parsed, &target, map[string]fleet.AuthCredentialApplier{
			"custom_sso": func(_ *fleet.Store, _ string, _ fleet.UpsertInput, p fleet.Node, dst *fleet.Node) error {
				customRan = true
				dst.Host = p.Host
				dst.SSHAlias = "sso-alias"
				return nil
			},
		})
		if err != nil || !customRan || target.SSHAlias != "sso-alias" {
			t.Fatalf("custom applier override failed: err=%v ran=%v target=%+v", err, customRan, target)
		}

		if err := store.Delete("n1"); err != nil {
			t.Fatalf("Delete failed: %v", err)
		}
		if _, err := os.Stat(nInline.KeyPath); !os.IsNotExist(err) {
			t.Fatalf("expected deleted node pem removed, stat err=%v", err)
		}
	})

	t.Run("probe_coalescing_idempotency_and_concurrent_race", func(t *testing.T) {
		store := fleet.NewStore(filepath.Join(t.TempDir(), "fleet.yaml"))
		if _, err := store.Upsert(fleet.UpsertInput{ID: "hk1", Host: "198.51.100.99", AuthType: fleet.AuthPassword, Password: "test-password"}); err != nil {
			t.Fatal(err)
		}

		_, err := store.UpdateProbeRuntimeState("hk1", func(n *fleet.Node) {
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
				_, _ = store.UpdateProbeRuntimeState("hk1", func(n *fleet.Node) {
					n.LatencyMs = 35
					n.LastProbeAt = time.Now().UTC().Format(time.RFC3339)
				}, time.Hour)
			}()
		}
		wg.Wait()
	})
}
