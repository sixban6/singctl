package test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"singctl/internal/cmd"
	"singctl/internal/fleet"
	"singctl/internal/heal"
	"singctl/internal/subhub"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFleetLifecycleAndSubHubAutoSync(t *testing.T) {
	tmpDir := t.TempDir()
	fleetPath := filepath.Join(tmpDir, "fleet.yaml")
	fleetStore := fleet.NewStore(fleetPath)
	subStore := subhub.NewStore(filepath.Join(tmpDir, "sub-store"), "")

	// Reject dangerous hostnames (SSH option injection defense)
	if _, err := fleetStore.Upsert(fleet.UpsertInput{
		ID:       "bad",
		Host:     "-oProxyCommand=evil",
		AuthType: fleet.AuthSSHAlias,
	}); err == nil {
		t.Fatal("expected leading '-' host/alias to be rejected")
	}

	node, err := fleetStore.Upsert(fleet.UpsertInput{
		ID:         "us-lax",
		Name:       "美西洛杉矶",
		Host:       "203.0.113.10",
		Port:       2222,
		User:       "root",
		AuthType:   fleet.AuthInlineKey,
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

	mgr := fleet.NewManager(fleetStore, subStore)
	mgr.Runner = func(ctx context.Context, n fleet.Node, script string) (string, int, error) {
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

	store := fleet.NewStore(targetYAML)
	nodes, err := store.List()
	if err != nil || len(nodes) != 1 {
		t.Fatalf("expected 1 migrated node, got %d (err=%v)", len(nodes), err)
	}
	n := nodes[0]
	if n.ID != "san" || n.AuthType != fleet.AuthKeyFile || n.Port != 2222 || n.DoctorScore != 100 || n.SyncedNodes != 2 {
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
	fleetStore := fleet.NewStore(fleetPath)
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

	mgr := fleet.NewManager(fleetStore, subStore)

	// Case 1: Cloud firewall blocks port 2222 -> external verify fails -> auto-rollback triggered, server NOT locked out!
	rollbackCalled := false
	mgr.Runner = func(ctx context.Context, n fleet.Node, script string) (string, int, error) {
		if strings.Contains(script, "SINGCTL_FLEET_SSH_VERIFIED") {
			return "", 0, errors.New("dial tcp 203.0.113.88:2222: i/o timeout")
		}
		if strings.Contains(script, "PasswordAuthentication yes") {
			rollbackCalled = true
		}
		return "OK", 20, nil
	}

	ctx := t.Context()
	failRes, err := mgr.BootstrapNode(ctx, fleet.BootstrapInput{
		UpsertInput: fleet.UpsertInput{
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
	mgr.Runner = func(ctx context.Context, n fleet.Node, script string) (string, int, error) {
		switch {
		case strings.Contains(script, "PasswordAuthentication no"):
			if n.Port != 2222 || n.AuthType != fleet.AuthKeyFile {
				t.Fatalf("finalize stage expected port 2222 + key_file, got %+v", n)
			}
			sawFinalize2222 = true
			return "OK", 18, nil
		case strings.Contains(script, "Port 22\nPort 2222"):
			if n.Port != 22 || n.AuthType != fleet.AuthPassword {
				t.Fatalf("stage 1 expected initial port 22 + password, got %+v", n)
			}
			sawDualPort = true
			return "OK", 25, nil
		case strings.Contains(script, "SINGCTL_FLEET_SSH_VERIFIED"):
			if n.Port != 2222 || n.AuthType != fleet.AuthKeyFile || n.Password != "" {
				t.Fatalf("verify stage expected port 2222 + key_file + empty password, got %+v", n)
			}
			sawVerify2222 = true
			return "SINGCTL_FLEET_SSH_VERIFIED\n", 18, nil
		case strings.Contains(script, "singctl sr install"):
			if n.Port != 2222 || n.AuthType != fleet.AuthKeyFile || n.Password != "" {
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

	okRes, err := mgr.BootstrapNode(ctx, fleet.BootstrapInput{
		UpsertInput: fleet.UpsertInput{
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
	if !ok || savedNode.Port != 2222 || savedNode.AuthType != fleet.AuthKeyFile || savedNode.Password != "" {
		t.Fatalf("expected saved node on port 2222 + key_file with wiped password, got %+v", savedNode)
	}
}

func TestZeroConfigBootstrapMasterInheritanceAndCloudflareDNS(t *testing.T) {
	tmpDir := t.TempDir()
	masterCfgPath := filepath.Join(tmpDir, "singctl.yaml")
	masterCfgYAML := `github:
  mirror_url: "https://mirror.example.com"
hy2:
  up: 80
  down: 500
server:
  node_tag: "los"
  node_domain: "cdn.l1.example.com"
  cf_dns_key: "cf-master-secret-token"
  sni: "itunes.apple.com"
`
	if err := os.WriteFile(masterCfgPath, []byte(masterCfgYAML), 0600); err != nil {
		t.Fatalf("write master singctl.yaml failed: %v", err)
	}

	// Mock Cloudflare API v4 server
	var mu sync.Mutex
	records := map[string]fleet.CFDNSRecord{
		// Pre-existing record pointing to a DIFFERENT IP -> must NEVER be overwritten!
		"rec-conflict": {
			ID:      "rec-conflict",
			Type:    "A",
			Name:    "sg2.cdn.example.com",
			Content: "198.51.100.77",
			Proxied: true,
		},
	}
	cfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cf-master-secret-token" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones") && !strings.Contains(r.URL.Path, "/dns_records"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result": []fleet.CFZone{
					{ID: "zone-example-1", Name: "example.com"},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/dns_records"):
			wantName := r.URL.Query().Get("name")
			var matched []fleet.CFDNSRecord
			for _, rec := range records {
				if rec.Name == wantName {
					matched = append(matched, rec)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": matched})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/dns_records"):
			var body struct {
				Type    string `json:"type"`
				Name    string `json:"name"`
				Content string `json:"content"`
				Proxied bool   `json:"proxied"`
				TTL     int    `json:"ttl"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Proxied {
				t.Errorf("SECURITY/AVAILABILITY BUG: Cloudflare DNS record created with proxied=true (orange cloud)!")
			}
			id := "rec-" + body.Name
			rec := fleet.CFDNSRecord{ID: id, Type: body.Type, Name: body.Name, Content: body.Content, Proxied: body.Proxied, TTL: body.TTL}
			records[id] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/dns_records/"):
			parts := strings.Split(r.URL.Path, "/")
			recID := parts[len(parts)-1]
			delete(records, recID)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": recID}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer cfSrv.Close()

	fleetStore := fleet.NewStore(filepath.Join(tmpDir, "fleet.yaml"))
	subStore := subhub.NewStore(filepath.Join(tmpDir, "sub-store"), "")
	mgr := fleet.NewManager(fleetStore, subStore)
	mgr.ConfigPath = masterCfgPath
	mgr.CFClient = &fleet.CloudflareDNSClient{BaseURL: cfSrv.URL, HTTPClient: cfSrv.Client()}
	mgr.GeoProber = func(ctx context.Context, host string) fleet.GeoInfo {
		return fleet.GeoInfo{Tag: "sg", CountryCode: "SG", City: "Singapore", DisplayName: "新加坡"}
	}

	var capturedYAML string
	mgr.Runner = func(ctx context.Context, n fleet.Node, script string) (string, int, error) {
		switch {
		case strings.Contains(script, "SINGCTL_FLEET_SSH_VERIFIED"):
			return "SINGCTL_FLEET_SSH_VERIFIED\n", 15, nil
		case strings.Contains(script, "singctl sr install"):
			// Extract base64 encoded singctl.yaml pushed to remote node
			for line := range strings.SplitSeq(script, "\n") {
				if strings.Contains(line, "base64 -d > /etc/singctl/singctl.yaml") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						b64 := strings.Trim(fields[2], `"'`)
						raw, _ := base64.StdEncoding.DecodeString(b64)
						capturedYAML = string(raw)
					}
				}
			}
			return "OK", 20, nil
		case strings.Contains(script, "SINGCTL_SUB_B64="):
			subDoc, _ := json.Marshal(map[string]any{
				"subs": []map[string]any{
					{"name": "auto_generated_hy2", "content": "hysteria2://p@" + n.Domain + ":443?sni=" + n.Domain + "#" + n.ID},
				},
			})
			return "SINGCTL_VER=SingCtl v1.14.34\nSINGCTL_SUB_B64=" + base64.StdEncoding.EncodeToString(subDoc) + "\n", 15, nil
		default:
			return "OK", 15, nil
		}
	}

	ctx := t.Context()

	// 1) Zero-config bootstrap #1: ONLY Host + Password provided!
	res1, err := mgr.BootstrapNode(ctx, fleet.BootstrapInput{
		UpsertInput: fleet.UpsertInput{
			Host:     "203.0.113.51",
			Password: "TempRootPassword1!",
		},
	})
	if err != nil || !res1.Success {
		t.Fatalf("zero-config bootstrap #1 failed: res=%+v err=%v", res1, err)
	}
	if res1.ID != "sg1" || res1.Name != "新加坡" {
		t.Fatalf("expected auto-GeoIP ID=sg1 Name=新加坡, got ID=%q Name=%q", res1.ID, res1.Name)
	}
	n1, ok, _ := fleetStore.Get("sg1")
	if !ok || n1.Domain != "sg1.cdn.example.com" || !n1.DNSAutoManaged {
		t.Fatalf("expected auto-provisioned domain sg1.cdn.example.com, got %+v", n1)
	}
	if !strings.Contains(capturedYAML, `sni: "itunes.apple.com"`) ||
		!strings.Contains(capturedYAML, `node_domain: "sg1.cdn.example.com"`) ||
		!strings.Contains(capturedYAML, `substore_domain: "sg1.cdn.example.com"`) ||
		!strings.Contains(capturedYAML, `up: 80`) ||
		!strings.Contains(capturedYAML, `cf_dns_key: "cf-master-secret-token"`) ||
		!strings.Contains(capturedYAML, `mirror_url: "https://mirror.example.com"`) {
		t.Fatalf("remote singctl.yaml did not inherit Master config:\n%s", capturedYAML)
	}

	preview2, err := mgr.PreviewBootstrapNode(ctx, fleet.BootstrapInput{
		UpsertInput: fleet.UpsertInput{Host: "203.0.113.52"},
	})
	if err != nil || preview2.ID != "sg2" || preview2.Domain != "sg2.cdn.example.com" {
		t.Fatalf("expected preview sg2 / sg2.cdn.example.com, got preview=%+v err=%v", preview2, err)
	}

	// 2) Zero-config bootstrap #2 in SAME country (Singapore):
	//    - ID auto-increments to "sg2", Name to "新加坡 #2"
	//    - Because "sg2.cdn.example.com" already points to 198.51.100.77 in Cloudflare, it MUST NOT overwrite it and must allocate "sg3.cdn.example.com"!
	res2, err := mgr.BootstrapNode(ctx, fleet.BootstrapInput{
		UpsertInput: fleet.UpsertInput{
			Host:     "203.0.113.52",
			Password: "TempRootPassword2!",
		},
	})
	if err != nil || !res2.Success {
		t.Fatalf("zero-config bootstrap #2 failed: res=%+v err=%v", res2, err)
	}
	if res2.ID != "sg2" || res2.Name != "新加坡 #2" {
		t.Fatalf("expected collision-free ID=sg2 Name='新加坡 #2', got ID=%q Name=%q", res2.ID, res2.Name)
	}
	n2, ok, _ := fleetStore.Get("sg2")
	if !ok || n2.Domain != "sg3.cdn.example.com" {
		t.Fatalf("expected DNS collision avoidance to pick sg3.cdn.example.com, got %+v", n2)
	}
	mu.Lock()
	if records["rec-conflict"].Content != "198.51.100.77" {
		t.Fatalf("CRITICAL: pre-existing DNS record sg2.cdn.example.com was overwritten!")
	}
	mu.Unlock()

	// 3) RemoveNodeWithOptions cleans up auto-managed DNS record ONLY if IP matches
	deletedDNS, err := mgr.RemoveNodeWithOptions(ctx, "sg1", false)
	if err != nil || !deletedDNS {
		t.Fatalf("expected RemoveNodeWithOptions to delete auto-managed DNS record sg1.cdn.example.com, got deleted=%v err=%v", deletedDNS, err)
	}
	mu.Lock()
	if _, exists := records["rec-sg1.cdn.example.com"]; exists {
		t.Fatalf("expected rec-sg1.cdn.example.com to be deleted from Cloudflare")
	}
	mu.Unlock()
}

func TestFleetHealSerialRollingRebootAndCircuitBreaker(t *testing.T) {
	tmpDir := t.TempDir()
	store := fleet.NewStore(filepath.Join(tmpDir, "fleet.yaml"))
	for _, spec := range []struct{ id, name, ip string }{
		{"n1", "节点一", "198.51.100.11"},
		{"n2", "节点二", "198.51.100.12"},
		{"n3", "节点三", "198.51.100.13"},
	} {
		_, err := store.Upsert(fleet.UpsertInput{
			ID:       spec.id,
			Name:     spec.name,
			Host:     spec.ip,
			Port:     2222,
			User:     "root",
			AuthType: fleet.AuthSSHAlias,
			SSHAlias: spec.id,
		})
		if err != nil {
			t.Fatalf("seed %s failed: %v", spec.id, err)
		}
	}

	mgr := fleet.NewManager(store, nil)

	// Scenario 1: All 3 nodes require kernel reboot -> MUST reboot strictly 1 at a time (never >=2 concurrently)
	var inFlightReboots atomic.Int32
	var maxConcurrentReboots atomic.Int32

	healJSON, _ := json.Marshal(heal.RunResult{
		Execution: heal.HealHistoryItem{Success: true, Summary: "已修复安全更新"},
		Status: heal.StatusReport{
			Posture: heal.PostureRebootRequired,
			Core: heal.CoreLayerStatus{
				Components: []heal.ComponentCheck{
					{Name: "singctl", CurrentVersion: "1.14.62"},
				},
			},
			Kernel: heal.KernelLayerStatus{RebootRequired: true},
		},
	})

	mgr.Runner = func(ctx context.Context, n fleet.Node, script string) (string, int, error) {
		switch {
		case strings.Contains(script, "singctl sr heal"):
			return string(healJSON), 12, nil
		case strings.Contains(script, "SINGCTL_REBOOT_TRIGGERED"):
			cur := inFlightReboots.Add(1)
			for {
				prev := maxConcurrentReboots.Load()
				if cur <= prev || maxConcurrentReboots.CompareAndSwap(prev, cur) {
					break
				}
			}
			return "SINGCTL_REBOOT_TRIGGERED\n", 10, nil
		case strings.Contains(script, "singctl sr doctor"):
			inFlightReboots.Add(-1)
			return "综合健康指数: 100 / 100\n", 15, nil
		default:
			return "OK", 10, nil
		}
	}

	rep1, err := mgr.HealFleet(t.Context(), fleet.FleetHealOptions{
		AllowReboot:           true,
		RebootPollInterval:    20 * time.Millisecond,
		RebootRecoveryTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("HealFleet scenario 1 failed: %v", err)
	}
	if maxConcurrentReboots.Load() != 1 {
		t.Fatalf("AVAILABILITY VIOLATION: expected strictly serial 1-by-1 reboot, got maxConcurrent=%d", maxConcurrentReboots.Load())
	}
	if rep1.RebootedNodes != 3 || rep1.CircuitBreakerHit {
		t.Fatalf("expected 3 rebooted healthy nodes with no circuit breaker, got %+v", rep1)
	}
	if n1, ok, _ := store.Get("n1"); !ok || n1.SingctlVersion != "v1.14.62" {
		t.Fatalf("expected HealFleet to persist updated worker SingctlVersion v1.14.62 into fleet.yaml, got %+v", n1)
	}

	// Scenario 2: n2 fails to come back healthy after reboot -> Circuit Breaker MUST abort rebooting n3!
	var n3RebootTriggered atomic.Bool
	mgr.Runner = func(ctx context.Context, n fleet.Node, script string) (string, int, error) {
		switch {
		case strings.Contains(script, "singctl sr heal"):
			return string(healJSON), 12, nil
		case strings.Contains(script, "SINGCTL_REBOOT_TRIGGERED"):
			if n.ID == "n3" {
				n3RebootTriggered.Store(true)
			}
			return "SINGCTL_REBOOT_TRIGGERED\n", 10, nil
		case strings.Contains(script, "singctl sr doctor"):
			if n.ID == "n2" {
				return "", 0, errors.New("ssh: connect to host 198.51.100.12 port 2222: Connection timed out")
			}
			return "综合健康指数: 100 / 100\n", 15, nil
		default:
			return "OK", 10, nil
		}
	}

	rep2, err := mgr.HealFleet(t.Context(), fleet.FleetHealOptions{
		AllowReboot:           true,
		RebootPollInterval:    20 * time.Millisecond,
		RebootRecoveryTimeout: 90 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("HealFleet scenario 2 failed: %v", err)
	}
	if !rep2.CircuitBreakerHit || n3RebootTriggered.Load() {
		t.Fatalf("CIRCUIT BREAKER FAILURE: expected abort after n2 failed, got hit=%v n3Rebooted=%v rep=%+v",
			rep2.CircuitBreakerHit, n3RebootTriggered.Load(), rep2)
	}
	if !rep2.Results[2].SkippedByCircuitBreaker {
		t.Fatalf("expected n3 to be marked SkippedByCircuitBreaker=true, got %+v", rep2.Results[2])
	}
}

func TestFleetHTTPSProbeAndPatrol(t *testing.T) {
	tmpDir := t.TempDir()
	store := fleet.NewStore(filepath.Join(tmpDir, "fleet.yaml"))

	var healthyFlag atomic.Bool
	healthyFlag.Store(true)
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthyFlag.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()

	srvHostPort := strings.TrimPrefix(tlsSrv.URL, "https://")
	if _, err := store.Upsert(fleet.UpsertInput{
		ID:       "sg1",
		Name:     "新加坡",
		Host:     srvHostPort, // pure IP:port exercises DefaultHTTPSProber end-to-end TLS handshake
		Port:     2222,
		User:     "root",
		AuthType: fleet.AuthKeyFile,
		KeyPath:  filepath.Join(tmpDir, "dummy_ed25519"),
	}); err != nil {
		t.Fatalf("seed sg1 failed: %v", err)
	}

	mgr := fleet.NewManager(store, nil)
	var sshCalls atomic.Int32
	mgr.Runner = func(ctx context.Context, n fleet.Node, script string) (string, int, error) {
		sshCalls.Add(1)
		return "", 0, errors.New("SSH runner must NOT be called during HTTPS :443 probe")
	}

	// 1) Direct ProbeNodes succeeds with zero SSH calls
	results, err := mgr.ProbeNodes(t.Context(), nil)
	if err != nil || len(results) != 1 || !results[0].Online {
		t.Fatalf("expected online HTTPS probe result, got results=%+v err=%v", results, err)
	}
	if sshCalls.Load() != 0 {
		t.Fatalf("expected 0 SSH invocations during HTTPS probe, got %d", sshCalls.Load())
	}
	n1, ok, _ := store.Get("sg1")
	if !ok || !n1.Online || n1.LastProbeAt == "" || n1.LatencyMs <= 0 {
		t.Fatalf("expected store runtime state updated with Online=true and LastProbeAt, got %+v", n1)
	}

	// 2) Simulate gateway failure (502) -> flips Online=false; then background patrol recovers Online=true automatically
	healthyFlag.Store(false)
	if _, err := mgr.RunAcross(t.Context(), "probe", []string{"sg1"}); err != nil {
		t.Fatalf("RunAcross(probe) failed: %v", err)
	}
	nDown, _, _ := store.Get("sg1")
	if nDown.Online || nDown.ProbeStatus != "unreachable" {
		t.Fatalf("expected Offline on HTTP 502, got %+v", nDown)
	}

	healthyFlag.Store(true)
	pCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	mgr.StartBackgroundPatrol(pCtx, 25*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	recovered := false
	for time.Now().Before(deadline) {
		cur, _, _ := store.Get("sg1")
		if cur.Online {
			recovered = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	cancel()
	if !recovered {
		t.Fatal("expected background HTTPS patrol to automatically recover sg1 Online=true")
	}
	if sshCalls.Load() != 0 {
		t.Fatalf("background patrol leaked SSH calls: %d", sshCalls.Load())
	}
}

func TestFleetBootstrapNATVPS_CustomSSHAndHy2VlessPorts(t *testing.T) {
	tmpDir := t.TempDir()
	masterCfgPath := filepath.Join(tmpDir, "singctl.yaml")
	masterYAML := `server:
  node_tag: "los"
  node_domain: "cdn.l1.example.com"
  cf_dns_key: "cf-test-token"
`
	if err := os.WriteFile(masterCfgPath, []byte(masterYAML), 0600); err != nil {
		t.Fatalf("write master config: %v", err)
	}

	store := fleet.NewStore(filepath.Join(tmpDir, "fleet.yaml"))
	subStore := subhub.NewStore(filepath.Join(tmpDir, "sub-store"), "")
	mgr := fleet.NewManager(store, subStore)
	mgr.ConfigPath = masterCfgPath
	mgr.GeoProber = func(ctx context.Context, host string) fleet.GeoInfo {
		return fleet.GeoInfo{CountryCode: "JP", Tag: "jp", DisplayName: "日本·东京"}
	}

	var sawStage1, sawFallbackVerify15500, sawFinalizeWithDNAT22, sawInstallCustomPorts bool
	mgr.Runner = func(ctx context.Context, n fleet.Node, script string) (string, int, error) {
		switch {
		case strings.Contains(script, "SINGCTL_LOCAL_SSH_PORT="):
			sawStage1 = true
			// Simulate NAT host forwarding external 15500 -> internal 22
			return "SINGCTL_LOCAL_SSH_PORT=22\n", 18, nil
		case strings.Contains(script, "echo SINGCTL_FLEET_SSH_VERIFIED"):
			if n.Port == 2222 {
				// Simulate NAT VPS where port 2222 is not mapped/allocated to this container
				return "", 0, errors.New("dial tcp 203.0.113.10:2222: i/o timeout")
			}
			if n.Port == 15500 && n.AuthType == fleet.AuthKeyFile && n.Password == "" {
				sawFallbackVerify15500 = true
				return "SINGCTL_FLEET_SSH_VERIFIED\n", 15, nil
			}
			t.Fatalf("unexpected verify call on node %+v", n)
			return "", 0, nil
		case strings.Contains(script, "PermitRootLogin prohibit-password"):
			if n.Port != 15500 {
				t.Fatalf("expected finalize over fallback port 15500, got %d", n.Port)
			}
			if !strings.Contains(script, "Port 22\nPort 15500") {
				t.Fatalf("expected finalize script to preserve internal DNAT Port 22 alongside Port 15500, got:\n%s", script)
			}
			sawFinalizeWithDNAT22 = true
			return "", 16, nil
		case strings.Contains(script, "singctl sr install"):
			if !strings.Contains(script, "SSH_PORT=15500 HY2_PORT=11501 VLESS_PORT=11502 singctl sr install") {
				t.Fatalf("expected install script to pass SSH_PORT=15500 HY2_PORT=11501 VLESS_PORT=11502, got:\n%s", script)
			}
			sawInstallCustomPorts = true
			return "", 95, nil
		default:
			subJSON := `{"subs":[{"name":"auto_generated_hy2","content":"hysteria2://pw@jp1.cdn.example.com:11501/?sni=jp1.cdn.example.com#sec_jp1_hy2"},{"name":"auto_generated_vless","content":"vless://11111111-1111-1111-1111-111111111111@jp1.cdn.example.com:11502?security=reality&sni=swdist.apple.com&pbk=7abc8def9ghi0jkl1mno2pqr3stu4vwx5yz6ABC7DEF&sid=1a2b#sec_jp1_vr"}]}`
			return "SINGCTL_VER=v1.14.59\nSINGCTL_CC=bbr\nSINGCTL_SUB_B64=" + base64.StdEncoding.EncodeToString([]byte(subJSON)) + "\n", 18, nil
		}
	}

	res, err := mgr.BootstrapNode(t.Context(), fleet.BootstrapInput{
		UpsertInput: fleet.UpsertInput{
			Host:      "203.0.113.10",
			Port:      15500,
			Hy2Port:   11501,
			VlessPort: 11502,
			Password:  "nat-initial-password",
		},
		SkipDNS: true,
	})
	if err != nil || !res.Success {
		t.Fatalf("NAT VPS bootstrap failed: res=%+v err=%v", res, err)
	}
	if !sawStage1 || !sawFallbackVerify15500 || !sawFinalizeWithDNAT22 || !sawInstallCustomPorts {
		t.Fatalf("missing expected NAT bootstrap stages: stage1=%v fallbackVerify=%v finalizeDNAT=%v installPorts=%v",
			sawStage1, sawFallbackVerify15500, sawFinalizeWithDNAT22, sawInstallCustomPorts)
	}
	saved, ok, _ := store.Get("jp1")
	if !ok || saved.Port != 15500 || saved.Hy2Port != 11501 || saved.VlessPort != 11502 || saved.AuthType != fleet.AuthKeyFile || saved.Password != "" {
		t.Fatalf("unexpected saved NAT node in fleet.yaml: %+v", saved)
	}

	// Verify CLI positional `ip:port` syntax: `singctl fl new 203.0.113.10:15500`
	var bsPos fleet.BootstrapInput
	cmd.ApplyPositionalFleetNewArgs([]string{"203.0.113.10:15500"}, &bsPos, false, false)
	if bsPos.Host != "203.0.113.10" || bsPos.Port != 15500 || bsPos.ID != "" {
		t.Fatalf("expected positional 203.0.113.10:15500 to set Host=203.0.113.10 Port=15500, got %+v", bsPos)
	}
	var bsNamed fleet.BootstrapInput
	cmd.ApplyPositionalFleetNewArgs([]string{"fr1", "root@203.0.113.10:11500"}, &bsNamed, false, false)
	if bsNamed.ID != "fr1" || bsNamed.Host != "203.0.113.10" || bsNamed.Port != 11500 || bsNamed.User != "root" {
		t.Fatalf("expected positional fr1 root@203.0.113.10:11500 to parse ID/Host/Port/User, got %+v", bsNamed)
	}
}
