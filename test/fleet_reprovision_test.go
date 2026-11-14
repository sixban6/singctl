package test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"singctl/internal/fleet"
	"singctl/internal/subhub"
)

func TestFleetBootstrapReprovisionAndDuplicateGuard(t *testing.T) {
	tmpDir := t.TempDir()
	masterCfgPath := filepath.Join(tmpDir, "singctl.yaml")
	masterYAML := `server:
  node_tag: "los"
  node_domain: "master.example.com"
  cf_dns_key: "cf-test-token"
`
	if err := os.WriteFile(masterCfgPath, []byte(masterYAML), 0600); err != nil {
		t.Fatal(err)
	}

	store := fleet.NewStore(filepath.Join(tmpDir, "fleet.yaml"))
	if err := os.MkdirAll(store.KeysDir, 0700); err != nil {
		t.Fatal(err)
	}

	existingNodeKey := filepath.Join(store.KeysDir, "san.key")
	_ = os.WriteFile(existingNodeKey, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n"), 0600)

	if _, err := store.Upsert(fleet.UpsertInput{
		ID:             "san",
		Name:           "美西圣何塞",
		Host:           "198.51.100.50",
		Port:           2222,
		User:           "root",
		AuthType:       fleet.AuthKeyFile,
		KeyPath:        existingNodeKey,
		Domain:         "san.example.com",
		DNSAutoManaged: new(true),
	}); err != nil {
		t.Fatalf("seed san failed: %v", err)
	}

	var cfPutCount atomic.Int32
	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones"):
			if strings.Contains(r.URL.Path, "/dns_records") {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"result": []map[string]any{
						{
							"id":      "rec-san",
							"type":    "A",
							"name":    "san.example.com",
							"content": "198.51.100.40", // stale IP to verify in-place PUT update
							"proxied": false,
						},
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result": []map[string]any{
					{"id": "zone-1", "name": "example.com"},
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/zones/zone-1/dns_records/rec-san":
			cfPutCount.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  map[string]any{"id": "rec-san"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer cfServer.Close()

	subStore := subhub.NewStore(filepath.Join(tmpDir, "sub-store"), "")
	mgr := fleet.NewManager(store, subStore)
	mgr.ConfigPath = masterCfgPath
	mgr.CFClient = &fleet.CloudflareDNSClient{
		BaseURL:    cfServer.URL,
		HTTPClient: cfServer.Client(),
	}
	mgr.GeoProber = func(ctx context.Context, host string) fleet.GeoInfo {
		return fleet.GeoInfo{CountryCode: "US", Tag: "us", DisplayName: "美国·圣何塞"}
	}

	ctx := t.Context()

	// 1. Reject duplicate ID when Reprovision is false.
	if _, err := mgr.PreviewBootstrapNode(ctx, fleet.BootstrapInput{
		ID:       "san",
		Host:     "203.0.113.88",
		AuthType: fleet.AuthPassword,
		Password: "pw",
	}); err == nil || !strings.Contains(err.Error(), "已在舰队清单中纳管") || !strings.Contains(err.Error(), "--reprovision") {
		t.Fatalf("expected duplicate ID error without --reprovision, got %v", err)
	}

	// 2. Reject duplicate Host (even with user@host:port normalization) when Reprovision is false.
	if _, err := mgr.PreviewBootstrapNode(ctx, fleet.BootstrapInput{
		ID:       "us-alt",
		Host:     "root@198.51.100.50:2222",
		AuthType: fleet.AuthPassword,
		Password: "pw",
	}); err == nil || !strings.Contains(err.Error(), "已在舰队清单中纳管") || !strings.Contains(err.Error(), "--reprovision") {
		t.Fatalf("expected duplicate Host error without --reprovision, got %v", err)
	}

	// 3. Reprovision=true reuses exact ID, Name, Domain, and Host in-place without generating san-2.
	plan, err := mgr.PreviewBootstrapNode(ctx, fleet.BootstrapInput{
		ID:          "san",
		Host:        "198.51.100.50",
		Port:        22,
		AuthType:    fleet.AuthKeyFile,
		KeyPath:     existingNodeKey,
		Reprovision: true,
	})
	if err != nil {
		t.Fatalf("PreviewBootstrapNode with Reprovision=true failed: %v", err)
	}
	if plan.ID != "san" || plan.Name != "美西圣何塞" || plan.Domain != "san.example.com" {
		t.Fatalf("expected reprovision plan to preserve san/美西圣何塞/san.example.com, got %+v", plan)
	}

	remoteSubDoc, _ := json.Marshal(map[string]any{
		"subs": []map[string]any{
			{
				"name":    "auto_generated_hy2",
				"content": "hysteria2://pass-san@san.example.com:443?sni=san.example.com#SAN-HY2",
			},
		},
	})
	b64Doc := base64.StdEncoding.EncodeToString(remoteSubDoc)

	mgr.Runner = func(ctx context.Context, n fleet.Node, script string) (string, int, error) {
		switch {
		case strings.Contains(script, "SINGCTL_LOCAL_SSH_PORT="):
			return "SINGCTL_LOCAL_SSH_PORT=22\n", 15, nil
		case strings.Contains(script, "echo SINGCTL_FLEET_SSH_VERIFIED"):
			return "SINGCTL_FLEET_SSH_VERIFIED\n", 12, nil
		case strings.Contains(script, "SINGCTL_SUB_B64="):
			return "SINGCTL_VER=SingCtl v1.14.99\nSINGCTL_LOAD=0.05 0.03 0.01\nSINGCTL_MEM=20.0\nSINGCTL_CC=bbr\nSINGCTL_SUB_B64=" + b64Doc + "\n", 18, nil
		default:
			return "OK", 10, nil
		}
	}

	res, err := mgr.BootstrapNode(ctx, fleet.BootstrapInput{
		ID:          "san",
		Host:        "198.51.100.50",
		Port:        22,
		AuthType:    fleet.AuthKeyFile,
		KeyPath:     existingNodeKey,
		Reprovision: true,
	})
	if err != nil {
		t.Fatalf("BootstrapNode with Reprovision=true failed: %v", err)
	}
	if !res.Success || res.ID != "san" {
		t.Fatalf("expected successful BootstrapNode for san, got %+v", res)
	}

	nodes, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].ID != "san" {
		t.Fatalf("expected exactly 1 node 'san' (no '-2' shadow copy), got %+v", nodes)
	}
	if nodes[0].Domain != "san.example.com" || !nodes[0].DNSAutoManaged {
		t.Fatalf("expected Domain san.example.com and DNSAutoManaged=true preserved, got %+v", nodes[0])
	}
	if cfPutCount.Load() != 1 {
		t.Fatalf("expected Cloudflare A record updated in-place via PUT once, got %d", cfPutCount.Load())
	}
}
