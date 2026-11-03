package fleet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/subhub"
)

func TestFleetLifecycleAndSubHubAutoSync(t *testing.T) {
	tmpDir := t.TempDir()
	fleetStore := NewStore(filepath.Join(tmpDir, "fleet.json"))
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
		Port:       22,
		User:       "root",
		AuthType:   AuthInlineKey,
		PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\ntestkey\n-----END OPENSSH PRIVATE KEY-----",
	})
	if err != nil {
		t.Fatalf("Upsert fleet node failed: %v", err)
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
			return "SINGCTL_VER=SingCtl v1.14.31\nSINGCTL_LOAD=0.08 0.05 0.01\nSINGCTL_MEM=36.5\nSINGCTL_CC=bbr\nSINGCTL_SUB_B64=" + b64Doc + "\n", 42, nil
		case strings.Contains(script, "singctl sr doctor"):
			return "体检时间: 2026-11-04 | 综合健康指数: 100 / 100\n[✓] 一切正常", 38, nil
		default:
			return "OK", 35, nil
		}
	}

	syncRes := mgr.SyncNode(context.Background(), "us-lax")
	if !syncRes.Success || syncRes.SyncedNodes != 2 || syncRes.SingctlVersion != "v1.14.31" {
		t.Fatalf("unexpected SyncNode result: %+v", syncRes)
	}

	// Verify Master SubHub automatically received fleet_us-lax source and includes it in "all" collection!
	bundle, err := subStore.ResolveCollection(context.Background(), "all")
	if err != nil {
		t.Fatalf("ResolveCollection failed: %v", err)
	}
	if len(bundle.Nodes) != 2 {
		t.Fatalf("expected 2 nodes synced into Master SubHub, got %d", len(bundle.Nodes))
	}

	// Verify concurrent Doctor across fleet
	docResults, err := mgr.RunAcross(context.Background(), "doctor", nil)
	if err != nil || len(docResults) != 1 || docResults[0].DoctorScore != 100 {
		t.Fatalf("unexpected fleet doctor result: %+v err=%v", docResults, err)
	}

	// Removing fleet node must also remove fleet_us-lax from Master SubHub
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
