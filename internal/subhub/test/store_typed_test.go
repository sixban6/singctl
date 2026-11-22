// 文件职责：覆盖 SubHub 强类型 subStoreDoc 保真编解码、零序列化深拷贝与 SyncAutoServerNodes 节点同步边界单测。
package subhub_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"singctl/internal/subhub"
)

func TestStore_SyncAutoServerNodes_TypedDocLosslessAndNoDualDisplayName(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "sub-store.json")

	otherVPSHy2 := "hysteria2://other-uuid@jp1.example.com:443/?sni=jp1.example.com&alpn=h3&insecure=0#sec_jp1_hy2"
	oldLocalHy2 := "hysteria2://old-uuid@us1.example.com:443/?sni=us1.example.com&alpn=h3&insecure=0#sec_us1_hy2"

	seed := `{
  "schemaVersion": "2.1",
  "customPlugin": {"enabled": true, "ttl": 300},
  "subs": [
    {
      "name": "auto_generated_hy2",
      "display-name": "Legacy Hy2 Name",
      "source": "local",
      "content": "` + otherVPSHy2 + `\n` + oldLocalHy2 + `",
      "customSubAttr": "keep-sub-extra"
    },
    {
      "name": "auto_generated_hy2",
      "displayName": "Duplicate Entry",
      "source": "local",
      "content": "` + oldLocalHy2 + `"
    },
    {
      "name": "auto_generated_tuic",
      "displayName": "Deprecated TUIC",
      "source": "local",
      "content": "tuic://11111111-1111-1111-1111-111111111111:pass@us1.example.com:443/#old"
    },
    {
      "name": "auto_generated_anytls",
      "displayName": "Deprecated AnyTLS",
      "source": "local",
      "content": "anytls://pass@us1.example.com:443/#old"
    },
    {
      "name": "manual_extra",
      "display-name": "Manual Legacy Display",
      "source": "local",
      "content": "ss://YWVzLTI1Ni1nY206cGFzcw@203.0.113.88:8388#Manual-SS",
      "icon": "https://example.com/icon.png"
    }
  ],
  "collections": [
    {
      "name": "Auto",
      "displayName": "Auto",
      "subscriptions": ["auto_generated_hy2"]
    },
    {
      "name": "all",
      "displayName": "all",
      "subscriptions": ["manual_extra", "ghost_sub", "auto_generated_tuic"],
      "customColAttr": "keep-col-extra"
    }
  ]
}`
	if err := os.WriteFile(filePath, []byte(seed), 0600); err != nil {
		t.Fatal(err)
	}

	st := subhub.NewStore(dir, filePath)
	newHy2 := "hysteria2://11111111-1111-1111-1111-111111111111@us1.example.com:8443/?sni=us1.example.com&alpn=h3&insecure=0#sec_us1_hy2"
	newVLESS := "vless://11111111-1111-1111-1111-111111111111@us1.example.com:443?type=tcp&encryption=none&security=reality&pbk=testpbk&fp=chrome&sni=www.example.com&sid=01020304&flow=xtls-rprx-vision#sec_us1_vr"

	if err := st.SyncAutoServerNodes(subhub.SyncServerNodesInput{
		NodeDomain: "us1.example.com",
		Hy2URI:     newHy2,
		Hy2Tag:     "sec_us1_hy2",
		VlessURI:   newVLESS,
		VrTag:      "sec_us1_vr",
	}); err != nil {
		t.Fatalf("SyncAutoServerNodes failed: %v", err)
	}

	bakInfo, err := os.Stat(filePath + ".bak")
	if err != nil || bakInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 .bak file, got info=%v err=%v", bakInfo, err)
	}

	mainInfo, err := os.Stat(filePath)
	if err != nil || mainInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 sub-store.json, got info=%v err=%v", mainInfo, err)
	}
	rawOut, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawOut), `"display-name"`) {
		t.Fatalf("must NOT dual-write legacy \"display-name\" key anymore, got:\n%s", string(rawOut))
	}

	var parsed map[string]any
	if err := json.Unmarshal(rawOut, &parsed); err != nil {
		t.Fatalf("invalid output JSON: %v", err)
	}
	if parsed["schemaVersion"] != "2.1" || parsed["customPlugin"] == nil {
		t.Fatalf("expected top-level Extra keys preserved, got: %v", parsed)
	}

	sources, err := st.ListSources()
	if err != nil {
		t.Fatalf("ListSources failed: %v", err)
	}
	if len(sources) != 3 {
		t.Fatalf("expected 3 clean sources (hy2, manual_extra, vless), got %d: %+v", len(sources), sources)
	}

	byName := make(map[string]subhub.SourceItem, len(sources))
	for _, src := range sources {
		byName[src.Name] = src
	}
	if byName["manual_extra"].DisplayName != "Manual Legacy Display" {
		t.Fatalf("expected legacy display-name migrated cleanly to DisplayName, got %q", byName["manual_extra"].DisplayName)
	}
	hy2Lines := strings.Split(byName["auto_generated_hy2"].Content, "\n")
	if len(hy2Lines) != 2 || hy2Lines[0] != otherVPSHy2 || hy2Lines[1] != newHy2 {
		t.Fatalf("expected other VPS preserved and current VPS updated in place, got %v", hy2Lines)
	}
	if byName["auto_generated_vless"].Content != newVLESS {
		t.Fatalf("unexpected vless content: %q", byName["auto_generated_vless"].Content)
	}

	subsRaw := parsed["subs"].([]any)
	foundSubExtra := false
	for _, s := range subsRaw {
		sm := s.(map[string]any)
		if sm["name"] == "auto_generated_hy2" && sm["customSubAttr"] == "keep-sub-extra" {
			foundSubExtra = true
		}
	}
	if !foundSubExtra {
		t.Fatalf("expected sub Extra field customSubAttr preserved, got %v", subsRaw)
	}

	colsRaw := parsed["collections"].([]any)
	if len(colsRaw) != 1 {
		t.Fatalf("expected legacy Auto collection removed leaving 1 'all' collection, got %v", colsRaw)
	}
	allCol := colsRaw[0].(map[string]any)
	if allCol["customColAttr"] != "keep-col-extra" {
		t.Fatalf("expected collection Extra field customColAttr preserved, got %v", allCol)
	}
	colSubs := allCol["subscriptions"].([]any)
	if len(colSubs) != 3 {
		t.Fatalf("expected dangling ghost_sub & deprecated tuic pruned leaving 3 subs in 'all', got %v", colSubs)
	}

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			_, _ = st.ListSources()
		})
		wg.Go(func() {
			_ = st.SyncAutoServerNodes(subhub.SyncServerNodesInput{
				NodeDomain: "us1.example.com",
				Hy2URI:     newHy2,
				Hy2Tag:     "sec_us1_hy2",
				VlessURI:   newVLESS,
				VrTag:      "sec_us1_vr",
			})
		})
	}
	wg.Wait()
}
