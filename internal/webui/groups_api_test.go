package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

func TestHandleGroups_GetPreviewPutBindRoutingAndReset(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "config.json")

	initialYAML := "subs:\n  - name: main\n    url: https://example.com/sub\n"
	if err := os.WriteFile(cfgPath, []byte(initialYAML), 0600); err != nil {
		t.Fatal(err)
	}

	// 在测试配置中放入港/日/自建三个代表性节点（不含真实 IP）
	baseSB := buildValidTestSingBoxJSON(t, dir)
	var sbDoc map[string]any
	if err := json.Unmarshal([]byte(baseSB), &sbDoc); err != nil {
		t.Fatal(err)
	}
	obs := sbDoc["outbounds"].([]any)
	obs = append(obs,
		map[string]any{"type": "socks", "tag": "香港-IEPL-01", "server": "198.51.100.21", "server_port": 1080},
		map[string]any{"type": "socks", "tag": "日本-Tokyo-01", "server": "198.51.100.22", "server_port": 1080},
		map[string]any{"type": "socks", "tag": "sec_us_hy2", "server": "198.51.100.23", "server_port": 1080},
	)
	sbDoc["outbounds"] = obs
	sbBytes, _ := json.MarshalIndent(sbDoc, "", "  ")
	if err := os.WriteFile(sbPath, sbBytes, 0600); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbPath,
		Listen:            "127.0.0.1:0",
	})

	doJSONReq := func(method, target string, payload any) *httptest.ResponseRecorder {
		var bodyReader *bytes.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			bodyReader = bytes.NewReader(b)
		} else {
			bodyReader = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, target, bodyReader)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("X-Requested-With", "SingCtlWebUI")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. GET /api/groups (初始未创建 groups.yaml 时返回模板、内置宏及当前节点预览)
	recGet := doJSONReq(http.MethodGet, "/api/groups", nil)
	if recGet.Code != http.StatusOK {
		t.Fatalf("GET /api/groups code=%d body=%s", recGet.Code, recGet.Body.String())
	}
	var getResp groupsGetResponse
	if err := json.Unmarshal(recGet.Body.Bytes(), &getResp); err != nil {
		t.Fatal(err)
	}
	if getResp.Exists || !getResp.HasLiveConfig || len(getResp.Macros) == 0 || len(getResp.Templates) == 0 {
		t.Fatalf("unexpected initial GET /api/groups response: %+v", getResp)
	}
	if getResp.Preview == nil || getResp.Preview.TotalLeafNodes != 4 {
		t.Fatalf("expected 4 leaf nodes in initial preview, got %+v", getResp.Preview)
	}

	// 2. POST /api/groups/preview (未知语义宏返回友好结构化错误，HTTP 200 ok=false)
	recBadPrev := doJSONReq(http.MethodPost, "/api/groups/preview", groupsPreviewRequest{
		Content: "version: 1\ngroups:\n  - name: \"#Mars\"\n    match: [\"@mars\"]\n",
	})
	if recBadPrev.Code != http.StatusOK {
		t.Fatalf("POST /api/groups/preview code=%d", recBadPrev.Code)
	}
	var badPrevMap map[string]any
	_ = json.Unmarshal(recBadPrev.Body.Bytes(), &badPrevMap)
	if badPrevMap["ok"] != false {
		t.Fatalf("expected ok=false for unknown @mars macro, got %v", badPrevMap)
	}

	// 3. PUT /api/groups (保存并热应用 #HK / #JP / Streaming)
	validYAML := `version: 1
mode: merge
groups:
  - name: "Streaming"
    type: selector
    use: ["#JP", "#HK", "#VPS"]
    default: "#JP"
    attach_to: []
  - name: "#HK"
    type: urltest
    match: ["@hk"]
  - name: "#JP"
    type: urltest
    match: ["@jp"]
`
	recPut := doJSONReq(http.MethodPut, "/api/groups", groupsPutRequest{Content: validYAML})
	if recPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/groups failed code=%d body=%s", recPut.Code, recPut.Body.String())
	}

	gPath := config.GroupsPathForConfig(cfgPath)
	st, err := os.Stat(gPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 groups.yaml on disk, got %v (err=%v)", st, err)
	}

	// 4. 立即在 PUT /api/traffic-routing 中将 Netflix 分流绑定到新建的 Streaming 分组
	recTR := doJSONReq(http.MethodPut, "/api/traffic-routing", map[string]any{
		"presets": map[string]any{
			"netflix": map[string]any{
				"enabled":  true,
				"outbound": "Streaming",
			},
		},
	})
	if recTR.Code != http.StatusOK {
		t.Fatalf("binding Netflix to new Streaming group failed: code=%d body=%s", recTR.Code, recTR.Body.String())
	}

	// 5. PUT /api/groups reset=true 恢复默认内置分组，且不因曾绑定 Streaming 导致配置崩溃
	recReset := doJSONReq(http.MethodPut, "/api/groups", groupsPutRequest{Reset: true})
	if recReset.Code != http.StatusOK {
		t.Fatalf("reset /api/groups failed: code=%d body=%s", recReset.Code, recReset.Body.String())
	}
	if _, err := os.Stat(gPath); !os.IsNotExist(err) {
		t.Fatalf("expected groups.yaml removed after reset, err=%v", err)
	}
	finalSB, _ := os.ReadFile(sbPath)
	finalGroups, _ := singbox.InspectClientRoutingOutbounds(string(finalSB))
	var finalTags []string
	for _, g := range finalGroups {
		finalTags = append(finalTags, g.Tag)
	}
	if slices.Contains(finalTags, "Streaming") || slices.Contains(finalTags, "#HK") {
		t.Fatalf("expected custom groups removed after reset, got %v", finalTags)
	}
}
