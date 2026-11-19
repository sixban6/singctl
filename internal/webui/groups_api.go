package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"singctl/configs"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/singbox"
	"singctl/internal/util/file"
)

// GroupTemplateSnippet 提供给前端一键插入的常用 YAML 模板片段。
type GroupTemplateSnippet struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

var builtinGroupTemplates = []GroupTemplateSnippet{
	{
		ID:          "region_pools",
		Name:        "常用地区测速池 (#HK / #JP / #SG / #US)",
		Description: "按语义宏自动归类港/日/新/美节点并开启自动测速择优，自动挂载进 Proxy 与分流中心",
		Content: `version: 1
mode: merge

groups:
  - name: "#HK"
    type: urltest
    match: ["@hk"]
    exclude: ["@high_rate"]
    tolerance: 50

  - name: "#JP"
    type: urltest
    match: ["@jp"]
    exclude: ["@high_rate"]
    tolerance: 50

  - name: "#SG"
    type: urltest
    match: ["@sg"]
    exclude: ["@high_rate"]
    tolerance: 50

  - name: "#US"
    type: urltest
    match: ["@us"]
    exclude: ["@high_rate"]
    tolerance: 80
`,
	},
	{
		ID:          "streaming_split",
		Name:        "流媒体专享组合组 (Streaming)",
		Description: "构建港/日/新子池并组合出独立的 Streaming 业务组，可在「智能分流中心」一键绑定 Netflix / YouTube",
		Content: `version: 1
mode: merge

groups:
  - name: "Streaming"
    type: selector
    use: ["#SG", "#JP", "#HK", "#VPS"]
    default: "#SG"
    attach_to: []

  - name: "#SG"
    type: urltest
    match: ["@sg"]
    exclude: ["@high_rate"]

  - name: "#JP"
    type: urltest
    match: ["@jp"]
    exclude: ["@high_rate"]

  - name: "#HK"
    type: urltest
    match: ["@hk"]
    exclude: ["@high_rate"]
`,
	},
	{
		ID:          "self_and_backup",
		Name:        "自建协议筛选 + 看门狗主备容灾",
		Description: "按协议/订阅源精准圈选节点，并开启 failover 交由看门狗自动故障切换与恢复回切",
		Content: `version: 1
mode: merge

groups:
  - name: "#Self-Hy2"
    type: selector
    match: ["@self"]
    protocol: ["hysteria2"]

  - name: "WorkVIP"
    type: selector
    use: ["#Self-Hy2", "#VPS", "#Auto"]
    default: "#Self-Hy2"
    failover: true
`,
	},
}

type groupsGetResponse struct {
	Path          string                       `json:"path"`
	Exists        bool                         `json:"exists"`
	Content       string                       `json:"content"`
	HasLiveConfig bool                         `json:"hasLiveConfig"`
	Macros        []config.GroupMacroInfo      `json:"macros"`
	Templates     []GroupTemplateSnippet       `json:"templates"`
	Preview       *singbox.GroupsPreviewReport `json:"preview,omitempty"`
	ParseError    string                       `json:"parseError,omitempty"`
}

type groupsPreviewRequest struct {
	Content string `json:"content"`
}

type groupsPutRequest struct {
	Content string `json:"content"`
	Reset   bool   `json:"reset,omitempty"`
}

func (s *Server) handleGroupsGet(w http.ResponseWriter, _ *http.Request) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfgPath := configPathFor(s)
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
		cfg.SetSourcePath(cfgPath)
	}
	gPath := config.GroupsPathForConfig(cfgPath)

	rawDisk, readErr := os.ReadFile(gPath)
	exists := readErr == nil
	content := string(configs.DefaultGroupsYAML)
	if exists {
		content = string(rawDisk)
	}

	rawSBBytes, sbErr := os.ReadFile(s.sbConfigPath())
	rawSB := string(rawSBBytes)
	hasLiveSB := sbErr == nil && strings.TrimSpace(rawSB) != ""

	resp := groupsGetResponse{
		Path:          gPath,
		Exists:        exists,
		Content:       content,
		HasLiveConfig: hasLiveSB,
		Macros:        config.BuiltinGroupMacros(),
		Templates:     builtinGroupTemplates,
	}

	parsed, parseErr := config.ParseGroupsYAML([]byte(content))
	if parseErr != nil {
		resp.ParseError = parseErr.Error()
		parsed = &config.GroupsConfig{Version: 1, Mode: config.GroupsModeMerge}
	}

	if hasLiveSB {
		_, preview, compErr := singbox.RecompileLiveConfigWithGroups(rawSB, cfg, parsed, "")
		if compErr != nil && resp.ParseError == "" {
			resp.ParseError = compErr.Error()
		} else {
			resp.Preview = preview
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGroupsPreviewPost(w http.ResponseWriter, r *http.Request) {
	var body groupsPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfgPath := configPathFor(s)
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
		cfg.SetSourcePath(cfgPath)
	}

	parsed, err := config.ParseGroupsYAML([]byte(body.Content))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	rawSBBytes, sbErr := os.ReadFile(s.sbConfigPath())
	rawSB := string(rawSBBytes)
	if sbErr != nil || strings.TrimSpace(rawSB) == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"hasLiveConfig": false,
			"preview": &singbox.GroupsPreviewReport{
				Mode:           parsed.EffectiveMode(),
				TotalLeafNodes: 0,
			},
		})
		return
	}

	_, preview, compErr := singbox.RecompileLiveConfigWithGroups(rawSB, cfg, parsed, "")
	if compErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": compErr.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"hasLiveConfig": true,
		"preview":       preview,
	})
}

func (s *Server) handleGroupsPut(w http.ResponseWriter, r *http.Request) {
	var body groupsPutRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfgPath := configPathFor(s)
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
		cfg.SetSourcePath(cfgPath)
	}
	gPath := config.GroupsPathForConfig(cfgPath)
	prevDiskBytes, prevDiskErr := os.ReadFile(gPath)

	var targetGC *config.GroupsConfig
	var savedContent string
	if body.Reset {
		targetGC = &config.GroupsConfig{Version: 1, Mode: config.GroupsModeMerge}
		savedContent = string(configs.DefaultGroupsYAML)
	} else {
		parsed, parseErr := config.ParseGroupsYAML([]byte(body.Content))
		if parseErr != nil {
			writeJSONError(w, http.StatusBadRequest, parseErr.Error())
			return
		}
		targetGC = parsed
		savedContent = body.Content
	}

	sbPath := s.sbConfigPath()
	rawSBBytes, sbErr := os.ReadFile(sbPath)
	rawSB := string(rawSBBytes)
	hasLiveSB := sbErr == nil && strings.TrimSpace(rawSB) != ""

	var updatedJSON string
	var preview *singbox.GroupsPreviewReport
	if hasLiveSB {
		var compErr error
		updatedJSON, preview, compErr = singbox.RecompileLiveConfigWithGroups(rawSB, cfg, targetGC, "")
		if compErr != nil {
			writeJSONError(w, http.StatusBadRequest, compErr.Error())
			return
		}
	}

	// 先更新或清理 groups.yaml，若后续 sing-box check 热重载失败则回滚磁盘文件
	restoreGroupsFile := func() {
		if prevDiskErr == nil {
			_ = file.WriteAtomic0600(gPath, prevDiskBytes)
		} else {
			_ = os.Remove(gPath)
		}
	}

	existsAfter := !body.Reset
	if body.Reset {
		_ = os.Remove(gPath)
	} else {
		if _, saveErr := config.SaveGroupsFile(gPath, []byte(savedContent)); saveErr != nil {
			writeJSONError(w, http.StatusInternalServerError, saveErr.Error())
			return
		}
	}

	applied := false
	liveJSON := rawSB
	if hasLiveSB {
		if applyErr := singbox.ApplyLiveSingBoxConfig(r.Context(), sbPath, s.sbWorkConfigPath(), updatedJSON, "groups"); applyErr != nil {
			restoreGroupsFile()
			writeJSONError(w, http.StatusBadRequest, "sing-box 校验或热重载失败: "+applyErr.Error())
			return
		}
		if baseRaw, bErr := singbox.LoadBaseSnapshot(sbPath); bErr == nil && strings.TrimSpace(baseRaw) != "" {
			if updatedBase, _, uErr := singbox.RecompileLiveConfigWithGroups(baseRaw, cfg, targetGC, ""); uErr == nil {
				_ = singbox.SaveBaseSnapshot(sbPath, updatedBase)
			}
		}
		applied = true
		liveJSON = updatedJSON
	}

	s.invalidateIOSCache()
	_ = daemon.NotifyReload()

	msg := "分组配置 (groups.yaml) 已保存并无损热重载生效"
	if body.Reset {
		msg = "已移除自定义分组并恢复默认内置策略组"
	} else if !applied {
		msg = "分组配置 (groups.yaml) 已保存，将在下次生成 sing-box 配置时生效"
	}

	routingReport := singbox.BuildClientRoutingReport(cfg, liveJSON)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"exists":        existsAfter,
		"applied":       applied,
		"content":       savedContent,
		"message":       msg,
		"preview":       preview,
		"routingReport": routingReport,
	})
}
