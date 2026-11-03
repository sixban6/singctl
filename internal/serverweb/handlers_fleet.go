package serverweb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"singctl/internal/fleet"
)

func (s *Server) handleFleetList(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.fleet.Store.ListPublic()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取节点舰队列表失败: "+err.Error())
		return
	}

	online := 0
	totalSynced := 0
	scoreSum := 0
	scoredNodes := 0
	for _, n := range nodes {
		if n.Online {
			online++
		}
		totalSynced += n.SyncedNodes
		if n.DoctorScore > 0 {
			scoreSum += n.DoctorScore
			scoredNodes++
		}
	}
	avgScore := 0
	if scoredNodes > 0 {
		avgScore = scoreSum / scoredNodes
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes,
		"summary": map[string]any{
			"total":                len(nodes),
			"online":               online,
			"totalSyncedEndpoints": totalSynced,
			"avgDoctorScore":       avgScore,
		},
	})
}

func (s *Server) handleFleetUpsertNode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		fleet.UpsertInput
		AutoSync bool `json:"autoSync"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求: "+err.Error())
		return
	}

	node, err := s.fleet.Store.Upsert(body.UpsertInput)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.recordAudit(r, fmt.Sprintf("保存舰队子节点 [%s (%s)]", node.Name, node.ID))

	var syncResult *fleet.NodeActionResult
	if body.AutoSync {
		res := s.fleet.SyncNode(r.Context(), node.ID)
		syncResult = &res
		if updated, ok, _ := s.fleet.Store.Get(node.ID); ok {
			node = updated
		}
	}

	msg := "子节点已保存"
	if syncResult != nil {
		if syncResult.Success {
			msg = syncResult.Message
		} else {
			msg = "子节点已保存，但首次连接同步未通过: " + syncResult.Message
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message":    msg,
		"node":       node.PublicView(),
		"syncResult": syncResult,
	})
}

func (s *Server) handleFleetDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		var body struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id = strings.TrimSpace(body.ID)
	}
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少子节点代号 (id)")
		return
	}
	if err := s.fleet.RemoveNode(id); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.recordAudit(r, fmt.Sprintf("移除舰队子节点 [%s] 并清理对应订阅源", id))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "子节点及关联聚合节点已成功移除",
	})
}

func (s *Server) handleFleetAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string   `json:"action"` // "sync" | "doctor" | "reset" | "update"
		IDs    []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求")
		return
	}
	action := strings.ToLower(strings.TrimSpace(body.Action))
	switch action {
	case "sync", "doctor", "reset", "update":
	default:
		writeJSONError(w, http.StatusBadRequest, "不支持的舰队操作: "+action)
		return
	}

	results, err := s.fleet.RunAcross(r.Context(), action, body.IDs)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	okCount := 0
	for _, res := range results {
		if res.Success {
			okCount++
		}
	}
	s.recordAudit(r, fmt.Sprintf("执行舰队批量操作 [%s] (%d/%d 成功)", action, okCount, len(results)))
	writeJSON(w, http.StatusOK, map[string]any{
		"message": fmt.Sprintf("舰队批量指令 [%s] 执行完成 (%d/%d 成功)", action, okCount, len(results)),
		"results": results,
	})
}

func (s *Server) handleFleetBootstrap(w http.ResponseWriter, r *http.Request) {
	var body fleet.BootstrapInput
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求: "+err.Error())
		return
	}
	res, err := s.fleet.BootstrapNode(r.Context(), body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.recordAudit(r, fmt.Sprintf("自动化初始化并纳管新节点 [%s (%s)]", res.Name, res.ID))
	writeJSON(w, http.StatusOK, map[string]any{
		"message": res.Message,
		"result":  res,
	})
}
