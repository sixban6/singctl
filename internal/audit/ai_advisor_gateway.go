// 文件职责：负责审计 AI 顾问的网关端点发现、可用模型探测、流量摘要脱敏及 OpenAI 兼容 HTTP 协议通信。
package audit

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// sanitizedFlowDigest 严格遵循规则 01 脱敏后的摘要结构，绝不包含内网真实 IP 或公网隐私 IP。
type sanitizedFlowDigest struct {
	ID            string  `json:"id"`
	DeviceRole    string  `json:"device_role"`
	Target        string  `json:"target"`
	IsDirectIP    bool    `json:"is_direct_ip"`
	Network       string  `json:"network"`
	DestPort      int     `json:"dest_port"`
	UploadMB      float64 `json:"upload_mb"`
	DownloadMB    float64 `json:"download_mb"`
	UploadRatio   float64 `json:"upload_ratio"`
	ConnCount     int     `json:"conn_count"`
	IntervalCV    float64 `json:"interval_cv"`
	DomainEntropy float64 `json:"domain_entropy"`
	SecurityScore int     `json:"security_score"`
	PrivacyScore  int     `json:"privacy_score"`
	RiskScore     int     `json:"risk_score"`
}

func (a *Advisor) candidateEndpoints(callerIP string) []string {
	var list []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		ep := normalizeChatCompletionsURL(raw)
		if !slices.Contains(list, ep) {
			list = append(list, ep)
		}
	}

	if a != nil && a.cfg.Endpoint != "" {
		add(a.cfg.Endpoint)
	}
	add(defaultMagpieLoopbackEndpoint)

	if ip := net.ParseIP(callerIP); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
		add("http://" + net.JoinHostPort(ip.String(), "3425") + "/v1/chat/completions")
	}
	return list
}

func normalizeChatCompletionsURL(raw string) string {
	ep := strings.TrimRight(strings.TrimSpace(raw), "/")
	if strings.HasSuffix(ep, "/chat/completions") {
		return ep
	}
	if strings.HasSuffix(ep, "/v1") {
		return ep + "/chat/completions"
	}
	return ep + "/v1/chat/completions"
}

func candidateModelListURLs(rawBase string, callerIP string) []string {
	var urls []string
	addURL := func(u string) {
		if u != "" && !slices.Contains(urls, u) {
			urls = append(urls, u)
		}
	}

	trimmed := strings.TrimRight(strings.TrimSpace(rawBase), "/")
	if trimmed != "" {
		trimmed = strings.TrimSuffix(trimmed, "/chat/completions")
		trimmed = strings.TrimSuffix(trimmed, "/models")
		trimmed = strings.TrimRight(trimmed, "/")
		if strings.HasSuffix(trimmed, "/v1") || strings.Contains(trimmed, "/v1beta") || strings.Contains(trimmed, "/api/v") {
			addURL(trimmed + "/models")
		} else {
			addURL(trimmed + "/v1/models")
			addURL(trimmed + "/models")
		}
		return urls
	}

	addURL("http://127.0.0.1:3425/v1/models")
	if ip := net.ParseIP(strings.TrimSpace(callerIP)); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
		addURL("http://" + net.JoinHostPort(ip.String(), "3425") + "/v1/models")
	}
	return urls
}

// FetchAvailableModels 向 OpenAI 兼容网关（或自动探测的本地/局域网 :3425 网关）拉取可用模型 ID 列表。
func (a *Advisor) FetchAvailableModels(ctx context.Context, callerIP string) ([]string, string, error) {
	rawBase := ""
	apiKey := ""
	if a != nil {
		rawBase = strings.TrimSpace(a.cfg.Endpoint)
		apiKey = strings.TrimSpace(a.cfg.APIKey)
	}

	candidates := candidateModelListURLs(rawBase, callerIP)
	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("未配置网关地址")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error

	for _, targetURL := range candidates {
		parsed, pErr := url.Parse(targetURL)
		if pErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			lastErr = fmt.Errorf("网关地址格式不合法: %s", targetURL)
			continue
		}
		if rawBase == "" && !probeEndpointReachable(targetURL, 600*time.Millisecond) {
			lastErr = fmt.Errorf("未检测到在线 :3425 AI 网关")
			continue
		}

		reqCtx, cancel := context.WithTimeout(ctx, 4500*time.Millisecond)
		req, rErr := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
		if rErr != nil {
			cancel()
			lastErr = rErr
			continue
		}
		req.Header.Set("Accept", "application/json")
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}

		resp, doErr := client.Do(req)
		if doErr != nil {
			cancel()
			lastErr = doErr
			continue
		}

		var bodyBuf bytes.Buffer
		_, _ = bodyBuf.ReadFrom(http.MaxBytesReader(nil, resp.Body, 2<<20))
		_ = resp.Body.Close()
		cancel()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("网关返回 HTTP %d", resp.StatusCode)
			continue
		}

		models := parseModelListPayload(bodyBuf.Bytes())
		if len(models) > 0 {
			return models, targetURL, nil
		}
		lastErr = fmt.Errorf("网关未返回可用模型列表")
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("无法连接 AI 网关拉取模型")
	}
	return nil, "", lastErr
}

func parseModelListPayload(raw []byte) []string {
	var parsed struct {
		Data   []json.RawMessage `json:"data"`
		Models []json.RawMessage `json:"models"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}

	items := parsed.Data
	if len(items) == 0 {
		items = parsed.Models
	}

	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	addID := func(id string) {
		clean := strings.TrimSpace(id)
		if clean == "" {
			return
		}
		if _, ok := seen[clean]; !ok {
			seen[clean] = struct{}{}
			out = append(out, clean)
		}
	}

	for _, rawItem := range items {
		var s string
		if json.Unmarshal(rawItem, &s) == nil && s != "" {
			addID(s)
			continue
		}
		var obj struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Model string `json:"model"`
		}
		if json.Unmarshal(rawItem, &obj) == nil {
			addID(cmp.Or(obj.ID, obj.Model, obj.Name))
		}
	}
	return out
}

func probeEndpointReachable(endpoint string, timeout time.Duration) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return false
	}
	hostPort := u.Host
	if !strings.Contains(hostPort, ":") {
		if strings.EqualFold(u.Scheme, "https") {
			hostPort = net.JoinHostPort(hostPort, "443")
		} else {
			hostPort = net.JoinHostPort(hostPort, "80")
		}
	}
	conn, err := net.DialTimeout("tcp", hostPort, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (a *Advisor) queryRemoteLLM(ctx context.Context, endpoint string, flows []FlowRecord, indices []int) (map[string]*AIReviewResult, error) {
	digests := make([]sanitizedFlowDigest, 0, len(indices))
	for _, idx := range indices {
		f := flows[idx]
		maskedTarget := f.Target
		if f.IsDirectIP {
			maskedTarget = maskIPv4Octet(f.Target)
		}
		digests = append(digests, sanitizedFlowDigest{
			ID:            f.Key,
			DeviceRole:    cmp.Or(f.DeviceRole, "unknown"),
			Target:        maskedTarget,
			IsDirectIP:    f.IsDirectIP,
			Network:       f.Network,
			DestPort:      f.DestPort,
			UploadMB:      float64(f.UploadBytes) / (1024.0 * 1024.0),
			DownloadMB:    float64(f.DownloadBytes) / (1024.0 * 1024.0),
			UploadRatio:   f.UploadRatio,
			ConnCount:     f.ConnCount,
			IntervalCV:    f.IntervalCV,
			DomainEntropy: f.DomainEntropy,
			SecurityScore: f.SecurityScore,
			PrivacyScore:  f.PrivacyScore,
			RiskScore:     f.RiskScore,
		})
	}

	payloadJSON, _ := json.Marshal(digests)
	sysPrompt := `你是一名资深的家庭网关网络安全审计专家。请分析以下已脱敏的局域网设备流量摘要，判断每个目标的真实用途并给出处置建议。
你必须严格遵守以下 verdict 判定铁律：
1. "safe_to_block"（可安全拉黑）：【仅限】明确属于「广告追踪、隐私遥测/埋点日志、商业 PCDN 偷跑、恶意远控/扫描」的不良连接，且拉黑后不影响设备与 App 核心功能。
2. "do_not_block"（建议放行）：凡属正常网络基础设施、TLS ECH 加密握手（如 cloudflare-ech.com）、公共 DNS/DoH、CDN 静态资源、系统更新、即时通讯或正常网页/业务通信，【即使拉黑后存在协议降级机制，也必须一律返回 "do_not_block"（recommend: "keep"）】！严禁将正当协议或正常网站标为 safe_to_block。
3. "caution"（谨慎拉黑）：疑似异常上传（如未知裸 IP 大流量上行），但可能与正常业务混用，建议按单设备观察。
严格只输出 JSON 数组，不要输出 Markdown 代码块以外的解释，格式为:
[{"id":"原样返回输入中的id", "category":"归属与用途简述(15字内)", "verdict":"safe_to_block|caution|do_not_block", "impact":"拉黑后的影响说明(25字内)", "recommend":"block_global|block_device|keep"}]`

	model := a.cfg.Model
	content, usedModel, err := a.callChatCompletions(ctx, endpoint, model, sysPrompt, string(payloadJSON))
	if err != nil {
		if fallbackModel := a.discoverFirstModel(ctx, endpoint); fallbackModel != "" && fallbackModel != model {
			content, usedModel, err = a.callChatCompletions(ctx, endpoint, fallbackModel, sysPrompt, string(payloadJSON))
		}
		if err != nil {
			return nil, err
		}
	}

	rawContent := extractJSONArray(content)
	var items []struct {
		ID        string `json:"id"`
		Category  string `json:"category"`
		Verdict   string `json:"verdict"`
		Impact    string `json:"impact"`
		Recommend string `json:"recommend"`
	}
	if err := json.Unmarshal([]byte(rawContent), &items); err != nil {
		return nil, err
	}

	sourceLabel := "Magpie · " + shortModelLabel(usedModel)
	out := make(map[string]*AIReviewResult, len(items))
	for _, it := range items {
		v := AIVerdict(it.Verdict)
		switch v {
		case AISafeToBlock, AICaution, AIDoNotBlock:
		default:
			v = AICaution
		}
		out[it.ID] = &AIReviewResult{
			Source:      sourceLabel,
			Category:    it.Category,
			Verdict:     v,
			VerdictText: v.Label(),
			Impact:      it.Impact,
			Recommend:   cmp.Or(it.Recommend, "block_global"),
		}
	}
	return out, nil
}

func (a *Advisor) callChatCompletions(ctx context.Context, endpoint, model, sysPrompt, userPayload string) (string, string, error) {
	doPost := func(withLowReasoning bool) (*http.Response, error) {
		payload := map[string]any{
			"model":       model,
			"temperature": 0.1,
			"messages": []map[string]string{
				{"role": "system", "content": sysPrompt},
				{"role": "user", "content": userPayload},
			},
		}
		if withLowReasoning {
			payload["reasoning_effort"] = "low"
		}
		reqBody, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if a.cfg.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
		}
		return a.httpClient.Do(req)
	}

	resp, err := doPost(true)
	if err != nil {
		return "", model, err
	}
	if resp.StatusCode == http.StatusBadRequest {
		_ = resp.Body.Close()
		resp, err = doPost(false)
		if err != nil {
			return "", model, err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", model, fmt.Errorf("llm status %d", resp.StatusCode)
	}

	var chatResp struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil || len(chatResp.Choices) == 0 {
		return "", model, fmt.Errorf("decode llm response failed")
	}
	return chatResp.Choices[0].Message.Content, cmp.Or(chatResp.Model, model), nil
}

func (a *Advisor) discoverFirstModel(ctx context.Context, chatEndpoint string) string {
	modelsURL := strings.TrimSuffix(chatEndpoint, "/chat/completions") + "/models"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
	if err != nil {
		return ""
	}
	if a.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var mResp struct {
		FirstID string `json:"first_id"`
		Data    []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&mResp); err != nil {
		return ""
	}
	if mResp.FirstID != "" {
		return mResp.FirstID
	}
	if len(mResp.Data) > 0 {
		return mResp.Data[0].ID
	}
	return ""
}

func shortModelLabel(m string) string {
	if idx := strings.LastIndex(m, "/"); idx >= 0 && idx+1 < len(m) {
		return m[idx+1:]
	}
	return m
}

func maskIPv4Octet(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return parts[0] + "." + parts[1] + "." + parts[2] + ".xxx"
	}
	return ip
}

func extractJSONArray(s string) string {
	start := strings.IndexByte(s, '[')
	end := strings.LastIndexByte(s, ']')
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}
