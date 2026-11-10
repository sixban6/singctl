package audit

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"singctl/internal/config"
)

// Advisor 提供 L2 深度语义研判能力：支持对接外部 OpenAI 兼容大模型（自动脱敏）与内置离线专家知识库回退。
type Advisor struct {
	cfg        config.AuditAIConfig
	httpClient *http.Client
}

// NewAdvisor 创建 L2 审计研判顾问。支持从环境变量 SINGCTL_AUDIT_AI_ENDPOINT / SINGCTL_AUDIT_AI_KEY / SINGCTL_AUDIT_AI_MODEL 覆盖。
func NewAdvisor(cfg config.AuditAIConfig) *Advisor {
	cfg.Endpoint = cmp.Or(strings.TrimSpace(cfg.Endpoint), strings.TrimSpace(os.Getenv("SINGCTL_AUDIT_AI_ENDPOINT")))
	cfg.APIKey = cmp.Or(strings.TrimSpace(cfg.APIKey), strings.TrimSpace(os.Getenv("SINGCTL_AUDIT_AI_KEY")))
	cfg.Model = cmp.Or(strings.TrimSpace(cfg.Model), strings.TrimSpace(os.Getenv("SINGCTL_AUDIT_AI_MODEL")), "deepseek-chat")
	if cfg.Endpoint != "" && cfg.APIKey != "" {
		cfg.Enabled = true
	}
	return &Advisor{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 12 * time.Second},
	}
}

// IsRemoteLLMConfigured 返回是否已配置远程大模型 API。
func (a *Advisor) IsRemoteLLMConfigured() bool {
	return a != nil && a.cfg.Enabled && a.cfg.Endpoint != "" && a.cfg.APIKey != ""
}

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
	RiskScore     int     `json:"risk_score"`
}

// ReviewSuspiciousFlows 对报告中的可疑/高危流（或前 N 条高上传流）执行 L2 深度研判与误杀影响评估。
func (a *Advisor) ReviewSuspiciousFlows(ctx context.Context, flows []FlowRecord) {
	if len(flows) == 0 {
		return
	}

	var candidatesIdx []int
	for i := range flows {
		if flows[i].RiskScore >= 35 || flows[i].Threat != ThreatNormal {
			candidatesIdx = append(candidatesIdx, i)
			if len(candidatesIdx) >= 12 {
				break
			}
		}
	}
	if len(candidatesIdx) == 0 {
		return
	}

	// 1. 若配置了远程 OpenAI 兼容大模型，先尝试发送脱敏摘要请求大模型研判
	if a.IsRemoteLLMConfigured() {
		if results, err := a.queryRemoteLLM(ctx, flows, candidatesIdx); err == nil && len(results) > 0 {
			for _, idx := range candidatesIdx {
				if rev, ok := results[flows[idx].Key]; ok {
					flows[idx].AIReview = rev
				}
			}
		}
	}

	// 2. 对未命中远程响应（或未配置 API Key）的候选流，使用内置离线专家知识库补全精准研判
	for _, idx := range candidatesIdx {
		if flows[idx].AIReview == nil {
			flows[idx].AIReview = evaluateBuiltinExpert(&flows[idx])
		}
	}
}

func (a *Advisor) queryRemoteLLM(ctx context.Context, flows []FlowRecord, indices []int) (map[string]*AIReviewResult, error) {
	digests := make([]sanitizedFlowDigest, 0, len(indices))
	for _, idx := range indices {
		f := flows[idx]
		maskedTarget := f.Target
		if f.IsDirectIP {
			// 对纯公网 IP 脱敏最后一段，保护隐私同时保留网段特征
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
			RiskScore:     f.RiskScore,
		})
	}

	payloadJSON, _ := json.Marshal(digests)
	sysPrompt := `你是一名资深的家庭网关网络安全审计专家。请分析以下已脱敏的局域网设备可疑上传流量摘要，判断每个目标的真实用途，并重点评估“在路由器 DNS 和 sing-box 中拉黑它是否会导致设备正常功能受损”。
严格只输出 JSON 数组，格式为:
[{"id":"...", "category":"归属与用途简述", "verdict":"safe_to_block|caution|do_not_block", "impact":"拉黑后的影响说明", "recommend":"block_global|block_device|keep"}]`

	endpoint := strings.TrimRight(a.cfg.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/chat/completions") {
		endpoint += "/chat/completions"
	}

	reqBody, _ := json.Marshal(map[string]any{
		"model":       a.cfg.Model,
		"temperature": 0.1,
		"messages": []map[string]string{
			{"role": "system", "content": sysPrompt},
			{"role": "user", "content": string(payloadJSON)},
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llm status %d", resp.StatusCode)
	}

	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil || len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("decode llm response failed")
	}

	rawContent := extractJSONArray(chatResp.Choices[0].Message.Content)
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

	out := make(map[string]*AIReviewResult, len(items))
	for _, it := range items {
		v := AIVerdict(it.Verdict)
		switch v {
		case AISafeToBlock, AICaution, AIDoNotBlock:
		default:
			v = AICaution
		}
		out[it.ID] = &AIReviewResult{
			Source:      "llm_api",
			Category:    it.Category,
			Verdict:     v,
			VerdictText: v.Label(),
			Impact:      it.Impact,
			Recommend:   cmp.Or(it.Recommend, "block_global"),
		}
	}
	return out, nil
}

// evaluateBuiltinExpert 内置离线专家决策树：无需外网 API Key 即可对常见遥测、PCDN、直连偷跑给出秒级研判与防误杀评估。
func evaluateBuiltinExpert(f *FlowRecord) *AIReviewResult {
	lower := strings.ToLower(f.Target)

	// 1. PCDN / 商业边缘节点偷跑特征
	for _, kw := range []string{"pcdn", "xycdn", "onething", "szbdyd", "mcdn", "bcdn", "uhabo", "stun."} {
		if strings.Contains(lower, kw) {
			return &AIReviewResult{
				Source:      "builtin_expert",
				Category:    "商业 PCDN 边缘计算 / P2P 穿透上报节点",
				Verdict:     AISafeToBlock,
				VerdictText: AISafeToBlock.Label(),
				Impact:      "拉黑后仅阻断后台共享上传带宽，不影响正常视频点播与网页浏览",
				Recommend:   "block_global",
			}
		}
	}

	// 2. 明确遥测 / 日志 / 广告追踪 SDK
	for _, kw := range []string{"telemetry", "collect", "beacon", "tracker", "track", "log.", "logs.", "applog", "sdklog", "crashlog", "stat.", "stats.", "metric", "report.", "analytics", "adlog", "adtrack"} {
		if strings.Contains(lower, kw) {
			return &AIReviewResult{
				Source:      "builtin_expert",
				Category:    "设备行为遥测 / 埋点日志与广告回传服务",
				Verdict:     AISafeToBlock,
				VerdictText: AISafeToBlock.Label(),
				Impact:      "拉黑后可阻止后台隐私数据回传，对系统及 App 核心功能无负面影响",
				Recommend:   "block_global",
			}
		}
	}

	// 3. 绕过 DNS 的裸公网 IP + 非标端口大流量上传
	if f.IsDirectIP && f.UploadRatio >= 2.0 {
		if strings.EqualFold(f.Network, "udp") && f.DestPort > 1024 {
			return &AIReviewResult{
				Source:      "builtin_expert",
				Category:    "无域名 UDP 裸 IP 高上行传输 (疑似 PCDN/BT 偷跑)",
				Verdict:     AISafeToBlock,
				VerdictText: AISafeToBlock.Label(),
				Impact:      "若当前未在进行语音通话或 PT 做种，可安全拉黑该 IP 或按设备隔离",
				Recommend:   "block_device",
			}
		}
		return &AIReviewResult{
			Source:      "builtin_expert",
			Category:    "绕过 DNS 解析的直连 IP 持续上传",
			Verdict:     AICaution,
			VerdictText: AICaution.Label(),
			Impact:      "建议优先按源设备 IP 拉黑，防止误伤同 IP 下的正常 CDN 节点",
			Recommend:   "block_device",
		}
	}

	// 4. 高信息熵或凌晨周期心跳
	if f.DomainEntropy >= 3.65 || (f.IntervalCV > 0 && f.IntervalCV < 0.25 && f.ConnCount >= 10) {
		return &AIReviewResult{
			Source:      "builtin_expert",
			Category:    "自动化周期信标 / 随机子域名回传接口",
			Verdict:     AISafeToBlock,
			VerdictText: AISafeToBlock.Label(),
			Impact:      "具有典型机器定时器与高熵子域名特征，拉黑通常不影响前台正常交互",
			Recommend:   "block_global",
		}
	}

	// 5. 常规域名伴随高上传（可能是用户云盘/IM传输或未知后台上传）
	if f.RiskScore >= 60 {
		return &AIReviewResult{
			Source:      "builtin_expert",
			Category:    "非对称高上传业务域名",
			Verdict:     AICaution,
			VerdictText: AICaution.Label(),
			Impact:      "若确认该设备当前未在主动上传文件/视频，建议先针对该设备单独拉黑观察",
			Recommend:   "block_device",
		}
	}

	return &AIReviewResult{
		Source:      "builtin_expert",
		Category:    "常规网络通信服务",
		Verdict:     AIDoNotBlock,
		VerdictText: AIDoNotBlock.Label(),
		Impact:      "未见明显恶意偷跑特征，强行拉黑可能影响正常联网服务",
		Recommend:   "keep",
	}
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
