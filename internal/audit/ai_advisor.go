// 文件职责：提供客户端审计 L2 深度语义研判顾问（Advisor）、持久化缓存与内置离线专家决策树回退。
package audit

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
)

const (
	defaultMagpieLoopbackEndpoint = "http://127.0.0.1:3425/v1/chat/completions"
	legacyAICachePath             = "/tmp/singctl-audit-ai-cache.json"
	defaultAICachePath            = "/tmp/singctl-audit-ai-cache-v2.json"
	maxCachedAITargets            = 600
)

type persistedAICacheEntry struct {
	Target    string          `json:"target"`
	Review    *AIReviewResult `json:"review"`
	UpdatedAt int64           `json:"updated_at"`
}

var (
	aiTargetCacheMu   sync.RWMutex
	aiTargetCacheOnce sync.Once
	aiTargetCachePath = defaultAICachePath
	aiTargetCache     = make(map[string]persistedAICacheEntry)
)

// ResetAICacheForTest 供单元测试隔离 AI 缓存文件路径并清空内存缓存。
func ResetAICacheForTest(customPath string) {
	aiTargetCacheMu.Lock()
	defer aiTargetCacheMu.Unlock()
	if customPath != "" {
		aiTargetCachePath = customPath
	} else {
		aiTargetCachePath = defaultAICachePath
	}
	aiTargetCache = make(map[string]persistedAICacheEntry)
}

func normalizeTargetKey(target string) string {
	return strings.ToLower(strings.TrimSpace(target))
}

func ensureAICacheLoaded() {
	aiTargetCacheOnce.Do(func() {
		_ = os.Remove(legacyAICachePath)
		aiTargetCacheMu.RLock()
		path := aiTargetCachePath
		aiTargetCacheMu.RUnlock()
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			return
		}
		var list []persistedAICacheEntry
		if err := json.Unmarshal(data, &list); err != nil {
			return
		}
		aiTargetCacheMu.Lock()
		defer aiTargetCacheMu.Unlock()
		for _, item := range list {
			k := normalizeTargetKey(item.Target)
			if k != "" && item.Review != nil && item.Review.Source != "" && item.Review.Source != "builtin_expert" {
				aiTargetCache[k] = item
			}
		}
	})
}

// LookupCachedAIReview 查询目标域名/IP 是否已有持久化的真实 AI 大模型研判结果（0ms 命中）。
func LookupCachedAIReview(target string) *AIReviewResult {
	ensureAICacheLoaded()
	k := normalizeTargetKey(target)
	if k == "" {
		return nil
	}
	aiTargetCacheMu.RLock()
	entry, ok := aiTargetCache[k]
	aiTargetCacheMu.RUnlock()
	if !ok || entry.Review == nil {
		return nil
	}
	cp := *entry.Review
	return &cp
}

// StoreCachedAIReviews 将新获得的真实大模型研判结果写入内存与 /tmp/singctl-audit-ai-cache-v2.json (0600)。
func StoreCachedAIReviews(entries map[string]*AIReviewResult) {
	if len(entries) == 0 {
		return
	}
	ensureAICacheLoaded()
	now := time.Now().Unix()
	changed := false

	aiTargetCacheMu.Lock()
	for target, rev := range entries {
		k := normalizeTargetKey(target)
		if k == "" || rev == nil || rev.Source == "" || rev.Source == "builtin_expert" {
			continue
		}
		cp := *rev
		aiTargetCache[k] = persistedAICacheEntry{
			Target:    k,
			Review:    &cp,
			UpdatedAt: now,
		}
		changed = true
	}
	if !changed {
		aiTargetCacheMu.Unlock()
		return
	}

	list := make([]persistedAICacheEntry, 0, len(aiTargetCache))
	for _, v := range aiTargetCache {
		list = append(list, v)
	}
	if len(list) > maxCachedAITargets {
		slices.SortFunc(list, func(a, b persistedAICacheEntry) int {
			return cmp.Compare(b.UpdatedAt, a.UpdatedAt)
		})
		list = list[:maxCachedAITargets]
		aiTargetCache = make(map[string]persistedAICacheEntry, len(list))
		for _, item := range list {
			aiTargetCache[item.Target] = item
		}
	}
	aiTargetCacheMu.Unlock()

	aiTargetCacheMu.RLock()
	path := aiTargetCachePath
	aiTargetCacheMu.RUnlock()

	if data, err := json.Marshal(list); err == nil {
		tmpPath := path + ".tmp"
		if err := os.WriteFile(tmpPath, data, 0600); err == nil {
			_ = os.Rename(tmpPath, path)
		}
	}
}

// Advisor 提供 L2 深度语义研判能力：支持对接本地 Magpie 反代网关 (:3425)、外部 OpenAI 兼容大模型（自动脱敏）与内置离线专家知识库回退。
type Advisor struct {
	cfg        config.AuditAIConfig
	httpClient *http.Client
}

// NewAdvisor 创建 L2 审计研判顾问。支持从环境变量 SINGCTL_AUDIT_AI_ENDPOINT / SINGCTL_AUDIT_AI_KEY / MAGPIE_GATEWAY_KEY / SINGCTL_AUDIT_AI_MODEL 覆盖。
func NewAdvisor(cfg config.AuditAIConfig) *Advisor {
	cfg.Endpoint = cmp.Or(strings.TrimSpace(cfg.Endpoint), strings.TrimSpace(os.Getenv("SINGCTL_AUDIT_AI_ENDPOINT")))
	cfg.APIKey = cmp.Or(strings.TrimSpace(cfg.APIKey), strings.TrimSpace(os.Getenv("SINGCTL_AUDIT_AI_KEY")), strings.TrimSpace(os.Getenv("MAGPIE_GATEWAY_KEY")))
	cfg.Model = cmp.Or(strings.TrimSpace(cfg.Model), strings.TrimSpace(os.Getenv("SINGCTL_AUDIT_AI_MODEL")), "antigravity/gemini-3.8-flash")
	if cfg.Endpoint != "" {
		cfg.Enabled = true
	}
	return &Advisor{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 35 * time.Second},
	}
}

// IsRemoteLLMConfigured 返回是否显式配置了远程大模型 API。
func (a *Advisor) IsRemoteLLMConfigured() bool {
	return a != nil && a.cfg.Enabled && a.cfg.Endpoint != ""
}

// ReviewSuspiciousFlows 对报告中的可疑/高危流（或前 N 条非白名单活跃上传流）执行 L2 深度研判与误杀影响评估。
func (a *Advisor) ReviewSuspiciousFlows(ctx context.Context, flows []FlowRecord, callerIPs ...string) {
	if len(flows) == 0 {
		return
	}

	var candidatesIdx []int
	for i := range flows {
		if flows[i].RiskScore >= 35 || flows[i].Threat != ThreatNormal {
			candidatesIdx = append(candidatesIdx, i)
			if len(candidatesIdx) >= 8 {
				break
			}
		}
	}
	if len(candidatesIdx) < 8 {
		for i := range flows {
			if slices.Contains(candidatesIdx, i) {
				continue
			}
			if flows[i].State != EnforcementWhitelisted && (flows[i].RiskScore >= 8 || flows[i].UploadBytes >= 16384) {
				candidatesIdx = append(candidatesIdx, i)
				if len(candidatesIdx) >= 8 {
					break
				}
			}
		}
	}
	if len(candidatesIdx) == 0 {
		return
	}

	var uncachedIdx []int
	for _, idx := range candidatesIdx {
		if sc := shortCircuitTrustedReview(&flows[idx]); sc != nil {
			flows[idx].AIReview = sc
			continue
		}
		if cached := LookupCachedAIReview(flows[idx].Target); cached != nil {
			flows[idx].AIReview = cached
			continue
		}
		uncachedIdx = append(uncachedIdx, idx)
	}

	if len(uncachedIdx) > 0 {
		var callerIP string
		if len(callerIPs) > 0 {
			callerIP = strings.TrimSpace(callerIPs[0])
		}

		llmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 35*time.Second)
		defer cancel()

		for _, ep := range a.candidateEndpoints(callerIP) {
			if !probeEndpointReachable(ep, 600*time.Millisecond) {
				continue
			}
			if results, err := a.queryRemoteLLM(llmCtx, ep, flows, uncachedIdx); err == nil && len(results) > 0 {
				toCache := make(map[string]*AIReviewResult, len(results))
				for _, idx := range uncachedIdx {
					if rev, ok := results[flows[idx].Key]; ok && rev != nil {
						flows[idx].AIReview = rev
						toCache[flows[idx].Target] = rev
					}
				}
				StoreCachedAIReviews(toCache)
				break
			}
		}
	}

	for _, idx := range candidatesIdx {
		if flows[idx].AIReview == nil {
			flows[idx].AIReview = evaluateBuiltinExpert(&flows[idx])
		}
	}
}

// ReviewFlowBatch 对前端传入的指定批次流（最多 12 条/批）执行大模型深度研判。
func (a *Advisor) ReviewFlowBatch(ctx context.Context, flows []FlowRecord, callerIP string, forceRefresh ...bool) (map[string]*AIReviewResult, bool) {
	out := make(map[string]*AIReviewResult, len(flows))
	if len(flows) == 0 {
		return out, false
	}
	if len(flows) > 12 {
		flows = flows[:12]
	}

	force := len(forceRefresh) > 0 && forceRefresh[0]
	var uncachedIndices []int
	usedRemote := false

	for i := range flows {
		if flows[i].Key == "" {
			flows[i].Key = fmt.Sprintf("%s|%s|%s", flows[i].DeviceIP, flows[i].Target, flows[i].Network)
		}
		if sc := shortCircuitTrustedReview(&flows[i]); sc != nil {
			out[flows[i].Key] = sc
			continue
		}
		if !force {
			if cached := LookupCachedAIReview(flows[i].Target); cached != nil {
				out[flows[i].Key] = cached
				usedRemote = true
				continue
			}
		}
		uncachedIndices = append(uncachedIndices, i)
	}

	if len(uncachedIndices) > 0 {
		llmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 35*time.Second)
		defer cancel()

		for _, ep := range a.candidateEndpoints(strings.TrimSpace(callerIP)) {
			if !probeEndpointReachable(ep, 600*time.Millisecond) {
				continue
			}
			if results, err := a.queryRemoteLLM(llmCtx, ep, flows, uncachedIndices); err == nil && len(results) > 0 {
				toCache := make(map[string]*AIReviewResult, len(results))
				for _, idx := range uncachedIndices {
					k := flows[idx].Key
					if v, ok := results[k]; ok && v != nil {
						out[k] = v
						toCache[flows[idx].Target] = v
					}
				}
				StoreCachedAIReviews(toCache)
				usedRemote = true
				break
			}
		}
	}

	for i := range flows {
		k := flows[i].Key
		if out[k] == nil {
			out[k] = evaluateBuiltinExpert(&flows[i])
		}
	}
	return out, usedRemote
}

func shortCircuitTrustedReview(f *FlowRecord) *AIReviewResult {
	if f == nil {
		return nil
	}
	if f.State == EnforcementWhitelisted || IsProtectedBootstrapDomain(f.Target) {
		return &AIReviewResult{
			Source:      "builtin_expert",
			Category:    "核心网络协议 / 可信基础服务",
			Verdict:     AIDoNotBlock,
			VerdictText: AIDoNotBlock.Label(),
			Impact:      "属于正常的底层加密握手或可信基础服务，拉黑会导致网页无法访问或隐私保护降级",
			Recommend:   "keep",
		}
	}
	return nil
}

// evaluateBuiltinExpert 内置离线专家决策树：无需外网 API Key 即可对常见遥测、PCDN、直连偷跑给出秒级研判与防误杀评估。
func evaluateBuiltinExpert(f *FlowRecord) *AIReviewResult {
	if sc := shortCircuitTrustedReview(f); sc != nil {
		return sc
	}
	lower := strings.ToLower(f.Target)

	// 1. PCDN / 商业边缘节点偷跑或拉流特征
	if f.PCDNKind == "swarm" {
		return &AIReviewResult{
			Source:      "builtin_expert",
			Category:    "PCDN/P2P 跨网段裸 IP 蜂群偷跑上传",
			Verdict:     AISafeToBlock,
			VerdictText: AISafeToBlock.Label(),
			Impact:      "单设备向多运营商网段高频散点上行，开启「内置防 PCDN」或按设备限流可制止带宽盗用",
			Recommend:   "block_device",
		}
	}
	if matched, _ := matchPCDNDomain(f.Target); matched {
		isDownloadOnly := f.PCDNKind == "download" || (f.UploadRatio < 0.8 && f.UploadBytes < 256*1024)
		if isDownloadOnly {
			return &AIReviewResult{
				Source:      "builtin_expert",
				Category:    "商业 PCDN 下行拉流节点",
				Verdict:     AISafeToBlock,
				VerdictText: AISafeToBlock.Label(),
				Impact:      "拉黑后播放器自动回落官方正规 CDN，通常可减少跨网卡顿并防止后续被调度上传",
				Recommend:   "block_global",
			}
		}
		return &AIReviewResult{
			Source:      "builtin_expert",
			Category:    "商业 PCDN 边缘计算 / 偷跑上传节点",
			Verdict:     AISafeToBlock,
			VerdictText: AISafeToBlock.Label(),
			Impact:      "拉黑后仅阻断后台共享上传带宽，不影响正常视频点播与网页浏览",
			Recommend:   "block_global",
		}
	}

	// 2. 明确遥测 / 日志 / 广告追踪 SDK
	for _, kw := range privacyTrackerKeywords {
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

	// 3. 绕过 DNS 的裸公网 IP + 非标端口传输
	if f.IsDirectIP && strings.EqualFold(f.Network, "udp") {
		switch {
		case f.DestPort == 8053 && f.UploadBytes < 20*1024*1024:
			return &AIReviewResult{
				Source:      "builtin_expert",
				Category:    "智能家居/米家 MiIO 设备直连心跳",
				Verdict:     AICaution,
				VerdictText: AICaution.Label(),
				Impact:      "常见于小米/米家智能网关或插座加密控制保活，误封可能导致智能家居离线",
				Recommend:   "keep",
			}
		case f.DestPort == 32100 && f.UploadBytes < 20*1024*1024:
			return &AIReviewResult{
				Source:      "builtin_expert",
				Category:    "TUTK / 智能摄像机 P2P 视频穿透",
				Verdict:     AICaution,
				VerdictText: AICaution.Label(),
				Impact:      "常见于家用智能摄像头实时预览 P2P 通道，误封可能导致手机无法看监控画面",
				Recommend:   "keep",
			}
		case f.DestPort == 3478 && f.UploadBytes < 20*1024*1024:
			return &AIReviewResult{
				Source:      "builtin_expert",
				Category:    "STUN/TURN 语音视频通话中继",
				Verdict:     AICaution,
				VerdictText: AICaution.Label(),
				Impact:      "常见于微信/会议等音视频通话 NAT 穿透，误封可能影响语音视频通话接通",
				Recommend:   "keep",
			}
		case isKnownGameUDPPort(f.DestPort) && f.UploadBytes < 20*1024*1024:
			return &AIReviewResult{
				Source:      "builtin_expert",
				Category:    "手游联机 / 游戏加速直连 UDP 节点",
				Verdict:     AICaution,
				VerdictText: AICaution.Label(),
				Impact:      "常见于王者荣耀国际服等手游实时对战加速通信，若确为游戏流量请勿拉黑",
				Recommend:   "keep",
			}
		}
	}
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

	// 5. 常规域名伴随高上传
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
