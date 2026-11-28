// 文件职责：提供单台局域网设备行为画像的手动脱敏 AI 总结与离线确定性回退。
package audit

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type sanitizedDeviceProfileDigest struct {
	DeviceRole     string `json:"device_role"`
	Range          string `json:"range"`
	TotalFgMinutes int    `json:"total_fg_minutes"`
	TotalBgMinutes int    `json:"total_bg_minutes"`
	ProxySharePct  float64 `json:"proxy_share_pct"`
	IsNatSubRouter bool   `json:"is_nat_sub_router"`
	PeakHour       string `json:"peak_hour,omitempty"`
	Categories     []struct {
		Label    string  `json:"label"`
		Minutes  int     `json:"minutes"`
		SharePct float64 `json:"share_pct"`
	} `json:"categories,omitempty"`
	TopApps []struct {
		Name       string `json:"name"`
		Category   string `json:"category"`
		Minutes    int    `json:"minutes"`
		Sessions   int    `json:"sessions"`
		LongestMin int    `json:"longest_min"`
		PeakPeriod string `json:"peak_period,omitempty"`
	} `json:"top_apps,omitempty"`
	PersonaTags []string `json:"persona_tags,omitempty"`
}

func buildSanitizedDeviceProfileDigest(prof *DeviceProfileReport) sanitizedDeviceProfileDigest {
	d := sanitizedDeviceProfileDigest{
		DeviceRole:     cmp.Or(prof.DeviceRole, "unknown"),
		Range:          string(prof.Range),
		TotalFgMinutes: prof.TotalForegroundMinutes,
		TotalBgMinutes: prof.TotalBackgroundMinutes,
		ProxySharePct:  prof.ProxySharePct,
		IsNatSubRouter: prof.IsNatSubRouter,
		PeakHour:       prof.PeakHourLabel,
	}
	for i, c := range prof.Categories {
		if i >= 5 {
			break
		}
		d.Categories = append(d.Categories, struct {
			Label    string  `json:"label"`
			Minutes  int     `json:"minutes"`
			SharePct float64 `json:"share_pct"`
		}{Label: c.Label, Minutes: c.Minutes, SharePct: c.SharePct})
	}
	for i, a := range prof.TopApps {
		if i >= 6 {
			break
		}
		d.TopApps = append(d.TopApps, struct {
			Name       string `json:"name"`
			Category   string `json:"category"`
			Minutes    int    `json:"minutes"`
			Sessions   int    `json:"sessions"`
			LongestMin int    `json:"longest_min"`
			PeakPeriod string `json:"peak_period,omitempty"`
		}{
			Name:       a.AppName,
			Category:   a.CategoryLabel,
			Minutes:    a.ForegroundMinutes,
			Sessions:   a.Sessions,
			LongestMin: a.LongestSessionMin,
			PeakPeriod: a.PeakPeriod,
		})
	}
	for _, t := range prof.PersonaTags {
		d.PersonaTags = append(d.PersonaTags, t.Label)
	}
	return d
}

func formatMinutesBrief(mins int) string {
	if mins < 60 {
		return fmt.Sprintf("%d 分钟", mins)
	}
	h := mins / 60
	m := mins % 60
	if m == 0 {
		return fmt.Sprintf("%d 小时", h)
	}
	return fmt.Sprintf("%d 小时 %d 分钟", h, m)
}

func buildOfflineDeviceProfileSummary(prof *DeviceProfileReport) string {
	if prof == nil || (prof.TotalForegroundMinutes == 0 && len(prof.TopApps) == 0) {
		return "当前统计周期内暂无足够的前景交互样本（仅有少量底层系统心跳或暂未产生主动上网行为）。"
	}
	windowLabel := "过去 24 小时"
	if prof.Range == ProfileRange7d {
		windowLabel = "过去 7 天"
	}
	roleLabel := map[string]string{
		"desktop": "桌面主机",
		"mobile":  "移动设备",
		"iot":     "智能家居终端",
		"router":  "下级路由器",
	}[prof.DeviceRole]
	if roleLabel == "" {
		roleLabel = "局域网终端"
	}

	var parts []string
	if prof.IsNatSubRouter {
		parts = append(parts, fmt.Sprintf("该节点为下级路由 NAT 汇总出口，%s累计前台活跃 %s。", windowLabel, formatMinutesBrief(prof.TotalForegroundMinutes)))
	} else {
		parts = append(parts, fmt.Sprintf("这台%s%s累计估算前台使用 %s。", roleLabel, windowLabel, formatMinutesBrief(prof.TotalForegroundMinutes)))
	}

	if len(prof.TopApps) > 0 {
		names := make([]string, 0, 3)
		for i, a := range prof.TopApps {
			if i >= 3 {
				break
			}
			names = append(names, fmt.Sprintf("%s（%s）", a.AppName, formatMinutesBrief(a.ForegroundMinutes)))
		}
		parts = append(parts, "最常使用的应用为 "+strings.Join(names, "、")+"。")
	}
	if prof.PeakHourLabel != "" {
		parts = append(parts, "活跃高峰集中在 "+prof.PeakHourLabel+"。")
	}
	if prof.ProxySharePct >= 30 {
		parts = append(parts, fmt.Sprintf("出海代理分流占比约 %.0f%%。", prof.ProxySharePct))
	}
	return strings.Join(parts, "")
}

// SummarizeDeviceProfile 根据已脱敏的设备画像统计摘要生成一句话性格/行为点评（用户手动点击触发，支持离线回退）。
func (a *Advisor) SummarizeDeviceProfile(ctx context.Context, prof *DeviceProfileReport, callerIP string) *DeviceProfileAISummary {
	nowStr := time.Now().Format("15:04:05")
	if prof == nil {
		return &DeviceProfileAISummary{
			OK:          true,
			Source:      "builtin_profiler",
			Summary:     buildOfflineDeviceProfileSummary(nil),
			GeneratedAt: nowStr,
		}
	}

	digest := buildSanitizedDeviceProfileDigest(prof)
	payloadJSON, _ := json.Marshal(digest)
	sysPrompt := `你是一名家庭智能网关的使用行为分析助手。请根据以下【已彻底脱敏、无任何 IP/MAC/真实主机名】的终端统计摘要，用 2 句自然、克制、客观的中文总结这台设备的日常使用偏好、活跃作息及主要 App 停留特征（不超过 110 字）。不要编造输入中没有的应用名称，也不要输出 Markdown 标题。`

	llmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 25*time.Second)
	defer cancel()

	for _, ep := range a.candidateEndpoints(strings.TrimSpace(callerIP)) {
		if !probeEndpointReachable(ep, 600*time.Millisecond) {
			continue
		}
		content, usedModel, err := a.callChatCompletions(llmCtx, ep, a.cfg.Model, sysPrompt, string(payloadJSON))
		if err != nil {
			if fallbackModel := a.discoverFirstModel(llmCtx, ep); fallbackModel != "" && fallbackModel != a.cfg.Model {
				content, usedModel, err = a.callChatCompletions(llmCtx, ep, fallbackModel, sysPrompt, string(payloadJSON))
			}
		}
		if err == nil && strings.TrimSpace(content) != "" {
			return &DeviceProfileAISummary{
				OK:          true,
				Source:      "Magpie · " + shortModelLabel(usedModel),
				Summary:     strings.TrimSpace(content),
				GeneratedAt: nowStr,
			}
		}
	}

	return &DeviceProfileAISummary{
		OK:          true,
		Source:      "builtin_profiler",
		Summary:     buildOfflineDeviceProfileSummary(prof),
		GeneratedAt: nowStr,
	}
}
