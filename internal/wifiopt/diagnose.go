// 文件职责：实现声明式可扩展的 Wi-Fi 体检规则表、健康分计算与一键全自动优化方案生成器。
package wifiopt

import (
	"cmp"
	"fmt"
	"strings"
)

type diagRule func(ov *Overview, st *probeState)

// diagRules 遵循开闭原则，新增 Wi-Fi 体检维度只需追加规则函数，无需修改主编排流程。
var diagRules = []diagRule{
	rule5GRadioDisabled,
	ruleSingleBandMainSSID,
	rule2GOverlappingChannel,
	rule2GWideBandwidth,
	rule5GDFSChannel,
	ruleHighRxErrorRate,
	ruleWeakClients,
	ruleIEEE80211kHint,
}

func runDiagnostics(ov *Overview, st *probeState) {
	for _, rule := range diagRules {
		rule(ov, st)
	}

	score := 100
	criticals, warns := 0, 0
	for _, d := range ov.Diagnostics {
		switch d.Severity {
		case "critical":
			score -= 28
			criticals++
		case "warn":
			score -= 12
			warns++
		case "info":
			score -= 3
		}
	}
	if score < 15 {
		score = 15
	}
	ov.HealthScore = score
	switch {
	case criticals > 0 || score < 60:
		ov.HealthLevel = "critical"
		ov.HealthSummary = fmt.Sprintf("检测到 %d 项高危无线瓶颈，强烈建议点击「一键全自动优化」彻底释放双频性能。", criticals)
	case warns > 0 || score < 85:
		ov.HealthLevel = "warn"
		ov.HealthSummary = fmt.Sprintf("检测到 %d 项可优化项，优化后可显著降低干扰抖动与多设备并发延迟。", warns)
	case score >= 95:
		ov.HealthLevel = "excellent"
		ov.HealthSummary = "双频射频与信道状态极佳，预计可流畅承载 20+ 台移动设备并发上网。"
	default:
		ov.HealthLevel = "good"
		ov.HealthSummary = "无线网络整体健康稳定，可按需微调高级参数。"
	}

	ov.AutoOptimizePlan = buildAutoOptimizePlan(ov, st, 0, 0, "")
}

func rule5GRadioDisabled(ov *Overview, _ *probeState) {
	for _, r := range ov.Radios {
		if r.Band == "5g" && r.Disabled {
			ov.Diagnostics = append(ov.Diagnostics, DiagnosisItem{
				ID:         "radio_5g_disabled",
				Severity:   "critical",
				Band:       "5g",
				Title:      "5 GHz 高速射频未开启",
				Detail:     fmt.Sprintf("射频 %s（5 GHz Wi-Fi 6）当前处于关闭状态，所有手机和平板被迫挤在 2.4 GHz，多设备并发时极易卡顿。", r.Device),
				ActionHint: "开启 5 GHz 并与主 Wi-Fi 组成双频合一（HE80 + 非 DFS 信道），无线容量可提升 4~8 倍。",
				AutoFix:    true,
			})
			return
		}
	}
}

func ruleSingleBandMainSSID(ov *Overview, _ *probeState) {
	has5G := false
	for _, r := range ov.Radios {
		if r.Band == "5g" {
			has5G = true
			break
		}
	}
	if !has5G {
		return
	}
	for _, s := range ov.SSIDs {
		if s.CanUpgradeDualBand {
			ov.Diagnostics = append(ov.Diagnostics, DiagnosisItem{
				ID:         "ssid_single_band_2g",
				Severity:   "critical",
				Band:       "2g",
				Title:      fmt.Sprintf("主 Wi-Fi「%s」仅工作在 2.4 GHz", s.SSID),
				Detail:     fmt.Sprintf("「%s」（网桥 %s）尚未在 5 GHz 射频建立同名热点，近距离手机无法享受 5G 千兆空口。", s.SSID, s.Bridge),
				ActionHint: "点击「一键升级双频合一」，自动同步密码与所属网桥，实现无缝漫游。",
				AutoFix:    true,
			})
			return
		}
	}
}

func rule2GOverlappingChannel(ov *Overview, _ *probeState) {
	for _, r := range ov.Radios {
		if r.Band == "2g" && !r.Disabled && r.OverlappingCh {
			ov.Diagnostics = append(ov.Diagnostics, DiagnosisItem{
				ID:         "ch_2g_overlap",
				Severity:   "critical",
				Band:       "2g",
				Title:      fmt.Sprintf("2.4 GHz 处于非正交重叠信道（信道 %d）", r.CurrentChannel),
				Detail:     "2.4 GHz 仅有信道 1 / 6 / 11 互不重叠；落在中间信道会同时遭受左右邻频碰撞，造成大量 CRC 错包与延迟抖动。",
				ActionHint: "点击「扫描周边干扰」自动挑出 1 / 6 / 11 中最干净信道并固定。",
				AutoFix:    true,
			})
		}
	}
}

func rule2GWideBandwidth(ov *Overview, _ *probeState) {
	for _, r := range ov.Radios {
		if r.Band == "2g" && !r.Disabled && strings.Contains(strings.ToUpper(r.HTMode), "40") {
			ov.Diagnostics = append(ov.Diagnostics, DiagnosisItem{
				ID:         "htmode_2g_wide",
				Severity:   "warn",
				Band:       "2g",
				Title:      fmt.Sprintf("2.4 GHz 配置了 40MHz 宽频（%s）", r.HTMode),
				Detail:     "在有邻居干扰的环境中，2.4G 40MHz 会使底噪增加 3dB 且常被 20/40 共存强制退避；固定 HE20 可明显提升穿墙信噪比与稳定性。",
				ActionHint: "将 2.4G 频宽设为 HE20，高速流量交给 5G HE80 承载。",
				AutoFix:    true,
			})
		}
	}
}

func rule5GDFSChannel(ov *Overview, _ *probeState) {
	for _, r := range ov.Radios {
		if r.Band == "5g" && !r.Disabled && r.DFSChannel {
			ov.Diagnostics = append(ov.Diagnostics, DiagnosisItem{
				ID:         "ch_5g_dfs",
				Severity:   "warn",
				Band:       "5g",
				Title:      fmt.Sprintf("5 GHz 工作在 DFS 雷达信道（信道 %d）", r.CurrentChannel),
				Detail:     "DFS 信道（52–144）在重启或检测到雷达信号时会静默等待 60 秒甚至强切信道，且部分设备扫描较慢。",
				ActionHint: "切换至非 DFS 高功率信道（如 149 / 153 / 36 / 44）+ HE80，即开即连零等待。",
				AutoFix:    true,
			})
		}
	}
}

func statsScopeLabel(scope string) string {
	switch scope {
	case "post_optimize":
		return "优化后实测"
	case "retest":
		return "重测实时"
	default:
		return "自开机累计"
	}
}

func ruleHighRxErrorRate(ov *Overview, st *probeState) {
	isMTWifi := st != nil && st.Driver == "mtwifi"
	scopeLabel := statsScopeLabel(ov.StatsScope)
	for _, r := range ov.Radios {
		if r.Disabled {
			continue
		}
		// 1. 真实接口丢包率（rx_dropped + tx_dropped + tx_errors）：>= 1% 才代表客户端实际掉包
		totalPkts := r.RxPackets + r.TxPackets
		if totalPkts >= 500 && r.PacketLossRatePct >= 1.0 {
			ov.Diagnostics = append(ov.Diagnostics, DiagnosisItem{
				ID:         "pkt_loss_high_" + r.Band,
				Severity:   "warn",
				Band:       r.Band,
				Title:      fmt.Sprintf("%s 射频%s丢包率偏高（%.2f%%）", strings.ToUpper(r.Band), scopeLabel, r.PacketLossRatePct),
				Detail:     fmt.Sprintf("收发共 %d 包中出现 %d 个丢包（RX 丢包 %d / TX 丢包 %d），可能导致视频卡顿或游戏跳 Ping。", totalPkts, r.RxDropped+r.TxDropped, r.RxDropped, r.TxDropped),
				ActionHint: "建议扫描周边干扰并切换更干净信道，同时开启下方多核 RPS 底盘加速。",
				AutoFix:    false,
			})
		}

		// 2. 空口 RX 错帧率（PHY/CRC 错帧）
		if r.RxPackets >= 500 && r.RxErrorRatePct >= 5.0 {
			// MediaTek mtwifi 2.4G 主射频的 rx_errs 计入周边 2.4G 背景底噪帧（邻居/蓝牙/微波炉），不代表已连设备丢包。
			if isMTWifi && r.Band == "2g" && !r.OverlappingCh && !strings.Contains(strings.ToUpper(r.HTMode), "40") {
				ov.Diagnostics = append(ov.Diagnostics, DiagnosisItem{
					ID:         "rx_err_env_" + r.Band,
					Severity:   "info",
					Band:       r.Band,
					Title:      fmt.Sprintf("2.4G 周边空口底噪计数较高（%s %.1f%%，实际丢包 %.2f%%）", scopeLabel, r.RxErrorRatePct, r.PacketLossRatePct),
					Detail:     "注：MTK 驱动把周边 2.4G 蓝牙/邻居背景干扰帧计入空口错帧，不等于已连设备掉包；当前已锁定正交信道与 20MHz 最佳抗干扰配置。",
					ActionHint: "可点击「重测丢包率」查看当前实时采样，或点击「扫描周边干扰」确认最干净信道。",
					AutoFix:    false,
				})
				continue
			}
			// MediaTek mtwifi 5G 已处于非 DFS 信道且实际丢包率 < 1% 时，轻度空口背景 CRC（< 15%）不误报「待优化」
			if isMTWifi && r.Band == "5g" && !r.DFSChannel && r.PacketLossRatePct < 1.0 && r.RxErrorRatePct < 15.0 {
				continue
			}
			ov.Diagnostics = append(ov.Diagnostics, DiagnosisItem{
				ID:         "rx_err_high_" + r.Band,
				Severity:   "warn",
				Band:       r.Band,
				Title:      fmt.Sprintf("%s 射频%s空口 RX 错帧率偏高（%.1f%%）", strings.ToUpper(r.Band), scopeLabel, r.RxErrorRatePct),
				Detail:     fmt.Sprintf("收包 %d 中出现 %d 个错帧（实际接口丢包率 %.2f%%），通常由邻频干扰或弱信号边缘设备引起。", r.RxPackets, r.RxErrors, r.PacketLossRatePct),
				ActionHint: "扫描并切换至更干净的正交/非 DFS 信道，再点击「重测丢包率」复核。",
				AutoFix:    false,
			})
		}
	}
}

func ruleWeakClients(ov *Overview, _ *probeState) {
	weak := 0
	for _, c := range ov.Clients {
		if c.WeakSignal {
			weak++
		}
	}
	if weak > 0 {
		ov.Diagnostics = append(ov.Diagnostics, DiagnosisItem{
			ID:         "weak_clients_present",
			Severity:   "info",
			Title:      fmt.Sprintf("当前有 %d 台弱信号/低速无线终端", weak),
			Detail:     "弱信号设备（≤ -82 dBm，或 ≤ -76 dBm 且协商速率 < 30 Mbps）容易占用更多空口时间，建议近处主力设备优先连 5G 隔离影响。",
			ActionHint: "保持双频合一 + 2.4G HE20 干净信道即可将影响降到最低。",
			AutoFix:    false,
		})
	}
}

func ruleIEEE80211kHint(ov *Overview, st *probeState) {
	if st != nil && st.Driver == "mtwifi" {
		// MediaTek mtwifi 驱动默认在 .dat 中已启用 RRMEnable=1（802.11k），无需冗余提醒
		return
	}
	missing := false
	for _, s := range ov.SSIDs {
		if !s.Disabled && !s.Isolate && !s.IEEE80211k {
			missing = true
			break
		}
	}
	if missing {
		ov.Diagnostics = append(ov.Diagnostics, DiagnosisItem{
			ID:         "missing_80211k",
			Severity:   "info",
			Title:      "尚未显式启用 802.11k 邻居报告",
			Detail:     "开启 802.11k 可帮助手机/平板更快发现同 SSID 的 5G 频段并加速双频切换。",
			ActionHint: "一键优化将自动为双频主 SSID 显式启用 802.11k。",
			AutoFix:    false,
		})
	}
}

func findPrimary2GMainSSID(ov *Overview) *SSIDInfo {
	for i := range ov.SSIDs {
		if ov.SSIDs[i].CanUpgradeDualBand {
			return &ov.SSIDs[i]
		}
	}
	return nil
}

func findRadioByBand(ov *Overview, band string) *RadioInfo {
	for i := range ov.Radios {
		if ov.Radios[i].Band == band {
			return &ov.Radios[i]
		}
	}
	return nil
}

func buildAutoOptimizePlan(ov *Overview, st *probeState, rec2GCh, rec5GCh int, pref5GWidth string) []OptimizationStep {
	steps := []OptimizationStep{}
	r2 := findRadioByBand(ov, "2g")
	r5 := findRadioByBand(ov, "5g")

	if r2 != nil && !r2.Disabled {
		if r2.OverlappingCh || r2.Channel == "auto" {
			targetCh := rec2GCh
			if !isNonOverlapping2GChannel(targetCh) {
				targetCh = 1
			}
			steps = append(steps, OptimizationStep{
				Target: r2.Device + " (2.4G)",
				Field:  "channel",
				Before: fmt.Sprintf("%s (实测 %d)", r2.Channel, r2.CurrentChannel),
				After:  fmt.Sprintf("%d", targetCh),
				Reason: "锁定正交无重叠信道，消除邻频碰撞并省去自动扫描延迟",
			})
		}
		if strings.Contains(strings.ToUpper(r2.HTMode), "40") {
			steps = append(steps, OptimizationStep{
				Target: r2.Device + " (2.4G)",
				Field:  "htmode",
				Before: r2.HTMode,
				After:  "HE20",
				Reason: "2.4G 固定 20MHz 降低底噪 3dB，提升穿墙与高并发抗干扰能力",
			})
		}
	}

	if r5 != nil {
		target5Ch := rec5GCh
		if !valid5GChannels[target5Ch] || isDFSChannel(target5Ch) {
			target5Ch = 149
		}
		target5W := "HE80"
		if pref5GWidth == "HE160" {
			target5W = "HE160"
		}

		if r5.Disabled {
			steps = append(steps, OptimizationStep{
				Target: r5.Device + " (5G)",
				Field:  "disabled",
				Before: "已关闭",
				After:  "开启",
				Reason: "启用 5 GHz Wi-Fi 6 高速射频释放空口容量",
			})
		}
		if r5.Disabled || r5.DFSChannel || r5.Channel == "auto" {
			steps = append(steps, OptimizationStep{
				Target: r5.Device + " (5G)",
				Field:  "channel",
				Before: fmt.Sprintf("%s (实测 %d)", r5.Channel, r5.CurrentChannel),
				After:  fmt.Sprintf("%d (非DFS)", target5Ch),
				Reason: "锁定非 DFS 高功率信道，零雷达静默等待、全终端秒连",
			})
		}
		if (r5.Disabled || r5.DFSChannel) && r5.HTMode != target5W {
			steps = append(steps, OptimizationStep{
				Target: r5.Device + " (5G)",
				Field:  "htmode",
				Before: r5.HTMode,
				After:  target5W,
				Reason: "HE80 兼顾千兆级速率与全设备 100% 兼容性（无 DFS 依赖）",
			})
		}
		if main2G := findPrimary2GMainSSID(ov); main2G != nil {
			targetSec := pickPrimary5GIfaceSection(st, r5.Device)
			beforeDesc := "独立/未启用"
			if targetSec != "" {
				if sec := st.IfaceBySec[targetSec]; sec != nil {
					beforeDesc = fmt.Sprintf("%s (%s)", sec.opt("ssid"), sec.opt("network"))
				}
			}
			steps = append(steps, OptimizationStep{
				Target: fmt.Sprintf("5G 热点 (%s)", main2G.SSID),
				Field:  "双频合一",
				Before: beforeDesc,
				After:  fmt.Sprintf("同名「%s」+ 同密码 + 同网桥(%s) + 802.11k", main2G.SSID, main2G.Network),
				Reason: "手机近处自动优先 5G 高速，远处平滑回落 2.4G 不换 IP",
			})
		}
	}

	return steps
}

func pickPrimary5GIfaceSection(st *probeState, dev5G string) string {
	if st == nil || st.WirelessUCI == nil {
		return ""
	}
	for _, sec := range st.WirelessUCI.byType("wifi-iface") {
		if sec.opt("device") != dev5G {
			continue
		}
		mode := strings.ToLower(cmp.Or(sec.opt("mode"), "ap"))
		if mode == "ap" {
			return sec.Name
		}
	}
	return ""
}
