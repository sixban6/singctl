package netdiag

import (
	"fmt"
	"singctl/internal/config"
	"strings"
	"time"
)

// GenerateAdvice 综合本地运营商、丢包抖动以及骨干线路特征生成建议
func GenerateAdvice(localISP *ISPInfo, ping *PingResult, trace *TraceResult, isPeakHour bool) *AdviceResult {
	adv := &AdviceResult{
		QualityLevel: ping.QualityLevel,
		CanAutoApply: true,
	}

	// 1. 协议推荐逻辑
	// 当丢包率 < 2% 且抖动平稳时，TCP 的握手延迟、资源消耗及稳定性全面优于 UDP，且不会触发运营商 UDP QoS 限速
	if ping.LossRate < 2.0 && ping.Jitter < 25*time.Millisecond {
		adv.RecommendedProtocol = ProtocolVLESSReality
		adv.ProtocolReason = "链路极度通畅且几乎 0 丢包。VLESS-Reality (TCP) 相比 UDP 更省电、发热小、延迟抖动更低，且 100% 免疫任何运营商 UDP QoS 降速风险。"
	} else {
		adv.RecommendedProtocol = ProtocolHysteria2
		if ping.LossRate >= 15.0 {
			adv.ProtocolReason = fmt.Sprintf("线路实测综合丢包率高达 %.1f%%（中重度拥堵），TCP 协议会因丢包频繁触发拥塞退避而严重降速或断流；必须使用 Hysteria 2 凭借 Brutal 拥塞控制暴力抗丢包保活。", ping.LossRate)
		} else {
			adv.ProtocolReason = fmt.Sprintf("检测到丢包 (%.1f%%) 或延迟抖动波动 (%v)；Hysteria 2 能更好抹平网络波动带来的卡顿感。", ping.LossRate, ping.Jitter.Round(time.Millisecond))
		}

		if ping.UDP != nil {
			if ping.UDP.Received == 0 && ((ping.TCP != nil && len(ping.TCP.RTTs) > 0) || (ping.ICMP != nil && ping.ICMP.Received > 0)) {
				adv.ProtocolReason += fmt.Sprintf(" ⚠️ 注意：实测 UDP %d 端口未响应 QUIC 握手，若启用 Hysteria 2 请确认服务端已放行 UDP 端口且未被运营商完全阻断 UDP。", ping.Port)
			} else if ping.UDP.Received > 0 && ping.TCP != nil && !ping.TCP.LocalProxied && ping.UDP.LossRate >= ping.TCP.LossRate+20.0 {
				adv.ProtocolReason += fmt.Sprintf(" (检测到 UDP 1200B 大包丢包率 %.1f%% 显著高于 TCP 小包，存在国际出口队列尾丢弃或运营商 UDP QoS 限流，务必限制 hy2 带宽参数以防链路被打死)", ping.UDP.LossRate)
			} else if ping.UDP.Received > 0 && ping.UDP.LossRate >= 15.0 {
				adv.ProtocolReason += fmt.Sprintf(" (实测 UDP/QUIC 1200B 真实载荷丢包率达 %.1f%%，建议采用保守 hy2 带宽设置以防触发运营商 UDP QoS)", ping.UDP.LossRate)
			}
		}
	}

	// 2. 推荐 Hysteria 2 上下行带宽 (hy2.up / hy2.down)
	// 根据实测丢包情况推算安全激进系数，避免暴力打满拥塞链路导致运营商 UDP QoS 扼死
	if ping.LossRate <= 1.0 && ping.Jitter < 50*time.Millisecond {
		adv.SuggestedHy2Down = 200
		adv.SuggestedHy2Up = 30
	} else if ping.LossRate <= 10.0 && ping.Jitter < 150*time.Millisecond {
		adv.SuggestedHy2Down = 120
		adv.SuggestedHy2Up = 20
	} else {
		// 丢包 > 10% 或重度拥堵抖动时，保守下调发包速率，防止将链路直接打死
		adv.SuggestedHy2Down = 80
		adv.SuggestedHy2Up = 15
	}

	// 3. 运营商与线路匹配度打分与晚高峰稳定性分析
	localType := ISPTelecom
	if localISP != nil {
		localType = localISP.Type
	}

	routeType := "UNKNOWN"
	if trace != nil {
		routeType = trace.RouteType
	}

	score, analysis := evaluateCarrierMatch(localType, routeType, isPeakHour)
	adv.CarrierMatchScore = score
	adv.CarrierAdvice = analysis

	return adv
}

func evaluateCarrierMatch(local ISPType, routeType string, isPeakHour bool) (int, string) {
	peakTag := ""
	if isPeakHour {
		peakTag = " [当前正值晚高峰 20:00-24:00 黄金观察期]"
	}

	switch local {
	case ISPTelecom:
		switch routeType {
		case "CN2_GIA":
			return 98, fmt.Sprintf("💯 完美契合！电信晚高峰 163 骨干极易拥堵，该 VPS 全程走 CN2 GIA 精品出口，晚高峰稳定秒开 4K，是电信宽带的最佳搭档机型。%s", peakTag)
		case "CN2_GT":
			return 75, fmt.Sprintf("⚠️ 半程优化。该线路国内省级节点仍走 163 骨干，国际出海口切入 CN2。晚高峰省级节点排队时可能会有轻度抖动，建议备好 Hysteria 2 兜底。%s", peakTag)
		case "163":
			return 45, fmt.Sprintf("❌ 严重警告！该节点走传统 163 骨干，电信晚高峰国际出口拥堵严重（丢包常达 20%%~40%%）。TCP 协议（VLESS）极易断流，务必强制启用 Hysteria 2 抗丢包，或考虑升级更换为 CN2 GIA / 联通 9929 线路。%s", peakTag)
		case "CU9929":
			return 92, fmt.Sprintf("✨ 联通 9929 反向优化！联通精品网出口对电信互联非常友好，晚高峰表现极其稳定，媲美 CN2 GIA。%s", peakTag)
		case "CMIN2":
			return 90, fmt.Sprintf("✨ 移动 CMIN2 高端网！三网互联表现优异，晚高峰丢包极低，对电信网络有极好的兼容性。%s", peakTag)
		default:
			return 60, fmt.Sprintf("走普通国际互联链路。电信直连普通海外机房受出海口总带宽限制，晚高峰波动较大，强烈建议配置 Hysteria 2 使用。%s", peakTag)
		}

	case ISPUnicom:
		switch routeType {
		case "CU9929":
			return 99, fmt.Sprintf("💯 极品专线！联通 A 网 (9929/10099) 属于政企精品网品质，晚高峰极度平稳，延迟与丢包表现登峰造极。%s", peakTag)
		case "CU4837":
			return 92, fmt.Sprintf("🎉 性价比之王！联通 169 (4837) 骨干网容量充沛，美西/欧洲直连速度极快且价格亲民，日常及晚高峰使用均非常舒心。%s", peakTag)
		case "CN2_GIA":
			return 88, fmt.Sprintf("优质线路。电信 CN2 GIA 对联通直连同样稳定，唯独性价比不如纯 4837/9929 机型。%s", peakTag)
		default:
			return 70, fmt.Sprintf("联通国际出口带宽相对充裕，即使普通直连线路晚高峰表现也优于电信，若有波动建议开启 Hysteria 2。%s", peakTag)
		}

	case ISPMobile:
		switch routeType {
		case "CMIN2":
			return 99, fmt.Sprintf("💯 移动官方王牌！CMIN2 是中国移动对标 CN2 GIA 的高端精品网，晚高峰 0 丢包极速体验。%s", peakTag)
		case "CMI":
			return 88, fmt.Sprintf("🚀 亚太特优！移动 CMI 国际出口连接香港、新加坡、日本机房延迟极低（通常 30~50ms）；若是美西机房，晚高峰建议注意丢包并配合 Hy2。%s", peakTag)
		case "CN2_GIA", "CU9929":
			return 85, fmt.Sprintf("高端优化机房。移动借道优质出口，晚高峰稳定性有坚实保障。%s", peakTag)
		default:
			return 55, fmt.Sprintf("普通国际线路。移动走欧美普通 Cogent/HE 互联晚高峰丢包波动大，建议首选亚太 CMI 节点或开启 Hysteria 2。%s", peakTag)
		}

	default:
		return 80, fmt.Sprintf("本地网络为教育网/广电/海外或混合接入。建议以实测丢包为准，若丢包较高优先选用 Hysteria 2。%s", peakTag)
	}
}

// ApplyHy2Config 将建议参数应用回写至 singctl.yaml
func ApplyHy2Config(configPath string, up, down int) error {
	return config.UpdateHy2Bandwidth(configPath, up, down)
}

// GetTailoredCarrierAdvice 根据检测到的具体本地宽带环境，生成深度定制的选型与配置指导
func GetTailoredCarrierAdvice(isp *ISPInfo) string {
	if isp == nil {
		return GetCarrierBuyingGuide()
	}

	var sb strings.Builder
	divider := strings.Repeat("=", 64)
	subDivider := strings.Repeat("-", 64)

	sb.WriteString("\n" + divider + "\n")
	sb.WriteString("🌐 SingCtl 本地网络画像与专属 VPS 选型指南\n")
	sb.WriteString(divider + "\n")

	locationStr := fmt.Sprintf("%s %s %s", isp.Country, isp.Region, isp.City)
	sb.WriteString("🏠 本地网络画像:\n")
	sb.WriteString(fmt.Sprintf("   ├─ 宽带运营商 : %s\n", isp.Type))
	sb.WriteString(fmt.Sprintf("   ├─ 地理位置   : %s\n", strings.TrimSpace(locationStr)))
	sb.WriteString(fmt.Sprintf("   └─ 出口公网IP : %s\n", isp.IP))
	sb.WriteString(subDivider + "\n")

	switch isp.Type {
	case ISPTelecom:
		sb.WriteString("🎯 【中国电信】网络特征与晚高峰痛点:\n")
		sb.WriteString("   • 晚高峰 (20:00 - 24:00) 电信传统 163 骨干 (AS4134, 202.97.*.*) 国际出口极度拥塞！\n")
		sb.WriteString("   • 晚高峰丢包常年高达 20%~50%，传统 TCP 协议（VLESS-Reality 等）会频繁触发拥塞退避，导致网页秒级超时、断流、YouTube 4K 降画质甚至直接卡死。\n\n")

		sb.WriteString("🏆 为【中国电信】量身定制的 VPS 线路梯队推荐:\n")
		sb.WriteString("   【第一梯队 - 闭眼入 / 晚高峰极稳】\n")
		sb.WriteString("   1. 美西 / 亚太 CN2 GIA (AS4809, 59.43.*.*)\n")
		sb.WriteString("      • 特点: 全程走电信精品骨干专线，晚高峰丢包 < 1%，延迟极低且平稳，秒开 4K（电信宽带首选）。\n")
		sb.WriteString("      • 推荐协议: VLESS-Reality (TCP) - 省电、低延迟、抗封锁、无 UDP QoS 干扰。\n")
		sb.WriteString("   2. 联通 9929 / CUG 10099 反向优化\n")
		sb.WriteString("      • 特点: 联通政企精品网对电信互联极度友好，晚高峰表现媲美 CN2 GIA，性价比略高。\n")
		sb.WriteString("   3. 移动 CMIN2 精品网\n")
		sb.WriteString("      • 特点: 中国移动高端出口对电信同样稳定，抗丢包能力极强。\n\n")

		sb.WriteString("   【第二梯队 - 预算有限 / 折中性价比方案】\n")
		sb.WriteString("   4. 日本软银 (Softbank) / IIJ 直连\n")
		sb.WriteString("      • 特点: 部分沿海地区电信白天极快，晚高峰可能轻度波动；建议备好 Hysteria 2 兜底。\n")
		sb.WriteString("   5. 普通 163 骨干 / 便宜大碗 VPS (如各类年付十几刀的廉价海外机房)\n")
		sb.WriteString("      • 特点: 价格便宜，但晚高峰卡顿严重。\n")
		sb.WriteString("      • ⚠️ 救命稻草: 必须强制使用 Hysteria 2 (UDP/QUIC) 凭借 Brutal 拥塞控制暴力抗丢包！\n\n")

		sb.WriteString("💣 【中国电信】绝对要避开的选型雷区:\n")
		sb.WriteString("   ❌ 绝对不要贪便宜买普通欧美 Cogent / HE 直连廉价机型（晚高峰必然瘫痪卡死）。\n")
		sb.WriteString("   ⚠️ 慎选普通 CN2 GT（半程 CN2，国内省级节点走 163，出海切 CN2，晚高峰在省级节点排队依旧丢包）。\n\n")

		sb.WriteString("⚙️ 推荐 singctl.yaml 参数调优搭配:\n")
		sb.WriteString("   • 若使用 CN2 GIA / 9929 节点: 推荐优先使用 VLESS-Reality (TCP)，性能与稳定性最佳。\n")
		sb.WriteString("   • 若使用普通 163 节点: 必须配置 Hysteria 2，并在 singctl.yaml 中配置稳健带宽:\n")
		sb.WriteString("     hy2:\n")
		sb.WriteString("       up: 15\n")
		sb.WriteString("       down: 80 # 保守限速，防止晚高峰暴力打满被电信运营商 UDP QoS 降速或掐断\n\n")

		sb.WriteString("🛒 常见代表性优质机房/商家参考:\n")
		sb.WriteString("   • 搬瓦工 (BandwagonHost): DC6 / DC9 机房 (美西纯血 CN2 GIA)\n")
		sb.WriteString("   • DMIT: P.MINI / P.Pro (美西/日本/香港 CN2 GIA, 稳定性行业标杆)\n")
		sb.WriteString("   • 各类提供 9929 / CMIN2 优化的美西机型\n")

	case ISPUnicom:
		sb.WriteString("🎯 【中国联通】网络特征与选型优势:\n")
		sb.WriteString("   • 联通国际出海口总带宽非常充裕，出国综合性价比是三网中最高的！\n")
		sb.WriteString("   • 普通公网互联在晚高峰的拥堵程度显著低于电信。\n\n")

		sb.WriteString("🏆 为【中国联通】量身定制的 VPS 线路梯队推荐:\n")
		sb.WriteString("   【第一梯队 - 性价比之王】\n")
		sb.WriteString("   1. 美西三网 AS4837 (CU169, 219.158.*.*)\n")
		sb.WriteString("      • 特点: 性价比首选！机器价格亲民（年付几十刀），晚高峰带宽巨大，轻松跑满 300M~500M+。\n")
		sb.WriteString("      • 推荐协议: 日常首选 VLESS-Reality (TCP) 即可丝滑秒开。\n")
		sb.WriteString("   2. 欧洲德国 / 英国 4837 直连\n")
		sb.WriteString("      • 特点: 联通直连欧洲路由极佳，延迟 130~160ms，欧洲机房大带宽极度稳定。\n\n")

		sb.WriteString("   【进阶梯队 - 追求极致】\n")
		sb.WriteString("   3. 联通 AS9929 / CUG 10099 (A 网)\n")
		sb.WriteString("      • 特点: 政企精品专线，追求极致低延迟与游戏体验的首选。\n\n")

		sb.WriteString("💣 【中国联通】避坑提示:\n")
		sb.WriteString("   💡 联通用户通常【无需花高价与电信抢昂贵的 CN2 GIA】，优质的 AS4837 机器体验就已经非常丝滑！\n\n")

		sb.WriteString("⚙️ 推荐 singctl.yaml 参数调优搭配:\n")
		sb.WriteString("   • 默认出站推荐使用 VLESS-Reality (TCP)；\n")
		sb.WriteString("   • 若使用 Hysteria 2，可放心设置更高带宽:\n")
		sb.WriteString("     hy2:\n")
		sb.WriteString("       up: 30\n")
		sb.WriteString("       down: 200 # 联通出口宽容度高，可充分发挥高带宽优势\n\n")

		sb.WriteString("🛒 常见代表性优质机房/商家参考:\n")
		sb.WriteString("   • SpartanHost (斯巴达 4837): 经典联通神机\n")
		sb.WriteString("   • 各类美西 4837 大带宽 VPS\n")

	case ISPMobile:
		sb.WriteString("🎯 【中国移动】网络特征与选型策略:\n")
		sb.WriteString("   • 移动出国走亚太地区（香港/新加坡/日本）延迟极度强势（通常 30~50ms）；\n")
		sb.WriteString("   • 但走欧美长途时多依赖第三方 Cogent 等转接，晚高峰波动较大。\n\n")

		sb.WriteString("🏆 为【中国移动】量身定制的 VPS 线路梯队推荐:\n")
		sb.WriteString("   【第一梯队 - 亚太超低延迟】\n")
		sb.WriteString("   1. 香港 / 新加坡 / 日本 CMI (AS9808, 221.183.*.* / 221.179.*.*)\n")
		sb.WriteString("      • 特点: 延迟极低（广东到香港仅 10-20ms，内地 30-50ms），体验与国内专线相仿。\n")
		sb.WriteString("      • 推荐协议: VLESS-Reality (TCP)。\n")
		sb.WriteString("   2. 移动 CMIN2 精品网 (AS58807, 223.120.*.*)\n")
		sb.WriteString("      • 特点: 移动官方对标 CN2 GIA 的高端精品专线，美西长途直连首选。\n\n")

		sb.WriteString("💣 【中国移动】避坑提示:\n")
		sb.WriteString("   ❌ 移动切忌直连普通的欧美 Cogent / HE 廉价机型，晚高峰容易恶性丢包并跳 ping。\n\n")

		sb.WriteString("⚙️ 推荐 singctl.yaml 参数调优搭配:\n")
		sb.WriteString("   • 亚太 CMI 节点: 推荐 VLESS-Reality，延迟与握手体验拉满；\n")
		sb.WriteString("   • 欧美普通节点: 建议强制配置 Hysteria 2 抗丢包保活。\n")

	default:
		sb.WriteString("🎯 【教育网/广电/海外或混合接入】网络建议:\n")
		sb.WriteString("   • 该网络出口多借道三大运营商或走教育网 CERNET (AS4538) 骨干；\n")
		sb.WriteString("   • 建议首选三网优化机房（如 CN2 GIA / 9929 / CMIN2）或多线 BGP 机房；\n")
		sb.WriteString("   • 协议推荐配置 Hysteria 2 以应对混合线路带来的路由震荡。\n")
	}

	sb.WriteString(divider + "\n")
	sb.WriteString("💡 提示: 若需查看三大运营商全量对比百科，可执行: singctl net advice --all\n")
	sb.WriteString("        若需指定特定运营商查看指南，可使用: singctl net advice --carrier ct/cu/cm\n\n")

	return sb.String()
}

// GetCarrierBuyingGuide 输出三网宽带选型与避坑全量对比指南
func GetCarrierBuyingGuide() string {
	var sb strings.Builder
	sb.WriteString("\n📚 【中国三大运营商 VPS 选型与网络避坑全量百科】\n")
	sb.WriteString("================================================================\n")
	sb.WriteString("1. 🔴 中国电信 (China Telecom):\n")
	sb.WriteString("   • 痛点: 晚高峰 (20:00-24:00) 传统 163 骨干 (AS4134, 202.97.*.*) 国际出口极度拥塞，丢包达 20%~50%。\n")
	sb.WriteString("   • 首选选型: 美西/亚太 【CN2 GIA (AS4809, 59.43.*.*)】 或 【联通 9929】 / 【移动 CMIN2】。\n")
	sb.WriteString("   • 避坑提示: 切忌贪图便宜买普通 163 直连机房；若预算受限买了 163，请务必使用 Hysteria 2 强力抗丢包。\n\n")

	sb.WriteString("2. 🔵 中国联通 (China Unicom):\n")
	sb.WriteString("   • 优势: 联通国际出海口总带宽较充裕，性价比极高。\n")
	sb.WriteString("   • 首选选型: 性价比首选 【AS4837 (219.158.*.*)】(美西斯巴达/各类4837大带宽)；极致高要求首选 【AS9929 / CUG 10099】。\n")
	sb.WriteString("   • 避坑提示: 普通 4837 机型物美价廉，通常无需加钱上昂贵的 CN2 GIA 即可跑满日常 4K。\n\n")

	sb.WriteString("3. 🟢 中国移动 (China Mobile):\n")
	sb.WriteString("   • 特点: 移动出国走亚太地区极度强势，欧美相对普通。\n")
	sb.WriteString("   • 首选选型: 首选 【香港 / 日本 / 新加坡 CMI 直连】(延迟 30~50ms，体验极佳)；欧美长途首选 【CMIN2 精品网】。\n")
	sb.WriteString("   • 避坑提示: 移动尽量避免直连欧美普通 Cogent 廉价机型，晚高峰容易严重丢包。\n\n")

	sb.WriteString("4. ⚡ 协议搭配金法则:\n")
	sb.WriteString("   • 丢包 < 2%: 优先选 [VLESS-Reality]，轻量省电、延迟平稳、无 UDP QoS 封锁隐患。\n")
	sb.WriteString("   • 丢包 >= 5%: 优先选 [Hysteria 2]，依靠 Brutal 拥塞控制暴力抗丢包，打满带宽。\n")
	sb.WriteString("================================================================\n")
	return sb.String()
}
