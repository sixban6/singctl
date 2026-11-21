// 文件职责：定义可插拔异常检测算子契约（Detector）与多维非线性风险评分引擎主干（白名单、黑名单与特征聚合）。
package audit

import (
	"math"
	"net"
	"net/netip"
	"net/url"
	"singctl/internal/config"
	"singctl/internal/singbox"
	"slices"
	"strings"
)

// Detector 定义可插拔的行为检测算子接口，支持无限扩展自定义规则算子。
type Detector interface {
	Name() string
	Evaluate(flow *FlowRecord) (score float64, reason string)
}

// NonlinearEngine 实现多维特征交叉与非线性风险评估引擎。
//
// 核心数学模型:
//
//	RawLogit = (AsymmetryScore + BeaconScore + EntropyScore + FingerprintScore) * InteractionMultiplier * TrustDamping
//	RiskScore = round(100 * Sigmoid((RawLogit - Center) / Scale))
type blockedRulesetRef struct {
	srcCIDR string
	tag     string
}

type blockedCIDRRef struct {
	srcCIDR string
	prefix  netip.Prefix
}

type NonlinearEngine struct {
	detectors       []Detector
	trustedDomains  map[string]struct{}
	trustedCIDRs    []*net.IPNet
	blockedKeys     map[string]struct{}
	blockedCIDRs    []blockedCIDRRef
	blockedRulesets []blockedRulesetRef
}

// defaultTrustedDomains 内置常见正常高上传办公/云同步/代码托管与底层网络加密握手/DoH/连通性探测白名单域名（触发信任阻尼衰减，防止误报）。
// 注意：严禁将 akamai.net / fastly.net / cloudfront.net 等通用商业 CDN 放入此列表，防止挂靠其上的第三方追踪器被洗白。
var defaultTrustedDomains = []string{
	"github.com",
	"githubusercontent.com",
	"gitlab.com",
	"icloud.com",
	"icloud-content.com",
	"apple.com",
	"apple-dns.net",
	"captive.apple.com",
	"mzstatic.com",
	"onedrive.live.com",
	"sharepoint.com",
	"dropbox.com",
	"drive.google.com",
	"googleapis.com",
	"connectivitycheck.gstatic.com",
	"msftconnecttest.com",
	"msftncsi.com",
	"tailscale.com",
	"tailscale.io",
	"cloudflare.com",
	"cloudflare-ech.com",
	"cloudflare-dns.com",
	"one.one.one.one",
	"dns.google",
	"dns.alidns.com",
	"doh.pub",
	"dot.pub",
}

// privacyTrackerKeywords 属于隐私窥探/行为画像/云端遥测维度的特征词（即使单次上传仅几 KB 也会触发隐私评分）。
var privacyTrackerKeywords = []string{
	"telemetry", "collect", "collector", "beacon", "tracker", "track",
	"log.", "logs.", "ulog", "applog", "sdklog", "crashlog", "stat.", "stats.",
	"metric", "metrics", "report.", "analytics", "adlog", "adtrack",
	"umeng", "appsflyer", "adjust.", "jpush", "getui", "sensorsdata", "miaozhen",
	"psmartcloud", "tuyaus", "tuyacn", "iot-log",
}

// nonPCDNPureCDNParents 显式排除常规主流 CDN / 浏览器 / 苹果等服务父域，避免 "ipcdn"、"pcdn.brave.com"、"dmcdn.net" 等子串误报。
var nonPCDNPureCDNParents = []string{
	"apple.com", "brave.com", "dmcdn.net", "icloud.com",
	"google.com", "googleapis.com", "cloudflare.com", "tailscale.com", "wechat.com",
}

var pcdnLabelExactTokens = map[string]struct{}{
	"pcdn": {}, "mcdn": {}, "bcdn": {}, "xycdn": {},
	"hcdn": {}, "tcdn": {}, "stun": {},
}

// matchPCDNDomain 精确识别商业 PCDN/MCDN 调度与节点域名，避免裸子串误伤常规合法域名。
func matchPCDNDomain(target string) (bool, string) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if d == "" || net.ParseIP(strings.Trim(d, "[]")) != nil {
		return false, ""
	}
	for _, p := range nonPCDNPureCDNParents {
		if d == p || strings.HasSuffix(d, "."+p) {
			return false, ""
		}
	}
	if matched, suffix := singbox.MatchBuiltinPCDNDomain(d); matched {
		return true, suffix
	}
	for lbl := range strings.SplitSeq(d, ".") {
		if _, ok := pcdnLabelExactTokens[lbl]; ok {
			return true, lbl
		}
		if strings.HasPrefix(lbl, "pcdn-") || strings.HasSuffix(lbl, "-pcdn") {
			return true, lbl
		}
	}
	return false, ""
}

func isKnownIoTOrVoIPUDPPort(port int) bool {
	return port == 3478 || port == 8053 || port == 32100
}

func isKnownGameUDPPort(port int) bool {
	if (port >= 6650 && port <= 6659) || (port >= 20000 && port <= 20002) {
		return true
	}
	return port == 5010 || port == 12346 || port == 30000
}

func isKnownLegitUDPServicePort(port int) bool {
	return port == 41641 || isKnownIoTOrVoIPUDPPort(port) || isKnownGameUDPPort(port)
}

// iotDeviceKeywords 智能家居/电视/摄像头主机名特征词（用于推断设备角色）。
var iotDeviceKeywords = []string{
	"tv", "mitv", "xiaomi-tv", "bravia", "lgwebos", "hisense", "tcl",
	"cam", "ipc", "camera", "mijia", "yeelink", "roborock", "dreame",
	"lumi", "aqara", "tuya", "esp", "broadlink", "speaker", "tmall", "xiaoai",
}

// NewNonlinearEngine 根据当前 singctl 配置初始化非线性风险评估引擎。
func NewNonlinearEngine(cfg *config.Config) *NonlinearEngine {
	eng := &NonlinearEngine{
		trustedDomains: make(map[string]struct{}),
		blockedKeys:    make(map[string]struct{}),
		detectors: []Detector{
			&uploadAsymmetryDetector{},
			&directIPUploadDetector{},
			&directIPSubnetClusterDetector{},
			&pcdnSwarmDetector{},
			&beaconHeartbeatDetector{},
			&domainEntropyDetector{},
			&telemetryFingerprintDetector{},
		},
	}

	for _, d := range defaultTrustedDomains {
		eng.addTrustedEntry(d)
	}
	// 默认信任 Tailscale CGNAT 网段与本地回环
	for _, cidr := range []string{"100.64.0.0/10", "127.0.0.0/8", "::1/128"} {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			eng.trustedCIDRs = append(eng.trustedCIDRs, ipNet)
		}
	}

	if cfg != nil {
		// 自动提取用户订阅链接域名与自建服务端节点域名至信任基线
		for _, sub := range cfg.Subs {
			if u, err := url.Parse(strings.TrimSpace(sub.URL)); err == nil && u.Hostname() != "" {
				eng.addTrustedEntry(u.Hostname())
			}
		}
		if nd := cfg.Server.GetNodeDomain(); nd != "" && nd != "node.example.com" {
			eng.addTrustedEntry(nd)
		}
		if sd := cfg.Server.GetSubstoreDomain(); sd != "" && sd != "node.example.com" {
			eng.addTrustedEntry(sd)
		}
		if sip := strings.TrimSpace(cfg.Server.ServerIP); sip != "" {
			eng.addTrustedEntry(sip)
		}
		for _, w := range cfg.Audit.Whitelist {
			eng.addTrustedEntry(w)
		}
	}

	for _, b := range singbox.EffectiveBlockRules(cfg) {
		target, isIPTarget := singbox.NormalizeBlockTarget(b.Target)
		if target == "" {
			continue
		}
		src := singbox.NormalizeSourceIPCIDR(b.SourceIP)
		if strings.HasPrefix(target, "ruleset:") {
			eng.blockedRulesets = append(eng.blockedRulesets, blockedRulesetRef{
				srcCIDR: src,
				tag:     strings.TrimPrefix(target, "ruleset:"),
			})
			continue
		}
		if isIPTarget {
			if prefix, ok := parseAuditIPPrefix(target); ok && !prefix.IsSingleIP() {
				eng.blockedCIDRs = append(eng.blockedCIDRs, blockedCIDRRef{
					srcCIDR: src,
					prefix:  prefix,
				})
			}
		}
		eng.blockedKeys[src+"|"+target] = struct{}{}
		// 同时索引去掉 /32 的纯 IP 键以便快速匹配
		if plainIP := strings.TrimSuffix(strings.TrimSuffix(target, "/32"), "/128"); plainIP != target {
			eng.blockedKeys[src+"|"+plainIP] = struct{}{}
		}
	}

	return eng
}

// RegisterDetector 允许外部动态注册新的自定义检测算子。
func (e *NonlinearEngine) RegisterDetector(d Detector) {
	if d != nil {
		e.detectors = append(e.detectors, d)
	}
}

func (e *NonlinearEngine) addTrustedEntry(raw string) {
	target, isIP := singbox.NormalizeBlockTarget(raw)
	if target == "" {
		return
	}
	if isIP {
		if _, ipNet, err := net.ParseCIDR(target); err == nil && ipNet != nil {
			e.trustedCIDRs = append(e.trustedCIDRs, ipNet)
		}
		return
	}
	e.trustedDomains[target] = struct{}{}
}

// IsTrusted 判断目标域名或 IP 是否命中可信白名单基线。
func (e *NonlinearEngine) IsTrusted(target string) bool {
	norm, isIP := singbox.NormalizeBlockTarget(target)
	if norm == "" {
		return false
	}
	if isIP {
		ipStr := strings.TrimSuffix(strings.TrimSuffix(norm, "/32"), "/128")
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return false
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return true
		}
		for _, cidr := range e.trustedCIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
		return false
	}

	if _, ok := e.trustedDomains[norm]; ok {
		return true
	}
	for s := norm; ; {
		idx := strings.IndexByte(s, '.')
		if idx < 0 {
			break
		}
		s = s[idx+1:]
		if _, ok := e.trustedDomains[s]; ok {
			return true
		}
	}
	return false
}

// IsBlocked 判断某条流是否已被納入自定义拉黑规则。
func (e *NonlinearEngine) IsBlocked(deviceIP, target string) bool {
	if len(e.blockedKeys) == 0 && len(e.blockedCIDRs) == 0 && len(e.blockedRulesets) == 0 {
		return false
	}
	norm, _ := singbox.NormalizeBlockTarget(target)
	if norm == "" {
		return false
	}
	plain := strings.TrimSuffix(strings.TrimSuffix(norm, "/32"), "/128")
	srcCIDR := singbox.NormalizeSourceIPCIDR(deviceIP)

	matchKey := func(t string) bool {
		if _, ok := e.blockedKeys["|"+t]; ok {
			return true
		}
		if srcCIDR != "" {
			if _, ok := e.blockedKeys[srcCIDR+"|"+t]; ok {
				return true
			}
		}
		return false
	}

	if matchKey(norm) || (plain != norm && matchKey(plain)) {
		return true
	}

	if len(e.blockedCIDRs) > 0 {
		if addr, err := netip.ParseAddr(plain); err == nil {
			addr = addr.Unmap()
			for _, bc := range e.blockedCIDRs {
				if (bc.srcCIDR == "" || bc.srcCIDR == srcCIDR) && bc.prefix.Contains(addr) {
					return true
				}
			}
		}
	}

	// 域名后缀零切片步进匹配（如拉黑了 example.com，则 sub.example.com 也处于已拉黑态）
	for s := plain; ; {
		idx := strings.IndexByte(s, '.')
		if idx < 0 {
			break
		}
		s = s[idx+1:]
		if matchKey(s) {
			return true
		}
	}

	for _, br := range e.blockedRulesets {
		if br.srcCIDR != "" && br.srcCIDR != srcCIDR {
			continue
		}
		if br.tag == singbox.BuiltinPCDNRuleSetTag {
			if matched, _ := singbox.MatchBuiltinPCDNDomain(plain); matched {
				return true
			}
			continue
		}
		if rs := loadBlockedRuleSetSummary(br.tag); rs != nil && matchDecompiledRuleSet(rs, plain, plain) {
			return true
		}
	}
	return false
}

// EvaluateFlow 对单条聚合流执行多维非线性评分并填充状态、威胁等级与可解释原因。
func (e *NonlinearEngine) EvaluateFlow(flow *FlowRecord) {
	if flow == nil {
		return
	}
	if flow.NonlinearFactors == nil {
		flow.NonlinearFactors = make(map[string]float64)
	}
	if flow.PCDNSwarm != nil && flow.PCDNSwarm.Suspicious {
		flow.PCDNKind = "swarm"
	} else {
		flow.PCDNKind = ""
	}

	// 计算基础衍生指标
	denom := float64(flow.DownloadBytes) + 65536.0 // +64KB 平滑项，避免除零并容忍握手包
	flow.UploadRatio = math.Round((float64(flow.UploadBytes)/denom)*100) / 100
	flow.AvgUploadBps = math.Round(avgUploadBytesPerSec(flow)*10) / 10
	if !flow.IsDirectIP && flow.Target != "" {
		flow.DomainEntropy = math.Round(ShannonEntropy(extractPrimaryLabel(flow.Target))*100) / 100
	}
	if flow.DeviceRole == "" {
		flow.DeviceRole = InferDeviceRole(flow.DeviceName)
	}

	// 1. 各独立非线性算子打分，并正交投射到「🛡️ 安全轴 (Security)」与「👁️ 隐私轴 (Privacy)」
	var secBase, privBase float64
	var reasons []string
	for _, det := range e.detectors {
		s, r := det.Evaluate(flow)
		if s > 0 {
			flow.NonlinearFactors[det.Name()] = math.Round(s*100) / 100
			switch det.Name() {
			case "upload_asymmetry", "direct_ip_upload", "direct_ip_subnet_cluster", "pcdn_swarm", "domain_entropy":
				secBase += s
			case "beacon_heartbeat":
				// 机器定时心跳既是远控信标特征(安全)，更是全天候状态打点画像特征(隐私)
				secBase += s * 0.55
				privBase += s * 0.85
			case "telemetry_fingerprint":
				if flow.PCDNKind != "" {
					secBase += s
				} else {
					privBase += s
				}
			default:
				secBase += s
			}
			if r != "" && !slices.Contains(reasons, r) {
				reasons = append(reasons, r)
			}
		}
	}

	// 补充专属隐私轴算子（针对几 KB 的小包高频遥测、凌晨作息窥探、明文 HTTP 裸奔）
	privExtra, privReasons := evaluatePrivacyAxisExtras(flow)
	if privExtra > 0 {
		privBase += privExtra
		flow.NonlinearFactors["privacy_axis_extra"] = math.Round(privExtra*100) / 100
		for _, pr := range privReasons {
			reasons = appendUniqueReason(reasons, pr)
		}
	}

	// 2. 双轴多维特征交叉倍增项 (Orthogonal Multiplicative Interaction Terms)
	secInteraction := 1.0
	privInteraction := 1.0
	slowTelemetry := isSlowLongSpanTelemetry(flow)
	isUploadDominant := flow.UploadBytes >= 256*1024 && flow.UploadRatio >= 1.8 && !slowTelemetry
	isNonStdPort := flow.DestPort > 0 && flow.DestPort != 80 && flow.DestPort != 443 && flow.DestPort != 53 && flow.DestPort != 123
	isPeriodicBeacon := flow.ConnCount >= 6 && flow.IntervalCV > 0 && flow.IntervalCV < 0.30

	// 安全交叉项 A: [无域名直连 IP] × [非标端口] × [上行主导] -> 区分已知 IoT/音视频/手游端口与不明 PCDN 偷跑
	if flow.IsDirectIP && isNonStdPort && isUploadDominant {
		isUDP := strings.EqualFold(flow.Network, "udp")
		hasSwarm := flow.PCDNSwarm != nil && flow.PCDNSwarm.Suspicious
		switch {
		case isUDP && isKnownIoTOrVoIPUDPPort(flow.DestPort) && flow.UploadBytes < 20*1024*1024 && !hasSwarm:
			reasons = appendUniqueReason(reasons, "已知 IoT/摄像头/音视频常用直连端口")
		case isUDP && isKnownGameUDPPort(flow.DestPort) && flow.UploadBytes < 20*1024*1024 && !hasSwarm:
			secInteraction *= 1.15
			reasons = appendUniqueReason(reasons, "直连IP非标UDP上行 (常见于手游联机/加速节点，如非游戏请核查)")
		default:
			secInteraction *= 1.75
			reasons = appendUniqueReason(reasons, "多维交叉: 直连IP+非标端口+持续上行(疑似PCDN/暗道回传)")
		}
	}
	// 安全/隐私交叉项 B: [凌晨 01:00-05:30 活跃] × [上行主导 或 规律心跳]
	if flow.NightHits > 0 && (isUploadDominant || isPeriodicBeacon) {
		secInteraction *= 1.30
		privInteraction *= 1.45
		reasons = appendUniqueReason(reasons, "多维交叉: 凌晨闲时静默上传活跃")
	}
	// 安全/隐私交叉项 C: [IoT/智能电视设备] × [上行主导 或 规律心跳]
	if flow.DeviceRole == "iot" && (isUploadDominant || isPeriodicBeacon) {
		secInteraction *= 1.35
		privInteraction *= 1.35
		reasons = appendUniqueReason(reasons, "多维交叉: 智能家居/IoT设备异常外发数据")
	}
	// 安全交叉项 D: [高信息熵域名] × [高频建连或上行主导]
	effConns := effectiveConnCountPerHour(flow)
	if flow.DomainEntropy >= 3.65 && (effConns >= 10 || isUploadDominant) {
		secInteraction *= 1.35
	}
	flow.NonlinearFactors["sec_interaction"] = math.Round(secInteraction*100) / 100
	flow.NonlinearFactors["priv_interaction"] = math.Round(privInteraction*100) / 100

	// 3. 信任白名单与 L2 AI 深度复核闭环阻尼衰减因子 (Trust & AI Damping)
	trustDamping := 1.0
	trusted := e.IsTrusted(flow.Target) || strings.EqualFold(flow.Outbound, "block")
	aiDamped := false
	if trusted {
		trustDamping = 0.08
		reasons = []string{"命中可信白名单基线 (自动阻尼降权)"}
	} else if flow.AIReview != nil && flow.AIReview.Verdict == AIDoNotBlock &&
		flow.AIReview.Source != "" && flow.AIReview.Source != "builtin_expert" && flow.AIReview.Source != "trusted_baseline" {
		// 安全护栏：对直连非标端口大上传、确认 PCDN 偷跑/蜂群或极端百兆倒挂上传保留警觉，下行 PCDN 拉流允许 AI 闭环降权
		isHardPCDN := flow.PCDNKind == "upload" || flow.PCDNKind == "swarm"
		isHardAnomaly := (flow.IsDirectIP && isNonStdPort && isUploadDominant) ||
			isHardPCDN ||
			(flow.UploadBytes >= 100*1024*1024 && flow.UploadRatio >= 4.0)
		if !isHardAnomaly {
			trustDamping = 0.25
			aiDamped = true
			flow.NonlinearFactors["ai_damping"] = 0.25
			if len(reasons) > 0 {
				reasons = []string{"AI 深度复核确认正常业务 (已自动降权)", "原启发式观察: " + reasons[0]}
			} else {
				reasons = []string{"AI 深度复核确认正常业务 (已自动降权)"}
			}
		}
	}
	flow.NonlinearFactors["trust_damping"] = trustDamping

	rawSec := secBase * secInteraction * trustDamping
	rawPriv := privBase * privInteraction * trustDamping
	flow.NonlinearFactors["raw_security"] = math.Round(rawSec*100) / 100
	flow.NonlinearFactors["raw_privacy"] = math.Round(rawPriv*100) / 100

	// 4. 双轴 Sigmoid 归一化 + Soft-Max 极值包络合成总分 (绝不因求平均而互相稀释)
	flow.SecurityScore = mapRawToSigmoidScore(rawSec, 36.0, 16.0)
	flow.PrivacyScore = mapRawToSigmoidScore(rawPriv, 32.0, 15.0)
	if aiDamped {
		flow.SecurityScore = min(flow.SecurityScore, 24)
		flow.PrivacyScore = min(flow.PrivacyScore, 24)
	}

	hiAxis := float64(max(flow.SecurityScore, flow.PrivacyScore))
	loAxis := float64(min(flow.SecurityScore, flow.PrivacyScore))
	finalScore := int(math.Round(min(100.0, hiAxis+0.25*loAxis)))
	if aiDamped {
		finalScore = min(finalScore, 28)
	}
	flow.RiskScore = finalScore

	switch {
	case flow.SecurityScore < 15 && flow.PrivacyScore < 15:
		flow.DominantAxis = "normal"
	case flow.SecurityScore >= 35 && flow.PrivacyScore >= 35 && math.Abs(float64(flow.SecurityScore-flow.PrivacyScore)) <= 15:
		flow.DominantAxis = "both"
	case flow.PrivacyScore > flow.SecurityScore:
		flow.DominantAxis = "privacy"
	default:
		flow.DominantAxis = "security"
	}

	// 5. 显式威胁等级状态流转
	switch {
	case finalScore >= 80:
		flow.Threat = ThreatHighRisk
	case finalScore >= 60:
		flow.Threat = ThreatSuspicious
	case finalScore >= 35:
		flow.Threat = ThreatNotice
	default:
		flow.Threat = ThreatNormal
	}
	flow.ThreatLabel = flow.Threat.Label()

	// 6. 显式封禁生命周期状态
	switch {
	case e.IsBlocked(flow.DeviceIP, flow.Target):
		flow.State = EnforcementBlocked
	case trusted:
		flow.State = EnforcementWhitelisted
	default:
		flow.State = EnforcementObserved
	}

	if len(reasons) == 0 {
		reasons = []string{"上下行比例与建连行为正常"}
	}
	flow.Reasons = reasons
}
