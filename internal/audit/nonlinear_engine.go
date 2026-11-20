package audit

import (
	"cmp"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"singctl/internal/config"
	"singctl/internal/singbox"
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

// ───────────────────────── 5 大非线性基础检测算子 ─────────────────────────

// 1. uploadAsymmetryDetector: 对数-不对称度算子
type uploadAsymmetryDetector struct{}

func (d *uploadAsymmetryDetector) Name() string { return "upload_asymmetry" }

func (d *uploadAsymmetryDetector) Evaluate(f *FlowRecord) (float64, string) {
	// 小于 128KB 的微弱握手包不计入异常上传
	if f.UploadBytes < 128*1024 {
		return 0, ""
	}
	// 当上传小于下载时，正常浏览/视频流不扣分（除非纯上传绝对量极大 > 200MB 且比值 > 0.8）
	if f.UploadRatio < 1.2 && f.UploadBytes < 200*1024*1024 {
		return 0, ""
	}

	avgBps := avgUploadBytesPerSec(f)
	if isSlowLongSpanTelemetry(f) {
		// 长周期（>=6h）且平均速率 < 2KB/s 的 IoT 状态心跳，按 1 小时等效上传量折算评分，避免误报 100 分偷跑高危
		effUpMB := (avgBps * 3600.0) / (1024.0 * 1024.0)
		ratioTerm := math.Log1p(math.Max(0, f.UploadRatio-0.8))
		volTerm := math.Log1p(effUpMB * 2.5)
		score := math.Min(16.0, 6.0*ratioTerm*volTerm)
		if score < 6.0 {
			return 0, ""
		}
		return score, "长时低速心跳累计上传 (↑" + formatBytesShort(f.UploadBytes) + ", 均速 " + formatBytesPerSec(avgBps) + ")"
	}

	// 非线性对数压缩: log(1 + Ratio) * log(1 + UploadMB)
	upMB := float64(f.UploadBytes) / (1024.0 * 1024.0)
	ratioTerm := math.Log1p(math.Max(0, f.UploadRatio-0.8))
	volTerm := math.Log1p(upMB * 2.5)
	score := math.Min(48.0, 9.5*ratioTerm*volTerm)

	if score < 6.0 {
		return 0, ""
	}
	if f.UploadRatio >= 5.0 {
		return score, "上下行流量严重倒挂 (" + strconv.FormatFloat(f.UploadRatio, 'f', 1, 64) + "x)"
	}
	return score, "持续大流量上传 (↑" + formatBytesShort(f.UploadBytes) + ")"
}

func avgUploadBytesPerSec(f *FlowRecord) float64 {
	if f == nil || f.UploadBytes <= 0 {
		return 0
	}
	span := max(int64(60), f.ActiveSpanSec)
	return float64(f.UploadBytes) / float64(span)
}

func isSlowLongSpanTelemetry(f *FlowRecord) bool {
	if f == nil || f.IsDirectIP || f.PCDNKind == "upload" || f.PCDNKind == "swarm" {
		return false
	}
	return f.ActiveSpanSec >= 6*3600 && avgUploadBytesPerSec(f) < 2048.0
}

func formatBytesPerSec(bps float64) string {
	switch {
	case bps < 1024:
		return fmt.Sprintf("%.0f B/s", bps)
	case bps < 1024*1024:
		return fmt.Sprintf("%.1f KB/s", bps/1024)
	default:
		return fmt.Sprintf("%.1f MB/s", bps/(1024*1024))
	}
}

// isKnownStandardHTTPSInfraApp 判断是否属于主流云厂商/操作系统基础设施服务（用于豁免标准 443 端口 HTTP/3 QUIC 无 SNI 迁移连接误报）。
func isKnownStandardHTTPSInfraApp(appName string) bool {
	switch strings.TrimSpace(appName) {
	case "Apple", "iCloud", "Cloudflare", "Cloudflare DNS", "Google", "Google DNS", "YouTube",
		"Microsoft", "OneDrive", "GitHub", "Telegram", "OpenAI", "Claude / Anthropic",
		"Tailscale", "Tailscale 组网":
		return true
	default:
		return false
	}
}

// effectiveConnCountPerHour 将累计连接次数按流存活时长归一化为每小时连接速率（<=1小时或未记录跨度时保持原始值）。
func effectiveConnCountPerHour(f *FlowRecord) float64 {
	if f == nil || f.ConnCount <= 0 {
		return 0
	}
	if f.ActiveSpanSec <= 3600 {
		return float64(f.ConnCount)
	}
	hours := float64(f.ActiveSpanSec) / 3600.0
	return float64(f.ConnCount) / hours
}

// 2. directIPUploadDetector: 绕过 DNS 直连公网 IP 上传算子
type directIPUploadDetector struct{}

func (d *directIPUploadDetector) Name() string { return "direct_ip_upload" }

func (d *directIPUploadDetector) Evaluate(f *FlowRecord) (float64, string) {
	if !f.IsDirectIP || f.UploadBytes < 64*1024 {
		return 0, ""
	}
	// 标准 443 端口下，Apple / Cloudflare / Google 等主流基础设施的 HTTP/3 QUIC 会话迁移常无明文 SNI，只要未出现显著上行倒挂即属正常加密传输
	if f.DestPort == 443 {
		if isKnownStandardHTTPSInfraApp(f.AppName) && f.UploadRatio < 1.8 {
			return 0, ""
		}
		if f.DownloadBytes > f.UploadBytes*2 && f.UploadRatio < 0.5 {
			return 6.0, "直连443端口加密传输 (下行主导)"
		}
	}
	score := 16.0
	isLightKnownUDP := strings.EqualFold(f.Network, "udp") && isKnownIoTOrVoIPUDPPort(f.DestPort) && f.UploadBytes < 10*1024*1024 && f.UploadRatio < 2.0
	if strings.EqualFold(f.Network, "udp") {
		if f.DestPort == 443 {
			score += 4.0
		} else if isLightKnownUDP {
			score += 2.0
		} else {
			score += 8.0
		}
	}
	if f.DestPort > 1024 && f.DestPort != 8080 && f.DestPort != 8443 && !isLightKnownUDP {
		score += 7.0
	}
	return score, "绕过DNS直连公网IP上传"
}

// directIPPublicAddr 解析并过滤出非私网/非回环/非保留段的公网单播 IP。
func directIPPublicAddr(rawIP string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return netip.Addr{}, false
	}
	for _, rp := range protectedReservedPrefixes {
		if rp.Contains(addr) {
			return netip.Addr{}, false
		}
	}
	if slices.Contains(ProtectedBootstrapIPs, addr.String()) {
		return netip.Addr{}, false
	}
	return addr, true
}

// directIPAuditSubnet 将公网直连 IP 归一化为用于聚集分析的 /24 (IPv4) 或 /48 (IPv6) 目的网段；
// 自动过滤回环、私网、Tailscale、FakeIP、基础 DNS 等受保护保留段。
func directIPAuditSubnet(rawIP string) (string, bool) {
	addr, ok := directIPPublicAddr(rawIP)
	if !ok {
		return "", false
	}
	bits := 24
	if addr.Is6() {
		bits = 48
	}
	return netip.PrefixFrom(addr, bits).Masked().String(), true
}

// directIPPublicSlash16 将公网直连 IP 归一化为用于 PCDN 跨网段蜂群分析的 /16 (IPv4) 或 /32 (IPv6) 前缀。
func directIPPublicSlash16(rawIP string) (string, bool) {
	addr, ok := directIPPublicAddr(rawIP)
	if !ok {
		return "", false
	}
	bits := 16
	if addr.Is6() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits).Masked().String(), true
}

// AnnotateDirectIPSubnetClusters 在单流评估前，按 (来源设备, 目的 /24 或 /48) 聚合并标注无域名纯裸 IP 的同网段访问簇。
func (e *NonlinearEngine) AnnotateDirectIPSubnetClusters(flows []FlowRecord) {
	type bucketKey struct {
		deviceIP string
		cidr     string
	}
	type ipUploadStat struct {
		ip     string
		upload int64
	}
	type bucket struct {
		cidr               string
		flowIndices        []int
		ipUploads          map[string]int64
		activeConns        int
		uploadBytes        int64
		downloadBytes      int64
		hasNonStdPort      bool
		allKnownInfraHTTPS bool
	}

	buckets := make(map[bucketKey]*bucket)
	for i := range flows {
		f := &flows[i]
		if !f.IsDirectIP || e.IsTrusted(f.Target) || strings.EqualFold(f.Outbound, "block") {
			continue
		}
		cidr, ok := directIPAuditSubnet(f.Target)
		if !ok {
			continue
		}
		addr, _ := netip.ParseAddr(strings.TrimSpace(f.Target))
		plainIP := addr.Unmap().String()

		bk := bucketKey{deviceIP: f.DeviceIP, cidr: cidr}
		b, exists := buckets[bk]
		if !exists {
			b = &bucket{
				cidr:               cidr,
				ipUploads:          make(map[string]int64),
				allKnownInfraHTTPS: true,
			}
			buckets[bk] = b
		}
		b.flowIndices = append(b.flowIndices, i)
		b.ipUploads[plainIP] += f.UploadBytes
		b.activeConns += f.ActiveConns
		b.uploadBytes += f.UploadBytes
		b.downloadBytes += f.DownloadBytes
		if f.DestPort > 0 && f.DestPort != 80 && f.DestPort != 443 && f.DestPort != 53 && f.DestPort != 123 {
			b.hasNonStdPort = true
		}
		if f.DestPort != 443 || !isKnownStandardHTTPSInfraApp(f.AppName) {
			b.allKnownInfraHTTPS = false
		}
	}

	for _, b := range buckets {
		uniqueIPs := len(b.ipUploads)
		denom := float64(b.downloadBytes) + 65536.0
		clusterRatio := float64(b.uploadBytes) / denom
		exemptKnownInfra := b.allKnownInfraHTTPS && clusterRatio < 1.8
		suspicious := uniqueIPs >= 3 && !exemptKnownInfra &&
			(b.hasNonStdPort || (b.uploadBytes >= 256*1024 && clusterRatio >= 1.2) || uniqueIPs >= 5)

		var sampleIPs []string
		if uniqueIPs > 1 {
			stats := make([]ipUploadStat, 0, uniqueIPs)
			for ip, up := range b.ipUploads {
				stats = append(stats, ipUploadStat{ip: ip, upload: up})
			}
			slices.SortFunc(stats, func(a, b ipUploadStat) int {
				if c := cmp.Compare(b.upload, a.upload); c != 0 {
					return c
				}
				return cmp.Compare(a.ip, b.ip)
			})
			limit := min(6, len(stats))
			sampleIPs = make([]string, 0, limit)
			for _, st := range stats[:limit] {
				sampleIPs = append(sampleIPs, st.ip)
			}
		}

		cluster := DirectIPSubnetCluster{
			CIDR:          b.cidr,
			UniqueIPs:     uniqueIPs,
			FlowCount:     len(b.flowIndices),
			ActiveConns:   b.activeConns,
			UploadBytes:   b.uploadBytes,
			DownloadBytes: b.downloadBytes,
			SampleIPs:     sampleIPs,
			Suspicious:    suspicious,
		}
		for _, idx := range b.flowIndices {
			cCopy := cluster
			flows[idx].SubnetCluster = &cCopy
		}
	}
}

// 2b. directIPSubnetClusterDetector: 同网段裸 IP 聚集外连算子（捕获 PCDN/P2P 节点池、固件多 IP 轮换回连）
type directIPSubnetClusterDetector struct{}

func (d *directIPSubnetClusterDetector) Name() string { return "direct_ip_subnet_cluster" }

func (d *directIPSubnetClusterDetector) Evaluate(f *FlowRecord) (float64, string) {
	if f == nil || !f.IsDirectIP || f.SubnetCluster == nil || !f.SubnetCluster.Suspicious {
		return 0, ""
	}
	c := f.SubnetCluster
	score := 12.0 + math.Min(16.0, float64(c.UniqueIPs-2)*3.5)
	denom := float64(c.DownloadBytes) + 65536.0
	ratio := float64(c.UploadBytes) / denom
	if c.UploadBytes >= 1024*1024 && ratio >= 1.5 {
		score += 6.0
	}
	score = math.Min(32.0, score)
	return score, fmt.Sprintf("同网段裸IP聚集: 连向 %s 共 %d 个不同IP", c.CIDR, c.UniqueIPs)
}

// AnnotatePCDNSwarmBehaviors 识别单台设备向大量分散公网 /16 (或 IPv6 /32) 网段发起非标高端口 UDP 裸 IP 上行的 PCDN/P2P 蜂群偷跑特征。
func (e *NonlinearEngine) AnnotatePCDNSwarmBehaviors(flows []FlowRecord) {
	type swarmBucket struct {
		flowIndices   []int
		slash16s      map[string]struct{}
		uniqueIPs     map[string]struct{}
		uploadBytes   int64
		downloadBytes int64
	}

	buckets := make(map[string]*swarmBucket)
	for i := range flows {
		f := &flows[i]
		if !f.IsDirectIP || !strings.EqualFold(f.Network, "udp") || e.IsTrusted(f.Target) || strings.EqualFold(f.Outbound, "block") {
			continue
		}
		if f.DestPort <= 1024 || isKnownLegitUDPServicePort(f.DestPort) {
			continue
		}
		slash16, ok := directIPPublicSlash16(f.Target)
		if !ok {
			continue
		}
		addr, _ := directIPPublicAddr(f.Target)
		b, exists := buckets[f.DeviceIP]
		if !exists {
			b = &swarmBucket{
				slash16s:  make(map[string]struct{}),
				uniqueIPs: make(map[string]struct{}),
			}
			buckets[f.DeviceIP] = b
		}
		b.flowIndices = append(b.flowIndices, i)
		b.slash16s[slash16] = struct{}{}
		b.uniqueIPs[addr.String()] = struct{}{}
		b.uploadBytes += f.UploadBytes
		b.downloadBytes += f.DownloadBytes
	}

	for _, b := range buckets {
		uniqueSlash16 := len(b.slash16s)
		denom := float64(b.downloadBytes) + 65536.0
		ratio := math.Round((float64(b.uploadBytes)/denom)*100) / 100
		if uniqueSlash16 < 8 || b.uploadBytes < 5*1024*1024 || ratio < 1.2 {
			continue
		}
		summary := PCDNSwarmSummary{
			UniqueSlash16: uniqueSlash16,
			UniqueIPs:     len(b.uniqueIPs),
			FlowCount:     len(b.flowIndices),
			UploadBytes:   b.uploadBytes,
			DownloadBytes: b.downloadBytes,
			UploadRatio:   ratio,
			Suspicious:    true,
		}
		for _, idx := range b.flowIndices {
			sCopy := summary
			flows[idx].PCDNSwarm = &sCopy
			flows[idx].PCDNKind = "swarm"
		}
	}
}

// 2c. pcdnSwarmDetector: PCDN/P2P 跨网段分散裸 IP 蜂群上传算子
type pcdnSwarmDetector struct{}

func (d *pcdnSwarmDetector) Name() string { return "pcdn_swarm" }

func (d *pcdnSwarmDetector) Evaluate(f *FlowRecord) (float64, string) {
	if f == nil || !f.IsDirectIP || f.PCDNSwarm == nil || !f.PCDNSwarm.Suspicious {
		return 0, ""
	}
	s := f.PCDNSwarm
	score := math.Min(36.0, 22.0+float64(s.UniqueSlash16-7)*1.8)
	return score, fmt.Sprintf("PCDN/P2P 跨网段分散裸IP蜂群偷跑: 横跨 %d 个公网网段，累计上行 %.1fMB", s.UniqueSlash16, float64(s.UploadBytes)/1048576.0)
}

// 3. beaconHeartbeatDetector: 建连间隔变异系数 (CV) 机器心跳算子
type beaconHeartbeatDetector struct{}

func (d *beaconHeartbeatDetector) Name() string { return "beacon_heartbeat" }

func (d *beaconHeartbeatDetector) Evaluate(f *FlowRecord) (float64, string) {
	if f.ConnCount < 6 {
		return 0, ""
	}
	var score float64
	var reason string

	// 若具备时间间隔变异系数 CV = sigma/mu，机器定时器的 CV 趋近于 0
	if f.IntervalCV > 0 && f.IntervalCV < 0.35 {
		regularity := math.Exp(-4.5 * f.IntervalCV) // CV=0.05 -> 0.80, CV=0.30 -> 0.26
		score += 24.0 * regularity
		reason = "固定周期机器心跳信标 (CV=" + strconv.FormatFloat(f.IntervalCV, 'f', 2, 64) + ")"
	}

	effConns := effectiveConnCountPerHour(f)
	isKnownQUIC443 := f.IsDirectIP && f.DestPort == 443 && isKnownStandardHTTPSInfraApp(f.AppName) && f.UploadRatio < 1.8
	matchedPCDN, _ := matchPCDNDomain(f.Target)
	hasSuspectTrait := f.UploadRatio >= 1.35 ||
		(f.IsDirectIP && !isKnownQUIC443) ||
		matchesAnyKeyword(f.Target, privacyTrackerKeywords) ||
		matchedPCDN ||
		(f.IntervalCV > 0 && f.IntervalCV < 0.45)

	if effConns >= 25 && f.UploadBytes >= 64*1024 && hasSuspectTrait {
		freqBonus := math.Min(16.0, 4.5*math.Log1p(effConns/10.0))
		score += freqBonus
		if reason == "" {
			reason = "高频重复建连上报 (" + strconv.Itoa(f.ConnCount) + "次)"
		}
	}
	return score, reason
}

// 4. domainEntropyDetector: 域名香农信息熵算子 (识别随机生成子域名/DGA/隧道)
type domainEntropyDetector struct{}

func (d *domainEntropyDetector) Name() string { return "domain_entropy" }

func (d *domainEntropyDetector) Evaluate(f *FlowRecord) (float64, string) {
	if f.IsDirectIP || f.DomainEntropy < 3.60 || f.UploadBytes < 32*1024 {
		return 0, ""
	}
	// 非线性阶跃: 熵值超过 3.60 后按指数爬升
	excess := f.DomainEntropy - 3.55
	score := math.Min(22.0, 18.0*(1.0-math.Exp(-2.2*excess)))
	if score < 5.0 {
		return 0, ""
	}
	return score, "高随机熵值伪装域名 (H=" + strconv.FormatFloat(f.DomainEntropy, 'f', 2, 64) + ")"
}

// 5. telemetryFingerprintDetector: 遥测/PCDN 词法与端口指纹算子
type telemetryFingerprintDetector struct{}

func (d *telemetryFingerprintDetector) Name() string { return "telemetry_fingerprint" }

func (d *telemetryFingerprintDetector) Evaluate(f *FlowRecord) (float64, string) {
	if f == nil {
		return 0, ""
	}
	if matched, label := matchPCDNDomain(f.Target); matched {
		if f.UploadBytes < 2048 && f.DownloadBytes < 100*1024 {
			return 0, ""
		}
		if (f.UploadBytes >= 256*1024 && f.UploadRatio >= 0.8) || (f.UploadBytes >= 64*1024 && f.UploadRatio >= 1.5) {
			f.PCDNKind = "upload"
			return 34.0, "命中商业 PCDN 偷跑上传节点 (" + label + ")"
		}
		f.PCDNKind = "download"
		return 18.0, "命中 PCDN 下行拉流节点 (" + label + "，拦截可回落官方 CDN 减少卡顿)"
	}

	if f.UploadBytes < 2048 {
		return 0, ""
	}
	lower := strings.ToLower(f.Target)
	for _, kw := range privacyTrackerKeywords {
		if strings.Contains(lower, kw) {
			return 24.0, "命中隐私遥测/画像上报指纹 (" + strings.Trim(kw, ".") + ")"
		}
	}
	return 0, ""
}

// evaluatePrivacyAxisExtras 评估专为「👁️ 隐私审计轴」设计的碎包高频打点、睡眠时段作息窥探与明文裸奔算子。
func evaluatePrivacyAxisExtras(f *FlowRecord) (float64, []string) {
	var score float64
	var reasons []string

	hasPrivacyKW := matchesAnyKeyword(f.Target, privacyTrackerKeywords)
	// 下行显著大于上行（下载超过上传 2 倍且平滑比值 < 0.6）且未命中任何隐私遥测词根时，属于正常网页浏览/流媒体/下载
	isDownloadDominantBrowsing := !hasPrivacyKW && !f.IsDirectIP &&
		f.DownloadBytes > f.UploadBytes*2 && f.UploadRatio < 0.6

	// 1. 睡眠时段作息窥探算子 (凌晨 01:00-05:30 无人操作时段的后台活跃上传)
	if f.NightHits > 0 && f.UploadBytes >= 2048 && !isDownloadDominantBrowsing {
		isPeriodic := f.IntervalCV > 0 && f.IntervalCV < 0.30
		if f.DeviceRole == "iot" || hasPrivacyKW || f.UploadRatio >= 0.8 || isPeriodic {
			nightScore := 16.0 + 4.5*math.Log1p(float64(f.NightHits))
			if f.DeviceRole == "iot" {
				nightScore *= 1.35
			}
			score += math.Min(28.0, nightScore)
			reasons = append(reasons, "凌晨熄屏时段后台静默上传 (作息窥探风险)")
		}
	}

	// 2. 小包高频画像打点算子 (仅在未触发固定周期信标算子时补充评估，避免同一连接频次双重扣分)
	alreadyScoredBeacon := f.ConnCount >= 6 && f.IntervalCV > 0 && f.IntervalCV < 0.35
	effConns := effectiveConnCountPerHour(f)
	if !alreadyScoredBeacon && effConns >= 10 && f.UploadBytes >= 1024 && f.UploadBytes < 512*1024 && !isDownloadDominantBrowsing {
		if hasPrivacyKW || f.UploadRatio >= 0.90 || f.DeviceRole == "iot" {
			freqScore := math.Min(18.0, 4.2*math.Log1p(effConns/5.0))
			score += freqScore
			reasons = append(reasons, "高频碎包持续回传 ("+strconv.Itoa(f.ConnCount)+"次连接)")
		}
	}

	// 3. 明文 HTTP 端口裸奔算子 (端口 80 / 8080 未加密上传，极易被链路嗅探)
	if (f.DestPort == 80 || f.DestPort == 8080) && f.UploadBytes >= 4096 {
		score += 18.0
		reasons = append(reasons, "明文HTTP端口未加密上传 (隐私易被嗅探)")
	}

	return score, reasons
}

func mapRawToSigmoidScore(raw, center, scale float64) int {
	if raw <= 1.0 {
		return 0
	}
	sig := 1.0 / (1.0 + math.Exp(-(raw-center)/scale))
	sigZero := 1.0 / (1.0 + math.Exp(center/scale))
	normalized := (sig - sigZero) / (1.0 - sigZero)
	return int(math.Round(min(100.0, max(0.0, normalized*100.0))))
}

func matchesAnyKeyword(target string, keywords []string) bool {
	lower := strings.ToLower(target)
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// ───────────────────────── 辅助数学与特征函数 ─────────────────────────

// ShannonEntropy 计算字符串的香农信息熵 H(X) = - sum P(x) * log2(P(x))。
func ShannonEntropy(s string) float64 {
	s = strings.ToLower(strings.TrimSpace(s))
	n := len(s)
	if n <= 1 {
		return 0
	}
	var counts [256]int
	total := 0
	for i := 0; i < n; i++ {
		c := s[i]
		if c == '.' || c == '-' {
			continue
		}
		counts[c]++
		total++
	}
	if total <= 1 {
		return 0
	}
	var entropy float64
	invTotal := 1.0 / float64(total)
	for _, count := range counts {
		if count > 0 {
			p := float64(count) * invTotal
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func extractPrimaryLabel(domain string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(domain)), ".")
	if len(parts) <= 2 {
		return parts[0]
	}
	// 拼接除顶级和二级域名外的子域名前缀，用于计算随机子域名信息熵
	return strings.Join(parts[:len(parts)-2], "")
}

// InferDeviceRole 根据局域网设备名推断设备角色 ("router" / "iot" / "desktop" / "mobile" / "unknown")。
func InferDeviceRole(deviceName string) string {
	lower := strings.ToLower(strings.TrimSpace(deviceName))
	if lower == "" {
		return "unknown"
	}
	for _, kw := range []string{"immortalwrt", "openwrt", "istoreos", "router", "ikuai", "mikrotik", "routeros", "padavan", "asuswrt", "merlin", "gl-inet", "glinet"} {
		if strings.Contains(lower, kw) {
			return "router"
		}
	}
	for _, kw := range iotDeviceKeywords {
		if strings.Contains(lower, kw) {
			return "iot"
		}
	}
	for _, kw := range []string{"macbook", "imac", "mac-mini", "pc", "desktop", "thinkpad", "ubuntu", "debian", "win"} {
		if strings.Contains(lower, kw) {
			return "desktop"
		}
	}
	for _, kw := range []string{"iphone", "ipad", "android", "redmi", "pixel", "galaxy", "mate", "pura"} {
		if strings.Contains(lower, kw) {
			return "mobile"
		}
	}
	return "unknown"
}

func appendUniqueReason(reasons []string, r string) []string {
	if r == "" || slices.Contains(reasons, r) {
		return reasons
	}
	return append(reasons, r)
}

func formatBytesShort(b int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return strconv.FormatFloat(float64(b)/float64(gb), 'f', 2, 64) + "GB"
	case b >= mb:
		return strconv.FormatFloat(float64(b)/float64(mb), 'f', 1, 64) + "MB"
	case b >= kb:
		return strconv.FormatFloat(float64(b)/float64(kb), 'f', 0, 64) + "KB"
	default:
		return strconv.FormatInt(b, 10) + "B"
	}
}
