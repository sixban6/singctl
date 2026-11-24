// 文件职责：定义可插拔异常检测算子契约（Detector）与多维非线性风险评分引擎主干（白名单、黑名单与特征聚合）。
package audit

import (
	"math"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

// Detector 定义可插拔的行为检测算子接口，支持无限扩展自定义规则算子。
type Detector interface {
	Name() string
	Evaluate(flow *FlowRecord) (score float64, reason string)
}

// AxisWeights 描述算子得分向安全轴与隐私轴的正交投射权重。
type AxisWeights struct {
	Security float64
	Privacy  float64
}

// AxisProjector 为需要自定义安全/隐私双轴投射比例的检测算子可选接口；
// 未实现该接口的 Detector 默认按纯安全轴（Security: 1.0, Privacy: 0.0）投射。
type AxisProjector interface {
	ProjectAxes(flow *FlowRecord) AxisWeights
}

type blockedRulesetRef struct {
	srcCIDR string
	tag     string
}

type blockedCIDRRef struct {
	srcCIDR string
	prefix  netip.Prefix
}

// NonlinearEngine 实现多维特征交叉与非线性风险评估引擎。
type NonlinearEngine struct {
	detectors       []Detector
	trustedDomains  map[string]struct{}
	trustedCIDRs    []*net.IPNet
	blockedKeys     map[string]struct{}
	blockedCIDRs    []blockedCIDRRef
	blockedRulesets []blockedRulesetRef
}

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
	// 微信 / WeChat 核心 MMTLS 短长链与表情/图片 CDN（非遥测域，避免 TCP:80 MMTLS 加密短链被误报拉黑）
	"sgshort.wechat.com",
	"sgminorshort.wechat.com",
	"sglong.wechat.com",
	"short.wechat.com",
	"minorshort.wechat.com",
	"long.wechat.com",
	"c2c.wechat.com",
	"cdn.wechat.com",
	"short.weixin.qq.com",
	"minorshort.weixin.qq.com",
	"extshort.weixin.qq.com",
	"long.weixin.qq.com",
	"szshort.weixin.qq.com",
	"szminorshort.weixin.qq.com",
	"szextshort.weixin.qq.com",
	"szlong.weixin.qq.com",
	"shshort.weixin.qq.com",
	"shminorshort.weixin.qq.com",
	"shextshort.weixin.qq.com",
	"shlong.weixin.qq.com",
	"hkshort.weixin.qq.com",
	"hkminorshort.weixin.qq.com",
	"hkextshort.weixin.qq.com",
	"hklong.weixin.qq.com",
	"sticker.weixin.qq.com",
	"emoji.qpic.cn",
	"mmbiz.qpic.cn",
	"mmsns.qpic.cn",
	"wx.qlogo.cn",
	"wyw-pics.wxqcloud.qq.com.cn",
}

var privacyTrackerKeywords = []string{
	"telemetry", "collect", "collector", "beacon", "tracker", "track",
	"log.", "logs.", "ulog", "applog", "sdklog", "crashlog", "stat.", "stats.",
	"metric", "metrics", "report.", "report-", "analytics", "adlog", "adtrack",
	"umeng", "appsflyer", "adjust.", "jpush", "getui", "sensorsdata", "miaozhen",
	"psmartcloud", "tuyaus", "tuyacn", "iot-log",
}

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
	seedTrustedBaseline(eng, cfg)
	indexEffectiveBlockRules(eng, cfg)
	return eng
}

func seedTrustedBaseline(eng *NonlinearEngine, cfg *config.Config) {
	for _, d := range defaultTrustedDomains {
		eng.addTrustedEntry(d)
	}
	for _, cidr := range []string{"100.64.0.0/10", "127.0.0.0/8", "::1/128"} {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			eng.trustedCIDRs = append(eng.trustedCIDRs, ipNet)
		}
	}
	if cfg == nil {
		return
	}
	for _, sub := range cfg.Subs {
		if u, err := url.Parse(strings.TrimSpace(sub.URL)); err == nil && u.Hostname() != "" {
			eng.addTrustedEntry(u.Hostname())
		}
	}
	for _, srv := range []string{cfg.Server.GetNodeDomain(), cfg.Server.GetSubstoreDomain()} {
		if srv != "" && srv != "node.example.com" {
			eng.addTrustedEntry(srv)
		}
	}
	if sip := strings.TrimSpace(cfg.Server.ServerIP); sip != "" {
		eng.addTrustedEntry(sip)
	}
	for _, w := range cfg.Audit.Whitelist {
		eng.addTrustedEntry(w)
	}
}

func indexEffectiveBlockRules(eng *NonlinearEngine, cfg *config.Config) {
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
				eng.blockedCIDRs = append(eng.blockedCIDRs, blockedCIDRRef{srcCIDR: src, prefix: prefix})
			}
		}
		eng.blockedKeys[src+"|"+target] = struct{}{}
		if plainIP := strings.TrimSuffix(strings.TrimSuffix(target, "/32"), "/128"); plainIP != target {
			eng.blockedKeys[src+"|"+plainIP] = struct{}{}
		}
	}
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
		return e.isTrustedIP(strings.TrimSuffix(strings.TrimSuffix(norm, "/32"), "/128"))
	}
	if _, ok := e.trustedDomains[norm]; ok {
		return true
	}
	for s := norm; ; {
		idx := strings.IndexByte(s, '.')
		if idx < 0 {
			return false
		}
		s = s[idx+1:]
		if _, ok := e.trustedDomains[s]; ok {
			return true
		}
	}
}

func (e *NonlinearEngine) isTrustedIP(ipStr string) bool {
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

func (e *NonlinearEngine) matchesBlockedKey(srcCIDR, target string) bool {
	if _, ok := e.blockedKeys["|"+target]; ok {
		return true
	}
	if srcCIDR == "" {
		return false
	}
	_, ok := e.blockedKeys[srcCIDR+"|"+target]
	return ok
}

func (e *NonlinearEngine) matchesBlockedCIDR(srcCIDR, plain string) bool {
	if len(e.blockedCIDRs) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(plain)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, bc := range e.blockedCIDRs {
		if (bc.srcCIDR == "" || bc.srcCIDR == srcCIDR) && bc.prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (e *NonlinearEngine) matchesBlockedDomainSuffix(srcCIDR, plain string) bool {
	for s := plain; ; {
		idx := strings.IndexByte(s, '.')
		if idx < 0 {
			return false
		}
		s = s[idx+1:]
		if e.matchesBlockedKey(srcCIDR, s) {
			return true
		}
	}
}

func (e *NonlinearEngine) matchesBlockedRuleSet(srcCIDR, plain string) bool {
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

// IsBlocked 判断某条流是否已被纳入自定义拉黑规则。
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

	if e.matchesBlockedKey(srcCIDR, norm) || (plain != norm && e.matchesBlockedKey(srcCIDR, plain)) {
		return true
	}
	return e.matchesBlockedCIDR(srcCIDR, plain) ||
		e.matchesBlockedDomainSuffix(srcCIDR, plain) ||
		e.matchesBlockedRuleSet(srcCIDR, plain)
}

func projectDetectorAxes(det Detector, flow *FlowRecord) AxisWeights {
	if p, ok := det.(AxisProjector); ok {
		return p.ProjectAxes(flow)
	}
	return AxisWeights{Security: 1.0}
}

func initFlowDerivedMetrics(flow *FlowRecord) {
	if flow.NonlinearFactors == nil {
		flow.NonlinearFactors = make(map[string]float64)
	}
	if flow.PCDNSwarm != nil && flow.PCDNSwarm.Suspicious {
		flow.PCDNKind = "swarm"
	} else {
		flow.PCDNKind = ""
	}
	denom := float64(flow.DownloadBytes) + 65536.0
	flow.UploadRatio = math.Round((float64(flow.UploadBytes)/denom)*100) / 100
	flow.AvgUploadBps = math.Round(avgUploadBytesPerSec(flow)*10) / 10
	if !flow.IsDirectIP && flow.Target != "" {
		flow.DomainEntropy = math.Round(ShannonEntropy(extractPrimaryLabel(flow.Target))*100) / 100
	}
	if flow.DeviceRole == "" {
		flow.DeviceRole = InferDeviceRole(flow.DeviceName)
	}
}

func scoreDetectorsOnAxes(detectors []Detector, flow *FlowRecord) (secBase, privBase float64, reasons []string) {
	for _, det := range detectors {
		s, r := det.Evaluate(flow)
		if s <= 0 {
			continue
		}
		flow.NonlinearFactors[det.Name()] = math.Round(s*100) / 100
		w := projectDetectorAxes(det, flow)
		secBase += s * w.Security
		privBase += s * w.Privacy
		if r != "" && !slices.Contains(reasons, r) {
			reasons = append(reasons, r)
		}
	}
	privExtra, privReasons := evaluatePrivacyAxisExtras(flow)
	if privExtra > 0 {
		privBase += privExtra
		flow.NonlinearFactors["privacy_axis_extra"] = math.Round(privExtra*100) / 100
		for _, pr := range privReasons {
			reasons = appendUniqueReason(reasons, pr)
		}
	}
	return secBase, privBase, reasons
}

func computeInteractionMultipliers(
	flow *FlowRecord,
	isUploadDominant, isNonStdPort, isPeriodicBeacon bool,
	reasons []string,
) (secInteraction, privInteraction float64, outReasons []string) {
	secInteraction, privInteraction = 1.0, 1.0
	outReasons = reasons

	if flow.IsDirectIP && isNonStdPort && isUploadDominant {
		isUDP := strings.EqualFold(flow.Network, "udp")
		hasSwarm := flow.PCDNSwarm != nil && flow.PCDNSwarm.Suspicious
		switch {
		case isUDP && isKnownIoTOrVoIPUDPPort(flow.DestPort) && flow.UploadBytes < 20*1024*1024 && !hasSwarm:
			outReasons = appendUniqueReason(outReasons, "已知 IoT/摄像头/音视频常用直连端口")
		case isUDP && isKnownGameUDPPort(flow.DestPort) && flow.UploadBytes < 20*1024*1024 && !hasSwarm:
			secInteraction *= 1.15
			outReasons = appendUniqueReason(outReasons, "直连IP非标UDP上行 (常见于手游联机/加速节点，如非游戏请核查)")
		default:
			secInteraction *= 1.75
			outReasons = appendUniqueReason(outReasons, "多维交叉: 直连IP+非标端口+持续上行(疑似PCDN/暗道回传)")
		}
	}
	if flow.NightHits > 0 && (isUploadDominant || isPeriodicBeacon) {
		secInteraction *= 1.30
		privInteraction *= 1.45
		outReasons = appendUniqueReason(outReasons, "多维交叉: 凌晨闲时静默上传活跃")
	}
	if flow.DeviceRole == "iot" && (isUploadDominant || isPeriodicBeacon) {
		secInteraction *= 1.35
		privInteraction *= 1.35
		outReasons = appendUniqueReason(outReasons, "多维交叉: 智能家居/IoT设备异常外发数据")
	}
	if flow.DomainEntropy >= 3.65 && (effectiveConnCountPerHour(flow) >= 10 || isUploadDominant) {
		secInteraction *= 1.35
	}
	return secInteraction, privInteraction, outReasons
}

func computeTrustAndAIDamping(
	e *NonlinearEngine,
	flow *FlowRecord,
	isNonStdPort, isUploadDominant bool,
	reasons []string,
) (trustDamping float64, trusted, aiDamped bool, outReasons []string) {
	trusted = e.IsTrusted(flow.Target) || strings.EqualFold(flow.Outbound, "block")
	if trusted {
		return 0.08, true, false, []string{"命中可信白名单基线 (自动阻尼降权)"}
	}

	rev := flow.AIReview
	if rev == nil || rev.Verdict != AIDoNotBlock || rev.Source == "" || rev.Source == "builtin_expert" || rev.Source == "trusted_baseline" {
		return 1.0, false, false, reasons
	}

	isHardPCDN := flow.PCDNKind == "upload" || flow.PCDNKind == "swarm"
	isHardAnomaly := (flow.IsDirectIP && isNonStdPort && isUploadDominant) ||
		isHardPCDN ||
		(flow.UploadBytes >= 100*1024*1024 && flow.UploadRatio >= 4.0)
	if isHardAnomaly {
		return 1.0, false, false, reasons
	}

	flow.NonlinearFactors["ai_damping"] = 0.25
	if len(reasons) > 0 {
		return 0.25, false, true, []string{"AI 深度复核确认正常业务 (已自动降权)", "原启发式观察: " + reasons[0]}
	}
	return 0.25, false, true, []string{"AI 深度复核确认正常业务 (已自动降权)"}
}

func finalizeAxisAndThreatState(
	e *NonlinearEngine,
	flow *FlowRecord,
	rawSec, rawPriv float64,
	trusted, aiDamped bool,
	reasons []string,
) {
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

// EvaluateFlow 对单条聚合流执行多维非线性评分并填充状态、威胁等级与可解释原因。
func (e *NonlinearEngine) EvaluateFlow(flow *FlowRecord) {
	if flow == nil {
		return
	}
	initFlowDerivedMetrics(flow)
	secBase, privBase, reasons := scoreDetectorsOnAxes(e.detectors, flow)

	isUploadDominant := flow.UploadBytes >= 256*1024 && flow.UploadRatio >= 1.8 && !isSlowLongSpanTelemetry(flow)
	isNonStdPort := flow.DestPort > 0 && flow.DestPort != 80 && flow.DestPort != 443 && flow.DestPort != 53 && flow.DestPort != 123
	isPeriodicBeacon := flow.ConnCount >= 6 && flow.IntervalCV > 0 && flow.IntervalCV < 0.30

	secInteraction, privInteraction, reasons := computeInteractionMultipliers(flow, isUploadDominant, isNonStdPort, isPeriodicBeacon, reasons)
	flow.NonlinearFactors["sec_interaction"] = math.Round(secInteraction*100) / 100
	flow.NonlinearFactors["priv_interaction"] = math.Round(privInteraction*100) / 100

	trustDamping, trusted, aiDamped, reasons := computeTrustAndAIDamping(e, flow, isNonStdPort, isUploadDominant, reasons)
	flow.NonlinearFactors["trust_damping"] = trustDamping

	rawSec := secBase * secInteraction * trustDamping
	rawPriv := privBase * privInteraction * trustDamping
	flow.NonlinearFactors["raw_security"] = math.Round(rawSec*100) / 100
	flow.NonlinearFactors["raw_privacy"] = math.Round(rawPriv*100) / 100

	finalizeAxisAndThreatState(e, flow, rawSec, rawPriv, trusted, aiDamped, reasons)
}
