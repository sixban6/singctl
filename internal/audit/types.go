package audit

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"singctl/internal/config"
)

// ThreatLevel 显式定义流量行为的威胁等级枚举（杜绝多个布尔值拼装出的隐式状态）。
type ThreatLevel string

const (
	ThreatNormal     ThreatLevel = "normal"     // 正常流量 (0-34分)
	ThreatNotice     ThreatLevel = "notice"     // 关注流量 (35-59分)
	ThreatSuspicious ThreatLevel = "suspicious" // 可疑上传 (60-79分)
	ThreatHighRisk   ThreatLevel = "high_risk"  // 高危上传 (80-100分)
)

// Label 返回威胁等级的中文标签。
func (t ThreatLevel) Label() string {
	switch t {
	case ThreatHighRisk:
		return "高危"
	case ThreatSuspicious:
		return "可疑"
	case ThreatNotice:
		return "关注"
	default:
		return "正常"
	}
}

// SeverityRank 返回用于排序的威胁等级权重。
func (t ThreatLevel) SeverityRank() int {
	switch t {
	case ThreatHighRisk:
		return 4
	case ThreatSuspicious:
		return 3
	case ThreatNotice:
		return 2
	default:
		return 1
	}
}

// EnforcementState 显式定义目标在封禁系统中的生命周期状态。
type EnforcementState string

const (
	EnforcementObserved    EnforcementState = "observed"    // 观察中（未封禁）
	EnforcementBlocked     EnforcementState = "blocked"     // 已双层拉黑（Sing-Box + DNS）
	EnforcementWhitelisted EnforcementState = "whitelisted" // 可信白名单豁免
)

// AIVerdict 显式定义 AI 顾问对“拉黑是否会影响正常使用”的评估结论。
type AIVerdict string

const (
	AISafeToBlock AIVerdict = "safe_to_block" // 可安全拉黑（广告/遥测/PCDN偷跑，不影响核心功能）
	AICaution     AIVerdict = "caution"       // 谨慎拉黑（可能影响部分非核心功能，建议仅按设备拉黑）
	AIDoNotBlock  AIVerdict = "do_not_block"  // 切勿拉黑（系统核心服务或正常业务上传）
	AIUnknown     AIVerdict = "unknown"       // 未知待定
)

// Label 返回 AI 结论的中文展示文案。
func (v AIVerdict) Label() string {
	switch v {
	case AISafeToBlock:
		return "可安全拉黑"
	case AICaution:
		return "谨慎拉黑"
	case AIDoNotBlock:
		return "建议放行"
	default:
		return "待确认"
	}
}

// AIReviewResult 存储 L2 AI 顾问（或内置离线专家库）对可疑目标的深度研判结论。
type AIReviewResult struct {
	Source      string    `json:"source"`      // "llm_api" 或 "builtin_expert"
	Category    string    `json:"category"`    // 归属分类，如 "智能电视遥测/广告 SDK"、"PCDN 边缘节点偷跑"
	Verdict     AIVerdict `json:"verdict"`     // safe_to_block / caution / do_not_block
	VerdictText string    `json:"verdictText"` // 中文结论标签
	Impact      string    `json:"impact"`      // 拉黑后的副作用评估
	Recommend   string    `json:"recommend"`   // 推荐操作: "block_global" / "block_device" / "keep"
}

// FlowRecord 表示按 (内网设备 IP, 目标域名/IP, 传输协议) 聚合后的连接行为画像。
type FlowRecord struct {
	Key              string             `json:"key"`
	DeviceIP         string             `json:"deviceIp"`
	DeviceName       string             `json:"deviceName"`
	DeviceMAC        string             `json:"deviceMac,omitempty"`
	DeviceRole       string             `json:"deviceRole,omitempty"` // "iot" / "desktop" / "mobile" / "unknown"
	Target           string             `json:"target"`               // 规范化后的目标域名或目的 IP
	AppName          string             `json:"appName,omitempty"`    // 基于本地 sing-box 规则集识别出的归属应用 (如 Telegram / 百度 / Apple)
	IsGame           bool               `json:"isGame,omitempty"`     // 是否命中主流游戏规则集或游戏特征库
	RawHost          string             `json:"rawHost,omitempty"`
	DestIP           string             `json:"destIp,omitempty"`
	DestPort         int                `json:"destPort"`
	IsDirectIP       bool               `json:"isDirectIp"` // 是否绕过域名直接访问 IP
	Network          string             `json:"network"`    // tcp / udp
	Outbound         string             `json:"outbound"`
	Rule             string             `json:"rule,omitempty"`
	UploadBytes      int64              `json:"uploadBytes"`
	DownloadBytes    int64              `json:"downloadBytes"`
	UploadRatio      float64            `json:"uploadRatio"`
	ConnCount        int                `json:"connCount"`
	ActiveConns      int                `json:"activeConns"`
	ActiveConnIDs    []string           `json:"-"`
	FirstSeen        string             `json:"firstSeen"`
	LastSeen         string             `json:"lastSeen"`
	NightHits        int                `json:"nightHits"`        // 凌晨 01:00-05:30 活跃采样次数
	IntervalCV       float64            `json:"intervalCv"`       // 建连时间间隔变异系数 (越小越像机器定时心跳)
	DomainEntropy    float64            `json:"domainEntropy"`    // 域名香农信息熵
	SecurityScore    int                `json:"securityScore"`    // 🛡️ 安全风险轴评分 (0-100)
	PrivacyScore     int                `json:"privacyScore"`     // 👁️ 隐私泄露轴评分 (0-100)
	DominantAxis     string             `json:"dominantAxis"`     // 主导风险维度: "security" / "privacy" / "both" / "normal"
	RiskScore        int                `json:"riskScore"`        // 非线性极值包络综合风险评分 (0-100)
	Threat           ThreatLevel        `json:"threat"`           // normal / notice / suspicious / high_risk
	ThreatLabel      string             `json:"threatLabel"`      // 中文威胁等级
	State            EnforcementState   `json:"state"`            // observed / blocked / whitelisted
	Reasons          []string           `json:"reasons"`          // 触发风险的具体诊断原因
	NonlinearFactors map[string]float64 `json:"nonlinearFactors"` // 各非线性分量明细（供调试与前端透明展示）
	AIReview         *AIReviewResult    `json:"aiReview,omitempty"`
}

// DeviceSummary 汇总单台局域网设备的流量与可疑行为统计。
type DeviceSummary struct {
	DeviceIP         string  `json:"deviceIp"`
	DeviceName       string  `json:"deviceName"`
	DeviceMAC        string  `json:"deviceMac,omitempty"`
	DeviceRole       string  `json:"deviceRole,omitempty"`
	UploadBytes      int64   `json:"uploadBytes"`
	DownloadBytes    int64   `json:"downloadBytes"`
	UploadRatio      float64 `json:"uploadRatio"`
	FlowCount        int     `json:"flowCount"`
	ActiveConns      int     `json:"activeConns"`
	SuspiciousCount  int     `json:"suspiciousCount"`
	HighRiskCount    int     `json:"highRiskCount"`
	MaxSecurityScore int     `json:"maxSecurityScore"`
	MaxPrivacyScore  int     `json:"maxPrivacyScore"`
	MaxRiskScore     int     `json:"maxRiskScore"`
}

// Report 汇总完整的设备审计分析报告与当前黑名单状态。
type Report struct {
	GeneratedAt     string             `json:"generatedAt"`
	Reachable       bool               `json:"reachable"`
	ControllerAddr  string             `json:"controllerAddr,omitempty"`
	Message         string             `json:"message,omitempty"`
	TotalFlows      int                `json:"totalFlows"`
	SuspiciousFlows int                `json:"suspiciousFlows"`
	HighRiskFlows   int                `json:"highRiskFlows"`
	BlockedCount    int                `json:"blockedCount"`
	AIEnabled       bool               `json:"aiEnabled"`
	Devices         []DeviceSummary    `json:"devices"`
	Flows           []FlowRecord       `json:"flows"`
	BlockRules      []config.BlockRule `json:"blockRules"`
}

// BlockActionResult 记录执行“一键双层拉黑”或“解封”后的各层执行反馈。
type BlockActionResult struct {
	Target            string `json:"target"`
	SourceIP          string `json:"sourceIp,omitempty"`
	ConfigSaved       bool   `json:"configSaved"`
	SingBoxSynced     bool   `json:"singboxSynced"`
	DNSBlocked        bool   `json:"dnsBlocked"`
	DNSMode           string `json:"dnsMode,omitempty"`
	KilledConnections int    `json:"killedConnections"`
	Message           string `json:"message"`
}

// WriteCSV 将审计明细流导出为纯正 UTF-8（不带 BOM）的 CSV 格式。
func (r *Report) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	header := []string{
		"first_seen",
		"last_seen",
		"device_name",
		"device_ip",
		"device_mac",
		"device_role",
		"target",
		"app_name",
		"dest_ip",
		"dest_port",
		"is_direct_ip",
		"network",
		"outbound",
		"upload_bytes",
		"download_bytes",
		"upload_ratio",
		"conn_count",
		"active_conns",
		"interval_cv",
		"domain_entropy",
		"security_score",
		"privacy_score",
		"dominant_axis",
		"risk_score",
		"threat_level",
		"threat_label",
		"state",
		"reasons",
		"ai_verdict",
		"ai_category",
		"ai_impact",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	if r == nil {
		cw.Flush()
		return cw.Error()
	}
	for _, f := range r.Flows {
		aiVerdict, aiCategory, aiImpact := "", "", ""
		if f.AIReview != nil {
			aiVerdict = f.AIReview.VerdictText
			aiCategory = f.AIReview.Category
			aiImpact = f.AIReview.Impact
		}
		row := []string{
			f.FirstSeen,
			f.LastSeen,
			f.DeviceName,
			f.DeviceIP,
			f.DeviceMAC,
			f.DeviceRole,
			f.Target,
			f.AppName,
			f.DestIP,
			strconv.Itoa(f.DestPort),
			strconv.FormatBool(f.IsDirectIP),
			f.Network,
			f.Outbound,
			strconv.FormatInt(f.UploadBytes, 10),
			strconv.FormatInt(f.DownloadBytes, 10),
			fmt.Sprintf("%.2f", f.UploadRatio),
			strconv.Itoa(f.ConnCount),
			strconv.Itoa(f.ActiveConns),
			fmt.Sprintf("%.4f", f.IntervalCV),
			fmt.Sprintf("%.4f", f.DomainEntropy),
			strconv.Itoa(f.SecurityScore),
			strconv.Itoa(f.PrivacyScore),
			f.DominantAxis,
			strconv.Itoa(f.RiskScore),
			string(f.Threat),
			f.ThreatLabel,
			string(f.State),
			strings.Join(f.Reasons, "; "),
			aiVerdict,
			aiCategory,
			aiImpact,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
