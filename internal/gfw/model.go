package gfw

import "time"

// RiskLevel 表示 GFW 判定风险级别
type RiskLevel string

const (
	RiskLevelClean    RiskLevel = "Clean (正常/安全)"
	RiskLevelLow      RiskLevel = "Low (低风险/轻度存疑)"
	RiskLevelHigh     RiskLevel = "High (高风险/高度存疑)"
	RiskLevelCritical RiskLevel = "Critical (极度危险/几乎确认为代理)"
)

// ProbeOptions 探测运行选项
type ProbeOptions struct {
	IP          string
	Ports       []int
	SNI         string
	Domain      string
	Timeout     time.Duration
	Verbose     bool
	JSONOutput  bool
}

// CheckItem 单项探测结果
type CheckItem struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Score       int    `json:"score"`     // 命中风险增加的分数
	MaxScore    int    `json:"max_score"` // 该项最高可能贡献的分数
	Passed      bool   `json:"passed"`    // 是否安全通过
	Details     string `json:"details"`   // 探测详情与观测到的行为
	Mitigation  string `json:"mitigation"`// 针对该项的整改建议
}

// Category 探测维度分类
type Category struct {
	Name     string      `json:"name"`
	Score    int         `json:"score"`
	MaxScore int         `json:"max_score"`
	Items    []CheckItem `json:"items"`
}

// Report 完整探测报告
type Report struct {
	TargetIP        string      `json:"target_ip"`
	TargetSNI       string      `json:"target_sni,omitempty"`
	TargetDomain    string      `json:"target_domain,omitempty"`
	ScanTime        time.Time   `json:"scan_time"`
	TotalScore      int         `json:"total_score"`
	RiskLevel       RiskLevel   `json:"risk_level"`
	Categories      []Category  `json:"categories"`
	Findings        []string    `json:"findings"`
	Recommendations []string    `json:"recommendations"`
}
