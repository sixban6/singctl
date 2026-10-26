package gfw

import (
	"context"
	"fmt"
	"time"
)

// Detector GFW 模拟主动探测分析器
type Detector struct {
	opts ProbeOptions
}

// NewDetector 创建检测器实例
func NewDetector(opts ProbeOptions) *Detector {
	if opts.Timeout <= 0 {
		opts.Timeout = 4 * time.Second
	}
	return &Detector{opts: opts}
}

// Run 执行全套模拟探测并生成打分报告
func (d *Detector) Run(ctx context.Context) (*Report, error) {
	if d.opts.IP == "" {
		return nil, fmt.Errorf("target IP is required for GFW probe")
	}

	report := &Report{
		TargetIP:        d.opts.IP,
		TargetSNI:       d.opts.SNI,
		TargetDomain:    d.opts.Domain,
		ScanTime:        time.Now(),
		Categories:      make([]Category, 0, 5),
		Findings:        make([]string, 0),
		Recommendations: make([]string, 0),
	}

	// 1. 端口与基础画像探测
	catPorts := probePorts(ctx, d.opts)
	report.Categories = append(report.Categories, catPorts)

	// 2. HTTP 规范与回落伪装测试
	catHTTP := probeHTTP(ctx, d.opts)
	report.Categories = append(report.Categories, catHTTP)

	// 3. TLS 与 Reality 伪装探测
	catTLS := probeTLS(ctx, d.opts)
	report.Categories = append(report.Categories, catTLS)

	// 4. 高熵随机垃圾数据探测 (Active Probing)
	catEntropy := probeEntropy(ctx, d.opts)
	report.Categories = append(report.Categories, catEntropy)

	// 5. UDP / QUIC 协议画像探测
	catQUIC := probeQUIC(ctx, d.opts)
	report.Categories = append(report.Categories, catQUIC)

	// 汇总计算总分
	totalScore := 0
	for _, cat := range report.Categories {
		totalScore += cat.Score
		for _, item := range cat.Items {
			if !item.Passed && item.Score > 0 {
				report.Findings = append(report.Findings, fmt.Sprintf("[+%d分] %s: %s", item.Score, item.Name, item.Details))
				if item.Mitigation != "" {
					report.Recommendations = append(report.Recommendations, fmt.Sprintf("• [%s] %s", item.Name, item.Mitigation))
				}
			}
		}
	}

	if totalScore > 100 {
		totalScore = 100
	}
	if totalScore < 0 {
		totalScore = 0
	}
	report.TotalScore = totalScore

	// 评估风险等级
	switch {
	case totalScore <= 20:
		report.RiskLevel = RiskLevelClean
	case totalScore <= 50:
		report.RiskLevel = RiskLevelLow
	case totalScore <= 75:
		report.RiskLevel = RiskLevelHigh
	default:
		report.RiskLevel = RiskLevelCritical
	}

	return report, nil
}
