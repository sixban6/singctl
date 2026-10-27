package gfw

import (
	"context"
	"fmt"
	"sync"
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

// Run 执行全套模拟探测并生成打分报告（各探测维度并发执行）
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

	// 5 大探测维度并发执行，将总体探测时间压缩至 3~5 秒内
	var wg sync.WaitGroup
	var (
		catPorts   Category
		catHTTP    Category
		catTLS     Category
		catEntropy Category
		catQUIC    Category
	)

	wg.Add(5)
	go func() {
		defer wg.Done()
		catPorts = probePorts(ctx, d.opts)
	}()
	go func() {
		defer wg.Done()
		catHTTP = probeHTTP(ctx, d.opts)
	}()
	go func() {
		defer wg.Done()
		catTLS = probeTLS(ctx, d.opts)
	}()
	go func() {
		defer wg.Done()
		catEntropy = probeEntropy(ctx, d.opts)
	}()
	go func() {
		defer wg.Done()
		catQUIC = probeQUIC(ctx, d.opts)
	}()

	wg.Wait()

	// 检查 context 是否在探测过程中被取消
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("probe canceled or timed out: %w", err)
	}

	// 按预定顺序组装报告分类
	report.Categories = append(report.Categories, catPorts, catHTTP, catTLS, catEntropy, catQUIC)

	// 汇总计算总分与整改建议
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
