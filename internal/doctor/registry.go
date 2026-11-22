// 文件职责：实现 OCP 声明式深度体检调度器（Runner），支持并发执行、5 秒单项超时、顺序输出、评分汇总与一键修复派发。
package doctor

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/safecommit"
)

const (
	// DefaultCheckTimeout 为单个体检算子的默认执行超时上限。
	DefaultCheckTimeout = 5 * time.Second

	failPenalty = 20
	warnPenalty = 8
)

// Runner 维护有序、并发安全的 Checker 注册表并并发调度全链路体检。
type Runner struct {
	mu           sync.RWMutex
	checkers     []Checker
	checkTimeout time.Duration
}

// NewRunner 创建包含指定体检算子的 Runner（不传参时创建空注册表供按需 Register）。
func NewRunner(checkers ...Checker) *Runner {
	r := &Runner{checkTimeout: DefaultCheckTimeout}
	r.Register(checkers...)
	return r
}

// DefaultCheckers 返回全部 8 个内置全链路深度体检算子（按固定展示顺序排列）。
func DefaultCheckers() []Checker {
	return []Checker{
		hardwareResourcesChecker{},
		remoteLifelineChecker{},
		firewallBackendChecker{},
		policyRoutingChecker{},
		hwOffloadConflictChecker{},
		sandboxAndConfigChecker{},
		dnsAntiHijackChecker{},
		dualStackConnectivityChecker{},
	}
}

// NewDefaultRunner 创建已注册全部 8 个内置深度体检算子的默认 Runner。
func NewDefaultRunner() *Runner {
	return NewRunner(DefaultCheckers()...)
}

// Register 按顺序追加一个或多个自定义 Checker。
func (r *Runner) Register(checkers ...Checker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range checkers {
		if c != nil {
			r.checkers = append(r.checkers, c)
		}
	}
}

// Checkers 返回已注册 Checker 的只读副本。
func (r *Runner) Checkers() []Checker {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.checkers)
}

// SetCheckTimeout 调整单项体检超时时间（供测试注入短超时）。
func (r *Runner) SetCheckTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checkTimeout = d
}

// Run 并发执行全部已注册 Checker，按注册顺序汇总评分与总体状态。
func (r *Runner) Run(ctx context.Context, env *Env) Report {
	if ctx == nil {
		ctx = context.Background()
	}

	r.mu.RLock()
	snapshot := slices.Clone(r.checkers)
	timeout := cmp.Or(r.checkTimeout, DefaultCheckTimeout)
	r.mu.RUnlock()

	resolved := env.withDefaults()
	wallStart := time.Now()
	checkedAt := resolved.NowFunc().Format("2006-01-02 15:04:05")

	results := make([]CheckResult, len(snapshot))
	var wg sync.WaitGroup
	for i, chk := range snapshot {
		wg.Go(func() {
			results[i] = runSingleChecker(ctx, chk, resolved, timeout)
		})
	}
	wg.Wait()

	rep := Report{
		Score:      100,
		Overall:    StatusPass,
		DurationMs: time.Since(wallStart).Milliseconds(),
		CheckedAt:  checkedAt,
		Checks:     results,
	}
	for _, res := range results {
		switch res.Status {
		case StatusPass:
			rep.Passed++
		case StatusWarn:
			rep.Warnings++
		case StatusFail:
			rep.Failed++
		case StatusSkip:
			rep.Skipped++
		}
	}

	rep.Score = max(0, min(100, 100-(rep.Failed*failPenalty)-(rep.Warnings*warnPenalty)))
	switch {
	case rep.Failed > 0:
		rep.Overall = StatusFail
	case rep.Warnings > 0:
		rep.Overall = StatusWarn
	case rep.Passed > 0 || len(results) == 0:
		rep.Overall = StatusPass
	default:
		rep.Overall = StatusSkip
	}
	return rep
}

// Fix 根据体检报告中的 FixAction 派发快捷修复动作。
func (r *Runner) Fix(ctx context.Context, env *Env, action string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	act := strings.TrimSpace(action)
	if act == "" {
		return "", errors.New("quick-fix action must not be empty")
	}

	resolved := env.withDefaults()
	if fn, ok := resolved.QuickFixHandlers[act]; ok && fn != nil {
		return fn(ctx)
	}

	switch act {
	case "protect-tailscale-oom":
		st, err := safecommit.ProtectTailscaledOOM(resolved.ProcRoot)
		if err != nil {
			return "", err
		}
		return cmp.Or(st.Message, fmt.Sprintf("已为 tailscaled (PID %d) 写入 oom_score_adj=%d", st.PID, st.ScoreAdj)), nil
	default:
		return "", fmt.Errorf("unsupported quick-fix action: %q", act)
	}
}

func runSingleChecker(parentCtx context.Context, chk Checker, env *Env, timeout time.Duration) CheckResult {
	cCtx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	start := time.Now()
	resCh := make(chan CheckResult, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				resCh <- CheckResult{
					ID:      chk.ID(),
					Title:   chk.ID(),
					Status:  StatusFail,
					Summary: "体检算子发生内部异常",
					Detail:  fmt.Sprintf("panic: %v", rec),
				}
			}
		}()
		resCh <- chk.Run(cCtx, env)
	}()

	var res CheckResult
	select {
	case res = <-resCh:
	case <-cCtx.Done():
		status := StatusWarn
		summary := fmt.Sprintf("检查超时（超过 %s）", timeout)
		if errors.Is(parentCtx.Err(), context.Canceled) {
			status = StatusSkip
			summary = "检查已取消"
		}
		res = CheckResult{
			ID:      chk.ID(),
			Title:   chk.ID(),
			Status:  status,
			Summary: summary,
			Detail:  cCtx.Err().Error(),
		}
	}

	res.ID = cmp.Or(res.ID, chk.ID())
	if res.Status == "" {
		res.Status = StatusSkip
	}
	elapsed := time.Since(start).Milliseconds()
	if res.DurationMs <= 0 {
		res.DurationMs = elapsed
	}
	return res
}
