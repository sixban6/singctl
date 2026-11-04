package fleet

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"singctl/internal/heal"
)

// FleetHealOptions configures fleet-wide 3-layer security self-healing and rolling kernel reboots.
type FleetHealOptions struct {
	CheckOnly             bool
	AllowReboot           bool
	EnableTimers          bool
	Schedule              string
	TargetIDs             []string
	RebootRecoveryTimeout time.Duration
	RebootPollInterval    time.Duration
}

// FleetHealNodeResult captures the self-healing outcome of a single fleet worker node.
type FleetHealNodeResult struct {
	ID                      string                   `json:"id"`
	Name                    string                   `json:"name"`
	Success                 bool                     `json:"success"`
	Posture                 string                   `json:"posture"`
	Summary                 string                   `json:"summary"`
	RebootRequired          bool                     `json:"rebootRequired"`
	Rebooted                bool                     `json:"rebooted,omitempty"`
	DoctorScoreAfterReboot  int                      `json:"doctorScoreAfterReboot,omitempty"`
	CircuitBroken           bool                     `json:"circuitBroken,omitempty"`
	SkippedByCircuitBreaker bool                     `json:"skippedByCircuitBreaker,omitempty"`
	Actions                 []heal.LayerActionDetail `json:"actions,omitempty"`
}

// FleetHealReport summarizes a coordinated fleet-wide security scan or self-healing run.
type FleetHealReport struct {
	CheckedAt          string                `json:"checkedAt"`
	TotalNodes         int                   `json:"totalNodes"`
	HealthyNodes       int                   `json:"healthyNodes"`
	RebootedNodes      int                   `json:"rebootedNodes"`
	CircuitBreakerHit  bool                  `json:"circuitBreakerHit"`
	CircuitBreakerNote string                `json:"circuitBreakerNote,omitempty"`
	Results            []FleetHealNodeResult `json:"results"`
}

// HealFleet runs 3-layer security self-healing across worker nodes and performs strictly serial
// one-by-one rolling reboots with health verification and automatic circuit-breaker protection.
func (m *Manager) HealFleet(ctx context.Context, opts FleetHealOptions) (FleetHealReport, error) {
	nodes, err := m.Store.List()
	if err != nil {
		return FleetHealReport{}, err
	}

	var selected []Node
	if len(opts.TargetIDs) == 0 {
		for _, n := range nodes {
			if n.Enabled {
				selected = append(selected, n)
			}
		}
	} else {
		want := make(map[string]bool, len(opts.TargetIDs))
		for _, id := range opts.TargetIDs {
			want[strings.TrimSpace(id)] = true
		}
		for _, n := range nodes {
			if want[n.ID] {
				selected = append(selected, n)
			}
		}
	}

	report := FleetHealReport{
		CheckedAt:  time.Now().Format(time.RFC3339),
		TotalNodes: len(selected),
		Results:    make([]FleetHealNodeResult, len(selected)),
	}
	if len(selected) == 0 {
		return report, nil
	}

	runner := m.runner()

	// ── Phase 1: Concurrent non-rebooting self-healing across workers ──
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, n := range selected {
		wg.Add(1)
		go func(idx int, node Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			report.Results[idx] = m.runRemoteHealOnce(ctx, runner, node, opts)
		}(i, n)
	}
	wg.Wait()

	// ── Phase 2: Availability-first strictly SERIAL rolling reboot (1 node at a time + circuit breaker) ──
	if !opts.CheckOnly && opts.AllowReboot {
		var rebootQueue []int
		for i, r := range report.Results {
			if r.Success && r.RebootRequired {
				rebootQueue = append(rebootQueue, i)
			}
		}

		recoveryTimeout := opts.RebootRecoveryTimeout
		if recoveryTimeout <= 0 {
			recoveryTimeout = 3 * time.Minute
		}
		pollInterval := opts.RebootPollInterval
		if pollInterval <= 0 {
			pollInterval = 5 * time.Second
		}

		for qPos, resIdx := range rebootQueue {
			node := selected[resIdx]
			rCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			rebootCmd := "nohup sh -c 'sleep 1 && (systemctl reboot || reboot)' </dev/null >/dev/null 2>&1 & echo SINGCTL_REBOOT_TRIGGERED"
			_, _, rErr := runner(rCtx, node, rebootCmd)
			cancel()

			if rErr != nil {
				report.CircuitBreakerHit = true
				report.CircuitBreakerNote = fmt.Sprintf("子节点 [%s (%s)] 触发滚动重启指令失败 (%v)，已触发熔断中止剩余 %d 台节点重启",
					node.Name, node.ID, rErr, len(rebootQueue)-qPos-1)
				report.Results[resIdx].Success = false
				report.Results[resIdx].CircuitBroken = true
				report.Results[resIdx].Summary += " | 重启指令下发失败: " + rErr.Error()
				for _, remIdx := range rebootQueue[qPos+1:] {
					report.Results[remIdx].SkippedByCircuitBreaker = true
					report.Results[remIdx].Summary += " | 因前序节点熔断已暂停重启以保障全网可用性"
				}
				break
			}

			// Wait briefly for shutdown to begin, then poll SSH + singctl sr doctor until healthy
			recoveredScore, ok := m.waitForNodeHealthyAfterReboot(ctx, node, pollInterval, recoveryTimeout)
			if !ok {
				report.CircuitBreakerHit = true
				report.CircuitBreakerNote = fmt.Sprintf("子节点 [%s (%s)] 重启后在 %s 内未恢复健康达标，已触发安全熔断中止剩余 %d 台节点重启！",
					node.Name, node.ID, recoveryTimeout.Round(time.Second), len(rebootQueue)-qPos-1)
				report.Results[resIdx].Success = false
				report.Results[resIdx].CircuitBroken = true
				report.Results[resIdx].Summary = fmt.Sprintf("滚动重启后未在 %s 内恢复健康，已触发全网熔断保护", recoveryTimeout.Round(time.Second))
				for _, remIdx := range rebootQueue[qPos+1:] {
					report.Results[remIdx].SkippedByCircuitBreaker = true
					report.Results[remIdx].Summary += " | 因前序节点熔断已暂停重启以保障全网可用性"
				}
				break
			}

			report.RebootedNodes++
			report.Results[resIdx].Rebooted = true
			report.Results[resIdx].RebootRequired = false
			report.Results[resIdx].Posture = heal.PostureHealthy
			report.Results[resIdx].DoctorScoreAfterReboot = recoveredScore
			report.Results[resIdx].Summary = fmt.Sprintf("%s → 滚动重启生效新内核并恢复健康 (%d/100)",
				report.Results[resIdx].Summary, recoveredScore)
			_ = m.syncNodeObj(ctx, node)
		}
	}

	for _, r := range report.Results {
		if r.Success && (r.Posture == heal.PostureHealthy || (!r.RebootRequired && r.Posture == "")) {
			report.HealthyNodes++
		}
	}

	return report, nil
}

func (m *Manager) runRemoteHealOnce(ctx context.Context, runner RunnerFunc, node Node, opts FleetHealOptions) FleetHealNodeResult {
	callTimeout := 6 * time.Minute
	if opts.CheckOnly {
		callTimeout = 45 * time.Second
	}
	cCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	var flags []string
	flags = append(flags, "--json", "--trigger", "fleet")
	if opts.CheckOnly {
		flags = append(flags, "--check")
	}
	if opts.EnableTimers {
		flags = append(flags, "--enable-timer")
		if s := strings.TrimSpace(opts.Schedule); s != "" && heal.ValidateSchedule(s) == nil {
			flags = append(flags, fmt.Sprintf("--schedule %q", s))
		}
	}

	script := fmt.Sprintf(`
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
if ! singctl sr heal --help >/dev/null 2>&1; then
  singctl update self >/dev/null 2>&1 || true
fi
singctl sr heal %s
`, strings.Join(flags, " "))

	out, _, err := runner(cCtx, node, script)
	if err != nil {
		return FleetHealNodeResult{
			ID:      node.ID,
			Name:    node.Name,
			Success: false,
			Posture: "error",
			Summary: "远端安全自愈执行失败: " + err.Error(),
		}
	}

	jsonRaw := extractLastJSONObject(out)
	if jsonRaw == "" {
		return FleetHealNodeResult{
			ID:      node.ID,
			Name:    node.Name,
			Success: true,
			Posture: heal.PostureHealthy,
			Summary: cmp.Or(truncateLine(out, 140), "远端执行完成"),
		}
	}

	var rr heal.RunResult
	if jErr := json.Unmarshal([]byte(jsonRaw), &rr); jErr != nil {
		return FleetHealNodeResult{
			ID:      node.ID,
			Name:    node.Name,
			Success: false,
			Posture: "error",
			Summary: "解析远端自愈报告失败: " + jErr.Error(),
		}
	}

	return FleetHealNodeResult{
		ID:             node.ID,
		Name:           node.Name,
		Success:        rr.Execution.Success,
		Posture:        rr.Status.Posture,
		Summary:        rr.Execution.Summary,
		RebootRequired: rr.Status.Kernel.RebootRequired,
		Actions:        rr.Execution.Actions,
	}
}

func (m *Manager) waitForNodeHealthyAfterReboot(ctx context.Context, node Node, pollInterval, timeout time.Duration) (int, bool) {
	// Initial grace delay so we don't catch the node BEFORE systemd actually shuts down sshd
	initialWait := min(2*pollInterval, 8*time.Second)
	select {
	case <-ctx.Done():
		return 0, false
	case <-time.After(initialWait):
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		docRes := m.doctorNodeObj(ctx, node)
		if docRes.Success && (docRes.DoctorScore >= 80 || docRes.DoctorScore == 0) {
			score := cmp.Or(docRes.DoctorScore, 100)
			return score, true
		}
		select {
		case <-ctx.Done():
			return 0, false
		case <-time.After(pollInterval):
		}
	}
	return 0, false
}

func extractLastJSONObject(s string) string {
	s = strings.TrimSpace(s)
	end := strings.LastIndexByte(s, '}')
	if end < 0 {
		return ""
	}
	// Find matching '{' from start of JSON block
	depth := 0
	inStr := false
	escaped := false
	for i := 0; i <= end; i++ {
		ch := s[i]
		if inStr {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inStr = false
			}
			continue
		}
		if ch == '"' {
			inStr = true
			continue
		}
		if ch == '{' {
			if depth == 0 {
				cand := s[i : end+1]
				var probe map[string]any
				if json.Unmarshal([]byte(cand), &probe) == nil {
					if _, ok := probe["status"]; ok {
						return cand
					}
				}
			}
			depth++
		} else if ch == '}' && depth > 0 {
			depth--
		}
	}
	if start := strings.IndexByte(s, '{'); start >= 0 && start < end {
		return s[start : end+1]
	}
	return ""
}
