// 文件职责：提供 tailscaled 进程 /proc OOM 免疫状态探测与 -1000 保护写入（防小内存设备 OOM Killer 失联）。
package safecommit

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

const (
	tailscaledCommName = "tailscaled"
	oomImmuneScoreAdj  = -1000
)

// ErrTailscaledNotFound 表示当前进程目录中未发现运行中的 tailscaled 进程。
var ErrTailscaledNotFound = errors.New("tailscaled process not found")

// OOMShieldStatus 描述 tailscaled 进程的 OOM Killer 免疫保护状态。
type OOMShieldStatus struct {
	Found     bool   `json:"found"`
	PID       int    `json:"pid,omitzero"`
	ScoreAdj  int    `json:"scoreAdj"`
	Protected bool   `json:"protected"`
	Message   string `json:"message,omitzero"`
}

// InspectTailscaledOOM 扫描 procRoot（空值在 Linux 默认 /proc）检测 tailscaled 进程及其 oom_score_adj。
func InspectTailscaledOOM(procRoot string) OOMShieldStatus {
	trimmed := strings.TrimSpace(procRoot)
	if trimmed == "" && runtime.GOOS != "linux" {
		return OOMShieldStatus{
			Found:   false,
			Message: "当前系统平台不支持 OOM 免疫探测",
		}
	}
	root := cmp.Or(trimmed, "/proc")

	entries, err := os.ReadDir(root)
	if err != nil {
		return OOMShieldStatus{
			Found:   false,
			Message: "无法读取系统进程信息",
		}
	}

	pids := make([]int, 0, 32)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, convErr := strconv.Atoi(entry.Name())
		if convErr != nil || pid <= 0 {
			continue
		}
		pids = append(pids, pid)
	}
	slices.Sort(pids)

	for _, pid := range pids {
		pidDir := filepath.Join(root, strconv.Itoa(pid))
		rawComm, readErr := os.ReadFile(filepath.Join(pidDir, "comm"))
		if readErr != nil {
			continue
		}
		if strings.TrimSpace(string(rawComm)) != tailscaledCommName {
			continue
		}

		rawAdj, adjErr := os.ReadFile(filepath.Join(pidDir, "oom_score_adj"))
		if adjErr != nil {
			return OOMShieldStatus{
				Found:     true,
				PID:       pid,
				Protected: false,
				Message:   "已检测到 tailscaled，暂无法读取其内存保护状态",
			}
		}
		score, parseErr := strconv.Atoi(strings.TrimSpace(string(rawAdj)))
		if parseErr != nil {
			return OOMShieldStatus{
				Found:     true,
				PID:       pid,
				Protected: false,
				Message:   "已检测到 tailscaled，内存保护状态异常",
			}
		}

		protected := score <= oomImmuneScoreAdj
		msg := "tailscaled 尚未开启内存防误杀保护"
		if protected {
			msg = "tailscaled 已开启内存防误杀保护"
		}
		return OOMShieldStatus{
			Found:     true,
			PID:       pid,
			ScoreAdj:  score,
			Protected: protected,
			Message:   msg,
		}
	}

	return OOMShieldStatus{
		Found:   false,
		Message: "未检测到运行中的 tailscaled 进程",
	}
}

// ProtectTailscaledOOM 为运行中的 tailscaled 写入 oom_score_adj=-1000（已受保护时幂等返回）。
func ProtectTailscaledOOM(procRoot string) (OOMShieldStatus, error) {
	status := InspectTailscaledOOM(procRoot)
	if !status.Found {
		return status, ErrTailscaledNotFound
	}
	if status.Protected {
		return status, nil
	}

	root := cmp.Or(strings.TrimSpace(procRoot), "/proc")
	adjPath := filepath.Join(root, strconv.Itoa(status.PID), "oom_score_adj")
	if err := os.WriteFile(adjPath, []byte(strconv.Itoa(oomImmuneScoreAdj)), 0644); err != nil {
		return status, fmt.Errorf("write %s: %w", adjPath, err)
	}

	updated := InspectTailscaledOOM(procRoot)
	if !updated.Found || !updated.Protected {
		return updated, fmt.Errorf("oom_score_adj verification failed for tailscaled pid %d (got %d)", status.PID, updated.ScoreAdj)
	}
	return updated, nil
}
