// 文件职责：提供 AdGuard Home 全内存段自适应 GOMEMLIMIT/GOGC 内存护栏计算与既有 procd/systemd 服务脚本幂等无损补强。
package adguard

import (
	"os"
	"strings"

	"singctl/internal/common/sysinfo"
	"singctl/internal/platform/servicemgr"
)

// ComputeMemoryEnv 根据宿主机总物理内存计算 AdGuard Home 的全内存段自适应 Go 内存护栏环境变量：
//   - 0：未知内存返回 nil（不盲猜）
//   - <= 288 MiB（超小内存路由）：GOMEMLIMIT=96MiB, GOGC=30
//   - 289~512 MiB（小内存路由）：GOMEMLIMIT=128MiB, GOGC=50
//   - 513 MiB~1 GiB：GOMEMLIMIT=160MiB（保持 Go 默认 GOGC=100）
//   - 1~2 GiB：GOMEMLIMIT=256MiB（保持 Go 默认 GOGC=100）
//   - > 2 GiB：GOMEMLIMIT=384MiB（保持 Go 默认 GOGC=100）
func ComputeMemoryEnv(totalRAMBytes uint64) map[string]string {
	const mib uint64 = 1024 * 1024
	if totalRAMBytes == 0 {
		return nil
	}
	switch {
	case sysinfo.IsUltraLowMemoryRAM(totalRAMBytes):
		return map[string]string{
			"GOMEMLIMIT": "96MiB",
			"GOGC":       "30",
		}
	case sysinfo.IsLowMemoryRAM(totalRAMBytes):
		return map[string]string{
			"GOMEMLIMIT": "128MiB",
			"GOGC":       "50",
		}
	case totalRAMBytes <= 1024*mib:
		return map[string]string{"GOMEMLIMIT": "160MiB"}
	case totalRAMBytes <= 2048*mib:
		return map[string]string{"GOMEMLIMIT": "256MiB"}
	default:
		return map[string]string{"GOMEMLIMIT": "384MiB"}
	}
}

func stripManagedProcdMemEnvLines(body string) string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "procd_set_param env ") &&
			(strings.Contains(trimmed, "GOMEMLIMIT=") || strings.Contains(trimmed, "GOGC=")) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func stripManagedSystemdMemEnvLines(body string) string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, `Environment="GOMEMLIMIT=`) ||
			strings.HasPrefix(trimmed, `Environment="GOGC=`) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// EnsureMemoryLimitServiceEnv 幂等为既有 AdGuard Home 服务文件（OpenWrt procd 或 systemd）补齐自适应 GOMEMLIMIT 护栏。
// 未知内存（totalRAMBytes == 0）静默跳过不做任何改动。
func EnsureMemoryLimitServiceEnv(initdPath, systemdPath string, totalRAMBytes uint64) (bool, string, error) {
	env := ComputeMemoryEnv(totalRAMBytes)
	if len(env) == 0 {
		return false, "", nil
	}

	if strings.TrimSpace(initdPath) != "" {
		if raw, err := os.ReadFile(initdPath); err == nil && strings.Contains(string(raw), "procd_open_instance") {
			orig := string(raw)
			cleaned := stripManagedProcdMemEnvLines(orig)
			rendered, rErr := servicemgr.RenderProcdBody(servicemgr.UnitSpec{
				Name:      "AdGuardHome",
				ProcdBody: cleaned,
				Env:       env,
			})
			if rErr != nil {
				return false, "procd", rErr
			}
			if rendered != orig {
				if wErr := os.WriteFile(initdPath, []byte(rendered), 0755); wErr != nil {
					return false, "procd", wErr
				}
				return true, "procd", nil
			}
			return false, "procd", nil
		}
	}

	if strings.TrimSpace(systemdPath) != "" {
		if raw, err := os.ReadFile(systemdPath); err == nil && strings.Contains(string(raw), "[Service]") {
			orig := string(raw)
			cleaned := stripManagedSystemdMemEnvLines(orig)
			rendered, rErr := servicemgr.RenderSystemdBody(servicemgr.UnitSpec{
				Name:        "AdGuardHome",
				SystemdBody: cleaned,
				Env:         env,
			})
			if rErr != nil {
				return false, "systemd", rErr
			}
			if rendered != orig {
				if wErr := os.WriteFile(systemdPath, []byte(rendered), 0644); wErr != nil {
					return false, "systemd", wErr
				}
				return true, "systemd", nil
			}
			return false, "systemd", nil
		}
	}

	return false, "", nil
}
