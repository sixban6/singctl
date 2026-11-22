// 文件职责：负责 WARP Endpoint 候选轮换恢复（SwitchWarpEndpoint）与配置规范化巡检自愈（SyncWarpConfigIfNeeded）。
package deploy

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// WarpEndpointSwitchDeps 允许测试注入 Endpoint 切换流程的外部依赖。
type WarpEndpointSwitchDeps struct {
	ConfPath           string
	CandidateEndpoints []string
	RestartService     func() error
	ProbeTargets       func(timeout time.Duration) (ip, loc string, err error)
	PollAttempts       int
	PollInterval       time.Duration
}

// SwitchWarpEndpoint 轮换 wireproxy Endpoint 节点并重启隧道，直至真实外网探测连通（全部失败自动恢复原配置）。
func SwitchWarpEndpoint() (endpoint, ip, loc string, err error) {
	return SwitchWarpEndpointWithDeps(nil)
}

func SwitchWarpEndpointWithDeps(deps *WarpEndpointSwitchDeps) (endpoint, ip, loc string, err error) {
	var d WarpEndpointSwitchDeps
	if deps != nil {
		d = *deps
	}
	confPath := cmp.Or(strings.TrimSpace(d.ConfPath), DefaultWireproxyConf)
	if len(d.CandidateEndpoints) == 0 {
		d.CandidateEndpoints = WarpCandidateEndpoints
	}
	if d.RestartService == nil {
		d.RestartService = func() error {
			return serviceMgr().Restart(context.Background(), "wireproxy")
		}
	}
	if d.ProbeTargets == nil {
		d.ProbeTargets = ProbeWarpRealTargets
	}
	if d.PollAttempts <= 0 {
		d.PollAttempts = 2
	}
	if d.PollInterval <= 0 {
		d.PollInterval = 350 * time.Millisecond
	}

	origBytes, readErr := os.ReadFile(confPath)
	if readErr != nil {
		return "", "", "", fmt.Errorf("读取 wireproxy 配置失败: %w", readErr)
	}
	origContent := string(origBytes)
	currentEP := ExtractWireproxyEndpoint(origContent)
	ordered := orderCandidateEndpointsAfterCurrent(d.CandidateEndpoints, currentEP)

	var lastErr error
	for _, cand := range ordered {
		updated := ReplaceWireproxyEndpoint(origContent, cand)
		if normalized, changed := NormalizeWireproxyConfigContent(updated); changed {
			updated = normalized
		}
		if wErr := writeFileAtomic0600(confPath, []byte(updated)); wErr != nil {
			lastErr = wErr
			continue
		}
		if rErr := d.RestartService(); rErr != nil {
			lastErr = rErr
			continue
		}
		for range d.PollAttempts {
			time.Sleep(d.PollInterval)
			if probeIP, probeLoc, pErr := d.ProbeTargets(2500 * time.Millisecond); pErr == nil && probeIP != "" {
				return cand, probeIP, probeLoc, nil
			} else if pErr != nil {
				lastErr = pErr
			}
		}
	}

	_ = writeFileAtomic0600(confPath, origBytes)
	_ = d.RestartService()
	return "", "", "", fmt.Errorf("所有备选 WARP Endpoint (%d 个) 均不可达: %v", len(ordered), lastErr)
}

// SyncWarpConfigIfNeeded 检查并自愈本机 WARP (wireproxy) 配置与隧道握手状态（同时自动清理遗留的 fscarmen 脚本产物）。
func SyncWarpConfigIfNeeded() (healed bool, msg string, err error) {
	purged, _ := PurgeLegacyFscarmenWarp()

	activePath, _, exists := ResolveWireproxyConfigPaths()
	if purged && (!exists || !IsWindtfWireproxyBinary(DefaultWireproxyBin)) {
		if dErr := DeployWarpWithConfig(nil); dErr != nil {
			return false, "", fmt.Errorf("已清理旧版 fscarmen WARP，但重建纯 Go wireproxy 失败: %w", dErr)
		}
		return true, "已清理旧版 fscarmen WARP 并迁移至内置纯 Go wireproxy (MTU=1280)", nil
	}

	if !exists {
		return false, "", nil
	}
	if !IsWindtfWireproxyBinary(DefaultWireproxyBin) {
		if dErr := DeployWarpWithConfig(nil); dErr != nil {
			return false, "", fmt.Errorf("升级为纯 Go wireproxy 失败: %w", dErr)
		}
		return true, "已替换升级为内置纯 Go windtf/wireproxy 引擎", nil
	}

	raw, rErr := os.ReadFile(activePath)
	if rErr != nil {
		return false, "", nil
	}
	anyChanged := purged
	if normalized, changed := NormalizeWireproxyConfigContent(string(raw)); changed {
		if wErr := writeFileAtomic0600(activePath, []byte(normalized)); wErr != nil {
			return false, "", fmt.Errorf("写入 %s 失败: %w", activePath, wErr)
		}
		anyChanged = true
	}

	if !anyChanged && isWarpSocksRunning() {
		if _, _, pErr := ProbeWarpRealTargets(3 * time.Second); pErr == nil {
			return false, "", nil
		}
	}

	_ = writeWireproxySystemdUnit(DefaultWireproxyService, DefaultWireproxyBin, activePath)
	ctx := context.Background()
	mgr := serviceMgr()
	_ = mgr.DaemonReload(ctx)
	_ = mgr.Restart(ctx, "wireproxy")
	for range 4 {
		time.Sleep(800 * time.Millisecond)
		if _, _, pErr := ProbeWarpRealTargets(3 * time.Second); pErr == nil {
			return true, "WARP (wireproxy) 已规范化 MTU=1280/IPv4 策略并恢复真实出口连通", nil
		}
	}

	if ep, _, _, swErr := SwitchWarpEndpoint(); swErr == nil {
		return true, fmt.Sprintf("WARP (wireproxy) 已自动切换至可用 Endpoint (%s)", ep), nil
	}

	if newIP, _, rErr := RotateWarpIdentity(); rErr == nil {
		return true, fmt.Sprintf("WARP (wireproxy) 已自动重新注册身份并切换出口 IP (%s)", newIP), nil
	} else {
		return false, "", rErr
	}
}
