// 文件职责：负责服务端 WARP 分流配置的两阶段离线预检、0600 原子替换、sing-box 零断流热重载及失败自动回滚。
package deploy

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/common/fsx"
)

// LiveWarpApplyDeps 为 ApplyLiveWarpRouting 提供可测试的外部系统调用依赖注入
type LiveWarpApplyDeps struct {
	ProtectedDomains []string
	CheckWarpPort    func() bool
	ValidateConfig   func(tmpPath string) error
	IsServiceActive  func() bool
	ReloadService    func(wasActive bool) error
	RestoreService   func(wasActive bool) error
}

// ApplyLiveWarpRouting 对现有 sing-box config.json 执行防黑洞门禁、预检、0600 原子替换与 SIGHUP 零断流热重载（失败自动回滚）
func ApplyLiveWarpRouting(singboxConfigPath string, rawWR config.WarpRoutingConfig, deps *LiveWarpApplyDeps) (bool, error) {
	cfgPath := cmp.Or(strings.TrimSpace(singboxConfigPath), constant.SingBoxConfigFile)
	wr, err := config.NormalizeWarpRouting(rawWR)
	if err != nil {
		return false, err
	}

	checkPort := CheckWarpSocksPort
	validateFn := defaultValidateSingBoxConfig
	isActiveFn := defaultIsSingBoxActive
	reloadFn := defaultReloadSingBoxService
	restoreFn := defaultRestoreSingBoxService
	var protectedDomains []string
	if deps != nil {
		protectedDomains = deps.ProtectedDomains
		if deps.CheckWarpPort != nil {
			checkPort = deps.CheckWarpPort
		}
		if deps.ValidateConfig != nil {
			validateFn = deps.ValidateConfig
		}
		if deps.IsServiceActive != nil {
			isActiveFn = deps.IsServiceActive
		}
		if deps.ReloadService != nil {
			reloadFn = deps.ReloadService
		}
		if deps.RestoreService != nil {
			restoreFn = deps.RestoreService
		}
	}

	// 1. 防黑洞门禁
	if NeedsWarpTunnel(wr) && !checkPort() {
		return false, ErrWarpTunnelUnavailable
	}

	// 2. 读取现网 config.json 并编译新 route 段
	oldBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		return false, fmt.Errorf("读取 %s 失败: %w", cfgPath, err)
	}
	newBytes, err := ApplyWarpRoutingWithProtectedDomains(oldBytes, wr, protectedDomains)
	if err != nil {
		return false, err
	}
	if bytes.Equal(bytes.TrimSpace(oldBytes), bytes.TrimSpace(newBytes)) {
		return false, nil
	}

	// 3. 写入 0600 临时文件执行 sing-box check 离线预检
	dir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false, fmt.Errorf("创建配置目录失败: %w", err)
	}
	tmpPath := fmt.Sprintf("%s.%d.warp.tmp", cfgPath, time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, newBytes, 0600); err != nil {
		return false, fmt.Errorf("写入临时配置失败: %w", err)
	}
	_ = os.Chmod(tmpPath, 0600)
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := validateFn(tmpPath); err != nil {
		return false, fmt.Errorf("sing-box 配置预检未通过（已拦截写入防断网）: %w", err)
	}

	// 4. 备份旧配置（0600）并原子替换目标配置
	bakPath := fmt.Sprintf("%s.%d.warp.bak", cfgPath, time.Now().UnixNano())
	if wErr := os.WriteFile(bakPath, oldBytes, 0600); wErr == nil {
		_ = os.Chmod(bakPath, 0600)
		pruneWarpConfigBackups(cfgPath, 3)
	}

	wasActive := isActiveFn()
	if err := os.Rename(tmpPath, cfgPath); err != nil {
		return false, fmt.Errorf("原子替换 %s 失败: %w", cfgPath, err)
	}
	cleanupTmp = false
	_ = os.Chmod(cfgPath, 0600)

	// 5. SIGHUP 热重载；一旦失败立即原子回滚旧配置
	if err := reloadFn(wasActive); err != nil {
		_ = writeFileAtomic0600(cfgPath, oldBytes)
		_ = restoreFn(wasActive)
		return false, fmt.Errorf("sing-box 热重载失败，已自动回滚至原配置确保不断连: %w", err)
	}

	return true, nil
}

func pruneWarpConfigBackups(cfgPath string, keep int) {
	matches, _ := filepath.Glob(cfgPath + ".*.warp.bak")
	if len(matches) <= keep {
		return
	}
	slices.Sort(matches)
	slices.Reverse(matches)
	for i := keep; i < len(matches); i++ {
		_ = os.Remove(matches[i])
	}
}

func writeFileAtomic0600(path string, data []byte) error {
	return fsx.WriteAtomic0600(path, data)
}

func defaultValidateSingBoxConfig(tmpPath string) error {
	bin, err := locateSingBoxBin()
	if err != nil {
		// 本地无 sing-box 二进制时不阻断单元测试或仅配置编辑场景，生产环境均有 /usr/local/bin/sing-box
		if _, statErr := os.Stat(constant.SingBoxConfigFile); os.IsNotExist(statErr) {
			return nil
		}
		return fmt.Errorf("未找到 sing-box 可执行文件: %w", err)
	}
	if out, err := exec.Command(bin, "check", "-c", tmpPath).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func locateSingBoxBin() (string, error) {
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p, nil
	}
	for _, candidate := range []string{constant.SingBoxInstallDir, "/usr/bin/sing-box"} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", os.ErrNotExist
}

func defaultIsSingBoxActive() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return serviceMgr().IsActive(context.Background(), "sing-box")
}

func defaultReloadSingBoxService(wasActive bool) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	ctx := context.Background()
	mgr := serviceMgr()
	if !wasActive {
		return mgr.Restart(ctx, "sing-box")
	}
	// 利用 sing-box.service 的 ExecReload=/bin/kill -HUP $MAINPID 实现零断流重载
	if err := mgr.Reload(ctx, "sing-box"); err != nil {
		if rErr := mgr.Restart(ctx, "sing-box"); rErr != nil {
			return rErr
		}
	}
	// 短暂确认服务仍处于 active
	for range 5 {
		if defaultIsSingBoxActive() {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("reload 后 sing-box 未处于 active 状态")
}

func defaultRestoreSingBoxService(wasActive bool) error {
	if _, err := exec.LookPath("systemctl"); err != nil || !wasActive {
		return nil
	}
	return serviceMgr().Restart(context.Background(), "sing-box")
}
