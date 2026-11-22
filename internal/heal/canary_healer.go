// 文件职责：提供可注入测试替身的核心组件金丝雀升级、健康探针校验与秒级回滚事务模板。
package heal

import (
	"cmp"
	"context"
	"fmt"
	"time"

	"singctl/internal/component"
	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/updater"
)

// BinaryHealthProbe 定义核心组件升级后的存活与语法健康探针签名。
type BinaryHealthProbe func(ctx context.Context, h *CoreHealer, binPath string, wasActive bool) error

// CoreHealerDeps 定义核心组件金丝雀升级器的可替换依赖（nil 字段自动回退生产默认实现）。
type CoreHealerDeps struct {
	ServiceMgr       servicemgr.Manager
	LocateBinaryFn   func(candidates []string, name string) string
	UpgradeCompFn    func(id string, cfg *config.Config) (updated bool, newVersion string, err error)
	ProbeOverride    map[string]BinaryHealthProbe
	ResolveSelfExeFn func() (string, error)
	SelfUpgradeFn    func(mirror, cfgPath, currentVer string) error
	RestartWebFn     func(async bool)
}

type binaryCanarySpec struct {
	componentID        string
	unitName           string
	binName            string
	binCandidates      []string
	upgradeErrFormat   string
	requireBackupOnErr bool
	probeFailFormat    string
	successFormat      string
	healthProbe        BinaryHealthProbe
}

// CoreHealer 负责对单组件执行二进制备份、金丝雀升级、存活探针与失败秒级回滚。
type CoreHealer struct {
	svcMgr           servicemgr.Manager
	locateBinaryFn   func(candidates []string, name string) string
	upgradeCompFn    func(id string, cfg *config.Config) (updated bool, newVersion string, err error)
	probeOverride    map[string]BinaryHealthProbe
	resolveSelfExeFn func() (string, error)
	selfUpgradeFn    func(mirror, cfgPath, currentVer string) error
	restartWebFn     func(async bool)
}

// NewCoreHealer 基于给定依赖构造核心金丝雀升级器。
func NewCoreHealer(deps CoreHealerDeps) *CoreHealer {
	return &CoreHealer{
		svcMgr:           deps.ServiceMgr,
		locateBinaryFn:   deps.LocateBinaryFn,
		upgradeCompFn:    deps.UpgradeCompFn,
		probeOverride:    deps.ProbeOverride,
		resolveSelfExeFn: deps.ResolveSelfExeFn,
		selfUpgradeFn:    deps.SelfUpgradeFn,
		restartWebFn:     deps.RestartWebFn,
	}
}

var builtinCanarySpecs = map[string]binaryCanarySpec{
	"singbox": {
		componentID:        "singbox",
		unitName:           "sing-box",
		binName:            "sing-box",
		binCandidates:      []string{"/usr/local/bin/sing-box", "/usr/bin/sing-box"},
		upgradeErrFormat:   "sing-box 升级异常，已自动回滚至 v%s: %v",
		requireBackupOnErr: true,
		probeFailFormat:    "sing-box 新版健康自检未通过 (%v)，已秒级回滚至 v%s",
		successFormat:      "sing-box 核心已安全升级 (v%s → v%s) 并通过健康校验",
		healthProbe: func(ctx context.Context, _ *CoreHealer, binPath string, wasActive bool) error {
			return verifySingBoxHealth(ctx, binPath, wasActive)
		},
	},
	"caddy": {
		componentID:        "caddy",
		unitName:           "caddy",
		binName:            "caddy",
		binCandidates:      []string{"/usr/bin/caddy", "/usr/local/bin/caddy"},
		upgradeErrFormat:   "Caddy 升级异常，已自动回滚至 v%s: %v",
		requireBackupOnErr: true,
		probeFailFormat:    "Caddy 新版网关校验未通过 (%v)，已秒级回滚至 v%s",
		successFormat:      "Caddy 网关已安全升级 (v%s → v%s) 并通过配置与存活验证",
		healthProbe: func(ctx context.Context, _ *CoreHealer, binPath string, wasActive bool) error {
			return verifyCaddyHealth(ctx, binPath, wasActive)
		},
	},
	"warp": {
		componentID:        "warp",
		unitName:           "wireproxy",
		binName:            "wireproxy",
		binCandidates:      []string{"/usr/local/bin/wireproxy", "/usr/bin/wireproxy"},
		upgradeErrFormat:   "WARP 升级失败，已保护性回滚: %v",
		requireBackupOnErr: false,
		probeFailFormat:    "WARP 新版进程未就绪，已自动回滚至稳定版",
		successFormat:      "WARP (wireproxy) 已平滑升级至 v%s",
		healthProbe: func(ctx context.Context, h *CoreHealer, _ string, wasActive bool) error {
			if !wasActive {
				return nil
			}
			deadline := time.Now().Add(12 * time.Second)
			for time.Now().Before(deadline) {
				if h.isActive(ctx, "wireproxy") {
					return nil
				}
				select {
				case <-ctx.Done():
					return fmt.Errorf("wireproxy health probe cancelled")
				case <-time.After(1 * time.Second):
				}
			}
			if h.isActive(ctx, "wireproxy") {
				return nil
			}
			return fmt.Errorf("wireproxy service failed to become active")
		},
	},
}

func (h *CoreHealer) serviceMgr() servicemgr.Manager {
	if h != nil && h.svcMgr != nil {
		return h.svcMgr
	}
	return healServiceMgr()
}

func (h *CoreHealer) isActive(ctx context.Context, unit string) bool {
	if h != nil && h.svcMgr != nil {
		return h.svcMgr.IsActive(ctx, unit)
	}
	return isServiceActive(unit)
}

func (h *CoreHealer) locate(candidates []string, name string) string {
	if h != nil && h.locateBinaryFn != nil {
		return h.locateBinaryFn(candidates, name)
	}
	return locateBinary(candidates, name)
}

func (h *CoreHealer) upgradeComponent(id string, cfg *config.Config) (bool, string, error) {
	if h != nil && h.upgradeCompFn != nil {
		return h.upgradeCompFn(id, cfg)
	}
	comp, err := deploy.ServerRegistry().Resolve(id)
	if err != nil {
		return false, "", err
	}
	up, ok := comp.(component.Upgradable)
	if !ok {
		return false, "", fmt.Errorf("component %s does not support upgrades", id)
	}
	info, err := up.Upgrade(cfg)
	if err != nil {
		return false, "", err
	}
	if info == nil {
		return false, "", nil
	}
	return info.Updated, info.NewVersion, nil
}

// HealComponent 对单个核心组件执行安全升级与异常自动回滚。
func (h *CoreHealer) HealComponent(ctx context.Context, cfg *config.Config, cfgPath string, comp ComponentCheck, asyncWebRestart bool) LayerActionDetail {
	if comp.Name == "singctl" {
		return h.healSingCtl(ctx, cfg, cfgPath, comp, asyncWebRestart)
	}
	if spec, ok := builtinCanarySpecs[comp.Name]; ok {
		return h.runBinaryCanaryUpgrade(ctx, cfg, comp, spec)
	}
	return LayerActionDetail{Layer: "core", Target: comp.Name, Success: true, Message: "无需变更"}
}

func (h *CoreHealer) rollbackBinary(ctx context.Context, bakPath, binPath, unit string, restart bool) {
	if bakPath == "" {
		return
	}
	_ = restoreBinary(bakPath, binPath)
	if restart {
		_ = h.serviceMgr().Restart(ctx, unit)
	}
}

func (h *CoreHealer) runBinaryCanaryUpgrade(ctx context.Context, cfg *config.Config, comp ComponentCheck, spec binaryCanarySpec) LayerActionDetail {
	binPath := h.locate(spec.binCandidates, spec.binName)
	bakPath := backupBinary(binPath)
	defer cleanupBackup(bakPath)

	wasActive := h.isActive(ctx, spec.unitName)
	updated, newVer, err := h.upgradeComponent(spec.componentID, cfg)
	if err != nil {
		h.rollbackBinary(ctx, bakPath, binPath, spec.unitName, wasActive)
		if spec.requireBackupOnErr && bakPath == "" {
			return LayerActionDetail{Layer: "core", Target: spec.componentID, Success: false, Message: err.Error()}
		}
		var msg string
		if spec.requireBackupOnErr {
			msg = fmt.Sprintf(spec.upgradeErrFormat, comp.CurrentVersion, err)
		} else {
			msg = fmt.Sprintf(spec.upgradeErrFormat, err)
		}
		return LayerActionDetail{
			Layer:      "core",
			Target:     spec.componentID,
			Success:    false,
			RolledBack: bakPath != "",
			Message:    msg,
		}
	}

	probe := spec.healthProbe
	if h != nil && h.probeOverride != nil {
		if custom, ok := h.probeOverride[spec.componentID]; ok {
			probe = custom
		}
	}
	if probe != nil {
		if probeErr := probe(ctx, h, binPath, wasActive); probeErr != nil {
			h.rollbackBinary(ctx, bakPath, binPath, spec.unitName, wasActive)
			msg := spec.probeFailFormat
			if spec.requireBackupOnErr {
				msg = fmt.Sprintf(spec.probeFailFormat, probeErr, comp.CurrentVersion)
			}
			return LayerActionDetail{
				Layer:      "core",
				Target:     spec.componentID,
				Success:    false,
				RolledBack: true,
				Message:    msg,
			}
		}
	}

	resolvedVer := cmp.Or(newVer, comp.LatestVersion)
	var successMsg string
	if spec.requireBackupOnErr {
		successMsg = fmt.Sprintf(spec.successFormat, comp.CurrentVersion, resolvedVer)
	} else {
		successMsg = fmt.Sprintf(spec.successFormat, resolvedVer)
	}
	return LayerActionDetail{
		Layer:   "core",
		Target:  spec.componentID,
		Success: true,
		Updated: updated,
		Message: successMsg,
	}
}

func (h *CoreHealer) healSingCtl(ctx context.Context, cfg *config.Config, cfgPath string, comp ComponentCheck, asyncWebRestart bool) LayerActionDetail {
	mirror := ""
	if cfg != nil {
		mirror = cfg.GitHub.MirrorURL
	}

	resolveExe := updater.ResolveExecutablePath
	if h != nil && h.resolveSelfExeFn != nil {
		resolveExe = h.resolveSelfExeFn
	}
	exePath, _ := resolveExe()
	bakPath := backupBinary(exePath)
	defer cleanupBackup(bakPath)

	var upErr error
	if h != nil && h.selfUpgradeFn != nil {
		upErr = h.selfUpgradeFn(mirror, cfgPath, comp.CurrentVersion)
	} else {
		upErr = updater.New(mirror, "").UpdateSelf(cfgPath, comp.CurrentVersion)
	}
	if upErr != nil {
		if bakPath != "" {
			_ = restoreBinary(bakPath, exePath)
		}
		return LayerActionDetail{
			Layer:   "core",
			Target:  "singctl",
			Success: false,
			Message: fmt.Sprintf("SingCtl 自升级未完成: %v", upErr),
		}
	}

	if h.isActive(ctx, "singctl-sub") {
		_ = h.serviceMgr().Restart(ctx, "singctl-sub")
	}
	if h != nil && h.restartWebFn != nil {
		h.restartWebFn(asyncWebRestart)
	} else {
		restartWebDaemonSafely(asyncWebRestart)
	}

	return LayerActionDetail{
		Layer:   "core",
		Target:  "singctl",
		Success: true,
		Updated: true,
		Message: fmt.Sprintf("SingCtl 与 SubHub 已通过 SHA-256 校验并平滑升级 (v%s → v%s)", comp.CurrentVersion, comp.LatestVersion),
	}
}
