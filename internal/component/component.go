// Package component 定义服务端与网关受管组件的可扩展契约与声明式注册表。
//
// 架构原则（参考 sing-box adapter/registry 模式）：
//   - 接口隔离：基础 Component 仅要求标识与服务动作，配置编辑（Configurable）、
//     版本升级（Upgradable）与部署生命周期（ServerLifecycle）按需实现；
//   - 单向依赖：本包仅依赖 stdlib、config 与 platform/servicemgr，绝不反向依赖具体组件实现包。
package component

import (
	"context"
	"os"

	"singctl/internal/config"
	"singctl/internal/platform/servicemgr"
)

// Component 描述一个可被 SingCtl 纳管的宿主运行组件基础契约。
type Component interface {
	ID() string
	Aliases() []string
	DisplayName() string
	UnitName() string
	ExecuteServiceAction(ctx context.Context, action string, mgr servicemgr.Manager, runner servicemgr.CmdRunner, cfgPathOverride string) error
}

// DispatchServiceAction 统一分发标准服务启停/重载动作，避免各组件重复编写 action 分支。
func DispatchServiceAction(ctx context.Context, mgr servicemgr.Manager, action, unit string) error {
	switch action {
	case "start":
		return mgr.Start(ctx, unit)
	case "stop":
		return mgr.Stop(ctx, unit)
	case "reload":
		return mgr.Reload(ctx, unit)
	default:
		return mgr.Restart(ctx, unit)
	}
}

// ConfigTarget 描述组件主配置文件路径、需要同步覆写的镜像路径及目标权限。
type ConfigTarget struct {
	PrimaryPath string
	MirrorPaths []string
	FileMode    os.FileMode
}

// Configurable 为支持 Web 控制台在线读取、预校验、原子写入与重载生效的组件可选接口。
type Configurable interface {
	ResolveConfigTarget(overridePath string) (ConfigTarget, error)
	ValidateConfig(ctx context.Context, content string, runner servicemgr.CmdRunner, binOverride string) error
	ApplyOwnership(path string)
	ReloadAfterSave(ctx context.Context, path string, mgr servicemgr.Manager, runner servicemgr.CmdRunner, canSystemctl bool) error
}

// CheckUpdateInfo 描述组件上游版本检查结果（供 deploy/WebUI 消费）。
type CheckUpdateInfo struct {
	Component      string
	DisplayName    string
	CurrentVersion string
	LatestVersion  string
	HasUpdate      bool
	Message        string
}

// UpgradeInfo 描述一次组件平滑升级执行结果。
type UpgradeInfo struct {
	Component   string
	DisplayName string
	OldVersion  string
	NewVersion  string
	Message     string
	Updated     bool
}

// Upgradable 为支持在线检查上游版本并执行平滑二进制替换的组件可选接口。
type Upgradable interface {
	CheckUpdate(cfg *config.Config) (*CheckUpdateInfo, error)
	Upgrade(cfg *config.Config) (*UpgradeInfo, error)
}

// ServerLifecycle 为支持服务端单组件部署、重装与卸载的组件可选接口。
type ServerLifecycle interface {
	DeployServer(cfg *config.Config) error
	ReinstallServer(cfg *config.Config) error
	UninstallServer() error
}
