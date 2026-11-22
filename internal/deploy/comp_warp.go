package deploy

import (
	"context"
	"fmt"

	"singctl/internal/component"
	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/util/github"
)

type warpServerComponent struct{}

func (*warpServerComponent) ID() string          { return "warp" }
func (*warpServerComponent) Aliases() []string   { return []string{"wireproxy"} }
func (*warpServerComponent) DisplayName() string { return "WARP 出口" }
func (*warpServerComponent) UnitName() string    { return "wireproxy" }

func (w *warpServerComponent) ExecuteServiceAction(ctx context.Context, action string, mgr servicemgr.Manager, _ servicemgr.CmdRunner, _ string) error {
	if action == "reload" {
		action = "restart"
	}
	return component.DispatchServiceAction(ctx, mgr, action, w.UnitName())
}

func (*warpServerComponent) ResolveConfigTarget(string) (component.ConfigTarget, error) {
	primary, mirrors, _ := ResolveWireproxyConfigPaths()
	return component.ConfigTarget{
		PrimaryPath: primary,
		MirrorPaths: mirrors,
		FileMode:    0600,
	}, nil
}

func (*warpServerComponent) ValidateConfig(context.Context, string, servicemgr.CmdRunner, string) error {
	return nil
}

func (*warpServerComponent) ApplyOwnership(string) {}

func (w *warpServerComponent) ReloadAfterSave(ctx context.Context, _ string, mgr servicemgr.Manager, _ servicemgr.CmdRunner, canSystemctl bool) error {
	if !canSystemctl {
		return nil
	}
	return mgr.Restart(ctx, w.UnitName())
}

func (w *warpServerComponent) CheckUpdate(cfg *config.Config) (*component.CheckUpdateInfo, error) {
	fetcher := github.NewReleaseFetcher(getMirrorURL(cfg), ReleaseClient)
	curr := GetInstalledWarpVersion()
	tag, err := fetcher.FetchLatestTag("windtf/wireproxy")
	latest := cleanVersion(tag)
	if err != nil || latest == "" {
		latest = curr
	}
	hasUp := IsNewerVersion(curr, latest)
	msg := fmt.Sprintf("WARP (wireproxy) 已是最新版本 (v%s)", curr)
	if hasUp {
		msg = fmt.Sprintf("发现 WARP (wireproxy) 新版本: v%s (当前: v%s)", latest, curr)
	}
	return &component.CheckUpdateInfo{
		Component:      w.ID(),
		DisplayName:    w.DisplayName(),
		CurrentVersion: curr,
		LatestVersion:  latest,
		HasUpdate:      hasUp,
		Message:        msg,
	}, nil
}

func (*warpServerComponent) Upgrade(cfg *config.Config) (*component.UpgradeInfo, error) {
	res, err := UpgradeWarp(cfg)
	if err != nil {
		return nil, err
	}
	return upgradeResultToInfo(res), nil
}

func (*warpServerComponent) InstalledVersion() string {
	return GetInstalledWarpVersion()
}

func (*warpServerComponent) DeployServer(*config.Config) error {
	return DeployWarp()
}

func (*warpServerComponent) ReinstallServer(*config.Config) error {
	logger.Info("Reinstalling WARP...")
	if err := UninstallWarp(); err != nil {
		logger.Warn("Failed to uninstall WARP: %v", err)
	}
	return DeployWarp()
}

func (*warpServerComponent) UninstallServer() error {
	return UninstallWarp()
}
