package deploy

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"singctl/internal/component"
	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/util/github"
)

type caddyServerComponent struct{}

func (*caddyServerComponent) ID() string          { return "caddy" }
func (*caddyServerComponent) Aliases() []string   { return nil }
func (*caddyServerComponent) DisplayName() string { return "Caddy 网关" }
func (*caddyServerComponent) UnitName() string    { return "caddy" }

func (c *caddyServerComponent) ExecuteServiceAction(ctx context.Context, action string, mgr servicemgr.Manager, runner servicemgr.CmdRunner, cfgPathOverride string) error {
	if action == "reload" {
		caddyCfg := cmp.Or(strings.TrimSpace(cfgPathOverride), caddyfilePath(), "/etc/caddy/Caddyfile")
		if runner != nil {
			if err := runner.Run(ctx, 25*time.Second, "caddy", "reload", "--config", caddyCfg); err == nil {
				return nil
			}
		}
		return mgr.Reload(ctx, c.UnitName())
	}
	return component.DispatchServiceAction(ctx, mgr, action, c.UnitName())
}

func (*caddyServerComponent) ResolveConfigTarget(overridePath string) (component.ConfigTarget, error) {
	return component.ConfigTarget{
		PrimaryPath: cmp.Or(strings.TrimSpace(overridePath), caddyfilePath(), "/etc/caddy/Caddyfile"),
		FileMode:    0640,
	}, nil
}

func (*caddyServerComponent) ValidateConfig(ctx context.Context, content string, runner servicemgr.CmdRunner, _ string) error {
	if runner == nil {
		return nil
	}
	tmp, err := os.CreateTemp("", "caddyfile-validate-*.caddy")
	if err != nil {
		return nil
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	_ = tmp.Chmod(0600)
	_, _ = tmp.WriteString(content)
	_ = tmp.Close()
	if out, err := runner.CombinedOutput(ctx, 15*time.Second, "caddy", "validate", "--config", tmpName, "--adapter", "caddyfile"); err != nil {
		return fmt.Errorf("Caddy 语法校验失败: %s", string(out))
	}
	return nil
}

func (*caddyServerComponent) ApplyOwnership(path string) {
	if g, err := user.LookupGroup("caddy"); err == nil {
		if gid, convErr := strconv.Atoi(g.Gid); convErr == nil {
			_ = os.Chown(path, 0, gid)
		}
	}
}

func (*caddyServerComponent) ReloadAfterSave(ctx context.Context, path string, _ servicemgr.Manager, runner servicemgr.CmdRunner, _ bool) error {
	if runner == nil {
		return nil
	}
	return runner.Run(ctx, 25*time.Second, "caddy", "reload", "--config", path)
}

func (c *caddyServerComponent) CheckUpdate(cfg *config.Config) (*component.CheckUpdateInfo, error) {
	fetcher := github.NewReleaseFetcher(getMirrorURL(cfg), ReleaseClient)
	curr := GetInstalledCaddyVersion()
	tag, err := fetcher.FetchLatestTag("caddyserver/caddy")
	latest := cleanVersion(tag)
	if err != nil || latest == "" {
		latest = curr
	}
	hasUp := IsNewerVersion(curr, latest)
	msg := fmt.Sprintf("Caddy 已是最新版本 (v%s)", curr)
	if hasUp {
		msg = fmt.Sprintf("发现 Caddy 新版本: v%s (当前: v%s)", latest, curr)
	}
	return &component.CheckUpdateInfo{
		Component:      c.ID(),
		DisplayName:    c.DisplayName(),
		CurrentVersion: curr,
		LatestVersion:  latest,
		HasUpdate:      hasUp,
		Message:        msg,
	}, nil
}

func (*caddyServerComponent) Upgrade(cfg *config.Config) (*component.UpgradeInfo, error) {
	res, err := UpgradeCaddy(cfg)
	if err != nil {
		return nil, err
	}
	return upgradeResultToInfo(res), nil
}

func (*caddyServerComponent) DeployServer(cfg *config.Config) error {
	return DeployCaddy(cfg)
}

func (*caddyServerComponent) ReinstallServer(cfg *config.Config) error {
	logger.Info("Reinstalling Caddy...")
	if err := MigrateLegacyCaddyMtlsToVault(); err != nil {
		logger.Warn("Migrate mTLS vault warning: %v", err)
	}
	if err := UninstallCaddy(); err != nil {
		logger.Warn("Failed to uninstall Caddy: %v", err)
	}
	return DeployCaddy(cfg)
}

func (*caddyServerComponent) UninstallServer() error {
	return UninstallCaddy()
}
