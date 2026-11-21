package deploy

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"singctl/internal/component"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/util/github"
)

type singboxServerComponent struct{}

func (*singboxServerComponent) ID() string          { return "singbox" }
func (*singboxServerComponent) Aliases() []string   { return []string{"sb", "sing-box"} }
func (*singboxServerComponent) DisplayName() string { return "sing-box 代理核心" }
func (*singboxServerComponent) UnitName() string    { return "sing-box" }

func (s *singboxServerComponent) ExecuteServiceAction(ctx context.Context, action string, mgr servicemgr.Manager, _ servicemgr.CmdRunner, _ string) error {
	if action == "reload" {
		action = "restart"
	}
	return component.DispatchServiceAction(ctx, mgr, action, s.UnitName())
}

func (*singboxServerComponent) ResolveConfigTarget(overridePath string) (component.ConfigTarget, error) {
	return component.ConfigTarget{
		PrimaryPath: cmp.Or(strings.TrimSpace(overridePath), constant.SingBoxConfigFile, "/etc/sing-box/config.json"),
		FileMode:    0600,
	}, nil
}

func (*singboxServerComponent) ValidateConfig(ctx context.Context, content string, runner servicemgr.CmdRunner, binOverride string) error {
	var js json.RawMessage
	if err := json.Unmarshal([]byte(content), &js); err != nil {
		return fmt.Errorf("sing-box 配置必须是合法的 JSON 格式: %w", err)
	}
	sbBin := strings.TrimSpace(binOverride)
	if sbBin == "" {
		sbBin, _ = locateSingBoxExecutable()
	}
	if sbBin == "" || runner == nil {
		return nil
	}
	tmp, err := os.CreateTemp("", "singbox-validate-*.json")
	if err != nil {
		return nil
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	_ = tmp.Chmod(0600)
	_, _ = tmp.WriteString(content)
	_ = tmp.Close()
	if out, err := runner.CombinedOutput(ctx, 15*time.Second, sbBin, "check", "-c", tmpName); err != nil {
		return fmt.Errorf("sing-box 配置预校验未通过（已拦截写入以防断网）: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (*singboxServerComponent) ApplyOwnership(string) {}

func (s *singboxServerComponent) ReloadAfterSave(ctx context.Context, _ string, mgr servicemgr.Manager, _ servicemgr.CmdRunner, canSystemctl bool) error {
	if !canSystemctl {
		return nil
	}
	return mgr.Restart(ctx, s.UnitName())
}

func (s *singboxServerComponent) CheckUpdate(cfg *config.Config) (*component.CheckUpdateInfo, error) {
	fetcher := github.NewReleaseFetcher(getMirrorURL(cfg), ReleaseClient)
	curr := GetInstalledSingBoxVersion()
	tag, err := fetcher.FetchLatestTag("SagerNet/sing-box")
	latest := cleanVersion(tag)
	if err != nil || latest == "" {
		latest = curr
	}
	hasUp := IsNewerVersion(curr, latest)
	msg := fmt.Sprintf("sing-box 已是最新版本 (v%s)", curr)
	if hasUp {
		msg = fmt.Sprintf("发现 sing-box 新版本: v%s (当前: v%s)", latest, curr)
	}
	return &component.CheckUpdateInfo{
		Component:      s.ID(),
		DisplayName:    s.DisplayName(),
		CurrentVersion: curr,
		LatestVersion:  latest,
		HasUpdate:      hasUp,
		Message:        msg,
	}, nil
}

func (*singboxServerComponent) Upgrade(cfg *config.Config) (*component.UpgradeInfo, error) {
	res, err := UpgradeSingbox(cfg)
	if err != nil {
		return nil, err
	}
	return upgradeResultToInfo(res), nil
}

func (*singboxServerComponent) DeployServer(cfg *config.Config) error {
	sbs, err := NewSingBoxServer(cfg)
	if err != nil {
		return err
	}
	_ = sbs.LoadExistingCredentials()
	if err := sbs.DeploySingbox(); err != nil {
		return err
	}
	syncSubHubIfPresent(cfg, sbs)
	return nil
}

func (*singboxServerComponent) ReinstallServer(cfg *config.Config) error {
	logger.Info("Reinstalling sing-box...")
	sbs, err := NewSingBoxServer(cfg)
	if err != nil {
		return err
	}
	_ = sbs.LoadExistingCredentials()
	if err := UninstallSingbox(); err != nil {
		logger.Warn("Failed to uninstall sing-box: %v", err)
	}
	sbs.RefreshCaddyCertPath()
	if err := sbs.DeploySingbox(); err != nil {
		return err
	}
	syncSubHubIfPresent(cfg, sbs)
	return nil
}

func (*singboxServerComponent) UninstallServer() error {
	return UninstallSingbox()
}

func syncSubHubIfPresent(cfg *config.Config, sbs *SingBoxServer) {
	if _, err := os.Stat(cmp.Or(constant.SubStoreDir, "/etc/sub-store")); err == nil {
		sbt := NewSubstore(cfg, "")
		if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
			logger.Warn("SubHub config sync failed (non-fatal): %v", err)
		}
	}
}

func locateSingBoxExecutable() (string, error) {
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p, nil
	}
	for _, candidate := range []string{"/usr/local/bin/sing-box", "/usr/bin/sing-box"} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", os.ErrNotExist
}
