// 文件职责：提供客户端 WebUI 对本地 AdGuard Home / SmartDNS 路径解析与订阅白名单异步同步辅助方法（全部 HTTP 接口已收敛至 dns_api.go）。
package webui

import (
	"cmp"
	"context"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
)

func (s *Server) newAdGuardManager(cfg *config.Config) *adguard.Manager {
	mgr := adguard.NewManager(cfg, s.opts.ConfigPath)
	mgr.SetPathsForTest(s.opts.AdGuardBinPath, s.opts.AdGuardConfigPath)
	if s.opts.AdGuardMemInfoForTest != nil {
		mgr.SetReadMemInfoForTest(s.opts.AdGuardMemInfoForTest)
	}
	return mgr
}

func (s *Server) adguardBinPath() string {
	return cmp.Or(strings.TrimSpace(s.opts.AdGuardBinPath), constant.AdGuardInstallPath)
}

func (s *Server) adguardConfigFilePath() string {
	return cmp.Or(strings.TrimSpace(s.opts.AdGuardConfigPath), constant.AdGuardConfigFile)
}

func (s *Server) smartDNSBinPath() string {
	return cmp.Or(strings.TrimSpace(s.opts.SmartDNSBinPath), constant.SmartDNSInstallPath)
}

func (s *Server) smartDNSConfigFilePath() string {
	return cmp.Or(strings.TrimSpace(s.opts.SmartDNSConfigPath), constant.SmartDNSConfigFile)
}

func (s *Server) syncAdGuardSubWhitelistAsync(cfg *config.Config) {
	if cfg == nil || len(cfg.Subs) == 0 {
		return
	}
	var urls []string
	for _, sub := range cfg.Subs {
		if strings.TrimSpace(sub.URL) != "" {
			urls = append(urls, sub.URL)
		}
	}
	if len(urls) == 0 {
		return
	}
	cfgCopy := cfg.Clone()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.newAdGuardManager(cfgCopy).SyncSubscriptionWhitelist(ctx, urls)
		reg := s.newDNSRegistry(cfgCopy)
		if active := reg.ActiveEngine(); active != nil && active.ID() == constant.DNSEngineSmartDNS && active.IsInstalled() {
			_ = active.SyncCommonConfig(ctx)
		}
	}()
}
