// 文件职责：管理 SmartDNS 第三方大体积去广告规则的内存盘 (/tmp) 缓存策略、历史闪存残留清理、重启缺失检测与有界异步自愈。
package smartdns

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/common/sysinfo"
	"singctl/internal/logger"
)

const backgroundFilterSyncTimeout = 30 * time.Second

func isThirdPartyFilterFileName(name string) bool {
	if name == "adblock.conf" {
		return true
	}
	return strings.HasPrefix(name, "filter-") && strings.HasSuffix(name, ".conf")
}

func hasActiveFilterRules(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return true
		}
	}
	return false
}

// ListActiveFilterFiles 扫描给定过滤规则目录中实际存在且包含有效规则的第三方去广告配置文件（adblock.conf 与 filter-*.conf），按字典序返回。
func ListActiveFilterFiles(filterDir string) []string {
	cleanDir := strings.TrimSpace(filterDir)
	if cleanDir == "" {
		return nil
	}
	entries, err := os.ReadDir(cleanDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isThirdPartyFilterFileName(name) {
			continue
		}
		fullPath := filepath.Join(cleanDir, name)
		if hasActiveFilterRules(fullPath) {
			out = append(out, fullPath)
		}
	}
	slices.Sort(out)
	return out
}

// CleanupLegacyFlashFilters 清理持久化规则目录（如 /etc/singctl/smartdns-rules.d）下历史遗留的第三方去广告大文件（adblock.conf 与 filter-*.conf），
// 严格保护用户轻量规则文件（whitelist.conf、rewrites.conf、audit_block.conf），帮助 128MB 小闪存路由器立即释放闪存。
func CleanupLegacyFlashFilters(rulesDir string) (removed int, freedBytes int64) {
	cleanDir := strings.TrimSpace(rulesDir)
	if cleanDir == "" {
		return 0, 0
	}
	entries, err := os.ReadDir(cleanDir)
	if err != nil {
		return 0, 0
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isThirdPartyFilterFileName(name) {
			continue
		}
		info, _ := entry.Info()
		if err := os.Remove(filepath.Join(cleanDir, name)); err == nil {
			removed++
			if info != nil {
				freedBytes += info.Size()
			}
		}
	}
	return removed, freedBytes
}

func (m *Manager) isOpenWrtHost() bool {
	if m.isOpenWrtFn != nil {
		return m.isOpenWrtFn()
	}
	return sysinfo.IsOpenWrt()
}

func (m *Manager) isLowFlashHost() bool {
	if m.isLowFlashFn != nil {
		return m.isLowFlashFn()
	}
	return sysinfo.IsLowFlashHost()
}

func (m *Manager) shouldUseTmpFilterCache(input ConfigInput) bool {
	if input.IsLowMemory || m.isOpenWrtHost() || m.isLowFlashHost() {
		return true
	}
	return sysinfo.IsLowMemoryMemInfo(m.currentMemInfo())
}

func (m *Manager) effectiveFilterCacheDir(input ConfigInput) string {
	if strings.TrimSpace(m.filterCacheDir) != "" {
		return m.filterCacheDir
	}
	if m.shouldUseTmpFilterCache(input) {
		return DefaultFilterCacheDir
	}
	return m.rulesDir
}

// FilterCacheDir 返回当前管理器解析后的第三方去广告规则缓存目录（OpenWrt/低闪存/低内存默认指向 /tmp/singctl-smartdns-filters）。
func (m *Manager) FilterCacheDir() string {
	return m.effectiveFilterCacheDir(m.snapshotConfig())
}

func (m *Manager) ensureManagedBasePlaceholders(filterDir string) error {
	if err := ensureRulesDir0700(m.rulesDir); err != nil {
		return err
	}
	placeholders := []string{
		"whitelist.conf",
		"rewrites.conf",
		"audit_block.conf",
	}
	if filepath.Clean(filterDir) == filepath.Clean(m.rulesDir) {
		placeholders = append(placeholders, "adblock.conf")
	}
	for _, name := range placeholders {
		p := filepath.Join(m.rulesDir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			content := fmt.Sprintf("# singctl managed smartdns %s (placeholder)\n", name)
			if writeErr := fsx.WriteAtomic0600(p, []byte(content)); writeErr != nil {
				return writeErr
			}
		}
	}
	return nil
}

func (m *Manager) configReferencesMissingFilterFile() bool {
	raw, err := os.ReadFile(m.configFile)
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(trimmed, "conf-file ")
		if !ok {
			continue
		}
		target := strings.TrimSpace(rest)
		if target == "" {
			continue
		}
		if !isThirdPartyFilterFileName(filepath.Base(target)) {
			continue
		}
		if !hasActiveFilterRules(target) {
			return true
		}
	}
	return false
}

func (m *Manager) writeBootSafeConfigWithoutNetwork(input ConfigInput) error {
	filterDir := m.effectiveFilterCacheDir(input)
	if err := m.ensureManagedBasePlaceholders(filterDir); err != nil {
		return err
	}
	if filepath.Clean(filterDir) != filepath.Clean(m.rulesDir) {
		if removed, freed := CleanupLegacyFlashFilters(m.rulesDir); removed > 0 {
			logger.Info("🧹 已清理 SmartDNS 历史闪存去广告缓存 %d 个文件（释放 %s）", removed, sysinfo.FormatBytes(freed))
		}
	}
	confText, err := BuildConfigWithOptions(input, BuildConfigOptions{
		RulesDir:               m.rulesDir,
		FilterCacheDir:         filterDir,
		AuditLogPath:           m.auditLogPath,
		LogFilePath:            m.logFilePath,
		RequireExistingFilters: true,
	})
	if err != nil {
		return err
	}
	return WriteConfig(m.configFile, confText)
}

func (m *Manager) triggerBackgroundFilterSync(input ConfigInput) {
	if input.ProtectionPaused || len(input.EnabledFilters) == 0 {
		return
	}
	filterDir := m.effectiveFilterCacheDir(input)
	if len(ListActiveFilterFiles(filterDir)) > 0 {
		return
	}
	if !m.bgSyncInFlight.CompareAndSwap(false, true) {
		return
	}

	parentCtx := m.bgCtx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	cfgSnapshot := cloneConfigInput(input)

	m.bgWG.Go(func() {
		defer m.bgSyncInFlight.Store(false)

		ctx, cancel := context.WithTimeout(parentCtx, backgroundFilterSyncTimeout)
		defer cancel()

		count, err := syncAdblockFiltersWithClient(ctx, m.httpClient, filterDir, cfgSnapshot.EnabledFilters, cfgSnapshot.ProtectionPaused, cfgSnapshot.MirrorURL)
		if err != nil {
			logger.Warn("SmartDNS 后台补拉去广告规则失败（不影响基础 DNS 解析）: %v", err)
			return
		}
		if ctx.Err() != nil {
			return
		}

		latest := m.snapshotConfig()
		if len(latest.EnabledFilters) == 0 {
			latest = cfgSnapshot
		}
		latestFilterDir := m.effectiveFilterCacheDir(latest)
		confText, err := BuildConfigWithOptions(latest, BuildConfigOptions{
			RulesDir:               m.rulesDir,
			FilterCacheDir:         latestFilterDir,
			AuditLogPath:           m.auditLogPath,
			LogFilePath:            m.logFilePath,
			RequireExistingFilters: true,
		})
		if err != nil {
			logger.Warn("SmartDNS 后台重建配置失败: %v", err)
			return
		}
		if err := WriteConfig(m.configFile, confText); err != nil {
			logger.Warn("SmartDNS 后台写入配置失败: %v", err)
			return
		}
		if m.isBinaryPresent() {
			if err := m.Reload(); err != nil {
				logger.Warn("SmartDNS 后台重载去广告规则失败: %v", err)
				return
			}
		}
		logger.Success("✅ SmartDNS 内存盘去广告规则后台自愈完成（共 %d 条规则，目录: %s）", count, latestFilterDir)
	})
}

// WaitBackgroundSync 等待所有已派发的 SmartDNS 后台过滤规则补拉任务完成（供优雅退出与单测确定性同步使用）。
func (m *Manager) WaitBackgroundSync() {
	if m == nil {
		return
	}
	m.bgWG.Wait()
}
