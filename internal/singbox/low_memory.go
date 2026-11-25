// 文件职责：实现 sing-box 低内存规则集裁剪（geosite-ad2）、自适应 Go 内存上限（GOMEMLIMIT/GOGC）计算与基础日志 256KiB 限流。
package singbox

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/singbox/sboption"
)

const (
	// LowMemoryUltraRAMBytes 超低内存分档阈值（复用 sysinfo.UltraLowMemoryThresholdBytes = 288 MiB）。
	LowMemoryUltraRAMBytes uint64 = sysinfo.UltraLowMemoryThresholdBytes
	// LowMemoryStandardRAMBytes 低内存分档阈值（复用 sysinfo.LowMemoryThresholdBytes = 512 MiB）。
	LowMemoryStandardRAMBytes uint64 = sysinfo.LowMemoryThresholdBytes
	// LowMemoryBasicLogMaxBytes 低内存模式下 /tmp/sing-box-basic.log 最大保留字节数（256 KiB）。
	LowMemoryBasicLogMaxBytes int64 = 256 * 1024
	// TmpCacheFilePath 定义 OpenWrt/低内存/小闪存设备零闪存磨损的 sing-box 状态缓存路径（落盘于 tmpfs 内存盘）。
	TmpCacheFilePath = "/tmp/sing-box-cache.db"

	prunedHeavyAdRuleSetTag = "geosite-ad2"
)

func readHostTotalRAMBytes() uint64 {
	return sysinfo.TotalRAMBytes()
}

// SetTotalRAMBytes 覆盖宿主机总物理内存字节数（供离线编译与单元测试显式注入，并发安全）。
func (g *ConfigGenerator) SetTotalRAMBytes(totalRAMBytes uint64) {
	if g == nil {
		return
	}
	val := totalRAMBytes
	g.totalRAMOverride.Store(&val)
}

// EffectiveLowMemory 返回当前生成器上下文是否启用低内存裁剪策略。
func (g *ConfigGenerator) EffectiveLowMemory() bool {
	if g == nil {
		return false
	}
	if p := g.totalRAMOverride.Load(); p != nil {
		return g.config.EffectiveLowMemory(*p)
	}
	if g.config != nil {
		if norm, ok := config.NormalizeLowMemoryMode(string(g.config.LowMemory)); ok {
			switch norm {
			case config.LowMemoryOn:
				return true
			case config.LowMemoryOff:
				return false
			}
		}
	}
	return g.config.EffectiveLowMemory(readHostTotalRAMBytes()) || sysinfo.IsLowMemoryHost()
}

// ShouldUseTmpCacheFile 判断当前配置生成器目标环境是否应将 experimental.cache_file.path 迁入 /tmp 内存盘以消除闪存磨损。
func (g *ConfigGenerator) ShouldUseTmpCacheFile() bool {
	if g == nil {
		return false
	}
	if g.EffectiveLowMemory() {
		return true
	}
	isOpenWrt := sysinfo.IsOpenWrt
	if g.isOpenWrtProbe != nil {
		isOpenWrt = g.isOpenWrtProbe
	}
	if isOpenWrt() {
		return true
	}
	isLowFlash := sysinfo.IsLowFlashHost
	if g.isLowFlashProbe != nil {
		isLowFlash = g.isLowFlashProbe
	}
	return isLowFlash()
}

// relocateTmpCacheFileInDoc 在强类型配置树上将启用中的客户端 cache_file.path 重写为 /tmp/sing-box-cache.db（已位于 /tmp/ 下的路径保持不变）。
func relocateTmpCacheFileInDoc(doc *sboption.Document) bool {
	if doc == nil || doc.Experimental == nil || doc.Experimental.CacheFile == nil {
		return false
	}
	cf := doc.Experimental.CacheFile
	if cf.Enabled != nil && !*cf.Enabled {
		return false
	}
	curPath := strings.TrimSpace(cf.Path)
	if strings.HasPrefix(curPath, "/tmp/") {
		return false
	}
	cf.Path = TmpCacheFilePath
	return true
}

// CleanupLegacyFlashCacheDB 当生效配置已将 cache_file.path 迁入 /tmp/ 时，自动清理配置文件同目录下残留的旧闪存 cache.db（如 /etc/sing-box/cache.db）。
func CleanupLegacyFlashCacheDB(configPath, configJSON string) bool {
	cleanCfg := strings.TrimSpace(configPath)
	if cleanCfg == "" || strings.TrimSpace(configJSON) == "" {
		return false
	}
	doc, err := sboption.ParseDocument([]byte(configJSON))
	if err != nil || doc.Experimental == nil || doc.Experimental.CacheFile == nil {
		return false
	}
	curPath := strings.TrimSpace(doc.Experimental.CacheFile.Path)
	if !strings.HasPrefix(curPath, "/tmp/") {
		return false
	}
	legacyPath := filepath.Join(filepath.Dir(cleanCfg), "cache.db")
	if filepath.Clean(legacyPath) == filepath.Clean(curPath) {
		return false
	}
	info, err := os.Stat(legacyPath)
	if err != nil || info.IsDir() {
		return false
	}
	return os.Remove(legacyPath) == nil
}

// PruneLowMemoryRuleSetsJSON 从给定 sing-box 配置 JSON 中无损剥离巨型广告规则集 geosite-ad2 及其引用（保留 geosite-ad1 等）。
func PruneLowMemoryRuleSetsJSON(rawJSON string) (string, bool, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, false, nil
	}
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", false, err
	}
	if !pruneLowMemoryRuleSetsInDoc(doc) {
		return rawJSON, false, nil
	}
	formatted, err := doc.MarshalPretty()
	if err != nil {
		return "", false, err
	}
	return formatted + "\n", true, nil
}

// pruneLowMemoryRuleSetsInDoc 在低内存模式下从内存配置树安全剥离巨无霸规则集 geosite-ad2（立省 ~25-30 MB 堆内存），
// 完整保留轻量高频广告集 geosite-ad1 与内置 PCDN 拦截集，并清理悬空规则引用。
func pruneLowMemoryRuleSetsInDoc(doc *sboption.Document) bool {
	if doc == nil {
		return false
	}
	changed := false

	if doc.DNS != nil && len(doc.DNS.Rules) > 0 {
		beforeLen := len(doc.DNS.Rules)
		nextDNS := stripRuleSetTagFromDNSRules(doc.DNS.Rules, prunedHeavyAdRuleSetTag)
		if len(nextDNS) != beforeLen || dnsRulesContainTag(doc.DNS.Rules, prunedHeavyAdRuleSetTag) {
			doc.DNS.Rules = nextDNS
			changed = true
		}
	}

	if doc.Route != nil {
		if len(doc.Route.Rules) > 0 {
			beforeLen := len(doc.Route.Rules)
			nextRoute := stripRuleSetTagFromRouteRules(doc.Route.Rules, prunedHeavyAdRuleSetTag)
			if len(nextRoute) != beforeLen || routeRulesContainTag(doc.Route.Rules, prunedHeavyAdRuleSetTag) {
				doc.Route.Rules = nextRoute
				changed = true
			}
		}
		if len(doc.Route.RuleSet) > 0 {
			kept := make([]sboption.RuleSet, 0, len(doc.Route.RuleSet))
			rsPruned := false
			for _, rs := range doc.Route.RuleSet {
				if strings.TrimSpace(rs.Tag) == prunedHeavyAdRuleSetTag {
					rsPruned = true
					continue
				}
				kept = append(kept, rs)
			}
			if rsPruned {
				changed = true
				if len(kept) == 0 {
					doc.Route.RuleSet = nil
				} else {
					doc.Route.RuleSet = kept
				}
			}
		}
	}

	return changed
}

func routeRulesContainTag(rules []sboption.RouteRule, target string) bool {
	for _, r := range rules {
		for _, t := range r.RuleSet.Slice() {
			if strings.TrimSpace(t) == target {
				return true
			}
		}
		if len(r.Rules) > 0 && routeRulesContainTag(r.Rules, target) {
			return true
		}
	}
	return false
}

func dnsRulesContainTag(rules []sboption.DNSRule, target string) bool {
	for _, r := range rules {
		for _, t := range r.RuleSet.Slice() {
			if strings.TrimSpace(t) == target {
				return true
			}
		}
		if len(r.Rules) > 0 && dnsRulesContainTag(r.Rules, target) {
			return true
		}
	}
	return false
}

// ComputeSingBoxMemoryEnvForMode 根据宿主机总物理内存与工作模式计算全内存段自适应 Go 软内存上限与 GC 步频：
//   - 0：未知内存返回空字符串（不盲猜）
//   - <= 288 MiB：审计模式 GOMEMLIMIT="20MiB", GOGC="25"；代理模式 GOMEMLIMIT="28MiB", GOGC="30"
//   - 289~512 MiB：GOMEMLIMIT="44MiB", GOGC="50"
//   - 513 MiB~1 GiB：GOMEMLIMIT="160MiB"（保持 Go 默认 GOGC=100，零性能损耗防泄漏软顶）
//   - 1~2 GiB：GOMEMLIMIT="256MiB"（保持 Go 默认 GOGC=100）
//   - > 2 GiB：GOMEMLIMIT="512MiB"（保持 Go 默认 GOGC=100）
func ComputeSingBoxMemoryEnvForMode(totalRAMBytes uint64, workMode string) (gomemlimit string, gogc string) {
	const mib uint64 = 1024 * 1024
	if totalRAMBytes == 0 {
		return "", ""
	}
	switch {
	case sysinfo.IsUltraLowMemoryRAM(totalRAMBytes):
		if strings.EqualFold(strings.TrimSpace(workMode), config.WorkModeAudit) {
			return "20MiB", "25"
		}
		return "28MiB", "30"
	case sysinfo.IsLowMemoryRAM(totalRAMBytes):
		return "44MiB", "50"
	case totalRAMBytes <= 1024*mib:
		return "160MiB", ""
	case totalRAMBytes <= 2048*mib:
		return "256MiB", ""
	default:
		return "512MiB", ""
	}
}

// ComputeSingBoxMemoryEnv 根据宿主机总物理内存计算自适应 Go 软内存上限与 GC 步频（默认代理档向后兼容签名）。
func ComputeSingBoxMemoryEnv(totalRAMBytes uint64) (gomemlimit string, gogc string) {
	return ComputeSingBoxMemoryEnvForMode(totalRAMBytes, "")
}

// SingBoxMemoryEnvMap 将自适应内存上限封装为服务环境变量映射（无需限制时返回 nil）。
func SingBoxMemoryEnvMap(totalRAMBytes uint64) map[string]string {
	limit, gogc := ComputeSingBoxMemoryEnv(totalRAMBytes)
	if limit == "" {
		return nil
	}
	out := map[string]string{
		"GOMEMLIMIT": limit,
	}
	if gogc != "" {
		out["GOGC"] = gogc
	}
	return out
}

// BuildSingBoxClientUnitSpec 构建注入了自适应 GOMEMLIMIT/GOGC 的客户端 sing-box 跨平台服务单元规格。
func BuildSingBoxClientUnitSpec(binPath, configPath string, totalRAMBytes uint64) servicemgr.UnitSpec {
	exe := cmp.Or(strings.TrimSpace(binPath), constant.SingBoxInstallDir)
	cfgFile := cmp.Or(strings.TrimSpace(configPath), constant.SingBoxConfigFile)
	systemdBody := fmt.Sprintf(`[Unit]
Description=sing-box client TProxy service (managed by singctl)
After=network.target

[Service]
Type=simple
ExecStart=%s run -c %s
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, exe, cfgFile)

	procdBody := fmt.Sprintf(`#!/bin/sh /etc/rc.common

START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance "sing-box"
    procd_set_param command %s run -c %s
    procd_set_param respawn 3600 5 5
    procd_set_param limits nofile="65536 65536"
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`, exe, cfgFile)

	return servicemgr.UnitSpec{
		Name:        "sing-box",
		SystemdBody: systemdBody,
		ProcdBody:   procdBody,
		Env:         SingBoxMemoryEnvMap(totalRAMBytes),
	}
}

// BuildSingBoxCommandEnv 构建执行客户端启动脚本时的进程环境变量切片，自动注入全内存段自适应 GOMEMLIMIT/GOGC 与低内存标识。
func BuildSingBoxCommandEnv(baseEnv []string, cfg *config.Config, totalRAMBytes uint64) []string {
	lowMem := cfg.EffectiveLowMemory(totalRAMBytes)
	explicitOff := false
	if cfg != nil {
		if norm, valid := config.NormalizeLowMemoryMode(string(cfg.LowMemory)); valid && norm == config.LowMemoryOff {
			explicitOff = true
		}
	}
	overrides := make(map[string]string, 3)
	if lowMem {
		overrides["SINGCTL_LOW_MEMORY"] = "1"
	} else {
		overrides["SINGCTL_LOW_MEMORY"] = "0"
	}
	if !explicitOff {
		workMode := ""
		if cfg != nil {
			workMode = cfg.EffectiveWorkMode()
		}
		if limit, gogc := ComputeSingBoxMemoryEnvForMode(totalRAMBytes, workMode); limit != "" {
			overrides["GOMEMLIMIT"] = limit
			if gogc != "" {
				overrides["GOGC"] = gogc
			}
		}
	}

	out := make([]string, 0, len(baseEnv)+len(overrides))
	for _, kv := range baseEnv {
		key, _, ok := strings.Cut(kv, "=")
		if ok {
			if _, replaced := overrides[key]; replaced {
				continue
			}
			// 若显式关闭低内存模式，剥离外部继承的 GOMEMLIMIT 防止误限流
			if explicitOff && (key == "GOMEMLIMIT" || key == "GOGC") {
				continue
			}
		}
		out = append(out, kv)
	}
	for _, k := range []string{"GOMEMLIMIT", "GOGC", "SINGCTL_LOW_MEMORY"} {
		if v, ok := overrides[k]; ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// CapSingBoxBasicLog 将指定日志文件原地截断限制在 maxBytes 以内（保留原 inode 适配 O_APPEND）并收紧权限为 0600。
func CapSingBoxBasicLog(logPath string, maxBytes int64) error {
	cleanPath := strings.TrimSpace(logPath)
	if cleanPath == "" || maxBytes <= 0 {
		return nil
	}
	f, err := os.OpenFile(cleanPath, os.O_RDWR, 0600)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	_ = f.Chmod(0600)
	if info.Size() <= maxBytes {
		return nil
	}

	offset := info.Size() - maxBytes
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	tail, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return err
	}
	if nl := bytes.IndexByte(tail, '\n'); nl >= 0 && nl+1 < len(tail) {
		tail = tail[nl+1:]
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	n, err := f.Write(tail)
	if err != nil {
		return err
	}
	if err := f.Truncate(int64(n)); err != nil {
		return err
	}
	return nil
}

// EnforceLowMemoryBasicLogCap 当配置处于低内存模式时对日志文件执行 256 KiB 原地截断保护。
func EnforceLowMemoryBasicLogCap(cfg *config.Config, totalRAMBytes uint64, logPath string) error {
	if !cfg.EffectiveLowMemory(totalRAMBytes) {
		return nil
	}
	return CapSingBoxBasicLog(logPath, LowMemoryBasicLogMaxBytes)
}
