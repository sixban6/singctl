// 文件职责：维护客户端内置防 PCDN 域名后缀清单、精确后缀匹配、规则集编译缓存与默认开关生效逻辑。
package singbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/singbox/sboption"
)

const (
	// BuiltinPCDNRuleSetTag 是 sing-box 中内置防 PCDN 规则集的规范化 tag。
	BuiltinPCDNRuleSetTag = "block-builtin-pcdn"
	// BuiltinPCDNRuleSetAlias 是便于 CLI/API 引用的内置防 PCDN 规则集短别名。
	BuiltinPCDNRuleSetAlias = "builtin-pcdn"
	// BuiltinPCDNRuleSetTarget 是 custom_rules.block 与黑名单 API 中使用的聚合规则集目标标识。
	BuiltinPCDNRuleSetTarget = "ruleset:" + BuiltinPCDNRuleSetTag
	// BuiltinPCDNRuleSetReason 是内置防 PCDN 规则集的默认展示说明。
	BuiltinPCDNRuleSetReason = "内置默认防 PCDN 偷跑与卡顿节点规则集"
)

// BuiltinPCDNDomainSuffixes 是精校、零误杀的商业 PCDN 调度域、Tracker 与边缘拉流节点后缀列表。
// 严禁收录通用主域（如 bilivideo.com / qiyipic.com / qq.com / apple.com / brave.com），确保屏蔽 PCDN 后播放器可无感回落官方正规 CDN。
var BuiltinPCDNDomainSuffixes = []string{
	// Bilibili MCDN / PCDN 边缘节点
	"mcdn.bilivideo.cn",
	"mcdn.bilivideo.com",
	"szbdyd.com",

	// 网心云 / 星域云 / 迅雷 PCDN 与 Tracker
	"xycdn.com",
	"onethingpcs.com",
	"onethingcloud.com",
	"onethingtech.net",
	"peiluyou.com",
	"p2cdn.com",
	"hub5btmain.sandai.net",
	"hub5emu.sandai.net",
	"hub5idx.sandai.net",
	"p2s.sandai.net",
	"tracker.sandai.net",

	// 爱奇艺 / 优酷 / 芒果 / 腾讯 / 百度 / 斗鱼 / 虎牙 / 快手 / 字节 / 音频 PCDN
	"71edge.com",
	"71edge.net",
	"hcdn.qiyi.com",
	"pcdn.qiyi.com",
	"p2p.qiyi.com",
	"p2p.iqiyi.com",
	"uhabo.com",
	"pcdn.youku.com",
	"p2p.youku.com",
	"yk-pcdn.youku.com",
	"kuiniuca.com",
	"pcdn.baidu.com",
	"p2p.baidu.com",
	"bsclink.cn",
	"jomodns.com",
	"saxysec.com",
	"p2p.huya.com",
	"pcdn.huya.com",
	"p2p.douyucdn.cn",
	"pcdn.douyucdn.cn",
	"p2p-v.douyucdn.cn",
	"p2p.qq.com",
	"pcdn.qq.com",
	"tcdn.qq.com",
	"p2p.kuaishou.com",
	"pcdn.kuaishou.com",
	"ksp2p.com",
	"pcdn.mgtv.com",
	"p2p.mgtv.com",
	"pcdn.bytedance.com",
	"p2p.bytedance.com",
	"pcdn.ixigua.com",
	"pcdn.snssdk.com",
	"pcdn.byteimg.com",
	"pcdn.xmcdn.com",
	"p2p.xmcdn.com",
	"pcdn.music.163.com",
	"p2p.music.163.com",

	// 第三方商业边缘 PCDN 节点域
	"baishancdnx.com",
	"baishancdnx.cn",
	"fogcdn.com",
	"fogcdn.net",
	"wankacdn.com",
	"nexitech.cn",
	"yirujs.com",
	"cqttech.com",
}

// IsBuiltinPCDNTag 判断规范化或原始 tag 是否指向内置防 PCDN 规则集。
func IsBuiltinPCDNTag(tag string) bool {
	s := SanitizeRuleSetTag(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(tag)), "ruleset:"))
	return s == BuiltinPCDNRuleSetTag || s == BuiltinPCDNRuleSetAlias
}

// IsBuiltinPCDNTarget 判断黑名单 target 是否指向内置防 PCDN 规则集。
func IsBuiltinPCDNTarget(raw string) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	if !strings.HasPrefix(s, "ruleset:") {
		return false
	}
	return IsBuiltinPCDNTag(strings.TrimPrefix(s, "ruleset:"))
}

// MatchBuiltinPCDNDomain 判断域名是否精确匹配内置防 PCDN 后缀列表（含子域名）。
func MatchBuiltinPCDNDomain(host string) (matched bool, suffix string) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if d == "" {
		return false, ""
	}
	for _, s := range BuiltinPCDNDomainSuffixes {
		if d == s || strings.HasSuffix(d, "."+s) {
			return true, s
		}
	}
	return false, ""
}

// BuiltinPCDNRuleSetJSON 返回 sing-box v2 源码规则集 JSON（兼容 sing-box 1.10~1.14 编译为 .srs）。
func BuiltinPCDNRuleSetJSON() []byte {
	payload := map[string]any{
		"version": 2,
		"rules": []map[string]any{
			{
				"domain_suffix": BuiltinPCDNDomainSuffixes,
			},
		},
	}
	b, _ := json.Marshal(payload)
	return b
}

// BuiltinPCDNInlineRuleSet 返回可跨平台（含 iOS SFI）免外部下载的 sing-box inline 规则集声明。
func BuiltinPCDNInlineRuleSet() sboption.RuleSet {
	rawRules, _ := json.Marshal([]map[string]any{
		{"domain_suffix": slices.Clone(BuiltinPCDNDomainSuffixes)},
	})
	return sboption.RuleSet{
		Tag:   BuiltinPCDNRuleSetTag,
		Type:  "inline",
		Rules: rawRules,
	}
}

// BuiltinPCDNBlockRule 构造用于配置编译与 WebUI 展示的内置防 PCDN 规则集条目。
func BuiltinPCDNBlockRule() config.BlockRule {
	sampleCount := min(4, len(BuiltinPCDNDomainSuffixes))
	preview := strings.Join(BuiltinPCDNDomainSuffixes[:sampleCount], ", ")
	if len(BuiltinPCDNDomainSuffixes) > sampleCount {
		preview += fmt.Sprintf(" 等共 %d 条", len(BuiltinPCDNDomainSuffixes))
	}
	return config.BlockRule{
		Target:    BuiltinPCDNRuleSetTarget,
		Reason:    BuiltinPCDNRuleSetReason,
		RuleCount: len(BuiltinPCDNDomainSuffixes),
		Preview:   preview,
	}
}

// EffectiveBlockRules 返回合并了默认内置防 PCDN 规则集后的有效黑名单列表。
// 当 cfg 为 nil 或 cfg.Audit.IsPCDNBlockEnabled() 为 true 且列表中无全局 block-builtin-pcdn 时，自动前置注入。
func EffectiveBlockRules(cfg *config.Config) []config.BlockRule {
	var base []config.BlockRule
	if cfg != nil {
		base = cfg.CustomRules.Block
	}

	pcdnEnabled := cfg == nil || cfg.Audit.IsPCDNBlockEnabled()
	out := make([]config.BlockRule, 0, len(base)+1)
	hasGlobalBuiltin := false
	for _, b := range base {
		norm, _ := NormalizeBlockTarget(b.Target)
		if IsBuiltinPCDNTarget(norm) && strings.TrimSpace(b.SourceIP) == "" {
			if !pcdnEnabled {
				continue
			}
			if hasGlobalBuiltin {
				continue
			}
			hasGlobalBuiltin = true
			item := BuiltinPCDNBlockRule()
			if strings.TrimSpace(b.Reason) != "" {
				item.Reason = strings.TrimSpace(b.Reason)
			}
			item.CreatedAt = b.CreatedAt
			out = append(out, item)
			continue
		}
		out = append(out, b)
	}

	if pcdnEnabled && !hasGlobalBuiltin {
		out = append([]config.BlockRule{BuiltinPCDNBlockRule()}, out...)
	}
	return out
}

func builtinPCDNRuleSetHash(srcJSON []byte) string {
	sum := sha256.Sum256(srcJSON)
	return hex.EncodeToString(sum[:])
}

// IsBuiltinPCDNRuleSetFileCurrent 判断磁盘上的 .srs 文件是否存在且摘要为最新版本；
// 若测试环境中不存在 .sha256 摘要文件且无 sing-box 可执行文件，仅要求文件非空（>16 字节）。
func IsBuiltinPCDNRuleSetFileCurrent(srsPath string) bool {
	info, statErr := os.Stat(srsPath)
	if statErr != nil || info.Size() <= 16 {
		return false
	}
	wantHash := builtinPCDNRuleSetHash(BuiltinPCDNRuleSetJSON())
	if curHashBytes, readErr := os.ReadFile(srsPath + ".sha256"); readErr == nil {
		return strings.TrimSpace(string(curHashBytes)) == wantHash
	}
	return FindSingBoxBin() == ""
}

// EnsureBuiltinPCDNRuleSetFile 幂等编译并落盘内置防 PCDN 二进制规则集 (.srs，权限 0644)。
// 若系统未安装 sing-box 或无写权限，优雅返回 (dstSRS, false, nil)，由调用方自动回退为 inline 规则集。
func EnsureBuiltinPCDNRuleSetFile(ctx context.Context, ruleSetDir string) (srsPath string, compiled bool, err error) {
	if strings.TrimSpace(ruleSetDir) == "" {
		ruleSetDir = RuleSetCacheDir()
	}
	dstSRS := filepath.Join(ruleSetDir, BuiltinPCDNRuleSetTag+".srs")
	hashPath := dstSRS + ".sha256"

	srcJSON := BuiltinPCDNRuleSetJSON()
	wantHash := builtinPCDNRuleSetHash(srcJSON)

	if IsBuiltinPCDNRuleSetFileCurrent(dstSRS) {
		return dstSRS, true, nil
	}

	sbBin := FindSingBoxBin()
	if sbBin == "" {
		return dstSRS, false, nil
	}
	if mkErr := os.MkdirAll(ruleSetDir, 0755); mkErr != nil {
		return dstSRS, false, nil
	}

	tmpJSON := filepath.Join(os.TempDir(), fmt.Sprintf("singctl-pcdn-%d.json", time.Now().UnixNano()))
	tmpSRS := dstSRS + ".tmp"
	if wErr := os.WriteFile(tmpJSON, srcJSON, 0600); wErr != nil {
		return dstSRS, false, fmt.Errorf("写入内置 PCDN 源码规则集失败: %w", wErr)
	}
	defer func() {
		_ = os.Remove(tmpJSON)
	}()

	compCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, compErr := exec.CommandContext(compCtx, sbBin, "rule-set", "compile", tmpJSON, "-o", tmpSRS).CombinedOutput()
	if compErr != nil {
		_ = os.Remove(tmpSRS)
		return dstSRS, false, fmt.Errorf("编译内置 PCDN 规则集失败: %v (%s)", compErr, strings.TrimSpace(string(out)))
	}
	_ = os.Chmod(tmpSRS, 0644)
	if renErr := os.Rename(tmpSRS, dstSRS); renErr != nil {
		_ = os.Remove(tmpSRS)
		return dstSRS, false, fmt.Errorf("原子替换内置 PCDN 规则集失败: %w", renErr)
	}
	_ = os.WriteFile(hashPath, []byte(wantHash+"\n"), 0600)
	return dstSRS, true, nil
}
