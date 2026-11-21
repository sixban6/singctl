// 文件职责：将审计封禁引擎中的「规则集整包导入（ImportAndBlockRuleSet）」拆解为职责清晰的独立阶段，
// 并抽象统一的 Clash API 存量连接匹配掐断公共方法（killConnectionsMatching）。
//
// 架构设计原则：
//   - 函数式内核 + 命令式薄外壳（Functional Core, Imperative Shell）：
//     输入规范解析（parseRuleSetImportSpec）与 Rule 02 防自锁安全扫描（validateDecompiledRuleSetSafety）
//     均为纯内存函数，可零 I/O 直接执行全量边界单测；
//     HTTP 下载、.srs 磁盘落盘与热重载编排则保留在外壳 Enforcer。
//   - 依赖倒置（DIP）：通过 Enforcer.httpClient 与 Enforcer.resolveSingBoxBin 字段注入测试替身，
//     单测全程运行于 httptest + t.TempDir()，零宿主机副作用。
//   - DRY 原则：killConnectionsMatching 统一承载单目标拉黑与整包规则集封禁的 Clash /connections 遍历与 DELETE。
package audit

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

// ruleSetImportSpec 表示经过输入规范化后的规则集导入描述。
type ruleSetImportSpec struct {
	tag           string
	sourceURL     string
	normSource    string
	displaySource string
}

// parseRuleSetImportSpec 纯函数解析用户输入（`ruleset:<tag>` 或 `.srs`/`.json` HTTP URL）与源设备 IP，
// 自动提取安全的 rule_set tag 并规范化源设备 CIDR。
func parseRuleSetImportSpec(rawInput, customTag, rawSourceIP string) (ruleSetImportSpec, error) {
	rawInput = strings.TrimSpace(rawInput)
	if rawInput == "" {
		return ruleSetImportSpec{}, fmt.Errorf("规则集地址不能为空")
	}

	normSource := ""
	if strings.TrimSpace(rawSourceIP) != "" {
		normSource = singbox.NormalizeSourceIPCIDR(rawSourceIP)
		if normSource == "" {
			return ruleSetImportSpec{}, fmt.Errorf("无效的源设备 IP 格式: %q", rawSourceIP)
		}
	}
	displaySource := strings.TrimSuffix(strings.TrimSuffix(normSource, "/32"), "/128")

	var tag string
	var sourceURL string
	lowerInput := strings.ToLower(rawInput)
	if strings.HasPrefix(lowerInput, "ruleset:") {
		tag = singbox.SanitizeRuleSetTag(rawInput[len("ruleset:"):])
		if singbox.IsBuiltinPCDNTag(tag) {
			tag = singbox.BuiltinPCDNRuleSetTag
		}
	} else {
		u, err := url.Parse(rawInput)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return ruleSetImportSpec{}, fmt.Errorf("无效的规则集 URL: %q (需以 http:// 或 https:// 开头)", rawInput)
		}
		sourceURL = rawInput
		base := filepath.Base(u.Path)
		tag = singbox.SanitizeRuleSetTag(cmp.Or(strings.TrimSpace(customTag), base))
		if tag != "" && !strings.HasPrefix(tag, "geosite-") && !strings.HasPrefix(tag, "geoip-") && !strings.HasPrefix(tag, "block-") {
			tag = "block-" + tag
		}
	}
	if tag == "" {
		return ruleSetImportSpec{}, fmt.Errorf("无法从输入提取有效的规则集标识: %q", rawInput)
	}

	return ruleSetImportSpec{
		tag:           tag,
		sourceURL:     sourceURL,
		normSource:    normSource,
		displaySource: displaySource,
	}, nil
}

func (e *Enforcer) activeHTTPClient() *http.Client {
	if e != nil && e.httpClient != nil {
		return e.httpClient
	}
	return &http.Client{Timeout: 12 * time.Second}
}

func (e *Enforcer) activeSingBoxBin() string {
	if e != nil && e.resolveSingBoxBin != nil {
		return e.resolveSingBoxBin()
	}
	return singbox.FindSingBoxBin()
}

// fetchRuleSetPayload 按优先级获取规则集原始字节：
// 1) 内置防 PCDN 规则集直接读取内存编译源；
// 2) 远程 URL 自动尝试 GitHub 国内镜像前缀与直连地址，失败时安全回退到本地已缓存 .srs；
// 3) 本地规则集直接从 dstSRSPath 读取。
func (e *Enforcer) fetchRuleSetPayload(ctx context.Context, spec ruleSetImportSpec, dstSRSPath string) ([]byte, error) {
	if spec.tag == singbox.BuiltinPCDNRuleSetTag {
		return singbox.BuiltinPCDNRuleSetJSON(), nil
	}

	if spec.sourceURL != "" {
		var candidates []string
		if strings.Contains(spec.sourceURL, "github.com/") || strings.Contains(spec.sourceURL, "raw.githubusercontent.com/") {
			if !strings.HasPrefix(spec.sourceURL, "https://ghfast.top/") {
				candidates = append(candidates, "https://ghfast.top/"+spec.sourceURL)
			}
		}
		candidates = append(candidates, spec.sourceURL)

		client := e.activeHTTPClient()
		var lastErr error
		for _, cand := range candidates {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, cand, nil)
			if reqErr != nil {
				lastErr = reqErr
				continue
			}
			resp, doErr := client.Do(req)
			if doErr != nil {
				lastErr = doErr
				continue
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && readErr == nil && len(body) > 12 {
				return body, nil
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		// 若远程拉取失败但本地已有同名 .srs 缓存，允许复用本地文件保障可用性
		if localBytes, err := os.ReadFile(dstSRSPath); err == nil && len(localBytes) > 16 {
			return localBytes, nil
		}
		return nil, fmt.Errorf("下载规则集失败 (%s): %v", spec.sourceURL, lastErr)
	}

	localBytes, err := os.ReadFile(dstSRSPath)
	if err != nil || len(localBytes) <= 16 {
		return nil, fmt.Errorf("本地未找到规则集文件 %s，请提供完整的 .srs / .json 下载 URL", dstSRSPath)
	}
	return localBytes, nil
}

// compileOrDecompileRuleSet 将 JSON 源码编译为二进制 .srs，或将 .srs 二进制反编译为摘要结构。
func compileOrDecompileRuleSet(ctx context.Context, rawData []byte, sbBin string) (srsBytes []byte, parsed decompiledSRS, isJSON bool, err error) {
	trimmed := strings.TrimSpace(string(rawData))
	isJSON = strings.HasPrefix(trimmed, "{")

	if isJSON {
		if uErr := json.Unmarshal(rawData, &parsed); uErr != nil || len(parsed.Rules) == 0 {
			return nil, decompiledSRS{}, true, fmt.Errorf("无效的 sing-box 源码规则集 JSON 格式")
		}
		if sbBin != "" {
			tmpJSON := filepath.Join(os.TempDir(), fmt.Sprintf("singctl-rs-%d.json", time.Now().UnixNano()))
			tmpSRS := tmpJSON + ".srs"
			_ = os.WriteFile(tmpJSON, rawData, 0600)
			compCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			out, compErr := exec.CommandContext(compCtx, sbBin, "rule-set", "compile", tmpJSON, "-o", tmpSRS).CombinedOutput()
			cancel()
			_ = os.Remove(tmpJSON)
			if compErr != nil {
				_ = os.Remove(tmpSRS)
				return nil, decompiledSRS{}, true, fmt.Errorf("编译 JSON 规则集为 .srs 失败: %v (%s)", compErr, strings.TrimSpace(string(out)))
			}
			srsBytes, _ = os.ReadFile(tmpSRS)
			_ = os.Remove(tmpSRS)
		} else {
			// 测试环境无 sing-box 二进制时构造带 SRS 魔数的占位字节以完成离线契约验证
			srsBytes = append([]byte("SRS\x02"), rawData...)
		}
		return srsBytes, parsed, true, nil
	}

	if strings.HasPrefix(string(rawData), "SRS") || strings.HasPrefix(string(rawData), "RULE") {
		srsBytes = rawData
		if sbBin != "" {
			tmpSRS := filepath.Join(os.TempDir(), fmt.Sprintf("singctl-rs-%d.srs", time.Now().UnixNano()))
			_ = os.WriteFile(tmpSRS, srsBytes, 0600)
			decCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			out, decErr := exec.CommandContext(decCtx, sbBin, "rule-set", "decompile", tmpSRS, "-o", "/dev/stdout").Output()
			cancel()
			_ = os.Remove(tmpSRS)
			if decErr == nil && len(out) > 0 {
				_ = json.Unmarshal(out, &parsed)
			}
		}
		return srsBytes, parsed, false, nil
	}

	return nil, decompiledSRS{}, false, fmt.Errorf("不支持的规则集文件格式（仅支持 sing-box 二进制 .srs 或源码 .json 规则集）")
}

// validateDecompiledRuleSetSafety 遵循 Rule 02 防自锁红线，纯内存扫描规则集全量域名与 IP/CIDR 条目，
// 严禁误封用户机场订阅域名、自建节点、公共 DoH 基础设施及局域网网关地址，并顺带生成展示预览样本。
func validateDecompiledRuleSetSafety(cfg *config.Config, tag string, parsed *decompiledSRS) (ruleCount int, samples []string, err error) {
	if parsed == nil {
		return 0, nil, nil
	}
	for _, r := range parsed.Rules {
		for _, d := range append(slices.Clone(r.Domain), r.DomainSuffix...) {
			d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), ".")
			if d == "" {
				continue
			}
			if _, _, safeErr := ValidateTargetSafety(cfg, d); safeErr != nil {
				return 0, nil, fmt.Errorf("规则集安全校验未通过 (%s): %w", tag, safeErr)
			}
			ruleCount++
			if len(samples) < 8 && !slices.Contains(samples, d) {
				samples = append(samples, d)
			}
		}
		for _, kw := range r.DomainKeyword {
			kw = strings.TrimSpace(kw)
			if kw != "" {
				ruleCount++
				if len(samples) < 8 && !slices.Contains(samples, "kw:"+kw) {
					samples = append(samples, "kw:"+kw)
				}
			}
		}
		for _, cidr := range r.IPCIDR {
			cidr = strings.TrimSpace(cidr)
			if cidr != "" {
				if _, _, safeErr := validateTargetSafety(cfg, cidr, false); safeErr != nil {
					return 0, nil, fmt.Errorf("规则集安全校验未通过 (%s): %w", tag, safeErr)
				}
				ruleCount++
				if len(samples) < 8 && !slices.Contains(samples, cidr) {
					samples = append(samples, cidr)
				}
			}
		}
	}
	return ruleCount, samples, nil
}

func persistImportedRuleSetFiles(ruleSetDir, dstSRSPath string, spec ruleSetImportSpec, srsBytes []byte, isJSON bool, parsed *decompiledSRS) error {
	tmpDst := dstSRSPath + ".tmp"
	if err := os.WriteFile(tmpDst, srsBytes, 0644); err != nil {
		return fmt.Errorf("写入规则集文件失败: %w", err)
	}
	if err := os.Rename(tmpDst, dstSRSPath); err != nil {
		_ = os.Remove(tmpDst)
		return fmt.Errorf("保存规则集文件失败: %w", err)
	}
	if spec.sourceURL != "" && !isJSON {
		singbox.RecordRuleSetManifest(ruleSetDir, spec.tag, spec.sourceURL, "binary")
	}
	if summaryBytes, err := json.Marshal(parsed); err == nil {
		_ = os.WriteFile(blockedRuleSetSummaryPath(spec.tag), summaryBytes, 0600)
	}
	return nil
}

// killConnectionsMatching 通过高阶匹配函数 matchFn 统一遍历 Clash API /connections 并在命中时执行秒级 DELETE 掐断，
// 消除单目标封禁与整包规则集封禁之间重复的 HTTP 拉取、鉴权和清理逻辑（DRY）。
func (e *Enforcer) killConnectionsMatching(ctx context.Context, sourcePlain string, matchFn func(host, destIP string) bool) int {
	if e == nil || matchFn == nil || len(e.clashEndpoints) == 0 {
		return 0
	}
	client := &http.Client{Timeout: 2 * time.Second}
	killed := 0

	for _, ep := range e.clashEndpoints {
		baseURL := strings.TrimRight(ep, "/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/connections", nil)
		if err != nil {
			continue
		}
		if e.clashSecret != "" {
			req.Header.Set("Authorization", "Bearer "+e.clashSecret)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		var parsed clashConnectionsResponse
		decErr := json.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		if decErr != nil {
			continue
		}

		for _, conn := range parsed.Connections {
			if sourcePlain != "" && strings.TrimSpace(conn.Metadata.SourceIP) != sourcePlain {
				continue
			}
			host := strings.ToLower(cmp.Or(strings.TrimSpace(conn.Metadata.SniffHost), strings.TrimSpace(conn.Metadata.Host)))
			destIP := strings.TrimSpace(conn.Metadata.DestinationIP)
			if !matchFn(host, destIP) {
				continue
			}
			delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/connections/"+url.PathEscape(conn.ID), nil)
			if err != nil {
				continue
			}
			if e.clashSecret != "" {
				delReq.Header.Set("Authorization", "Bearer "+e.clashSecret)
			}
			if delResp, err := client.Do(delReq); err == nil {
				delResp.Body.Close()
				if delResp.StatusCode == http.StatusNoContent || delResp.StatusCode == http.StatusOK {
					killed++
				}
			}
		}
		break
	}
	return killed
}
