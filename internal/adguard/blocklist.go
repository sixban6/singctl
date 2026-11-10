package adguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"

	"gopkg.in/yaml.v3"
)

const (
	managedBlockStartMarker = "! >>> singctl-audit-blocklist start >>>"
	managedBlockEndMarker   = "! <<< singctl-audit-blocklist end <<<"
)

// FormatAdGuardBlockRule 将单条 BlockRule 转换为 AdGuard Home 标准高优拦截语法。
//   - 全局域名/IP 拦截: ||example.com^$important
//   - 指定内网设备拦截: ||example.com^$client=192.168.1.55,important
func FormatAdGuardBlockRule(b config.BlockRule) string {
	target := normalizeAdGuardTarget(b.Target)
	if target == "" {
		return ""
	}
	clientIP := normalizeAdGuardClientIP(b.SourceIP)
	if clientIP != "" {
		return fmt.Sprintf("||%s^$client=%s,important", target, clientIP)
	}
	return fmt.Sprintf("||%s^$important", target)
}

func normalizeAdGuardTarget(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimSuffix(s, "^")
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
		s = h
	}
	// 若是 /32 或 /128 单主机 CIDR，提取纯 IP 以便 AdGuard Home 拦截规则识别
	if ip, ipNet, err := net.ParseCIDR(s); err == nil && ipNet != nil {
		ones, bits := ipNet.Mask.Size()
		if ones == bits && ip != nil {
			return ip.String()
		}
		return ipNet.String()
	}
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	s = strings.Trim(s, "[]")
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	return strings.ToLower(strings.TrimSpace(s))
}

func normalizeAdGuardClientIP(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if ip, ipNet, err := net.ParseCIDR(s); err == nil && ipNet != nil {
		ones, bits := ipNet.Mask.Size()
		if ones == bits && ip != nil {
			return ip.String()
		}
		return ipNet.String()
	}
	if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
		s = h
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

// MergeManagedUserRules 在完整保留用户原有自定义规则与订阅白名单的前提下，
// 幂等替换受 singctl 审计模块管理的黑名单规则段。
func MergeManagedUserRules(existing []string, blocks []config.BlockRule) []string {
	var managed []string
	seen := make(map[string]struct{}, len(blocks))
	for _, b := range blocks {
		rule := FormatAdGuardBlockRule(b)
		if rule == "" {
			continue
		}
		if _, ok := seen[rule]; ok {
			continue
		}
		seen[rule] = struct{}{}
		managed = append(managed, rule)
	}

	// 清理旧的受管区块及任何与当前受管规则完全相同的散落条目
	cleaned := make([]string, 0, len(existing)+len(managed)+2)
	inManagedBlock := false
	for _, line := range existing {
		trimmed := strings.TrimSpace(line)
		if trimmed == managedBlockStartMarker {
			inManagedBlock = true
			continue
		}
		if trimmed == managedBlockEndMarker {
			inManagedBlock = false
			continue
		}
		if inManagedBlock {
			continue
		}
		if _, dup := seen[trimmed]; dup {
			continue
		}
		cleaned = append(cleaned, line)
	}

	if len(managed) == 0 {
		return cleaned
	}

	cleaned = append(cleaned, managedBlockStartMarker)
	cleaned = append(cleaned, managed...)
	cleaned = append(cleaned, managedBlockEndMarker)
	return cleaned
}

// SyncUserBlockRulesYAML 直接在磁盘上的 AdGuardHome.yaml 中无损同步 user_rules 黑名单（保留 0600 权限与原有 AST 结构）。
func SyncUserBlockRulesYAML(configPath string, blocks []config.BlockRule) (bool, error) {
	if strings.TrimSpace(configPath) == "" {
		configPath = constant.AdGuardConfigFile
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return false, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return false, fmt.Errorf("parse AdGuardHome.yaml: %w", err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return false, fmt.Errorf("invalid AdGuardHome.yaml root node")
	}
	doc := root.Content[0]

	var existing []string
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "user_rules" && doc.Content[i+1].Kind == yaml.SequenceNode {
			for _, item := range doc.Content[i+1].Content {
				existing = append(existing, item.Value)
			}
			break
		}
	}

	merged := MergeManagedUserRules(existing, blocks)
	if slices.Equal(existing, merged) {
		return false, nil
	}

	setYAMLStringSlice(doc, "user_rules", merged)
	out, err := yaml.Marshal(&root)
	if err != nil {
		return false, fmt.Errorf("marshal AdGuardHome.yaml: %w", err)
	}
	if err := WriteConfigAtomically(configPath, out); err != nil {
		return false, err
	}
	return true, nil
}

// SyncBlockRules 优先通过 AdGuard Home 本地 HTTP API 毫秒级热更新黑名单（零断网、无需重启进程）；
// 若服务未运行或 API 不可达，则自动回退为直接修改 AdGuardHome.yaml 配置文件。
func (m *Manager) SyncBlockRules(ctx context.Context, blocks []config.BlockRule) (applied bool, mode string, err error) {
	if m == nil {
		return false, "skipped", nil
	}
	if _, statErr := os.Stat(m.aghConfigFile); os.IsNotExist(statErr) && !m.isBinaryPresent() {
		return false, "not_installed", nil
	}

	// 1. 尝试通过本地 Web API 零停机热更新
	if ok, apiErr := m.syncBlockRulesViaHTTP(ctx, blocks); ok && apiErr == nil {
		return true, "hot_api", nil
	}

	// 2. 回退为直接更新 AdGuardHome.yaml AST
	if _, statErr := os.Stat(m.aghConfigFile); statErr == nil {
		changed, yamlErr := SyncUserBlockRulesYAML(m.aghConfigFile, blocks)
		if yamlErr != nil {
			return false, "yaml_error", yamlErr
		}
		if changed && isProcessRunning() {
			_ = m.Restart()
		}
		return true, "yaml_file", nil
	}

	return false, "not_configured", nil
}

func (m *Manager) syncBlockRulesViaHTTP(ctx context.Context, blocks []config.BlockRule) (bool, error) {
	webAddr := ReadCurrentHTTPAddress(m.aghConfigFile)
	if webAddr == "" || !ProbeTCPPort(webAddr, 600*time.Millisecond) {
		return false, fmt.Errorf("adguard web api not reachable")
	}

	user := m.cfg.DNS.GetUsername()
	pass := m.cfg.DNS.GetPassword()
	if pass == "" {
		return false, fmt.Errorf("plaintext password unavailable for basic auth")
	}

	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 3 * time.Second}
	statusURL := fmt.Sprintf("http://%s/control/filtering/status", webAddr)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, statusURL, nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(user, pass)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("status code %d", resp.StatusCode)
	}

	var statusPayload struct {
		UserRules []string `json:"user_rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&statusPayload); err != nil {
		return false, err
	}

	merged := MergeManagedUserRules(statusPayload.UserRules, blocks)
	bodyBytes, err := json.Marshal(map[string]any{
		"rules": merged,
	})
	if err != nil {
		return false, err
	}

	setURL := fmt.Sprintf("http://%s/control/filtering/set_rules", webAddr)
	setReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, setURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return false, err
	}
	setReq.SetBasicAuth(user, pass)
	setReq.Header.Set("Content-Type", "application/json")

	setResp, err := client.Do(setReq)
	if err != nil {
		return false, err
	}
	defer setResp.Body.Close()
	if setResp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("set_rules status %d", setResp.StatusCode)
	}
	return true, nil
}
