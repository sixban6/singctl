package config

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"singctl/internal/common/fsx"

	"gopkg.in/yaml.v3"
)

const (
	GroupsModeMerge   = "merge"
	GroupsModeReplace = "replace"

	GroupTypeSelector = "selector"
	GroupTypeURLTest  = "urltest"

	DefaultGroupsFileName = "groups.yaml"
)

// GroupMacroInfo 描述一条内置语义筛选宏，供编译器展开与 WebUI 提示气泡展示。
type GroupMacroInfo struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
}

var builtinGroupMacros = []GroupMacroInfo{
	{
		ID:          "@hk",
		Label:       "香港",
		Description: "匹配香港地区节点 (香港 / HK / HK01 / Hong Kong / 🇭🇰)",
		Pattern:     `(香港|🇭🇰|(?:^|[^a-zA-Z])(?:HK|HKG|HKSAR)(?:[^a-zA-Z]|$)|Hong\s*Kong)`,
	},
	{
		ID:          "@tw",
		Label:       "台湾",
		Description: "匹配台湾地区节点 (台湾 / 台灣 / TW / TW01 / Taiwan / 🇹🇼)",
		Pattern:     `(台湾|台灣|台北|臺北|🇹🇼|(?:^|[^a-zA-Z])(?:TW|TPE)(?:[^a-zA-Z]|$)|Taiwan|Taipei)`,
	},
	{
		ID:          "@jp",
		Label:       "日本",
		Description: "匹配日本地区节点 (日本 / JP / JP1 / Tokyo / Osaka / 🇯🇵)",
		Pattern:     `(日本|東京|东京|大阪|🇯🇵|(?:^|[^a-zA-Z])(?:JP|JPN|NRT|KIX|TYO)(?:[^a-zA-Z]|$)|Japan|Tokyo|Osaka)`,
	},
	{
		ID:          "@sg",
		Label:       "新加坡",
		Description: "匹配新加坡地区节点 (新加坡 / 狮城 / SG / SG1 / Singapore / 🇸🇬)",
		Pattern:     `(新加坡|狮城|獅城|🇸🇬|(?:^|[^a-zA-Z])(?:SG|SGP|SIN)(?:[^a-zA-Z]|$)|Singapore)`,
	},
	{
		ID:          "@kr",
		Label:       "韩国",
		Description: "匹配韩国地区节点 (韩国 / 韓國 / KR / KR01 / Seoul / 🇰🇷)",
		Pattern:     `(韩国|韓國|首尔|首爾|🇰🇷|(?:^|[^a-zA-Z])(?:KR|KOR|ICN|SEL)(?:[^a-zA-Z]|$)|Korea|Seoul)`,
	},
	{
		ID:          "@us",
		Label:       "美国",
		Description: "匹配美国地区节点 (美国 / 美西 / US / LAX / SJC / LOS / SAN / 🇺🇸)",
		Pattern:     `(美国|美國|美西|美东|美東|圣何塞|聖荷西|洛杉矶|洛杉磯|西雅图|🇺🇸|(?:^|[^a-zA-Z])(?:US|USA|LAX|SJC|LOS|SAN|SEA|ORD|JFK)(?:[^a-zA-Z]|$)|United\s*States|America|Los\s*Angeles|San\s*Jose|Seattle)`,
	},
	{
		ID:          "@eu",
		Label:       "欧洲",
		Description: "匹配欧洲主流地区节点 (欧洲 / 英 / 德 / 法 / 荷 / FR1 / DE1 / UK / 🇬🇧🇩🇪🇫🇷🇳🇱)",
		Pattern:     `(欧洲|歐洲|英国|英國|德国|德國|法国|法國|荷兰|荷蘭|法兰克福|伦敦|巴黎|阿姆斯特丹|🇬🇧|🇩🇪|🇫🇷|🇳🇱|(?:^|[^a-zA-Z])(?:EU|UK|GBR|DE|DEU|FR|FRA|NL|NLD|LON|AMS)(?:[^a-zA-Z]|$)|Europe|London|Frankfurt|Paris|Amsterdam|Germany|France|Netherlands)`,
	},
	{
		ID:          "@self",
		Label:       "自建节点",
		Description: "匹配 SingCtl 自建与专属节点 (sec_ 前缀 / 自建)",
		Pattern:     `(^sec_|自建|Self[-_\s]*Hosted)`,
	},
	{
		ID:          "@home",
		Label:       "家宽住宅",
		Description: "匹配原生/家宽/ISP 住宅 IP 节点",
		Pattern:     `(家宽|家寬|住宅|原生|\bISP\b|Residential|Native)`,
	},
	{
		ID:          "@iplc",
		Label:       "专线节点",
		Description: "匹配 IPLC / IEPL / 专线低延迟节点",
		Pattern:     `(\bIPLC\b|\bIEPL\b|专线|專線|内网|內網|深港|沪日|广港)`,
	},
	{
		ID:          "@high_rate",
		Label:       "高倍率/提示",
		Description: "剔除 >=2x 高倍率节点及剩余流量/到期官网提示项",
		Pattern:     `(网站|地址|剩余|过期|时间|有效|官网|流量|到期|套餐|重置|[2-9](\.[0-9]+)?\s*[倍xX]|[0-9]{2,}\s*[倍xX]|倍率|[xX][2-9])`,
	},
}

// BuiltinGroupMacros 返回全部内置分组语义宏的拷贝。
func BuiltinGroupMacros() []GroupMacroInfo {
	return slices.Clone(builtinGroupMacros)
}

func lookupGroupMacroPattern(token string) (string, bool) {
	clean := strings.ToLower(strings.TrimSpace(token))
	for _, m := range builtinGroupMacros {
		if m.ID == clean {
			return m.Pattern, true
		}
	}
	return "", false
}

// StringList 兼容 YAML 中写单个字符串 (`match: "@hk"`) 或字符串数组 (`match: ["@hk", "@sg"]`)。
type StringList []string

func (s *StringList) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
		*s = nil
		return nil
	}
	switch value.Kind {
	case yaml.ScalarNode:
		var single string
		if err := value.Decode(&single); err != nil {
			return err
		}
		trimmed := strings.TrimSpace(single)
		if trimmed == "" {
			*s = nil
		} else {
			*s = []string{trimmed}
		}
		return nil
	case yaml.SequenceNode:
		var list []string
		if err := value.Decode(&list); err != nil {
			return err
		}
		cleaned := make([]string, 0, len(list))
		for _, item := range list {
			if t := strings.TrimSpace(item); t != "" {
				cleaned = append(cleaned, t)
			}
		}
		*s = cleaned
		return nil
	default:
		return fmt.Errorf("expected string or list of strings")
	}
}

// OptionalStringList 区分「YAML 未显式设置 (Set=false)」与「显式设为空数组 attach_to: [] (Set=true, Items=[])」。
type OptionalStringList struct {
	Set   bool     `json:"set"`
	Items []string `json:"items,omitempty"`
}

func (o *OptionalStringList) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || (value.Kind == yaml.ScalarNode && value.Tag == "!!null") {
		o.Set = false
		o.Items = nil
		return nil
	}
	o.Set = true
	var sl StringList
	if err := sl.UnmarshalYAML(value); err != nil {
		return err
	}
	o.Items = []string(sl)
	return nil
}

func (o OptionalStringList) MarshalYAML() (any, error) {
	if !o.Set {
		return nil, nil
	}
	if len(o.Items) == 0 {
		return []string{}, nil
	}
	return o.Items, nil
}

// GroupSpec 描述单个声明式代理策略组。
type GroupSpec struct {
	Name                      string             `yaml:"name" json:"name"`
	TagAlias                  string             `yaml:"tag,omitempty" json:"-"`
	Type                      string             `yaml:"type,omitempty" json:"type,omitempty"`
	Match                     StringList         `yaml:"match,omitempty" json:"match,omitempty"`
	IncludeAlias              StringList         `yaml:"include,omitempty" json:"-"`
	Exclude                   StringList         `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	FromSub                   StringList         `yaml:"from_sub,omitempty" json:"from_sub,omitempty"`
	Protocol                  StringList         `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	Use                       StringList         `yaml:"use,omitempty" json:"use,omitempty"`
	Default                   string             `yaml:"default,omitempty" json:"default,omitempty"`
	Fallback                  string             `yaml:"fallback,omitempty" json:"fallback,omitempty"`
	AttachTo                  OptionalStringList `yaml:"attach_to,omitempty" json:"attach_to,omitempty"`
	Failover                  bool               `yaml:"failover,omitempty" json:"failover,omitempty"`
	URL                       string             `yaml:"url,omitempty" json:"url,omitempty"`
	Interval                  string             `yaml:"interval,omitempty" json:"interval,omitempty"`
	Tolerance                 int                `yaml:"tolerance,omitempty" json:"tolerance,omitempty"`
	InterruptExistConnections *bool              `yaml:"interrupt_exist_connections,omitempty" json:"interrupt_exist_connections,omitempty"`
}

// EffectiveName 返回归一化后的策略组名称（兼容 name 与 tag 别名）。
func (g GroupSpec) EffectiveName() string {
	return cmp.Or(strings.TrimSpace(g.Name), strings.TrimSpace(g.TagAlias))
}

// EffectiveType 返回策略组类型（默认 selector）。
func (g GroupSpec) EffectiveType() string {
	switch strings.ToLower(strings.TrimSpace(g.Type)) {
	case "", GroupTypeSelector:
		return GroupTypeSelector
	case GroupTypeURLTest, "url-test", "auto":
		return GroupTypeURLTest
	default:
		return strings.ToLower(strings.TrimSpace(g.Type))
	}
}

// EffectiveMatch 合并 match 与兼容别名 include。
func (g GroupSpec) EffectiveMatch() []string {
	out := make([]string, 0, len(g.Match)+len(g.IncludeAlias))
	for _, m := range g.Match {
		if t := strings.TrimSpace(m); t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	for _, m := range g.IncludeAlias {
		if t := strings.TrimSpace(m); t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// GroupsConfig 对应 /etc/singctl/groups.yaml 顶层结构。
type GroupsConfig struct {
	Version int         `yaml:"version,omitempty" json:"version,omitempty"`
	Mode    string      `yaml:"mode,omitempty" json:"mode,omitempty"`
	Groups  []GroupSpec `yaml:"groups,omitempty" json:"groups,omitempty"`
}

// EffectiveMode 返回生效编排模式（默认 merge）。
func (gc *GroupsConfig) EffectiveMode() string {
	if gc == nil {
		return GroupsModeMerge
	}
	if strings.EqualFold(strings.TrimSpace(gc.Mode), GroupsModeReplace) {
		return GroupsModeReplace
	}
	return GroupsModeMerge
}

// IsEmpty 判断是否未配置任何自定义分组且未开启 replace 模式。
func (gc *GroupsConfig) IsEmpty() bool {
	if gc == nil {
		return true
	}
	return len(gc.Groups) == 0 && gc.EffectiveMode() == GroupsModeMerge
}

var groupsKnownYAMLKeys = []string{
	"version", "mode", "groups", "name", "tag", "type",
	"match", "include", "exclude", "from_sub", "protocol", "use",
	"default", "fallback", "attach_to", "failover",
	"url", "interval", "tolerance", "interrupt_exist_connections",
}

var groupsColonSpaceFixRegex = regexp.MustCompile(
	fmt.Sprintf("(?m)^([ \\t-]*(?:%s)):([^\\s].*)", strings.Join(groupsKnownYAMLKeys, "|")),
)

// NormalizeOutboundProtocol 将用户简写协议名归一化为 sing-box 标准 outbound.type。
func NormalizeOutboundProtocol(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "hy2", "hysteria2":
		return "hysteria2", nil
	case "hysteria":
		return "hysteria", nil
	case "vless":
		return "vless", nil
	case "vmess":
		return "vmess", nil
	case "ss", "shadowsocks":
		return "shadowsocks", nil
	case "trojan":
		return "trojan", nil
	case "tuic":
		return "tuic", nil
	case "anytls":
		return "anytls", nil
	case "wg", "wireguard":
		return "wireguard", nil
	case "http", "socks":
		return strings.ToLower(strings.TrimSpace(raw)), nil
	default:
		return "", fmt.Errorf("不支持的协议类型 %q (可选: hysteria2/hy2, vless, shadowsocks/ss, trojan, vmess, tuic, anytls, wireguard)", raw)
	}
}

// CompileGroupMatcher 将 match / exclude 规则列表编译为单个大小写不敏感正则（各条目之间为 OR 关系）。
// 支持 3 种写法：
//  1. 内置语义宏：`@hk`、`@jp`、`@high_rate` 等
//  2. 显式正则字面量：`/^VIP-.*$/`
//  3. 含 `|` 等正则元字符的表达式或普通纯文本子串（普通词自动安全转义匹配）
func CompileGroupMatcher(patterns []string) (*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	branches := make([]string, 0, len(patterns))
	for _, raw := range patterns {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		if strings.HasPrefix(token, "@") {
			macroPat, ok := lookupGroupMacroPattern(token)
			if !ok {
				validIDs := make([]string, 0, len(builtinGroupMacros))
				for _, m := range builtinGroupMacros {
					validIDs = append(validIDs, m.ID)
				}
				return nil, fmt.Errorf("未知的语义宏 %q（支持的内置宏: %s）", token, strings.Join(validIDs, ", "))
			}
			branches = append(branches, macroPat)
			continue
		}
		if len(token) >= 2 && strings.HasPrefix(token, "/") && strings.HasSuffix(token, "/") {
			inner := token[1 : len(token)-1]
			if strings.TrimSpace(inner) == "" {
				continue
			}
			if _, err := regexp.Compile(inner); err != nil {
				return nil, fmt.Errorf("无效的正则表达式 %q: %w", token, err)
			}
			branches = append(branches, "(?:"+inner+")")
			continue
		}
		if strings.ContainsAny(token, "|()[]^$+*?\\") {
			if _, err := regexp.Compile(token); err != nil {
				return nil, fmt.Errorf("无效的匹配表达式 %q: %w", token, err)
			}
			branches = append(branches, "(?:"+token+")")
			continue
		}
		branches = append(branches, regexp.QuoteMeta(token))
	}
	if len(branches) == 0 {
		return nil, nil
	}
	combined := "(?i)(?:" + strings.Join(branches, "|") + ")"
	re, err := regexp.Compile(combined)
	if err != nil {
		return nil, fmt.Errorf("编译匹配规则失败: %w", err)
	}
	return re, nil
}

// ParseGroupsYAML 解析并严格校验 groups.yaml 内容。
func ParseGroupsYAML(raw []byte) (*GroupsConfig, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return &GroupsConfig{Version: 1, Mode: GroupsModeMerge}, nil
	}
	fixed := groupsColonSpaceFixRegex.ReplaceAll(raw, []byte("$1: $2"))
	var gc GroupsConfig
	dec := yaml.NewDecoder(strings.NewReader(string(fixed)))
	dec.KnownFields(true)
	if err := dec.Decode(&gc); err != nil {
		return nil, fmt.Errorf("解析 groups.yaml 失败: %w", err)
	}
	if gc.Version == 0 {
		gc.Version = 1
	}
	mode := strings.ToLower(strings.TrimSpace(gc.Mode))
	switch mode {
	case "", GroupsModeMerge:
		gc.Mode = GroupsModeMerge
	case GroupsModeReplace:
		gc.Mode = GroupsModeReplace
	default:
		return nil, fmt.Errorf("不支持的 mode %q（仅支持 merge 或 replace）", gc.Mode)
	}
	if gc.Mode == GroupsModeReplace && len(gc.Groups) == 0 {
		return nil, fmt.Errorf("replace 模式下 groups 列表不能为空（至少需要定义一个代理策略组）")
	}

	seenNames := make(map[string]int, len(gc.Groups))
	for i := range gc.Groups {
		g := &gc.Groups[i]
		name := g.EffectiveName()
		if name == "" {
			return nil, fmt.Errorf("groups[%d]: 分组名称 (name) 不能为空", i)
		}
		if err := ValidateTrafficOutboundChars(name); err != nil {
			return nil, fmt.Errorf("groups[%d] (%s): %w", i, name, err)
		}
		if strings.EqualFold(name, "#DC") || strings.EqualFold(name, "direct") || strings.EqualFold(name, "block") {
			return nil, fmt.Errorf("groups[%d] (%s): 不能覆盖系统保留直连/阻断出站标识", i, name)
		}
		if prevIdx, exists := seenNames[name]; exists {
			return nil, fmt.Errorf("groups[%d]: 分组名称 %q 与 groups[%d] 重复", i, name, prevIdx)
		}
		seenNames[name] = i
		g.Name = name
		g.TagAlias = ""

		typ := g.EffectiveType()
		if typ != GroupTypeSelector && typ != GroupTypeURLTest {
			return nil, fmt.Errorf("groups[%d] (%s): 不支持的分组类型 %q（仅支持 selector 或 urltest）", i, name, g.Type)
		}
		g.Type = typ

		matchList := g.EffectiveMatch()
		g.Match = StringList(matchList)
		g.IncludeAlias = nil
		if _, err := CompileGroupMatcher(matchList); err != nil {
			return nil, fmt.Errorf("groups[%d] (%s) match: %w", i, name, err)
		}
		if _, err := CompileGroupMatcher(g.Exclude); err != nil {
			return nil, fmt.Errorf("groups[%d] (%s) exclude: %w", i, name, err)
		}

		normProtos := make([]string, 0, len(g.Protocol))
		for _, p := range g.Protocol {
			np, err := NormalizeOutboundProtocol(p)
			if err != nil {
				return nil, fmt.Errorf("groups[%d] (%s) protocol: %w", i, name, err)
			}
			if !slices.Contains(normProtos, np) {
				normProtos = append(normProtos, np)
			}
		}
		g.Protocol = StringList(normProtos)

		if iv := strings.TrimSpace(g.Interval); iv != "" {
			if _, err := time.ParseDuration(iv); err != nil {
				return nil, fmt.Errorf("groups[%d] (%s): 无效的测速间隔 interval=%q (示例: 3m, 30s): %w", i, name, iv, err)
			}
			g.Interval = iv
		}
		if g.Tolerance < 0 || g.Tolerance > 5000 {
			return nil, fmt.Errorf("groups[%d] (%s): tolerance 必须在 0~5000 毫秒之间", i, name)
		}
		if slices.Contains(g.Use, name) {
			return nil, fmt.Errorf("groups[%d] (%s): use 不能引用自身", i, name)
		}
	}

	return &gc, nil
}

// ValidateTrafficOutboundChars 校验分组/出站名称安全性（禁止控制字符、引号与空白换行注入）。
func ValidateTrafficOutboundChars(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("名称不能为空")
	}
	if len(trimmed) > 64 {
		return fmt.Errorf("名称长度不能超过 64 字符")
	}
	if strings.ContainsAny(trimmed, "\r\n\t\"'\\`") {
		return fmt.Errorf("名称包含非法字符")
	}
	return nil
}

// GroupsPathForConfig 根据主配置文件 singctl.yaml 路径推导同目录下的 groups.yaml 路径。
func GroupsPathForConfig(cfgPath string) string {
	clean := strings.TrimSpace(cfgPath)
	if clean == "" {
		return filepath.Join("/etc/singctl", DefaultGroupsFileName)
	}
	return filepath.Join(filepath.Dir(clean), DefaultGroupsFileName)
}

// SourcePath 返回加载当前 Config 时的主配置文件路径（内存构造未落盘时为空字符串）。
func (c *Config) SourcePath() string {
	if c == nil {
		return ""
	}
	return c.sourcePath
}

// SetSourcePath 显式绑定主配置文件路径（供测试或新建配置对象定位同目录的 groups.yaml）。
func (c *Config) SetSourcePath(path string) {
	if c == nil {
		return
	}
	c.sourcePath = strings.TrimSpace(path)
}

// GroupsPath 返回当前 Config 关联的 groups.yaml 路径；若 Config 未绑定磁盘文件则返回空字符串。
func (c *Config) GroupsPath() string {
	if c == nil || strings.TrimSpace(c.sourcePath) == "" {
		return ""
	}
	return GroupsPathForConfig(c.sourcePath)
}

// LoadGroupsFile 读取并解析磁盘上的 groups.yaml。
// 若文件不存在，返回默认空 merge 配置与 exists=false（不报错）。
func LoadGroupsFile(path string) (*GroupsConfig, bool, error) {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return &GroupsConfig{Version: 1, Mode: GroupsModeMerge}, false, nil
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return &GroupsConfig{Version: 1, Mode: GroupsModeMerge}, false, nil
		}
		return nil, false, fmt.Errorf("读取 %s 失败: %w", clean, err)
	}
	parsed, err := ParseGroupsYAML(data)
	if err != nil {
		return nil, true, err
	}
	return parsed, true, nil
}

// SaveGroupsFile 先校验 YAML 语法与语义合法性，再以 0600 权限原子落盘。
func SaveGroupsFile(path string, content []byte) (*GroupsConfig, error) {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return nil, fmt.Errorf("groups.yaml 目标路径不能为空")
	}
	parsed, err := ParseGroupsYAML(content)
	if err != nil {
		return nil, err
	}
	// 保持文件末尾换行整洁
	out := content
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(slices.Clone(out), '\n')
	}
	if err := fsx.WriteAtomic0600(clean, out); err != nil {
		return nil, fmt.Errorf("保存 %s 失败: %w", clean, err)
	}
	return parsed, nil
}

// EffectiveFailoverConfig 返回合并了 groups.yaml 中 `failover: true` 分组后的看门狗故障切换配置。
func (c *Config) EffectiveFailoverConfig() WatchdogFailoverConfig {
	if c == nil {
		return WatchdogFailoverConfig{}
	}
	fc := c.Watchdog.Failover
	gPath := c.GroupsPath()
	if gPath == "" {
		return fc
	}
	gc, exists, err := LoadGroupsFile(gPath)
	if err != nil || !exists || gc == nil {
		return fc
	}
	extra := make([]string, 0)
	for _, g := range gc.Groups {
		if g.Failover && g.EffectiveType() == GroupTypeSelector {
			extra = append(extra, g.EffectiveName())
		}
	}
	if len(extra) == 0 {
		return fc
	}
	base := slices.Clone(fc.Groups)
	if len(base) == 0 {
		base = slices.Clone(DefaultWatchdogFailoverGroups)
	}
	for _, name := range extra {
		if !slices.Contains(base, name) {
			base = append(base, name)
		}
	}
	fc.Groups = base
	return fc
}
