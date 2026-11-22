// 文件职责：承载 singgen 订阅源拉取、节点正则过滤/重命名、静默日志脱敏及出站节点去重格式化。
//
// 架构设计原则：
//   - 单一职责原则（SRP）：将上游订阅适配、节点规则过滤与 JSON 格式化从配置主控与规则编译器中剥离，
//     避免订阅拉取逻辑的演进误伤防火墙/DNS 规则或 iOS 适配代码。
package singbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/netx"
	"singctl/internal/config"
	log "singctl/internal/logger"
	"singctl/internal/singbox/sboption"

	"github.com/sixban6/singgen/pkg/model"
	"github.com/sixban6/singgen/pkg/singgen"
)

// GetWebUIAddress 返回当前生成器初始化的 Clash WebUI 监听地址。
func (g *ConfigGenerator) GetWebUIAddress() string {
	return g.webui
}

// generateSingleSubscription 处理单订阅配置生成。
func (g *ConfigGenerator) generateSingleSubscription(ctx context.Context, dnsServer, platform string) (string, error) {
	sub := g.config.Subs[0]
	if !g.silent {
		log.Info("Platform for singgen:%s", platform)
	}
	authKey, lanIpcidr := "", ""
	clientSubnet := ""
	webui := g.webuiForPlatform(platform)
	if platform != PlatformIOS {
		authKey, lanIpcidr = g.getTailScaleParmas()
		clientSubnet = g.getSubnetFromIP(dnsServer)
	}

	handler := newSubLogHandlerWithSilent(g.silent)
	logger := slog.New(handler)

	opts := []singgen.Option{
		singgen.WithTemplate(g.defaultTplVer),
		singgen.WithPlatform(platform),
		singgen.WithOutputFormat("json"),
		singgen.WithDNSServer(dnsServer),
		singgen.WithExternalController(webui),
		singgen.WithClientSubnet(clientSubnet),
		singgen.WithMirrorURL(g.config.GitHub.MirrorURL),
		singgen.WithEmojiRemoval(sub.RemoveEmoji),
		singgen.WithBandwidthParams(g.config.Hy2.Up, g.config.Hy2.Down),
		singgen.WithTSAuthKey(authKey),
		singgen.WithTSLanIPCIDR(lanIpcidr),
		singgen.WithLogger(logger),
	}
	if g.cacheDir != "" {
		opts = append(opts, singgen.WithCacheDir(g.cacheDir))
	}

	var configBytes []byte
	var err error
	if hasSubNodeRules(sub) {
		filterParser, ruleErr := newRuleFilteringParser(sub, logger)
		if ruleErr != nil {
			return "", fmt.Errorf("failed to generate single subscription config (订阅 [%s]): %w", sub.Name, ruleErr)
		}
		pipeline := singgen.NewPipeline(
			singgen.WithPipelineOptions(opts...),
			singgen.WithCustomParser(filterParser),
		)
		configBytes, err = pipeline.ExecuteBytes(ctx, sub.URL)
	} else {
		configBytes, err = singgen.GenerateConfigBytes(ctx, sub.URL, opts...)
	}

	if err != nil {
		return "", fmt.Errorf("failed to generate single subscription config (订阅 [%s]): %w", sub.Name, err)
	}

	return string(configBytes), nil
}

func (g *ConfigGenerator) getTailScaleParmas() (string, string) {
	// 如果不开启内置 tailscale 则返回空，singgen 就不会生成 tailscale 配置
	if !g.config.Tailscale.UseBuild {
		return "", ""
	}

	subnet := ""
	if g.config.Tailscale.AuthKey != "" {
		s := g.config.Tailscale.Subnets
		err := errors.New("")
		if s == "" {
			s, err = netx.GetLANSubnet()
		}
		if err == nil {
			subnet = s
		}
	}
	return g.config.Tailscale.AuthKey, subnet
}

// generateMultiSubscription 处理多订阅聚合生成，汇总失败原因以便排查节点为空的场景。
func (g *ConfigGenerator) generateMultiSubscription(ctx context.Context, dnsServer, platform string) (string, error) {
	authKey, lanIpcidr := "", ""
	clientSubnet := ""
	webui := g.webuiForPlatform(platform)
	if platform != PlatformIOS {
		authKey, lanIpcidr = g.getTailScaleParmas()
		clientSubnet = g.getSubnetFromIP(dnsServer)
	}

	multiConfig := &singgen.MultiConfig{
		Global: singgen.GlobalConfig{
			Template:       g.defaultTplVer,
			Platform:       platform,
			MirrorURL:      g.config.GitHub.MirrorURL,
			DNSLocalServer: dnsServer,
			WebUIAddress:   webui,
			ClientSubnet:   clientSubnet,
			RemoveEmoji:    false, // 全局默认不移除，由各订阅控制
			SkipTLSVerify:  false,
			HTTPTimeout:    30 * time.Second,
			Format:         "json",
			UpMbps:         g.config.Hy2.Up,
			DownMbps:       g.config.Hy2.Down,
			TSAuthKey:      authKey,
			TSLanIPCIDR:    lanIpcidr,
		},
		Subscriptions: make([]singgen.SubscriptionConfig, 0, len(g.config.Subs)),
	}

	if !g.silent {
		log.Info("Platform for singgen:%s", platform)
	}

	for _, sub := range g.config.Subs {
		removeEmoji := sub.RemoveEmoji
		skipTLS := sub.SkipTlsVerify
		subConfig := singgen.SubscriptionConfig{
			Name:          sub.Name,
			URL:           sub.URL,
			RemoveEmoji:   &removeEmoji, // 每个订阅独立控制 emoji
			SkipTLSVerify: &skipTLS,     // 使用订阅的 skip_tls_verify 设置
		}
		if sub.Include != "" {
			inc := sub.Include
			subConfig.Include = &inc
		}
		if sub.Exclude != "" {
			exc := sub.Exclude
			subConfig.Exclude = &exc
		}
		if len(sub.Rename) > 0 {
			renames := make([]singgen.RenameRule, len(sub.Rename))
			for i, rr := range sub.Rename {
				renames[i] = singgen.RenameRule{Match: rr.Match, Replace: rr.Replace}
			}
			subConfig.Rename = renames
		}
		multiConfig.Subscriptions = append(multiConfig.Subscriptions, subConfig)
	}

	handler := newSubLogHandlerWithSilent(g.silent)
	logger := slog.New(handler)

	multiOpts := []singgen.Option{singgen.WithLogger(logger)}
	if g.cacheDir != "" {
		multiOpts = append(multiOpts, singgen.WithCacheDir(g.cacheDir))
	}

	configData, err := singgen.GenerateConfigBytesFromMulti(ctx, multiConfig, multiOpts...)
	if err != nil {
		handler.mu.Lock()
		defer handler.mu.Unlock()
		if len(handler.failedSubs) > 0 {
			var details []string
			for _, sub := range g.config.Subs {
				if reason, ok := handler.failedSubs[sub.Name]; ok {
					details = append(details, fmt.Sprintf("- 订阅 [%s]: %s", sub.Name, reason))
				}
			}
			return "", fmt.Errorf("所有订阅均未获取到有效节点，配置生成终止。失败详情:\n%s", strings.Join(details, "\n"))
		}
		return "", fmt.Errorf("failed to generate multi-subscription config: %w", err)
	}

	return string(configData), nil
}

type subLogHandler struct {
	mu          sync.Mutex
	silent      bool
	failedSubs  map[string]string // 订阅名 -> 失败原因
	successSubs map[string]int    // 订阅名 -> 解析节点数量
}

func newSubLogHandlerWithSilent(silent bool) *subLogHandler {
	return &subLogHandler{
		silent:      silent,
		failedSubs:  make(map[string]string),
		successSubs: make(map[string]int),
	}
}

func (h *subLogHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *subLogHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := make(map[string]any)
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})

	name, _ := attrs["name"].(string)

	h.mu.Lock()
	defer h.mu.Unlock()

	switch r.Message {
	case "Processing subscription":
		if !h.silent {
			url, _ := attrs["url"].(string)
			log.Info("正在解析订阅 [%s] (%s)...", name, MaskSensitiveText(url))
		}
	case "Failed to parse subscription":
		errVal := attrs["error"]
		errStr := MaskSensitiveText(fmt.Sprintf("%v", errVal))
		h.failedSubs[name] = errStr
		if !h.silent {
			log.Warn("订阅 [%s] 获取或解析失败 (原因: %s)，已跳过该订阅", name, errStr)
		}
	case "No nodes found in subscription":
		h.failedSubs[name] = "未获取到有效节点"
		if !h.silent {
			log.Warn("订阅 [%s] 未获取到有效节点，已跳过该订阅", name)
		}
	case "Node rules applied":
		if !h.silent {
			dropped := attrInt(attrs, "dropped")
			kept := attrInt(attrs, "kept")
			log.Info("订阅 [%s] 节点过滤规则已生效: 保留 %d 个，剔除 %d 个", name, kept, dropped)
		}
	case "All nodes were filtered out by node rules":
		h.failedSubs[name] = "所有节点均被过滤规则剔除"
		if !h.silent {
			log.Warn("订阅 [%s] 所有节点均被过滤规则剔除，已跳过该订阅", name)
		}
	case "Failed to transform nodes":
		errVal := attrs["error"]
		errStr := fmt.Sprintf("节点转换失败: %v", errVal)
		h.failedSubs[name] = errStr
		if !h.silent {
			log.Warn("订阅 [%s] 节点转换失败 (原因: %v)，已跳过该订阅", name, errVal)
		}
	case "Successfully processed subscription":
		nodeCount := attrInt(attrs, "node_count")
		outboundCount := attrInt(attrs, "outbound_count")
		h.successSubs[name] = nodeCount
		if !h.silent {
			log.Success("订阅 [%s] 成功解析 %d 个有效节点 (生成 %d 个出站)", name, nodeCount, outboundCount)
		}
	case "Removed duplicate nodes across subscriptions":
		if !h.silent {
			removed := attrInt(attrs, "removed")
			log.Info("跨订阅节点去重: 已移除 %d 个重复节点", removed)
		}
	case "Merged all subscriptions":
		if !h.silent {
			total := attrInt(attrs, "total_outbounds")
			log.Info("所有可用订阅合并完成，有效出站节点总计: %d 个", total)
		}
	case "Subscription usage":
		if !h.silent {
			u, _ := attrs["url"].(string)
			used, _ := attrs["used"].(string)
			total, _ := attrs["total"].(string)
			remaining, _ := attrs["remaining"].(string)
			expire, _ := attrs["expire"].(string)
			summary := fmt.Sprintf("已用 %s", used)
			if total != "" {
				summary += fmt.Sprintf(" / 总计 %s (剩余 %s)", total, remaining)
			}
			if expire != "" {
				summary += fmt.Sprintf(", 到期 %s", expire)
			}
			log.Info("订阅用量 (%s): %s", MaskSensitiveText(u), summary)
		}
	case "Subscription traffic is running low":
		if !h.silent {
			u, _ := attrs["url"].(string)
			remaining, _ := attrs["remaining"].(string)
			total, _ := attrs["total"].(string)
			log.Warn("⚠️ 订阅流量即将耗尽 (%s): 剩余 %s / 总计 %s", MaskSensitiveText(u), remaining, total)
		}
	case "Subscription has expired":
		if !h.silent {
			u, _ := attrs["url"].(string)
			expire, _ := attrs["expire"].(string)
			log.Warn("⚠️ 订阅已过期 (%s): 到期日 %s", MaskSensitiveText(u), expire)
		}
	case "Subscription expires soon":
		if !h.silent {
			u, _ := attrs["url"].(string)
			expire, _ := attrs["expire"].(string)
			log.Warn("⚠️ 订阅即将到期 (%s): 到期日 %s", MaskSensitiveText(u), expire)
		}
	case "Subscription fetch failed, using cached copy":
		if !h.silent {
			u, _ := attrs["url"].(string)
			age, _ := attrs["age"].(string)
			errVal := attrs["error"]
			log.Warn("⚠️ 订阅拉取失败 (%s)，已回退使用本地缓存副本 (缓存距今 %s, 原因: %s)", MaskSensitiveText(u), age, MaskSensitiveText(fmt.Sprintf("%v", errVal)))
		}
	}

	return nil
}

func (h *subLogHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

func (h *subLogHandler) WithGroup(_ string) slog.Handler {
	return h
}

func attrInt(attrs map[string]any, key string) int {
	switch v := attrs[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	default:
		return 0
	}
}

func hasSubNodeRules(sub config.Subscription) bool {
	return sub.Include != "" || sub.Exclude != "" || len(sub.Rename) > 0
}

type compiledRenameRule struct {
	re      *regexp.Regexp
	replace string
}

type ruleFilteringParser struct {
	base    singgen.ContextParser
	subName string
	include *regexp.Regexp
	exclude *regexp.Regexp
	rename  []compiledRenameRule
	logger  *slog.Logger
}

func newRuleFilteringParser(sub config.Subscription, logger *slog.Logger) (*ruleFilteringParser, error) {
	p := &ruleFilteringParser{
		base:    singgen.NewContextParser(singgen.GenerateOptions{Logger: logger}),
		subName: sub.Name,
		logger:  logger,
	}
	var err error
	if sub.Include != "" {
		p.include, err = regexp.Compile(sub.Include)
		if err != nil {
			return nil, fmt.Errorf("%w: subscription %q include %q: %v", singgen.ErrInvalidNodeRule, sub.Name, sub.Include, err)
		}
	}
	if sub.Exclude != "" {
		p.exclude, err = regexp.Compile(sub.Exclude)
		if err != nil {
			return nil, fmt.Errorf("%w: subscription %q exclude %q: %v", singgen.ErrInvalidNodeRule, sub.Name, sub.Exclude, err)
		}
	}
	for i, rr := range sub.Rename {
		if rr.Match == "" {
			continue
		}
		re, err := regexp.Compile(rr.Match)
		if err != nil {
			return nil, fmt.Errorf("%w: subscription %q rename[%d] %q: %v", singgen.ErrInvalidNodeRule, sub.Name, i, rr.Match, err)
		}
		p.rename = append(p.rename, compiledRenameRule{re: re, replace: rr.Replace})
	}
	return p, nil
}

func (p *ruleFilteringParser) DetectFormat(ctx context.Context, data []byte) string {
	return p.base.DetectFormat(ctx, data)
}

func (p *ruleFilteringParser) Parse(ctx context.Context, data []byte) ([]model.Node, error) {
	return p.ParseWithHint(ctx, data, "")
}

func (p *ruleFilteringParser) ParseWithHint(ctx context.Context, data []byte, formatHint string) ([]model.Node, error) {
	nodes, err := p.base.ParseWithHint(ctx, data, formatHint)
	if err != nil || len(nodes) == 0 {
		return nodes, err
	}

	kept := make([]model.Node, 0, len(nodes))
	for _, node := range nodes {
		name := node.Tag
		if name == "" {
			name = node.Addr
		}
		if p.exclude != nil && p.exclude.MatchString(name) {
			continue
		}
		if p.include != nil && !p.include.MatchString(name) {
			continue
		}
		for _, rr := range p.rename {
			name = rr.re.ReplaceAllString(name, rr.replace)
		}
		node.Tag = name
		kept = append(kept, node)
	}

	dropped := len(nodes) - len(kept)
	if dropped > 0 && p.logger != nil {
		p.logger.Info("Node rules applied", "name", p.subName, "dropped", dropped, "kept", len(kept))
	}
	if len(kept) == 0 && p.logger != nil {
		p.logger.Warn("All nodes were filtered out by node rules", "name", p.subName)
	}
	return kept, nil
}

// deduplicateOutboundsInDoc 直接在 *sboption.Document 上原地执行出站节点去重（供单树编译流水线复用）。
func deduplicateOutboundsInDoc(doc *sboption.Document) (bool, error) {
	if doc == nil || doc.Outbounds == nil {
		return false, nil
	}

	// fingerprints: tag → canonical JSON bytes，用于识别实质内容是否完全一致
	fingerprints := make(map[string]string, len(doc.Outbounds))
	// counter: originalTag → 冲突后缀计数器，用于生成 tag_1, tag_2...
	counter := make(map[string]int)

	clean := make([]sboption.Outbound, 0, len(doc.Outbounds))
	for _, node := range doc.Outbounds {
		// 无 tag 节点直接保留（direct/block/dns 等基础固定出站）
		if node.Tag == "" {
			clean = append(clean, node)
			continue
		}

		fpStr, err := sboption.CanonicalJSON(node)
		if err != nil {
			return false, fmt.Errorf("dedup: marshal node failed: %w", err)
		}

		existingFP, seen := fingerprints[node.Tag]
		switch {
		case !seen:
			fingerprints[node.Tag] = fpStr
			clean = append(clean, node)
		case existingFP == fpStr:
			log.Info("dedup: dropping exact duplicate outbound tag=%q", node.Tag)
		default:
			counter[node.Tag]++
			newTag := fmt.Sprintf("%s_%d", node.Tag, counter[node.Tag])
			newNode := node.Clone()
			newNode.Tag = newTag
			newFP, _ := sboption.CanonicalJSON(newNode)
			fingerprints[newTag] = newFP
			log.Info("dedup: renamed conflicting outbound %q → %q", node.Tag, newTag)
			clean = append(clean, newNode)
		}
	}

	doc.Outbounds = clean
	return true, nil
}

// DeduplicateOutbounds 对 sing-box JSON 配置中的 outbounds 进行去重。
//   - Tag 相同且内容完全相同 → 丢弃（完全重复）
//   - Tag 相同但内容不同     → 重命名为 tag_1, tag_2...（冲突保留）
//   - 无 tag 字段的节点      → 直接保留（不参与去重）
func DeduplicateOutbounds(jsonStr string) (string, error) {
	doc, err := sboption.ParseDocument([]byte(jsonStr))
	if err != nil {
		return "", fmt.Errorf("dedup: invalid JSON: %w", err)
	}
	changed, err := deduplicateOutboundsInDoc(doc)
	if err != nil {
		return "", err
	}
	if !changed {
		return jsonStr, nil
	}
	out, err := doc.MarshalCompact()
	if err != nil {
		return "", fmt.Errorf("dedup: re-marshal config failed: %w", err)
	}
	return out, nil
}

// PrettyJSON 将紧凑 JSON 字符串格式化为缩进可读格式。
func PrettyJSON(jsonStr string) (string, error) {
	return sboption.PrettyBytes([]byte(jsonStr))
}
