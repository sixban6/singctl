package subhub

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"singctl/internal/singbox"

	"github.com/sixban6/singgen/pkg/model"
	"github.com/sixban6/singgen/pkg/singgen"
	"gopkg.in/yaml.v3"
)

// TargetFormat identifies the output subscription configuration format.
type TargetFormat string

const (
	TargetBase64    TargetFormat = "base64"
	TargetPlain     TargetFormat = "plain"
	TargetClashMeta TargetFormat = "clashmeta"
	TargetSingBox   TargetFormat = "singbox"
	TargetSurge     TargetFormat = "surge"
	TargetLoon      TargetFormat = "loon"
)

// RenderOptions customizes target rendering.
type RenderOptions struct {
	Target         TargetFormat
	Platform       string // optional sing-box platform ("ios", "darwin", "linux", "windows")
	SingBoxVersion string // optional sing-box template version ("v1.14", "v1.13", "v1.12")
	MirrorURL      string
	RequestURL     string // full URL for Surge #!MANAGED-CONFIG header
	UpMbps         int
	DownMbps       int
}

// RenderResult holds the rendered payload and HTTP response metadata.
type RenderResult struct {
	Body        []byte
	ContentType string
	Filename    string
	Format      TargetFormat
}

type targetRendererFunc func(ctx context.Context, bundle *ResolvedBundle, opts RenderOptions, baseName string) (*RenderResult, error)

var targetRenderers = map[TargetFormat]targetRendererFunc{
	TargetPlain: func(_ context.Context, bundle *ResolvedBundle, _ RenderOptions, baseName string) (*RenderResult, error) {
		lines := bundleURIs(bundle)
		return &RenderResult{
			Body:        []byte(strings.Join(lines, "\n") + "\n"),
			ContentType: "text/plain; charset=utf-8",
			Filename:    baseName + ".txt",
			Format:      TargetPlain,
		}, nil
	},
	TargetBase64: func(_ context.Context, bundle *ResolvedBundle, _ RenderOptions, baseName string) (*RenderResult, error) {
		lines := bundleURIs(bundle)
		encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
		return &RenderResult{
			Body:        []byte(encoded),
			ContentType: "text/plain; charset=utf-8",
			Filename:    baseName + ".txt",
			Format:      TargetBase64,
		}, nil
	},
	TargetClashMeta: func(_ context.Context, bundle *ResolvedBundle, opts RenderOptions, baseName string) (*RenderResult, error) {
		data, err := renderClashMeta(bundle, opts)
		if err != nil {
			return nil, err
		}
		return &RenderResult{
			Body:        data,
			ContentType: "text/yaml; charset=utf-8",
			Filename:    baseName + "-clash.yaml",
			Format:      TargetClashMeta,
		}, nil
	},
	TargetSingBox: func(ctx context.Context, bundle *ResolvedBundle, opts RenderOptions, baseName string) (*RenderResult, error) {
		data, err := renderSingBox(ctx, bundle, opts)
		if err != nil {
			return nil, err
		}
		return &RenderResult{
			Body:        data,
			ContentType: "application/json; charset=utf-8",
			Filename:    baseName + "-singbox.json",
			Format:      TargetSingBox,
		}, nil
	},
	TargetSurge: func(_ context.Context, bundle *ResolvedBundle, opts RenderOptions, baseName string) (*RenderResult, error) {
		return &RenderResult{
			Body:        renderSurge(bundle, opts),
			ContentType: "text/plain; charset=utf-8",
			Filename:    baseName + "-surge.conf",
			Format:      TargetSurge,
		}, nil
	},
	TargetLoon: func(_ context.Context, bundle *ResolvedBundle, opts RenderOptions, baseName string) (*RenderResult, error) {
		return &RenderResult{
			Body:        renderLoon(bundle, opts),
			ContentType: "text/plain; charset=utf-8",
			Filename:    baseName + "-loon.conf",
			Format:      TargetLoon,
		}, nil
	},
}

// DetectTarget determines the target format from query parameters and User-Agent.
func DetectTarget(queryTarget, rawParam, userAgent string) TargetFormat {
	rawLower := strings.ToLower(strings.TrimSpace(rawParam))
	if rawLower == "1" || rawLower == "true" {
		return TargetPlain
	}

	switch strings.ToLower(strings.TrimSpace(queryTarget)) {
	case "plain", "plaintext", "raw":
		return TargetPlain
	case "uri", "base64", "v2ray", "shadowrocket":
		return TargetBase64
	case "clash", "clashmeta", "clash.meta", "mihomo", "stash":
		return TargetClashMeta
	case "sing-box", "singbox", "sfi", "sfa", "sfm":
		return TargetSingBox
	case "surge", "surge5", "surge4":
		return TargetSurge
	case "loon":
		return TargetLoon
	}

	ua := strings.ToLower(strings.TrimSpace(userAgent))
	// Keep internal SubHub/singgen fetchers on Base64 URI mode
	if strings.Contains(ua, "singctl-subhub") {
		return TargetBase64
	}
	switch {
	case strings.Contains(ua, "sfi/") || strings.Contains(ua, "sfa/") || strings.Contains(ua, "sfm/") || strings.Contains(ua, "sing-box"):
		return TargetSingBox
	case strings.Contains(ua, "clash") || strings.Contains(ua, "mihomo") || strings.Contains(ua, "stash") || strings.Contains(ua, "flclash"):
		return TargetClashMeta
	case strings.Contains(ua, "surge/"):
		return TargetSurge
	case strings.Contains(ua, "loon/"):
		return TargetLoon
	default:
		return TargetBase64
	}
}

// RenderBundle converts a ResolvedBundle into the requested client configuration format.
func RenderBundle(ctx context.Context, bundle *ResolvedBundle, opts RenderOptions) (*RenderResult, error) {
	if bundle == nil || (len(bundle.Nodes) == 0 && len(bundle.URIs) == 0) {
		return nil, errors.New("当前订阅集合暂无可用节点")
	}

	target := cmp.Or(opts.Target, TargetBase64)
	baseName := cmp.Or(strings.TrimSpace(bundle.Name), DefaultCollectionName)

	renderer, ok := targetRenderers[target]
	if !ok {
		renderer = targetRenderers[TargetBase64]
	}
	return renderer(ctx, bundle, opts, baseName)
}

func bundleURIs(bundle *ResolvedBundle) []string {
	if len(bundle.URIs) > 0 {
		return bundle.URIs
	}
	var out []string
	for _, n := range bundle.Nodes {
		if u := NodeToURI(n); u != "" {
			out = append(out, u)
		}
	}
	return out
}

type memoryFetcher struct {
	data []byte
}

func (m memoryFetcher) Fetch(_ context.Context, _ string) ([]byte, error) {
	return m.data, nil
}

func renderSingBox(ctx context.Context, bundle *ResolvedBundle, opts RenderOptions) ([]byte, error) {
	uris := bundleURIs(bundle)
	if len(uris) == 0 {
		return nil, errors.New("no valid proxy URIs available for sing-box generation")
	}

	// Default to "ios" profile conventions (remote rule_set URLs, no local host LAN/Tailscale assumptions)
	// which imports cleanly across iOS SFI, Android SFA, macOS SFM, and desktop GUI clients.
	platform := strings.ToLower(strings.TrimSpace(opts.Platform))
	switch platform {
	case "darwin", "linux", "windows", "ios":
	default:
		platform = "ios"
	}

	tplVer := cmp.Or(strings.TrimSpace(opts.SingBoxVersion), "v1.14")
	pipeOpts := []singgen.Option{
		singgen.WithTemplate(tplVer),
		singgen.WithPlatform(platform),
		singgen.WithOutputFormat("json"),
	}
	if opts.MirrorURL != "" {
		pipeOpts = append(pipeOpts, singgen.WithMirrorURL(opts.MirrorURL))
	}
	if opts.UpMbps > 0 && opts.DownMbps > 0 {
		pipeOpts = append(pipeOpts, singgen.WithBandwidthParams(opts.UpMbps, opts.DownMbps))
	}

	pipeline := singgen.NewPipeline(
		singgen.WithPipelineOptions(pipeOpts...),
		singgen.WithCustomFetcher(memoryFetcher{data: []byte(strings.Join(uris, "\n"))}),
	)
	rawBytes, err := pipeline.ExecuteBytes(ctx, "in-memory-subhub")
	if err != nil {
		return nil, fmt.Errorf("singgen pipeline failed: %w", err)
	}

	if platform == "ios" {
		adapted, adaptErr := singbox.AdaptIOSConfigForVersion(string(rawBytes), opts.MirrorURL, tplVer)
		if adaptErr != nil {
			return nil, fmt.Errorf("ios config adaptation failed: %w", adaptErr)
		}
		rawBytes = []byte(adapted)
	}

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, rawBytes, "", "  "); err == nil {
		pretty.WriteByte('\n')
		return pretty.Bytes(), nil
	}
	return rawBytes, nil
}

func renderClashMeta(bundle *ResolvedBundle, opts RenderOptions) ([]byte, error) {
	proxies := make([]map[string]any, 0, len(bundle.Nodes))
	proxyNames := make([]string, 0, len(bundle.Nodes))

	for _, n := range bundle.Nodes {
		p, ok := nodeToClashProxy(n, opts)
		if !ok {
			continue
		}
		name, _ := p["name"].(string)
		proxies = append(proxies, p)
		proxyNames = append(proxyNames, name)
	}

	if len(proxies) == 0 {
		return nil, errors.New("no Clash.Meta compatible nodes found")
	}

	selectProxies := make([]string, 0, len(proxyNames)+3)
	selectProxies = append(selectProxies, "♻️ 自动选择", "🔯 故障转移", "DIRECT")
	selectProxies = append(selectProxies, proxyNames...)

	type clashConfig struct {
		MixedPort          int              `yaml:"mixed-port"`
		AllowLan           bool             `yaml:"allow-lan"`
		Mode               string           `yaml:"mode"`
		LogLevel           string           `yaml:"log-level"`
		UnifiedDelay       bool             `yaml:"unified-delay"`
		TCPConcurrent      bool             `yaml:"tcp-concurrent"`
		ExternalController string           `yaml:"external-controller"`
		DNS                map[string]any   `yaml:"dns"`
		Proxies            []map[string]any `yaml:"proxies"`
		ProxyGroups        []map[string]any `yaml:"proxy-groups"`
		Rules              []string         `yaml:"rules"`
	}

	cfg := clashConfig{
		MixedPort:          7890,
		AllowLan:           false,
		Mode:               "rule",
		LogLevel:           "info",
		UnifiedDelay:       true,
		TCPConcurrent:      true,
		ExternalController: "127.0.0.1:9090",
		DNS: map[string]any{
			"enable":             true,
			"ipv6":               true,
			"enhanced-mode":      "fake-ip",
			"fake-ip-range":      "198.18.0.1/16",
			"default-nameserver": []string{"223.5.5.5", "119.29.29.29"},
			"nameserver":         []string{"https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"},
			"fallback":           []string{"https://1.1.1.1/dns-query", "https://dns.google/dns-query"},
			"fallback-filter": map[string]any{
				"geoip":      true,
				"geoip-code": "CN",
			},
		},
		Proxies: proxies,
		ProxyGroups: []map[string]any{
			{
				"name":    "🚀 节点选择",
				"type":    "select",
				"proxies": selectProxies,
			},
			{
				"name":      "♻️ 自动选择",
				"type":      "url-test",
				"proxies":   proxyNames,
				"url":       "https://www.gstatic.com/generate_204",
				"interval":  300,
				"tolerance": 50,
			},
			{
				"name":     "🔯 故障转移",
				"type":     "fallback",
				"proxies":  proxyNames,
				"url":      "https://www.gstatic.com/generate_204",
				"interval": 300,
			},
			{
				"name":    "🎯 全球直连",
				"type":    "select",
				"proxies": []string{"DIRECT", "🚀 节点选择"},
			},
		},
		Rules: []string{
			"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
			"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
			"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
			"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
			"IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
			"IP-CIDR6,::1/128,DIRECT,no-resolve",
			"IP-CIDR6,fc00::/7,DIRECT,no-resolve",
			"IP-CIDR6,fe80::/10,DIRECT,no-resolve",
			"DOMAIN-SUFFIX,local,DIRECT",
			"DOMAIN-SUFFIX,cn,🎯 全球直连",
			"DOMAIN-KEYWORD,-cn,🎯 全球直连",
			"GEOIP,CN,🎯 全球直连",
			"MATCH,🚀 节点选择",
		},
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&cfg); err != nil {
		return nil, fmt.Errorf("encode Clash.Meta YAML: %w", err)
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

func nodeToClashProxy(n model.Node, opts RenderOptions) (map[string]any, bool) {
	if n.Addr == "" || n.Port == 0 {
		return nil, false
	}
	base := map[string]any{
		"name":   cmp.Or(n.Tag, fmt.Sprintf("%s-%s", n.Type, n.Addr)),
		"server": n.Addr,
		"port":   int(n.Port),
		"udp":    true,
	}
	return defaultProtocols.encodeClash(n, base, opts)
}

func sanitizeConfTag(tag string) string {
	r := strings.NewReplacer(",", "_", "=", "_", "\r", "", "\n", "")
	return strings.TrimSpace(r.Replace(tag))
}

func renderSurge(bundle *ResolvedBundle, opts RenderOptions) []byte {
	var proxyLines []string
	var proxyNames []string

	for _, n := range bundle.Nodes {
		tag := sanitizeConfTag(cmp.Or(n.Tag, fmt.Sprintf("%s-%s", n.Type, n.Addr)))
		if line, ok := defaultProtocols.encodeSurgeLine(n, tag, opts); ok {
			proxyLines = append(proxyLines, line)
			proxyNames = append(proxyNames, tag)
		}
	}

	var b strings.Builder
	if opts.RequestURL != "" {
		fmt.Fprintf(&b, "#!MANAGED-CONFIG %s interval=43200 strict=false\n\n", opts.RequestURL)
	}
	b.WriteString("[General]\n")
	b.WriteString("loglevel = notify\n")
	b.WriteString("dns-server = 223.5.5.5, 119.29.29.29\n")
	b.WriteString("encrypted-dns-server = https://dns.alidns.com/dns-query\n")
	b.WriteString("skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local\n")
	b.WriteString("ipv6 = true\n\n")

	b.WriteString("[Proxy]\n")
	b.WriteString("DIRECT = direct\n")
	for _, line := range proxyLines {
		b.WriteString(line + "\n")
	}
	b.WriteString("\n[Proxy Group]\n")
	if len(proxyNames) > 0 {
		joined := strings.Join(proxyNames, ", ")
		fmt.Fprintf(&b, "🚀 节点选择 = select, ♻️ 自动选择, %s, DIRECT\n", joined)
		fmt.Fprintf(&b, "♻️ 自动选择 = url-test, %s, url=http://www.gstatic.com/generate_204, interval=300\n", joined)
	} else {
		b.WriteString("🚀 节点选择 = select, DIRECT\n")
	}
	b.WriteString("\n[Rule]\n")
	b.WriteString("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n")
	b.WriteString("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n")
	b.WriteString("IP-CIDR,172.16.0.0/12,DIRECT,no-resolve\n")
	b.WriteString("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve\n")
	b.WriteString("IP-CIDR,100.64.0.0/10,DIRECT,no-resolve\n")
	b.WriteString("DOMAIN-SUFFIX,cn,DIRECT\n")
	b.WriteString("GEOIP,CN,DIRECT\n")
	b.WriteString("FINAL,🚀 节点选择,dns-failed\n")
	return []byte(b.String())
}

func renderLoon(bundle *ResolvedBundle, opts RenderOptions) []byte {
	var proxyLines []string
	var proxyNames []string

	for _, n := range bundle.Nodes {
		tag := sanitizeConfTag(cmp.Or(n.Tag, fmt.Sprintf("%s-%s", n.Type, n.Addr)))
		if line, ok := defaultProtocols.encodeLoonLine(n, tag, opts); ok {
			proxyLines = append(proxyLines, line)
			proxyNames = append(proxyNames, tag)
		}
	}

	var b strings.Builder
	b.WriteString("[General]\n")
	b.WriteString("dns-server = 223.5.5.5, 119.29.29.29\n")
	b.WriteString("doh-server = https://dns.alidns.com/dns-query\n")
	b.WriteString("skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local\n")
	b.WriteString("ipv6 = true\n\n")

	b.WriteString("[Proxy]\n")
	for _, line := range proxyLines {
		b.WriteString(line + "\n")
	}
	b.WriteString("\n[Proxy Group]\n")
	if len(proxyNames) > 0 {
		joined := strings.Join(proxyNames, ", ")
		fmt.Fprintf(&b, "🚀 节点选择 = select, ♻️ 自动选择, %s, DIRECT\n", joined)
		fmt.Fprintf(&b, "♻️ 自动选择 = url-test, %s, url=http://www.gstatic.com/generate_204, interval=300\n", joined)
	} else {
		b.WriteString("🚀 节点选择 = select, DIRECT\n")
	}
	b.WriteString("\n[Rule]\n")
	b.WriteString("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n")
	b.WriteString("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n")
	b.WriteString("IP-CIDR,172.16.0.0/12,DIRECT,no-resolve\n")
	b.WriteString("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve\n")
	b.WriteString("DOMAIN-SUFFIX,cn,DIRECT\n")
	b.WriteString("GEOIP,CN,DIRECT\n")
	b.WriteString("FINAL,🚀 节点选择\n")
	return []byte(b.String())
}

// NodeToURI synthesizes a canonical share link URI from a parsed model.Node.
func NodeToURI(n model.Node) string {
	hostPort := net.JoinHostPort(n.Addr, strconv.Itoa(int(n.Port)))
	frag := url.PathEscape(n.Tag)
	return defaultProtocols.encodeURI(n, hostPort, frag)
}
