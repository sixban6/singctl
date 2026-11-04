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

	switch target {
	case TargetPlain:
		lines := bundleURIs(bundle)
		return &RenderResult{
			Body:        []byte(strings.Join(lines, "\n") + "\n"),
			ContentType: "text/plain; charset=utf-8",
			Filename:    baseName + ".txt",
			Format:      TargetPlain,
		}, nil

	case TargetBase64:
		lines := bundleURIs(bundle)
		encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
		return &RenderResult{
			Body:        []byte(encoded),
			ContentType: "text/plain; charset=utf-8",
			Filename:    baseName + ".txt",
			Format:      TargetBase64,
		}, nil

	case TargetClashMeta:
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

	case TargetSingBox:
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

	case TargetSurge:
		data := renderSurge(bundle, opts)
		return &RenderResult{
			Body:        data,
			ContentType: "text/plain; charset=utf-8",
			Filename:    baseName + "-surge.conf",
			Format:      TargetSurge,
		}, nil

	case TargetLoon:
		data := renderLoon(bundle, opts)
		return &RenderResult{
			Body:        data,
			ContentType: "text/plain; charset=utf-8",
			Filename:    baseName + "-loon.conf",
			Format:      TargetLoon,
		}, nil

	default:
		lines := bundleURIs(bundle)
		encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
		return &RenderResult{
			Body:        []byte(encoded),
			ContentType: "text/plain; charset=utf-8",
			Filename:    baseName + ".txt",
			Format:      TargetBase64,
		}, nil
	}
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
			"enable":            true,
			"ipv6":              true,
			"enhanced-mode":     "fake-ip",
			"fake-ip-range":     "198.18.0.1/16",
			"default-nameserver": []string{"223.5.5.5", "119.29.29.29"},
			"nameserver":        []string{"https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"},
			"fallback":          []string{"https://1.1.1.1/dns-query", "https://dns.google/dns-query"},
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
	p := map[string]any{
		"name":   cmp.Or(n.Tag, fmt.Sprintf("%s-%s", n.Type, n.Addr)),
		"server": n.Addr,
		"port":   int(n.Port),
		"udp":    true,
	}

	applyTransport := func() {
		netType := strings.ToLower(n.Transport.Net)
		if netType != "" && netType != "tcp" {
			p["network"] = netType
			switch netType {
			case "ws":
				wsOpts := map[string]any{}
				if n.Transport.Path != "" {
					wsOpts["path"] = n.Transport.Path
				}
				if n.Transport.Host != "" {
					wsOpts["headers"] = map[string]string{"Host": n.Transport.Host}
				}
				if len(wsOpts) > 0 {
					p["ws-opts"] = wsOpts
				}
			case "grpc":
				if n.Transport.Path != "" {
					p["grpc-opts"] = map[string]any{"grpc-service-name": n.Transport.Path}
				}
			}
		}
	}

	switch n.Type {
	case "vless":
		p["type"] = "vless"
		p["uuid"] = n.UUID
		if flow, ok := n.Extra["flow"].(string); ok && flow != "" {
			p["flow"] = flow
		}
		if n.Security.TLS {
			p["tls"] = true
			p["skip-cert-verify"] = n.Security.SkipVerify
			if n.Security.ServerName != "" {
				p["servername"] = n.Security.ServerName
			}
			if len(n.Security.ALPN) > 0 {
				p["alpn"] = n.Security.ALPN
			}
			fp, _ := n.Extra["fingerprint"].(string)
			p["client-fingerprint"] = cmp.Or(fp, "chrome")
			if sec, _ := n.Extra["security"].(string); sec == "reality" {
				ro := map[string]any{}
				if pk, _ := n.Extra["public_key"].(string); pk != "" {
					ro["public-key"] = pk
				}
				if sid, _ := n.Extra["short_id"].(string); sid != "" {
					ro["short-id"] = sid
				}
				p["reality-opts"] = ro
			}
		}
		applyTransport()
		return p, true

	case "hysteria2":
		p["type"] = "hysteria2"
		p["password"] = n.Password
		p["skip-cert-verify"] = n.Security.SkipVerify
		if n.Security.ServerName != "" {
			p["sni"] = n.Security.ServerName
		}
		if len(n.Security.ALPN) > 0 {
			p["alpn"] = n.Security.ALPN
		}
		if obfsMap, ok := n.Extra["obfs"].(map[string]string); ok && obfsMap["type"] != "" {
			p["obfs"] = obfsMap["type"]
			if obfsMap["password"] != "" {
				p["obfs-password"] = obfsMap["password"]
			}
		}
		if opts.UpMbps > 0 {
			p["up"] = fmt.Sprintf("%d Mbps", opts.UpMbps)
		}
		if opts.DownMbps > 0 {
			p["down"] = fmt.Sprintf("%d Mbps", opts.DownMbps)
		}
		return p, true

	case "trojan":
		p["type"] = "trojan"
		p["password"] = n.Password
		p["skip-cert-verify"] = n.Security.SkipVerify
		if n.Security.ServerName != "" {
			p["sni"] = n.Security.ServerName
		}
		if len(n.Security.ALPN) > 0 {
			p["alpn"] = n.Security.ALPN
		}
		applyTransport()
		return p, true

	case "shadowsocks", "ss":
		p["type"] = "ss"
		cipher, _ := n.Extra["method"].(string)
		p["cipher"] = cmp.Or(cipher, "aes-256-gcm")
		p["password"] = n.Password
		return p, true

	case "vmess":
		p["type"] = "vmess"
		p["uuid"] = n.UUID
		p["alterId"] = 0
		p["cipher"] = "auto"
		if n.Security.TLS {
			p["tls"] = true
			p["skip-cert-verify"] = n.Security.SkipVerify
			if n.Security.ServerName != "" {
				p["servername"] = n.Security.ServerName
			}
		}
		applyTransport()
		return p, true

	case "tuic":
		p["type"] = "tuic"
		p["uuid"] = n.UUID
		p["password"] = n.Password
		p["skip-cert-verify"] = n.Security.SkipVerify
		if n.Security.ServerName != "" {
			p["sni"] = n.Security.ServerName
		}
		if len(n.Security.ALPN) > 0 {
			p["alpn"] = n.Security.ALPN
		} else {
			p["alpn"] = []string{"h3"}
		}
		if cc, _ := n.Extra["congestion_control"].(string); cc != "" {
			p["congestion-controller"] = cc
		}
		return p, true

	case "anytls":
		p["type"] = "anytls"
		p["password"] = n.Password
		p["skip-cert-verify"] = n.Security.SkipVerify
		if n.Security.ServerName != "" {
			p["sni"] = n.Security.ServerName
		}
		if len(n.Security.ALPN) > 0 {
			p["alpn"] = n.Security.ALPN
		}
		p["client-fingerprint"] = "chrome"
		return p, true

	default:
		return nil, false
	}
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
		switch n.Type {
		case "hysteria2":
			parts := []string{
				fmt.Sprintf("%s = hysteria2", tag),
				n.Addr,
				strconv.Itoa(int(n.Port)),
				fmt.Sprintf("password=%s", n.Password),
			}
			if n.Security.ServerName != "" {
				parts = append(parts, fmt.Sprintf("sni=%s", n.Security.ServerName))
			}
			if n.Security.SkipVerify {
				parts = append(parts, "skip-cert-verify=true")
			}
			if opts.DownMbps > 0 {
				parts = append(parts, fmt.Sprintf("download-bandwidth=%d", opts.DownMbps))
			}
			proxyLines = append(proxyLines, strings.Join(parts, ", "))
			proxyNames = append(proxyNames, tag)

		case "trojan":
			parts := []string{
				fmt.Sprintf("%s = trojan", tag),
				n.Addr,
				strconv.Itoa(int(n.Port)),
				fmt.Sprintf("password=%s", n.Password),
			}
			if n.Security.ServerName != "" {
				parts = append(parts, fmt.Sprintf("sni=%s", n.Security.ServerName))
			}
			if n.Security.SkipVerify {
				parts = append(parts, "skip-cert-verify=true")
			}
			proxyLines = append(proxyLines, strings.Join(parts, ", "))
			proxyNames = append(proxyNames, tag)

		case "shadowsocks", "ss":
			method, _ := n.Extra["method"].(string)
			parts := []string{
				fmt.Sprintf("%s = ss", tag),
				n.Addr,
				strconv.Itoa(int(n.Port)),
				fmt.Sprintf("encrypt-method=%s", cmp.Or(method, "aes-256-gcm")),
				fmt.Sprintf("password=%s", n.Password),
				"udp-relay=true",
			}
			proxyLines = append(proxyLines, strings.Join(parts, ", "))
			proxyNames = append(proxyNames, tag)

		case "tuic":
			parts := []string{
				fmt.Sprintf("%s = tuic-v5", tag),
				n.Addr,
				strconv.Itoa(int(n.Port)),
				fmt.Sprintf("uuid=%s", n.UUID),
				fmt.Sprintf("password=%s", n.Password),
			}
			if n.Security.ServerName != "" {
				parts = append(parts, fmt.Sprintf("sni=%s", n.Security.ServerName))
			}
			proxyLines = append(proxyLines, strings.Join(parts, ", "))
			proxyNames = append(proxyNames, tag)

		case "vmess":
			parts := []string{
				fmt.Sprintf("%s = vmess", tag),
				n.Addr,
				strconv.Itoa(int(n.Port)),
				fmt.Sprintf("username=%s", n.UUID),
				"vmess-aead=true",
			}
			if n.Security.TLS {
				parts = append(parts, "tls=true")
				if n.Security.ServerName != "" {
					parts = append(parts, fmt.Sprintf("sni=%s", n.Security.ServerName))
				}
			}
			proxyLines = append(proxyLines, strings.Join(parts, ", "))
			proxyNames = append(proxyNames, tag)

		case "anytls":
			parts := []string{
				fmt.Sprintf("%s = anytls", tag),
				n.Addr,
				strconv.Itoa(int(n.Port)),
				fmt.Sprintf("password=%s", n.Password),
			}
			if n.Security.ServerName != "" {
				parts = append(parts, fmt.Sprintf("sni=%s", n.Security.ServerName))
			}
			if n.Security.SkipVerify {
				parts = append(parts, "skip-cert-verify=true")
			}
			proxyLines = append(proxyLines, strings.Join(parts, ", "))
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

func renderLoon(bundle *ResolvedBundle, _ RenderOptions) []byte {
	var proxyLines []string
	var proxyNames []string

	for _, n := range bundle.Nodes {
		tag := sanitizeConfTag(cmp.Or(n.Tag, fmt.Sprintf("%s-%s", n.Type, n.Addr)))
		switch n.Type {
		case "hysteria2":
			parts := []string{
				fmt.Sprintf("%s = Hysteria2", tag),
				n.Addr,
				strconv.Itoa(int(n.Port)),
				fmt.Sprintf("\"%s\"", n.Password),
			}
			if n.Security.ServerName != "" {
				parts = append(parts, fmt.Sprintf("tls-name=%s", n.Security.ServerName))
			}
			parts = append(parts, fmt.Sprintf("skip-cert-verify=%t", n.Security.SkipVerify), "udp=true")
			proxyLines = append(proxyLines, strings.Join(parts, ", "))
			proxyNames = append(proxyNames, tag)

		case "vless":
			parts := []string{
				fmt.Sprintf("%s = VLESS", tag),
				n.Addr,
				strconv.Itoa(int(n.Port)),
				fmt.Sprintf("\"%s\"", n.UUID),
				"transport=tcp",
			}
			if flow, _ := n.Extra["flow"].(string); flow != "" {
				parts = append(parts, fmt.Sprintf("flow=%s", flow))
			}
			if n.Security.TLS {
				parts = append(parts, "over-tls=true")
				if n.Security.ServerName != "" {
					parts = append(parts, fmt.Sprintf("tls-name=%s", n.Security.ServerName))
				}
				parts = append(parts, fmt.Sprintf("skip-cert-verify=%t", n.Security.SkipVerify))
				if sec, _ := n.Extra["security"].(string); sec == "reality" {
					if pk, _ := n.Extra["public_key"].(string); pk != "" {
						parts = append(parts, fmt.Sprintf("public-key=\"%s\"", pk))
					}
					if sid, _ := n.Extra["short_id"].(string); sid != "" {
						parts = append(parts, fmt.Sprintf("short-id=%s", sid))
					}
				}
			}
			parts = append(parts, "udp=true")
			proxyLines = append(proxyLines, strings.Join(parts, ", "))
			proxyNames = append(proxyNames, tag)

		case "trojan":
			parts := []string{
				fmt.Sprintf("%s = trojan", tag),
				n.Addr,
				strconv.Itoa(int(n.Port)),
				fmt.Sprintf("\"%s\"", n.Password),
			}
			if n.Security.ServerName != "" {
				parts = append(parts, fmt.Sprintf("tls-name=%s", n.Security.ServerName))
			}
			parts = append(parts, fmt.Sprintf("skip-cert-verify=%t", n.Security.SkipVerify), "udp=true")
			proxyLines = append(proxyLines, strings.Join(parts, ", "))
			proxyNames = append(proxyNames, tag)

		case "shadowsocks", "ss":
			method, _ := n.Extra["method"].(string)
			parts := []string{
				fmt.Sprintf("%s = Shadowsocks", tag),
				n.Addr,
				strconv.Itoa(int(n.Port)),
				cmp.Or(method, "aes-256-gcm"),
				fmt.Sprintf("\"%s\"", n.Password),
				"udp=true",
			}
			proxyLines = append(proxyLines, strings.Join(parts, ", "))
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

	switch n.Type {
	case "hysteria2":
		q := url.Values{}
		if n.Security.ServerName != "" {
			q.Set("sni", n.Security.ServerName)
		}
		if len(n.Security.ALPN) > 0 {
			q.Set("alpn", strings.Join(n.Security.ALPN, ","))
		}
		if n.Security.SkipVerify {
			q.Set("insecure", "1")
		} else {
			q.Set("insecure", "0")
		}
		if obfsMap, ok := n.Extra["obfs"].(map[string]string); ok && obfsMap["type"] != "" {
			q.Set("obfs", obfsMap["type"])
			if obfsMap["password"] != "" {
				q.Set("obfs-password", obfsMap["password"])
			}
		}
		return fmt.Sprintf("hysteria2://%s@%s/?%s#%s", url.User(n.Password).String(), hostPort, q.Encode(), frag)

	case "vless":
		q := url.Values{}
		q.Set("encryption", "none")
		q.Set("type", cmp.Or(n.Transport.Net, "tcp"))
		if flow, _ := n.Extra["flow"].(string); flow != "" {
			q.Set("flow", flow)
		}
		if sec, _ := n.Extra["security"].(string); sec == "reality" {
			q.Set("security", "reality")
			if pk, _ := n.Extra["public_key"].(string); pk != "" {
				q.Set("pbk", pk)
			}
			if sid, _ := n.Extra["short_id"].(string); sid != "" {
				q.Set("sid", sid)
			}
			fp, _ := n.Extra["fingerprint"].(string)
			q.Set("fp", cmp.Or(fp, "chrome"))
		} else if n.Security.TLS {
			q.Set("security", "tls")
			if n.Security.SkipVerify {
				q.Set("allowInsecure", "1")
			}
		}
		if n.Security.ServerName != "" {
			q.Set("sni", n.Security.ServerName)
		}
		if len(n.Security.ALPN) > 0 {
			q.Set("alpn", strings.Join(n.Security.ALPN, ","))
		}
		if n.Transport.Host != "" {
			q.Set("host", n.Transport.Host)
		}
		if n.Transport.Path != "" {
			q.Set("path", n.Transport.Path)
		}
		return fmt.Sprintf("vless://%s@%s?%s#%s", url.PathEscape(n.UUID), hostPort, q.Encode(), frag)

	case "trojan":
		q := url.Values{}
		if n.Security.ServerName != "" {
			q.Set("sni", n.Security.ServerName)
		}
		if len(n.Security.ALPN) > 0 {
			q.Set("alpn", strings.Join(n.Security.ALPN, ","))
		}
		if n.Security.SkipVerify {
			q.Set("allowInsecure", "1")
		}
		if n.Transport.Net != "" && n.Transport.Net != "tcp" {
			q.Set("type", n.Transport.Net)
			if n.Transport.Host != "" {
				q.Set("host", n.Transport.Host)
			}
			if n.Transport.Path != "" {
				q.Set("path", n.Transport.Path)
			}
		}
		return fmt.Sprintf("trojan://%s@%s?%s#%s", url.User(n.Password).String(), hostPort, q.Encode(), frag)

	case "shadowsocks", "ss":
		method, _ := n.Extra["method"].(string)
		b64 := base64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", cmp.Or(method, "aes-256-gcm"), n.Password)))
		cred := strings.ReplaceAll(b64, "/", "%2F")
		return fmt.Sprintf("ss://%s@%s#%s", cred, hostPort, frag)

	case "anytls":
		q := url.Values{}
		if n.Security.ServerName != "" {
			q.Set("sni", n.Security.ServerName)
		}
		if len(n.Security.ALPN) > 0 {
			q.Set("alpn", strings.Join(n.Security.ALPN, ","))
		}
		if n.Security.SkipVerify {
			q.Set("insecure", "1")
		} else {
			q.Set("insecure", "0")
		}
		for _, extraKey := range []string{"idle_session_check_interval", "idle_session_timeout", "min_idle_session"} {
			if val := strings.TrimSpace(fmt.Sprint(n.Extra[extraKey])); val != "" && val != "<nil>" && val != "0" {
				q.Set(extraKey, val)
			}
		}
		return fmt.Sprintf("anytls://%s@%s/?%s#%s", url.User(n.Password).String(), hostPort, q.Encode(), frag)

	case "tuic":
		q := url.Values{}
		if n.Security.ServerName != "" {
			q.Set("sni", n.Security.ServerName)
		}
		if len(n.Security.ALPN) > 0 {
			q.Set("alpn", strings.Join(n.Security.ALPN, ","))
		}
		if n.Security.SkipVerify {
			q.Set("insecure", "1")
		}
		if cc, _ := n.Extra["congestion_control"].(string); cc != "" {
			q.Set("congestion_control", cc)
		}
		if udpMode, _ := n.Extra["udp_relay_mode"].(string); udpMode != "" {
			q.Set("udp_relay_mode", udpMode)
		}
		return fmt.Sprintf("tuic://%s@%s/?%s#%s", url.UserPassword(n.UUID, n.Password).String(), hostPort, q.Encode(), frag)

	case "vmess":
		dto := map[string]any{
			"v":    "2",
			"ps":   n.Tag,
			"add":  n.Addr,
			"port": strconv.Itoa(int(n.Port)),
			"id":   n.UUID,
			"aid":  "0",
			"scy":  "auto",
			"net":  cmp.Or(n.Transport.Net, "tcp"),
			"type": "none",
			"host": n.Transport.Host,
			"path": n.Transport.Path,
			"tls":  "",
			"sni":  n.Security.ServerName,
		}
		if n.Security.TLS {
			dto["tls"] = "tls"
		}
		if len(n.Security.ALPN) > 0 {
			dto["alpn"] = strings.Join(n.Security.ALPN, ",")
		}
		raw, err := json.Marshal(dto)
		if err != nil {
			return ""
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(raw)

	default:
		return ""
	}
}
