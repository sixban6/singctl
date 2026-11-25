// 文件职责：封装 OpenWrt UCI 输出解析、防注入单引号转义、/etc/board.json 与 /tmp/dhcp.leases 读取及生产环境默认执行器。
package vlan

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"singctl/internal/constant"
	"singctl/internal/platform/servicemgr"
)

// UCISection 表示 `uci show <pkg>` 解析出的单个配置节。
type UCISection struct {
	Package   string
	Name      string
	Type      string
	Anonymous bool
	Options   map[string]string
	Lists     map[string][]string
}

// UCIConfig 保存单个 UCI 包的全部有序配置节。
type UCIConfig struct {
	Package  string
	Sections []*UCISection
	byName   map[string]*UCISection
}

func newUCIConfig(pkg string) *UCIConfig {
	return &UCIConfig{
		Package: pkg,
		byName:  make(map[string]*UCISection),
	}
}

func (c *UCIConfig) ensureSection(name string) *UCISection {
	if s, ok := c.byName[name]; ok {
		return s
	}
	s := &UCISection{
		Package:   c.Package,
		Name:      name,
		Anonymous: strings.HasPrefix(name, "@"),
		Options:   make(map[string]string),
		Lists:     make(map[string][]string),
	}
	c.Sections = append(c.Sections, s)
	c.byName[name] = s
	return s
}

func (c *UCIConfig) ByName(name string) *UCISection {
	if c == nil {
		return nil
	}
	return c.byName[name]
}

func (c *UCIConfig) ByType(typ string) []*UCISection {
	if c == nil {
		return nil
	}
	var out []*UCISection
	for _, s := range c.Sections {
		if s.Type == typ {
			out = append(out, s)
		}
	}
	return out
}

func (s *UCISection) Opt(key string) string {
	if s == nil {
		return ""
	}
	return s.Options[key]
}

func (s *UCISection) List(key string) []string {
	if s == nil {
		return nil
	}
	if vals, ok := s.Lists[key]; ok {
		return slices.Clone(vals)
	}
	if v := strings.TrimSpace(s.Options[key]); v != "" {
		return strings.Fields(v)
	}
	return nil
}

// parseUCIShow 解析 `uci show <pkg>` 的标准输出（兼容单值与多值单引号列表及转义引号）。
func parseUCIShow(pkg, raw string) *UCIConfig {
	cfg := newUCIConfig(pkg)
	prefix := pkg + "."
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		lhs, rhs, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		rest := strings.TrimPrefix(lhs, prefix)
		secName, optName, hasOpt := strings.Cut(rest, ".")
		if secName == "" {
			continue
		}
		sec := cfg.ensureSection(secName)
		if !hasOpt {
			sec.Type = strings.TrimSpace(rhs)
			continue
		}
		tokens := parseUCIValueTokens(rhs)
		if len(tokens) == 0 {
			sec.Options[optName] = ""
			continue
		}
		if len(tokens) == 1 {
			sec.Options[optName] = tokens[0]
			sec.Lists[optName] = tokens
		} else {
			sec.Options[optName] = strings.Join(tokens, " ")
			sec.Lists[optName] = tokens
		}
	}
	return cfg
}

func parseUCIValueTokens(rhs string) []string {
	s := strings.TrimSpace(rhs)
	if s == "" {
		return nil
	}
	var tokens []string
	var cur strings.Builder
	inQuote := false
	hasToken := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !inQuote {
			switch ch {
			case '\'':
				inQuote = true
				hasToken = true
			case ' ', '\t':
				if hasToken {
					tokens = append(tokens, cur.String())
					cur.Reset()
					hasToken = false
				}
			default:
				cur.WriteByte(ch)
				hasToken = true
			}
		} else {
			if ch == '\'' {
				// UCI encodes literal single quote inside single-quoted string as '\''
				if i+3 < len(s) && s[i+1] == '\\' && s[i+2] == '\'' && s[i+3] == '\'' {
					cur.WriteByte('\'')
					i += 3
					continue
				}
				inQuote = false
			} else {
				cur.WriteByte(ch)
			}
		}
	}
	if hasToken {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// quoteUCI 对 UCI 值进行安全单引号封装，严禁注入换行或控制字符。
func quoteUCI(val string) string {
	clean := strings.ReplaceAll(val, "\r", "")
	clean = strings.ReplaceAll(clean, "\n", "")
	clean = strings.ReplaceAll(clean, "\x00", "")
	escaped := strings.ReplaceAll(clean, "'", `'\''`)
	return "'" + escaped + "'"
}

type boardInfo struct {
	Model struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"model"`
	Network struct {
		LAN struct {
			Ports  []string `json:"ports"`
			Device string   `json:"device"`
		} `json:"lan"`
		WAN struct {
			Device string `json:"device"`
		} `json:"wan"`
	} `json:"network"`
	Switch map[string]struct {
		Enable bool `json:"enable"`
		Reset  bool `json:"reset"`
		Ports  []struct {
			Num    int    `json:"num"`
			Role   string `json:"role"`
			Device string `json:"device"`
		} `json:"ports"`
	} `json:"switch"`
}

func parseBoardJSON(raw []byte) *boardInfo {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var b boardInfo
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil
	}
	return &b
}

func countDHCPLeasesByCIDR(raw []byte, segments []Segment) map[string]int {
	counts := make(map[string]int, len(segments))
	type segPrefix struct {
		id  string
		pfx netip.Prefix
	}
	var prefixes []segPrefix
	for _, seg := range segments {
		if pfx, err := netip.ParsePrefix(seg.CIDR); err == nil {
			prefixes = append(prefixes, segPrefix{id: seg.ID, pfx: pfx})
		}
	}
	if len(prefixes) == 0 || len(raw) == 0 {
		return counts
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		addr, err := netip.ParseAddr(fields[2])
		if err != nil {
			continue
		}
		for _, sp := range prefixes {
			if sp.pfx.Contains(addr) {
				counts[sp.id]++
				break
			}
		}
	}
	return counts
}

func (s *Service) isOpenWrt() bool {
	if s.env.IsOpenWrt != nil {
		return s.env.IsOpenWrt()
	}
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := os.Stat("/etc/openwrt_release"); err != nil {
		return false
	}
	_, err := exec.LookPath("uci")
	return err == nil
}

func (s *Service) runUCI(ctx context.Context, args ...string) (string, error) {
	if s.env.RunUCI != nil {
		return s.env.RunUCI(ctx, args...)
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "uci", args...).CombinedOutput()
	return string(out), err
}

// DirtyUCIPackages 从一批 UCI 命令中提取实际涉及的配置文件包名（固定返回顺序：network/dhcp/wireless/firewall）。
func DirtyUCIPackages(commands []string) []string {
	seen := make(map[string]bool, 4)
	for _, line := range commands {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		target := fields[1]
		if pkg, _, ok := strings.Cut(target, "."); ok {
			seen[pkg] = true
		}
	}
	ordered := []string{"network", "dhcp", "wireless", "firewall"}
	out := make([]string, 0, len(seen))
	for _, pkg := range ordered {
		if seen[pkg] {
			out = append(out, pkg)
		}
	}
	return out
}

func (s *Service) batchUCI(ctx context.Context, commands []string) error {
	if len(commands) == 0 {
		return nil
	}
	if s.env.BatchUCI != nil {
		return s.env.BatchUCI(ctx, commands)
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "uci", "batch")
	cmd.Stdin = strings.NewReader(strings.Join(commands, "\n") + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("uci batch failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	for _, pkg := range DirtyUCIPackages(commands) {
		if cOut, cErr := exec.CommandContext(cctx, "uci", "commit", pkg).CombinedOutput(); cErr != nil {
			// Skip committing packages that do not exist (e.g. wireless on x86 softrouter).
			if pkg == "wireless" && strings.Contains(strings.ToLower(string(cOut)), "entry not found") {
				continue
			}
			return fmt.Errorf("uci commit %s failed: %w (%s)", pkg, cErr, strings.TrimSpace(string(cOut)))
		}
	}
	return nil
}

// ReloadOpenWrtNetworkWithOptions 在 OpenWrt 上按需重载网络、防火墙、dnsmasq，并仅当无线变更时执行 DMA 护盾与单次 wifi reload。
func ReloadOpenWrtNetworkWithOptions(ctx context.Context, opts ReloadOptions, prepareDMA func()) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	var errs []error
	mgr := servicemgr.Detect(nil)
	if mgr.Kind() == servicemgr.InitProcd {
		if err := mgr.Reload(cctx, "network"); err != nil {
			errs = append(errs, fmt.Errorf("reload network: %w", err))
		}
		// Give netifd a brief moment to register new br-lan.<vid> interfaces in ubus before fw4 compiles zones.
		select {
		case <-cctx.Done():
		case <-time.After(1200 * time.Millisecond):
		}
		for _, unit := range []string{"firewall", "dnsmasq"} {
			if err := mgr.Reload(cctx, unit); err != nil {
				errs = append(errs, fmt.Errorf("reload %s: %w", unit, err))
			}
		}
	}
	if opts.WirelessChanged {
		if prepareDMA != nil {
			prepareDMA()
		} else {
			prepareWirelessDMAHeadroomOS()
		}
		if wifiPath, err := exec.LookPath("wifi"); err == nil {
			_ = exec.CommandContext(cctx, wifiPath, "reload").Run()
		}
	}
	if cidrs := ReadProxyBypassList(constant.VLANProxyBypassFile); len(cidrs) > 0 {
		applyRuntimeProxyBypass(cctx, cidrs)
	}
	if dnsRules := ReadDNSBypassRules(constant.VLANDNSBypassFile); len(dnsRules) > 0 {
		applyRuntimeDNSBypass(cctx, dnsRules)
	}
	return errors.Join(errs...)
}

// ReloadOpenWrtNetwork 在 OpenWrt 上通过统一 servicemgr 热重载网络、防火墙、dnsmasq 与无线配置（供 Safe Commit 自动回滚复用，含 DMA 护盾）。
func ReloadOpenWrtNetwork(ctx context.Context) error {
	return ReloadOpenWrtNetworkWithOptions(ctx, ReloadOptions{WirelessChanged: true}, nil)
}

// ReloadWithOptions 按 ReloadOptions 执行网络及可选的无线重载（未改动无线时跳过 wifi reload 与 DMA 整理）。
func (s *Service) ReloadWithOptions(ctx context.Context, opts ReloadOptions) error {
	if s.env.ReloadNetworkWithOpts != nil {
		if opts.WirelessChanged && s.env.PrepareDMAHeadroom != nil {
			s.env.PrepareDMAHeadroom()
		}
		return s.env.ReloadNetworkWithOpts(ctx, opts)
	}
	if s.env.ReloadNetwork != nil {
		return s.env.ReloadNetwork(ctx)
	}
	return ReloadOpenWrtNetworkWithOptions(ctx, opts, s.env.PrepareDMAHeadroom)
}

func (s *Service) readFile(path string) ([]byte, error) {
	if s.env.ReadFile != nil {
		return s.env.ReadFile(path)
	}
	return os.ReadFile(path)
}

func (s *Service) listNetDevs() []string {
	if s.env.ListNetDevs != nil {
		devs, _ := s.env.ListNetDevs()
		return devs
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func (s *Service) readIPv4Addrs() map[string]string {
	if s.env.ReadIPv4Addrs != nil {
		m, _ := s.env.ReadIPv4Addrs()
		if m != nil {
			return m
		}
	}
	out := make(map[string]string)
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.IP.To4() == nil {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			out[iface.Name] = fmt.Sprintf("%s/%d", ipNet.IP.To4().String(), ones)
			break
		}
	}
	return out
}

func (s *Service) readSysTrimmed(path string) string {
	raw, err := s.readFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func (s *Service) readPortLink(devName string) (linkUp bool, speedMbps int) {
	carrier := s.readSysTrimmed("/sys/class/net/" + devName + "/carrier")
	oper := strings.ToLower(s.readSysTrimmed("/sys/class/net/" + devName + "/operstate"))
	linkUp = carrier == "1" || oper == "up"
	if spd, err := strconv.Atoi(s.readSysTrimmed("/sys/class/net/" + devName + "/speed")); err == nil && spd > 0 {
		speedMbps = spd
	}
	return linkUp, speedMbps
}

func (s *Service) proxyBypassFile() string {
	return cmp.Or(strings.TrimSpace(s.env.ProxyBypassFile), constant.VLANProxyBypassFile)
}

func (s *Service) dnsBypassFile() string {
	return cmp.Or(strings.TrimSpace(s.env.DNSBypassFile), constant.VLANDNSBypassFile)
}

func (s *Service) boardJSONPath() string {
	return cmp.Or(strings.TrimSpace(s.env.BoardJSONPath), "/etc/board.json")
}

func (s *Service) dhcpLeasesPath() string {
	return cmp.Or(strings.TrimSpace(s.env.DHCPLeasesPath), "/tmp/dhcp.leases")
}
