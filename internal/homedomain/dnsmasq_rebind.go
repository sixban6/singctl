// 文件职责：负责 OpenWrt dnsmasq 精准受管后缀豁免（rebind_domain）、局域网快速直转（server=/<suffix>/127.0.0.1#<port>）及 tailscale0 接口让渡（绝不触碰全局 localservice 与 rebind_protection）。
package homedomain

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/platform/servicemgr"
)

// DnsmasqDesired 描述 OpenWrt dnsmasq 应达到的本地域名协同状态。
type DnsmasqDesired struct {
	Enabled          bool
	Suffix           string
	PrevSuffix       string
	LocalDNSPort     int
	ExcludeTailscale bool
}

// DnsmasqDeps 显式注入 OpenWrt dnsmasq UCI 与服务重载依赖（零值回退生产默认，支持完全离线测试）。
type DnsmasqDeps struct {
	IsOpenWrt     func() bool
	RunUCI        func(ctx context.Context, args ...string) (string, error)
	ReloadDnsmasq func(ctx context.Context) error
}

func (d DnsmasqDeps) isOpenWrt() bool {
	if d.IsOpenWrt != nil {
		return d.IsOpenWrt()
	}
	if runtime.GOOS != "linux" || !sysinfo.IsOpenWrt() {
		return false
	}
	_, err := exec.LookPath("uci")
	return err == nil
}

func (d DnsmasqDeps) runUCI(ctx context.Context, args ...string) (string, error) {
	if d.RunUCI != nil {
		return d.RunUCI(ctx, args...)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "uci", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (d DnsmasqDeps) reloadDnsmasq(ctx context.Context) error {
	if d.ReloadDnsmasq != nil {
		return d.ReloadDnsmasq(ctx)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	mgr := servicemgr.Detect(nil)
	if mgr.Kind() == servicemgr.InitProcd {
		return mgr.Reload(ctx, "dnsmasq")
	}
	return nil
}

func parseUCIListValues(raw string) []string {
	var out []string
	for field := range strings.FieldsSeq(raw) {
		val := strings.Trim(strings.TrimSpace(field), "'\"")
		if val != "" {
			out = append(out, val)
		}
	}
	return out
}

func formatSuffixServerRule(suffix string, dnsPort int) string {
	if dnsPort <= 0 || dnsPort > 65535 {
		dnsPort = 5353
	}
	return "/" + suffix + "/127.0.0.1#" + strconv.Itoa(dnsPort)
}

// ReconcileOpenWrtDnsmasq 幂等对账 OpenWrt dnsmasq 本地域名协同配置：
//   - 启用时追加 rebind_domain=<suffix> 与 server=/<suffix>/127.0.0.1#<dnsPort>（仅对受管后缀生效，绝不修改全局 rebind_protection / localservice）
//   - 启用 Tailscale Split-DNS 时追加 notinterface=tailscale0，让出 <tailscale_ip>:53 给内置零递归应答器
//   - 后缀变更或禁用时自动清理陈旧条目并平滑重载 dnsmasq
func ReconcileOpenWrtDnsmasq(ctx context.Context, desired DnsmasqDesired, deps DnsmasqDeps) (bool, error) {
	if !deps.isOpenWrt() {
		return false, nil
	}
	suffix, err := config.NormalizeHomeDomainSuffix(desired.Suffix)
	if err != nil {
		return false, err
	}
	dnsPort := desired.LocalDNSPort
	if dnsPort <= 0 || dnsPort > 65535 {
		dnsPort = 5353
	}

	getList := func(key string) []string {
		raw, _ := deps.runUCI(ctx, "-q", "get", key)
		return parseUCIListValues(raw)
	}

	rebindList := getList("dhcp.@dnsmasq[0].rebind_domain")
	serverList := getList("dhcp.@dnsmasq[0].server")
	notIfaceList := getList("dhcp.@dnsmasq[0].notinterface")

	changed := false

	// 若发生后缀切换，清理旧后缀的受管条目
	if prev := strings.ToLower(strings.Trim(strings.TrimSpace(desired.PrevSuffix), ".")); prev != "" && prev != suffix {
		if slices.Contains(rebindList, prev) {
			if _, err := deps.runUCI(ctx, "del_list", "dhcp.@dnsmasq[0].rebind_domain="+prev); err == nil {
				changed = true
			}
		}
		prevPrefix := "/" + prev + "/127.0.0.1#"
		for _, srv := range serverList {
			if strings.HasPrefix(srv, prevPrefix) {
				if _, err := deps.runUCI(ctx, "del_list", "dhcp.@dnsmasq[0].server="+srv); err == nil {
					changed = true
				}
			}
		}
	}

	wantServer := formatSuffixServerRule(suffix, dnsPort)
	sfxPrefix := "/" + suffix + "/127.0.0.1#"

	if desired.Enabled {
		if !slices.Contains(rebindList, suffix) {
			if _, err := deps.runUCI(ctx, "add_list", "dhcp.@dnsmasq[0].rebind_domain="+suffix); err != nil {
				return false, fmt.Errorf("uci add_list rebind_domain: %w", err)
			}
			changed = true
		}
		// 移除同后缀旧端口条目并确保目标端口存在
		hasWantServer := false
		for _, srv := range serverList {
			if srv == wantServer {
				hasWantServer = true
			} else if strings.HasPrefix(srv, sfxPrefix) {
				if _, err := deps.runUCI(ctx, "del_list", "dhcp.@dnsmasq[0].server="+srv); err == nil {
					changed = true
				}
			}
		}
		if !hasWantServer {
			if _, err := deps.runUCI(ctx, "add_list", "dhcp.@dnsmasq[0].server="+wantServer); err != nil {
				return false, fmt.Errorf("uci add_list server: %w", err)
			}
			changed = true
		}
	} else {
		if slices.Contains(rebindList, suffix) {
			if _, err := deps.runUCI(ctx, "del_list", "dhcp.@dnsmasq[0].rebind_domain="+suffix); err == nil {
				changed = true
			}
		}
		for _, srv := range serverList {
			if strings.HasPrefix(srv, sfxPrefix) {
				if _, err := deps.runUCI(ctx, "del_list", "dhcp.@dnsmasq[0].server="+srv); err == nil {
					changed = true
				}
			}
		}
	}

	wantExcludeTS := desired.Enabled && desired.ExcludeTailscale
	hasExcludeTS := slices.Contains(notIfaceList, "tailscale0")
	if wantExcludeTS && !hasExcludeTS {
		if _, err := deps.runUCI(ctx, "add_list", "dhcp.@dnsmasq[0].notinterface=tailscale0"); err != nil {
			return false, fmt.Errorf("uci add_list notinterface=tailscale0: %w", err)
		}
		changed = true
	} else if !wantExcludeTS && hasExcludeTS {
		if _, err := deps.runUCI(ctx, "del_list", "dhcp.@dnsmasq[0].notinterface=tailscale0"); err == nil {
			changed = true
		}
	}

	if !changed {
		return false, nil
	}
	if _, err := deps.runUCI(ctx, "commit", "dhcp"); err != nil {
		return false, fmt.Errorf("uci commit dhcp: %w", err)
	}
	if err := deps.reloadDnsmasq(ctx); err != nil {
		return true, fmt.Errorf("reload dnsmasq: %w", err)
	}
	return true, nil
}
