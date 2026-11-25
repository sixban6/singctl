// 文件职责：在旁路由模式下经主路由 DNS 执行带绕行标记的内网 IP 反向 PTR 设备名解析与 TTL 缓存收敛。
package audit

import (
	"cmp"
	"context"
	"maps"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	ptrPositiveTTL      = 10 * time.Minute
	ptrNegativeTTL      = 2 * time.Minute
	ptrLookupBudgetWait = 150 * time.Millisecond
	ptrMaxLookupsPerRun = 8
	ptrMaxCacheEntries  = 512
)

type ptrCacheEntry struct {
	name      string
	expiresAt time.Time
}

// NormalizePTRHostname 规范化并清洗 PTR 反向解析返回的主机名，过滤通配符、本机回环与纯 IP。
func NormalizePTRHostname(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return ""
	}
	if strings.ContainsAny(s, " \t\r\n;|&$`\"'<>\\/") {
		return ""
	}
	for _, suffix := range []string{".lan", ".home", ".local", ".arpa"} {
		if len(s) > len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix) {
			s = strings.TrimSuffix(s, s[len(s)-len(suffix):])
			break
		}
	}
	s = strings.TrimSpace(s)
	if s == "" || s == "*" || strings.EqualFold(s, "localhost") {
		return ""
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return ""
	}
	return s
}

func (c *Collector) isSideRouterPTREnabledLocked() (mainRouterIP string, ok bool) {
	if c.cfg == nil || !c.cfg.Gateway.IsSideRouter() {
		return "", false
	}
	mainIP := strings.TrimSpace(c.cfg.Gateway.MainRouterIP)
	if mainIP == "" {
		return "", false
	}
	addr, err := netip.ParseAddr(mainIP)
	if err != nil || !addr.Is4() {
		return "", false
	}
	if c.ptrLookupFunc == nil && c.customEndpoints {
		return "", false
	}
	return addr.String(), true
}

func lookupSideRouterPTR(ctx context.Context, mainRouterIP, targetIP string) (string, error) {
	dialer := &net.Dialer{
		Timeout: ptrLookupBudgetWait,
		Control: ptrBypassDialControl,
	}
	targetDNS := net.JoinHostPort(mainRouterIP, "53")
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(dctx, network, targetDNS)
		},
	}
	names, err := resolver.LookupAddr(ctx, targetIP)
	if err != nil || len(names) == 0 {
		return "", err
	}
	return names[0], nil
}

func (c *Collector) enrichSideRouterPTRDevicesLocked(
	ctx context.Context,
	devDir map[string]lanDeviceInfo,
	selfIPs map[string]bool,
	candidateIPs []string,
) {
	mainIP, enabled := c.isSideRouterPTREnabledLocked()
	if !enabled || len(candidateIPs) == 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := c.currentTimeLocked()
	if c.ptrCache == nil {
		c.ptrCache = make(map[string]ptrCacheEntry)
	}

	var needLookup []string
	seen := make(map[string]struct{}, len(candidateIPs))
	for _, rawIP := range candidateIPs {
		ipStr := normalizeSourceDeviceIP(rawIP, selfIPs, devDir)
		if ipStr == "" || ipStr == "127.0.0.1" || ipStr == "::1" || selfIPs[ipStr] {
			continue
		}
		if _, dup := seen[ipStr]; dup {
			continue
		}
		seen[ipStr] = struct{}{}

		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsPrivate() && !addr.IsLinkLocalUnicast() {
			continue
		}
		canonIP := addr.String()

		// 本地 DHCP 租约/ARP/hosts 已知名称优先，无需 PTR 探测
		if localInfo, inLease := c.cachedLeaseDevs[canonIP]; inLease && localInfo.Name != "" && localInfo.Name != canonIP {
			continue
		}

		if cached, ok := c.ptrCache[canonIP]; ok && now.Before(cached.expiresAt) {
			if cached.name != "" {
				info := devDir[canonIP]
				if info.Name == "" || info.Name == canonIP {
					info.Name = cached.name
					devDir[canonIP] = info
				}
			}
			continue
		}
		if len(needLookup) < ptrMaxLookupsPerRun {
			needLookup = append(needLookup, canonIP)
		}
	}

	if len(needLookup) == 0 {
		c.cachedMergedLANDevs = maps.Clone(devDir)
		return
	}

	lookupFn := c.ptrLookupFunc
	if lookupFn == nil {
		lookupFn = func(lctx context.Context, ip string) (string, error) {
			return lookupSideRouterPTR(lctx, mainIP, ip)
		}
	}

	lctx, cancel := context.WithTimeout(ctx, ptrLookupBudgetWait)
	defer cancel()

	type ptrResult struct {
		ip   string
		name string
	}
	results := make([]ptrResult, len(needLookup))
	var wg sync.WaitGroup
	for i, ip := range needLookup {
		wg.Add(1)
		go func(idx int, targetIP string) {
			defer wg.Done()
			rawName, err := lookupFn(lctx, targetIP)
			clean := ""
			if err == nil {
				clean = NormalizePTRHostname(rawName)
			}
			results[idx] = ptrResult{ip: targetIP, name: clean}
		}(i, ip)
	}
	wg.Wait()

	if len(c.ptrCache)+len(results) > ptrMaxCacheEntries {
		maps.DeleteFunc(c.ptrCache, func(_ string, e ptrCacheEntry) bool {
			return !now.Before(e.expiresAt)
		})
		if len(c.ptrCache)+len(results) > ptrMaxCacheEntries {
			clear(c.ptrCache)
		}
	}

	for _, res := range results {
		ttl := ptrNegativeTTL
		if res.name != "" {
			ttl = ptrPositiveTTL
			info := devDir[res.ip]
			info.Name = cmp.Or(res.name, info.Name)
			devDir[res.ip] = info
		}
		c.ptrCache[res.ip] = ptrCacheEntry{
			name:      res.name,
			expiresAt: now.Add(ttl),
		}
	}
	c.cachedMergedLANDevs = maps.Clone(devDir)
}
