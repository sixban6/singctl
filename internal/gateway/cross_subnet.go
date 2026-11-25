// 文件职责：在旁路由模式下维护多子网真实客户端 IP 透传所需的 RFC1918 回程路由（优先零子进程 RTNL）与 OpenWrt dnsmasq 跨网段响应配置，并支持 0600 快照与可逆还原。
package gateway

import (
	"cmp"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"singctl/internal/common/fsx"
	"singctl/internal/logger"
	"singctl/internal/platform/rtnl"
	"singctl/internal/platform/servicemgr"
)

const (
	sideReturnRoutePriority = uint32(200)
	sideReturnRouteMetric   = "200"
)

var defaultReturnRouteCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

type returnRouteSnapshot struct {
	GatewayIP string   `json:"gatewayIP"`
	LANIface  string   `json:"lanIface"`
	Metric    string   `json:"metric"`
	CIDRs     []string `json:"cidrs"`
}

type dnsmasqOrigSnapshot struct {
	HadOption bool   `json:"hadOption"`
	OrigValue string `json:"origValue"`
}

func (c *Controller) isHostOpenWrt() bool {
	if c.IsOpenWrt != nil {
		return c.IsOpenWrt()
	}
	return isOpenWrtSystem()
}

func (c *Controller) serviceMgr() servicemgr.Manager {
	if c.ServiceMgr != nil {
		return c.ServiceMgr
	}
	if c.Exec == nil && runtime.GOOS == "linux" {
		return servicemgr.Detect(nil)
	}
	return servicemgr.NewNoop()
}

func (c *Controller) applySideRouterCrossSubnet(ctx context.Context, plan ResolvedPlan) {
	c.applySideRouterReturnRoutes(ctx, plan)
	c.applySideRouterDnsmasqCrossSubnet(ctx)
}

func (c *Controller) restoreSideRouterCrossSubnet(ctx context.Context) {
	c.restoreSideRouterReturnRoutes(ctx)
	c.restoreSideRouterDnsmasqCrossSubnet(ctx)
}

func (c *Controller) replaceUnicastReturnRoute(ctx context.Context, cidr, gwIP, lanIface string) bool {
	if rc := c.rtnlClient(); rc != nil {
		dstPfx, dErr := netip.ParsePrefix(cidr)
		gwAddr, gErr := netip.ParseAddr(gwIP)
		if dErr == nil && gErr == nil {
			spec := rtnl.UnicastRouteSpec{
				Dst:      dstPfx.Masked(),
				Gateway:  gwAddr.Unmap(),
				IfName:   lanIface,
				Priority: sideReturnRoutePriority,
			}
			if rc.ReplaceUnicastRoute(spec) == nil || rc.ReplaceUnicastRoute(rtnl.UnicastRouteSpec{
				Dst:      spec.Dst,
				Gateway:  spec.Gateway,
				Priority: spec.Priority,
			}) == nil {
				return true
			}
		}
	}
	if out, err := c.runCmd(ctx, "ip", "-4", "route", "replace", cidr, "via", gwIP, "dev", lanIface, "metric", sideReturnRouteMetric); err != nil {
		logger.Warn("添加旁路由跨子网回程路由 %s via %s dev %s 失败: %v (%s)", cidr, gwIP, lanIface, err, strings.TrimSpace(string(out)))
		return false
	}
	return true
}

func (c *Controller) deleteUnicastReturnRoute(ctx context.Context, cidr, gwIP, lanIface, metric string) {
	if rc := c.rtnlClient(); rc != nil {
		dstPfx, dErr := netip.ParsePrefix(cidr)
		gwAddr, gErr := netip.ParseAddr(gwIP)
		if dErr == nil && gErr == nil {
			if rc.DeleteUnicastRoute(rtnl.UnicastRouteSpec{
				Dst:      dstPfx.Masked(),
				Gateway:  gwAddr.Unmap(),
				IfName:   lanIface,
				Priority: sideReturnRoutePriority,
			}) == nil {
				return
			}
		}
	}
	_, _ = c.runCmd(ctx, "ip", "-4", "route", "del", cidr, "via", gwIP, "dev", lanIface, "metric", cmp.Or(metric, sideReturnRouteMetric))
}

func (c *Controller) applySideRouterReturnRoutes(ctx context.Context, plan ResolvedPlan) {
	if plan.MainRouterIP == "" || plan.LANIface == "" {
		return
	}
	snapPath := filepath.Join(c.stateDir(), "return_routes.json")
	if raw, err := os.ReadFile(snapPath); err == nil {
		var prev returnRouteSnapshot
		if json.Unmarshal(raw, &prev) == nil && prev.GatewayIP != "" && prev.LANIface != "" {
			if prev.GatewayIP != plan.MainRouterIP || prev.LANIface != plan.LANIface {
				for _, cidr := range prev.CIDRs {
					c.deleteUnicastReturnRoute(ctx, cidr, prev.GatewayIP, prev.LANIface, prev.Metric)
				}
			}
		}
	}

	installed := make([]string, 0, len(defaultReturnRouteCIDRs))
	for _, cidr := range defaultReturnRouteCIDRs {
		if c.replaceUnicastReturnRoute(ctx, cidr, plan.MainRouterIP, plan.LANIface) {
			installed = append(installed, cidr)
		}
	}
	if len(installed) == 0 {
		return
	}
	snap := returnRouteSnapshot{
		GatewayIP: plan.MainRouterIP,
		LANIface:  plan.LANIface,
		Metric:    sideReturnRouteMetric,
		CIDRs:     installed,
	}
	if b, err := json.Marshal(snap); err == nil {
		_ = fsx.WriteAtomic0600(snapPath, b)
	}
}

func (c *Controller) restoreSideRouterReturnRoutes(ctx context.Context) {
	snapPath := filepath.Join(c.stateDir(), "return_routes.json")
	raw, err := os.ReadFile(snapPath)
	if err != nil {
		return
	}
	var snap returnRouteSnapshot
	if json.Unmarshal(raw, &snap) == nil && snap.GatewayIP != "" && snap.LANIface != "" {
		for _, cidr := range snap.CIDRs {
			c.deleteUnicastReturnRoute(ctx, cidr, snap.GatewayIP, snap.LANIface, snap.Metric)
		}
	}
	_ = os.Remove(snapPath)
}

func (c *Controller) applySideRouterDnsmasqCrossSubnet(ctx context.Context) {
	if !c.isHostOpenWrt() {
		return
	}
	out, err := c.runCmd(ctx, "uci", "-q", "get", "dhcp.@dnsmasq[0].localservice")
	cur := strings.TrimSpace(string(out))
	if cur == "0" {
		return
	}

	hadOption := err == nil && cur != ""
	if err != nil && cur == "" {
		// Unset in OpenWrt UCI defaults localservice to enabled (1); verify dnsmasq[0] section exists before mutating.
		if _, secErr := c.runCmd(ctx, "uci", "-q", "get", "dhcp.@dnsmasq[0]"); secErr != nil {
			return
		}
	}

	snapPath := filepath.Join(c.stateDir(), "dnsmasq.orig.json")
	if _, statErr := os.Stat(snapPath); os.IsNotExist(statErr) {
		snap := dnsmasqOrigSnapshot{
			HadOption: hadOption,
			OrigValue: cur,
		}
		if b, mErr := json.Marshal(snap); mErr == nil {
			_ = fsx.WriteAtomic0600(snapPath, b)
		}
	}

	if setOut, setErr := c.runCmd(ctx, "uci", "set", "dhcp.@dnsmasq[0].localservice=0"); setErr != nil {
		logger.Warn("设置 dnsmasq 跨子网响应 localservice=0 失败: %v (%s)", setErr, strings.TrimSpace(string(setOut)))
		return
	}
	if comOut, comErr := c.runCmd(ctx, "uci", "commit", "dhcp"); comErr != nil {
		logger.Warn("提交 dhcp.@dnsmasq[0] 配置失败: %v (%s)", comErr, strings.TrimSpace(string(comOut)))
		return
	}
	if mgr := c.serviceMgr(); mgr != nil && mgr.Kind() != servicemgr.InitUnknown {
		if relErr := mgr.Reload(ctx, "dnsmasq"); relErr != nil {
			logger.Warn("重载 dnsmasq 服务失败: %v", relErr)
		}
	}
}

func (c *Controller) restoreSideRouterDnsmasqCrossSubnet(ctx context.Context) {
	snapPath := filepath.Join(c.stateDir(), "dnsmasq.orig.json")
	raw, err := os.ReadFile(snapPath)
	if err != nil {
		return
	}
	var snap dnsmasqOrigSnapshot
	if uErr := json.Unmarshal(raw, &snap); uErr == nil {
		if snap.HadOption && snap.OrigValue != "" {
			_, _ = c.runCmd(ctx, "uci", "set", "dhcp.@dnsmasq[0].localservice="+snap.OrigValue)
		} else {
			_, _ = c.runCmd(ctx, "uci", "delete", "dhcp.@dnsmasq[0].localservice")
		}
		_, _ = c.runCmd(ctx, "uci", "commit", "dhcp")
		if mgr := c.serviceMgr(); mgr != nil && mgr.Kind() != servicemgr.InitUnknown {
			_ = mgr.Reload(ctx, "dnsmasq")
		}
	}
	_ = os.Remove(snapPath)
}
