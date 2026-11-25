// 文件职责：实现「局域网设备活跃排行」单设备允许/禁止外网分流开关的状态持久化、sing-box 路由+DNS 热同步及存量连接秒断。
package audit

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

// ValidateLANDeviceIP 校验局域网设备单机 IP（禁止回环、未指定、组播及公网 IP 误操作自锁）。
func ValidateLANDeviceIP(rawIP string) (string, error) {
	s := strings.TrimSpace(rawIP)
	if s == "" {
		return "", fmt.Errorf("设备 IP 不能为空")
	}
	if strings.ContainsAny(s, " \t\r\n;|&$`\"'<>") {
		return "", fmt.Errorf("设备 IP 包含非法字符: %q", rawIP)
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		if !p.IsSingleIP() {
			return "", fmt.Errorf("仅支持对单个局域网设备 IP 配置开关: %q", rawIP)
		}
		s = p.Addr().String()
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("无效的设备 IP 格式: %q", rawIP)
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
		return "", fmt.Errorf("安全拦截: 禁止修改本机回环或保留地址 %s 的外网策略", addr.String())
	}
	if !addr.IsPrivate() && !addr.IsLinkLocalUnicast() {
		return "", fmt.Errorf("安全拦截: %s 非私网/局域网设备地址，拒绝加入直连控制列表", addr.String())
	}
	return addr.String(), nil
}

func (e *Enforcer) syncDirectDevicesSingBoxLayer(ctx context.Context, directDevices []string) (bool, error) {
	if strings.TrimSpace(e.sbConfigPath) == "" {
		return false, nil
	}
	rawBytes, err := os.ReadFile(e.sbConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	updatedJSON, err := singbox.SyncDirectDevicesInConfigJSON(string(rawBytes), directDevices)
	if err != nil {
		return false, err
	}
	if err := singbox.ApplyLiveSingBoxConfig(ctx, e.sbConfigPath, e.sbWorkConfigPath, updatedJSON, "direct-dev"); err != nil {
		return false, err
	}
	if baseRaw, bErr := singbox.LoadBaseSnapshot(e.sbConfigPath); bErr == nil && strings.TrimSpace(baseRaw) != "" {
		if updatedBase, uErr := singbox.SyncDirectDevicesInConfigJSON(baseRaw, directDevices); uErr == nil {
			_ = singbox.SaveBaseSnapshot(e.sbConfigPath, updatedBase)
		}
	}
	return true, nil
}

// SetDeviceOverseasAccess 设置单台局域网设备是否允许走海外外网分流（allowOverseas=false 时全部流量强制从 Direct 出站并走 dns_local）。
func (e *Enforcer) SetDeviceOverseasAccess(ctx context.Context, rawDeviceIP string, allowOverseas bool) (*DeviceAccessResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normIP, err := ValidateLANDeviceIP(rawDeviceIP)
	if err != nil {
		return nil, err
	}

	oldList := slices.Clone(e.cfg.Audit.DirectDevices)
	e.cfg.Audit.SetDeviceOverseasAllowed(normIP, allowOverseas)

	res := &DeviceAccessResult{
		OK:            true,
		DeviceIP:      normIP,
		AllowOverseas: allowOverseas,
		DirectDevices: slices.Clone(e.cfg.Audit.DirectDevices),
	}

	if e.configPath != "" {
		if err := config.Save(e.configPath, e.cfg); err != nil {
			e.cfg.Audit.DirectDevices = oldList
			return nil, fmt.Errorf("保存设备外网开关至 %s 失败: %w", e.configPath, err)
		}
		res.ConfigSaved = true
	}

	if sbApplied, sbErr := e.syncDirectDevicesSingBoxLayer(ctx, e.cfg.Audit.DirectDevices); sbErr == nil && sbApplied {
		res.SingBoxSynced = true
	} else if sbErr != nil && e.sbConfigPath != "" {
		res.Message = fmt.Sprintf("配置已保存，但 sing-box 同步异常: %v", sbErr)
		return res, sbErr
	}

	res.KilledConnections = e.killConnectionsMatching(ctx, normIP, func(_, _ string) bool { return true })

	if e.cfg != nil && e.cfg.IsDelegatedMode() {
		sideIP := strings.TrimSpace(e.cfg.Gateway.SideRouterIP)
		if sideIP != "" {
			res.Message = fmt.Sprintf("已更新主路由本地配置 %s；当前处于旁路由托管模式，单设备外网分流请前往旁路由 (%s:8090) 的「行为与审计」页面设置", normIP, sideIP)
		} else {
			res.Message = fmt.Sprintf("已更新主路由本地配置 %s；当前处于旁路由托管模式，单设备外网分流请前往旁路由「行为与审计」页面设置", normIP)
		}
		return res, nil
	}

	if allowOverseas {
		res.Message = fmt.Sprintf("已允许 %s 访问外网（恢复 sing-box 分流, 断开存量连接=%d 条）", normIP, res.KilledConnections)
	} else {
		res.Message = fmt.Sprintf("已限制 %s 禁止走海外代理（全部流量直连 Direct, 断开存量连接=%d 条）", normIP, res.KilledConnections)
	}
	return res, nil
}
