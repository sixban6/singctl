// 文件职责：实现守护进程主动告警分发、tailscaled OOM 免疫巡检、宿主机资源预警与审计高危/新设备观察闭环。
package daemon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"singctl/internal/audit"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/notify"
	"singctl/internal/safecommit"
)

const (
	resourceDiskWarnUsedPct       = 88
	resourceDiskCritUsedPct       = 92
	resourceDiskCritAvailBytes    = 8 * 1024 * 1024
	resourceMemCritAvailBytes     = 48 * 1024 * 1024
	maxTrackedLANMACs             = 512
	defaultAuditAlertScanInterval = 60 * time.Second
)

type resourceGuardState struct {
	mu              sync.Mutex
	diskAlertActive bool
	diskAlertKey    string
	memAlertActive  bool
}

type auditNotifyGuard struct {
	mu            sync.Mutex
	seeded        bool
	knownMACs     map[string]struct{}
	knownMACOrder []string
	lastScanAt    time.Time
}

func newAuditNotifyGuard() *auditNotifyGuard {
	return &auditNotifyGuard{
		knownMACs: make(map[string]struct{}),
	}
}

func (g *auditNotifyGuard) shouldScanNow(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.lastScanAt.IsZero() && now.Sub(g.lastScanAt) < defaultAuditAlertScanInterval {
		return false
	}
	g.lastScanAt = now
	return true
}

// Notifier 返回守护进程持有的多渠道告警调度器（供单进程合体 WebUI 共享同一实例与历史缓冲）。
func (d *Daemon) Notifier() *notify.Dispatcher {
	if d == nil {
		return nil
	}
	return d.notifier
}

func (d *Daemon) emitNotify(ev notify.Event) {
	if d == nil || d.notifier == nil {
		return
	}
	d.notifier.Emit(ev)
}

func (d *Daemon) syncNotifierConfig(cfg *config.Config) {
	if d == nil || d.notifier == nil || cfg == nil {
		return
	}
	d.notifier.UpdateOptions(notify.OptionsFromConfig(cfg.Notify))
}

// GuardTailscaleOOMOnce 按配置检查并维持 tailscaled 的 oom_score_adj=-1000（无 tailscaled 时静默跳过）。
func (d *Daemon) GuardTailscaleOOMOnce() bool {
	if d == nil {
		return false
	}
	cfg := d.currentConfig()
	if cfg == nil || !cfg.SafeCommit.IsProtectTailscaleOOM() {
		return false
	}
	if d.protectOOMFn == nil && strings.TrimSpace(d.oomProcRoot) == "" && runtime.GOOS != "linux" {
		return false
	}

	protectFn := d.protectOOMFn
	if protectFn == nil {
		protectFn = safecommit.ProtectTailscaledOOM
	}
	st, err := protectFn(d.oomProcRoot)
	if err != nil {
		if errors.Is(err, safecommit.ErrTailscaledNotFound) {
			return false
		}
		logger.Warn("[Watchdog] 维护 tailscaled OOM 免疫保护失败: %v", err)
		return false
	}
	if !st.Protected {
		return false
	}

	d.oomGuardMu.Lock()
	changedPID := st.PID > 0 && st.PID != d.lastOOMProtectedPID
	if changedPID {
		d.lastOOMProtectedPID = st.PID
	}
	d.oomGuardMu.Unlock()

	if changedPID {
		logger.Info("[Watchdog] 已为 tailscaled (PID %d) 锁定 OOM 免疫保护 (oom_score_adj=%d)", st.PID, st.ScoreAdj)
	}
	return true
}

// CheckHostResourcesOnce 采集一次宿主机实时遥测，对闪存/根分区与可用内存执行预警与恢复通知。
func (d *Daemon) CheckHostResourcesOnce() {
	if d == nil || d.resourceGuard == nil {
		return
	}
	_ = d.currentConfig()

	var tel sysinfo.HostTelemetry
	if d.telemetryDeps != nil {
		tel = sysinfo.CollectHostTelemetryWithDeps(d.cpuSampler, *d.telemetryDeps)
	} else {
		tel = sysinfo.CollectHostTelemetry(d.cpuSampler)
	}

	d.evaluateDiskResource(tel.Disk)
	d.evaluateMemResource(tel.Mem)
}

func (d *Daemon) evaluateDiskResource(disk sysinfo.DiskTelemetry) {
	if disk.TotalBytes == 0 {
		return
	}
	mount := cmp.Or(strings.TrimSpace(disk.MountPath), "/")
	dedupKey := "disk:" + mount
	breached := disk.UsedPercent >= resourceDiskWarnUsedPct || disk.AvailBytes < resourceDiskCritAvailBytes

	d.resourceGuard.mu.Lock()
	wasActive := d.resourceGuard.diskAlertActive
	prevKey := cmp.Or(d.resourceGuard.diskAlertKey, dedupKey)
	if breached {
		d.resourceGuard.diskAlertActive = true
		d.resourceGuard.diskAlertKey = dedupKey
	} else if wasActive {
		d.resourceGuard.diskAlertActive = false
	}
	d.resourceGuard.mu.Unlock()

	availMiB := float64(disk.AvailBytes) / (1024.0 * 1024.0)
	if breached {
		sev := notify.SeverityWarn
		if disk.UsedPercent >= resourceDiskCritUsedPct || disk.AvailBytes < resourceDiskCritAvailBytes {
			sev = notify.SeverityCritical
		}
		d.emitNotify(notify.Event{
			Type:     notify.EventResourceGuard,
			Severity: sev,
			DedupKey: dedupKey,
			Title:    fmt.Sprintf("存储空间告急 (%s)", mount),
			Body:     fmt.Sprintf("%s 已用 %d%%，剩余 %.1f MiB，请及时清理日志或缓存防止升级/写入失败。", mount, disk.UsedPercent, availMiB),
			Resolved: false,
		})
		return
	}

	if wasActive {
		d.emitNotify(notify.Event{
			Type:     notify.EventResourceGuard,
			Severity: notify.SeverityInfo,
			DedupKey: prevKey,
			Title:    fmt.Sprintf("存储空间已恢复 (%s)", mount),
			Body:     fmt.Sprintf("%s 当前已用 %d%%，剩余 %.1f MiB，已退出告急阈值。", mount, disk.UsedPercent, availMiB),
			Resolved: true,
		})
	}
}

func (d *Daemon) evaluateMemResource(mem sysinfo.MemTelemetry) {
	if mem.TotalBytes == 0 {
		return
	}
	const dedupKey = "mem:avail"
	breached := mem.AvailBytes < resourceMemCritAvailBytes

	d.resourceGuard.mu.Lock()
	wasActive := d.resourceGuard.memAlertActive
	if breached {
		d.resourceGuard.memAlertActive = true
	} else if wasActive {
		d.resourceGuard.memAlertActive = false
	}
	d.resourceGuard.mu.Unlock()

	availMiB := float64(mem.AvailBytes) / (1024.0 * 1024.0)
	totalMiB := float64(mem.TotalBytes) / (1024.0 * 1024.0)
	if breached {
		d.emitNotify(notify.Event{
			Type:     notify.EventResourceGuard,
			Severity: notify.SeverityCritical,
			DedupKey: dedupKey,
			Title:    "宿主机可用内存告急",
			Body:     fmt.Sprintf("当前 MemAvailable 仅剩 %.1f MiB / %.1f MiB（阈值 48 MiB），存在 OOM 风险。", availMiB, totalMiB),
			Resolved: false,
		})
		return
	}

	if wasActive {
		d.emitNotify(notify.Event{
			Type:     notify.EventResourceGuard,
			Severity: notify.SeverityInfo,
			DedupKey: dedupKey,
			Title:    "宿主机可用内存已恢复",
			Body:     fmt.Sprintf("当前 MemAvailable 已恢复至 %.1f MiB / %.1f MiB。", availMiB, totalMiB),
			Resolved: true,
		})
	}
}

// RecordWatchdogHealEvent 发送 sing-box 看门狗异常自愈或恢复健康通知（与 notify 冷却恢复配对联动）。
func (d *Daemon) RecordWatchdogHealEvent(recovered bool, reason, detail string) {
	if d == nil {
		return
	}
	body := cmp.Or(strings.TrimSpace(detail), strings.TrimSpace(reason), "sing-box 状态变化")
	if recovered {
		d.emitNotify(notify.Event{
			Type:     notify.EventWatchdogHeal,
			Severity: notify.SeverityInfo,
			DedupKey: "singbox:health",
			Title:    "sing-box 已自愈恢复健康",
			Body:     body,
			Resolved: true,
		})
		return
	}
	title := "sing-box 异常触发看门狗自愈"
	if r := strings.TrimSpace(reason); r != "" {
		title = fmt.Sprintf("sing-box 异常自愈 (%s)", r)
	}
	d.emitNotify(notify.Event{
		Type:     notify.EventWatchdogHeal,
		Severity: notify.SeverityCritical,
		DedupKey: "singbox:health",
		Title:    title,
		Body:     body,
		Resolved: false,
	})
}

func (d *Daemon) recordSubOrNodeFailEvent(dedupKey string, severity notify.Severity, resolved bool, title, body string) {
	if d == nil {
		return
	}
	d.emitNotify(notify.Event{
		Type:     notify.EventSubOrNodeFail,
		Severity: severity,
		DedupKey: dedupKey,
		Title:    title,
		Body:     body,
		Resolved: resolved,
	})
}

// ObserveAuditReport 观察审计报告中的首次出现未知 LAN MAC 与未封禁高危连接并异步触发告警。
func (d *Daemon) ObserveAuditReport(report *audit.Report) {
	if d == nil || d.auditGuard == nil || report == nil || !report.Reachable {
		return
	}

	var newDevices []audit.DeviceSummary
	if len(report.Devices) > 0 {
		d.auditGuard.mu.Lock()
		if !d.auditGuard.seeded {
			for _, dev := range report.Devices {
				mac := normalizeMAC(dev.DeviceMAC)
				if mac != "" {
					d.auditGuard.recordMACLocked(mac)
				}
			}
			d.auditGuard.seeded = true
		} else {
			for _, dev := range report.Devices {
				mac := normalizeMAC(dev.DeviceMAC)
				if mac == "" {
					continue
				}
				if _, seen := d.auditGuard.knownMACs[mac]; !seen {
					d.auditGuard.recordMACLocked(mac)
					newDevices = append(newDevices, dev)
				}
			}
		}
		d.auditGuard.mu.Unlock()
	}

	for _, dev := range newDevices {
		mac := normalizeMAC(dev.DeviceMAC)
		name := cmp.Or(strings.TrimSpace(dev.DeviceName), strings.TrimSpace(dev.DeviceIP), mac)
		d.emitNotify(notify.Event{
			Type:     notify.EventNewDevice,
			Severity: notify.SeverityInfo,
			DedupKey: "mac:" + mac,
			Title:    fmt.Sprintf("发现新局域网设备: %s", name),
			Body:     fmt.Sprintf("IP: %s | MAC: %s", cmp.Or(strings.TrimSpace(dev.DeviceIP), "-"), mac),
		})
	}

	for _, flow := range report.Flows {
		if flow.Threat != audit.ThreatHighRisk || flow.State != audit.EnforcementObserved {
			continue
		}
		devLabel := cmp.Or(strings.TrimSpace(flow.DeviceName), strings.TrimSpace(flow.DeviceIP), "未知设备")
		target := strings.TrimSpace(flow.Target)
		if target == "" {
			continue
		}
		reasonText := strings.Join(flow.Reasons, "；")
		body := fmt.Sprintf("设备 %s (%s) 访问 %s，风险评分 %d。", devLabel, flow.DeviceIP, target, flow.RiskScore)
		if reasonText != "" {
			body += " 原因: " + reasonText
		}
		d.emitNotify(notify.Event{
			Type:     notify.EventAuditHighRisk,
			Severity: notify.SeverityWarn,
			DedupKey: fmt.Sprintf("risk:%s:%s", strings.TrimSpace(flow.DeviceIP), target),
			Title:    fmt.Sprintf("审计高危告警: %s -> %s", devLabel, target),
			Body:     body,
		})
	}
}

func (g *auditNotifyGuard) recordMACLocked(mac string) {
	if _, exists := g.knownMACs[mac]; exists {
		return
	}
	if len(g.knownMACOrder) >= maxTrackedLANMACs {
		oldest := g.knownMACOrder[0]
		copy(g.knownMACOrder, g.knownMACOrder[1:])
		g.knownMACOrder = g.knownMACOrder[:len(g.knownMACOrder)-1]
		delete(g.knownMACs, oldest)
	}
	g.knownMACs[mac] = struct{}{}
	g.knownMACOrder = append(g.knownMACOrder, mac)
}

func normalizeMAC(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func (d *Daemon) maybeObserveAuditAlerts(ctx context.Context, cfg *config.Config, collector *audit.Collector) {
	if d == nil || d.auditGuard == nil || cfg == nil || collector == nil || !cfg.Notify.Enabled {
		return
	}
	evs := cfg.Notify.EffectiveEvents()
	if !evs.AuditHighRisk && !evs.NewDevice {
		return
	}
	if !d.auditGuard.shouldScanNow(time.Now()) {
		return
	}
	rep := collector.CollectWithConfig(ctx, cfg, audit.CollectOptions{
		OnlySuspect: false,
		EnableAI:    false,
		Limit:       50,
	})
	d.ObserveAuditReport(rep)
}
