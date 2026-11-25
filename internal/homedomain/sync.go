// 文件职责：负责设备托管重写与用户手动重写的无损差量合并、双引擎本地 DNS 同步、sing-box 配置热补丁及四项端到端连通性自检。
package homedomain

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/localdns"
	"singctl/internal/singbox"
)

func rewriteKey(r config.DNSRewriteRule) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(r.Domain), ".")) + "|" + strings.TrimSpace(r.Answer)
}

// ComputeRewriteDiff 将旧托管集与新托管集无损合并进既有 DNS.Rewrites，严格保留所有用户手动自定义重写，
// 返回合并后的完整列表及需要向运行中 DNS 引擎执行的增量增删清单。
func ComputeRewriteDiff(existing, prevManaged, nextManaged []config.DNSRewriteRule) (merged, toAdd, toDelete []config.DNSRewriteRule) {
	prevSet := make(map[string]struct{}, len(prevManaged))
	for _, r := range prevManaged {
		prevSet[rewriteKey(r)] = struct{}{}
	}
	nextSet := make(map[string]struct{}, len(nextManaged))
	for _, r := range nextManaged {
		nextSet[rewriteKey(r)] = struct{}{}
	}

	// 1. 保留所有非旧托管的手动规则；若某条规则同时存在于新托管集中，去重后合并
	manualKept := make([]config.DNSRewriteRule, 0, len(existing))
	existingKeySet := make(map[string]struct{}, len(existing))
	for _, r := range existing {
		k := rewriteKey(r)
		existingKeySet[k] = struct{}{}
		if _, wasManaged := prevSet[k]; wasManaged {
			if _, stillManaged := nextSet[k]; !stillManaged {
				toDelete = append(toDelete, r)
			}
			continue
		}
		if _, nowManaged := nextSet[k]; nowManaged {
			continue
		}
		manualKept = append(manualKept, r)
	}

	// 2. 计算需要新增至引擎的新托管规则
	for _, r := range nextManaged {
		if _, exists := existingKeySet[rewriteKey(r)]; !exists {
			toAdd = append(toAdd, r)
		}
	}

	merged = make([]config.DNSRewriteRule, 0, len(manualKept)+len(nextManaged))
	merged = append(merged, manualKept...)
	merged = append(merged, nextManaged...)
	return merged, toAdd, toDelete
}

// SyncAllDeps 注入同步全部底层链路所需的引擎、路径与系统替身（零值回退生产默认）。
type SyncAllDeps struct {
	Engine             localdns.Engine
	SingBoxConfigPath  string
	DnsmasqDeps        DnsmasqDeps
	ApplySingBoxConfig func(ctx context.Context, sbPath, updatedJSON string) error
	ReloadSingBox      func(ctx context.Context) error
}

// SyncResult 汇总一次本地域名全链路同步的执行结果。
type SyncResult struct {
	AddedRewrites    int
	DeletedRewrites  int
	SingBoxPatched   bool
	DnsmasqChanged   bool
	Warnings         []string
}

// SyncAllReconcile 将 cfg.HomeDomain 同步到 cfg.DNS.Rewrites、活跃本地 DNS 引擎（AdGuard/SmartDNS）、
// sing-box 本地解析规则以及 OpenWrt dnsmasq 精准豁免配置。
func SyncAllReconcile(ctx context.Context, cfg *config.Config, prevManaged []config.DNSRewriteRule, prevSuffix string, deps SyncAllDeps) SyncResult {
	var res SyncResult
	if cfg == nil {
		return res
	}
	if ctx == nil {
		ctx = context.Background()
	}

	nextManaged := cfg.HomeDomain.BuildManagedRewrites()
	merged, toAdd, toDelete := ComputeRewriteDiff(cfg.DNS.Rewrites, prevManaged, nextManaged)
	cfg.DNS.Rewrites = merged
	res.AddedRewrites = len(toAdd)
	res.DeletedRewrites = len(toDelete)

	// 1. 推送差量至当前活跃本地 DNS 引擎（AdGuard Home 或 SmartDNS）
	if deps.Engine != nil && deps.Engine.IsInstalled() {
		for _, r := range toDelete {
			if err := deps.Engine.DeleteRewrite(ctx, r.Domain, r.Answer); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("清理旧重写 %s 失败: %v", r.Domain, err))
			}
		}
		for _, r := range toAdd {
			if err := deps.Engine.AddRewrite(ctx, r.Domain, r.Answer); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("同步重写 %s -> %s 失败: %v", r.Domain, r.Answer, err))
			}
		}
		// 确保同步后 cfg.DNS.Rewrites 与合并结果完全一致（避免引擎方法覆盖切片顺序）
		cfg.DNS.Rewrites = merged
	}

	// 2. 热补丁 sing-box 配置，置顶 .<suffix> 走 dns_local 与 direct 路由
	sbPath := strings.TrimSpace(deps.SingBoxConfigPath)
	if sbPath == "" {
		sbPath = constant.SingBoxConfigFile
	}
	activeSuffix := ""
	if cfg.HomeDomain.IsEnabled() && len(cfg.HomeDomain.Devices) > 0 {
		activeSuffix = cfg.HomeDomain.EffectiveSuffix()
	}
	if sbPath != "" {
		if raw, err := os.ReadFile(sbPath); err == nil && len(raw) > 0 {
			patched, changed, pErr := singbox.PatchHomeDomainDNSJSON(string(raw), activeSuffix, prevSuffix)
			if pErr != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("修补 sing-box 本地域名规则失败: %v", pErr))
			} else if changed {
				if deps.ApplySingBoxConfig != nil {
					if aErr := deps.ApplySingBoxConfig(ctx, sbPath, patched); aErr != nil {
						res.Warnings = append(res.Warnings, fmt.Sprintf("安全校验并应用 sing-box 配置失败: %v", aErr))
					} else {
						res.SingBoxPatched = true
					}
				} else if wErr := fsx.WriteAtomic(sbPath, []byte(patched), 0600); wErr != nil {
					res.Warnings = append(res.Warnings, fmt.Sprintf("写入 sing-box 配置失败: %v", wErr))
				} else {
					res.SingBoxPatched = true
					if deps.ReloadSingBox != nil {
						if rErr := deps.ReloadSingBox(ctx); rErr != nil {
							res.Warnings = append(res.Warnings, fmt.Sprintf("热重载 sing-box 失败: %v", rErr))
						}
					}
				}
			}
		}
	}

	// 3. OpenWrt dnsmasq 精准 rebind_domain + server=/<suffix>/127.0.0.1#<port> + notinterface=tailscale0
	hasActiveDevices := cfg.HomeDomain.IsEnabled() && len(cfg.HomeDomain.Devices) > 0
	dmChanged, dmErr := ReconcileOpenWrtDnsmasq(ctx, DnsmasqDesired{
		Enabled:          hasActiveDevices,
		Suffix:           cfg.HomeDomain.EffectiveSuffix(),
		PrevSuffix:       prevSuffix,
		LocalDNSPort:     cfg.DNS.GetDNSPort(),
		ExcludeTailscale: cfg.HomeDomain.IsTailscaleDNSEnabled(),
	}, deps.DnsmasqDeps)
	res.DnsmasqChanged = dmChanged
	if dmErr != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("同步 OpenWrt dnsmasq 配置失败: %v", dmErr))
	}

	return res
}

// VerifyCheck 描述端到端自检报告中的单项验证结果。
type VerifyCheck struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Status  string `json:"status"` // "pass" | "warn" | "fail"
	Detail  string `json:"detail"`
	RTTMs   int64  `json:"rttMs,omitempty"`
	FixHint string `json:"fixHint,omitempty"`
}

// VerifyReport 汇总 4 项本地域名 + Tailscale Split-DNS 端到端自检结果。
type VerifyReport struct {
	SampleDomain string        `json:"sampleDomain,omitempty"`
	ExpectedIP   string        `json:"expectedIp,omitempty"`
	OverallOK    bool          `json:"overallOk"`
	Checks       []VerifyCheck `json:"checks"`
}

// VerifyDeps 显式注入端到端探活所需参数。
type VerifyDeps struct {
	LocalDNSAddr      string
	LanDNSAddr        string
	TailscaleDNSAddr  string
	AdvertisedSubnets []string
	TailscalePeers    []DiscoveredTailscalePeer
	ProbeFunc         func(ctx context.Context, addr, domain string, timeout time.Duration) ([]string, time.Duration, error)
}

// Verify 执行四项端到端解析与外网可达性自检（本地 DNS 引擎、LAN dnsmasq、Tailscale Split-DNS 端口、外网路由覆盖）。
func Verify(ctx context.Context, cfg *config.Config, deps VerifyDeps) VerifyReport {
	var rep VerifyReport
	if cfg == nil || len(cfg.HomeDomain.Devices) == 0 {
		rep.Checks = []VerifyCheck{{
			ID:     "devices",
			Title:  "命名设备检查",
			Status: "warn",
			Detail: "当前尚未添加任何本地域名设备，请先为至少一台设备（如本机路由）设置短域名",
		}}
		return rep
	}

	suffix := cfg.HomeDomain.EffectiveSuffix()
	sampleDev := cfg.HomeDomain.Devices[0]
	sampleFQDN := strings.ToLower(strings.TrimSpace(sampleDev.Alias)) + "." + suffix
	rep.SampleDomain = sampleFQDN
	rep.ExpectedIP = strings.TrimSpace(sampleDev.IP)

	probe := deps.ProbeFunc
	if probe == nil {
		probe = ProbeDNSRecord
	}

	// 1. 本地防劫持 DNS 引擎 (127.0.0.1:<dnsPort>)
	localAddr := deps.LocalDNSAddr
	if localAddr == "" {
		localAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.DNS.GetDNSPort()))
	}
	ips, rtt, err := probe(ctx, localAddr, sampleFQDN, 2*time.Second)
	if err == nil && slices.Contains(ips, rep.ExpectedIP) {
		rep.Checks = append(rep.Checks, VerifyCheck{
			ID:     "local_dns",
			Title:  "本地防劫持 DNS 解析",
			Status: "pass",
			Detail: fmt.Sprintf("%s 返回 %s -> %s", localAddr, sampleFQDN, rep.ExpectedIP),
			RTTMs:  rtt.Milliseconds(),
		})
	} else {
		detail := fmt.Sprintf("查询 %s 失败: %v", localAddr, err)
		if err == nil {
			detail = fmt.Sprintf("%s 返回 %v，期望 %s", localAddr, ips, rep.ExpectedIP)
		}
		rep.Checks = append(rep.Checks, VerifyCheck{
			ID:      "local_dns",
			Title:   "本地防劫持 DNS 解析",
			Status:  "fail",
			Detail:  detail,
			FixHint: "请确认 AdGuard Home 或 SmartDNS 正在运行并重新保存一次本地域名设置",
		})
	}

	// 2. 局域网 dnsmasq (LAN:53) Rebind 防护豁免探测
	lanAddr := strings.TrimSpace(deps.LanDNSAddr)
	if lanAddr != "" {
		lIPs, lRTT, lErr := probe(ctx, lanAddr, sampleFQDN, 2*time.Second)
		if lErr == nil && slices.Contains(lIPs, rep.ExpectedIP) {
			rep.Checks = append(rep.Checks, VerifyCheck{
				ID:     "lan_dnsmasq",
				Title:  "局域网网关 DNS (含 Rebind 放行)",
				Status: "pass",
				Detail: fmt.Sprintf("%s 正常返回 %s", lanAddr, rep.ExpectedIP),
				RTTMs:  lRTT.Milliseconds(),
			})
		} else {
			detail := fmt.Sprintf("%s 查询未返回预期私网 IP (%v / %v)", lanAddr, lIPs, lErr)
			rep.Checks = append(rep.Checks, VerifyCheck{
				ID:      "lan_dnsmasq",
				Title:   "局域网网关 DNS (含 Rebind 放行)",
				Status:  "warn",
				Detail:  detail,
				FixHint: "若 OpenWrt dnsmasq 拦截了私网回包，请保存设置触发 rebind_domain 自动同步",
			})
		}
	}

	// 3. Tailscale Split-DNS 内置应答器 (<TS_IP>:53)
	tsAddr := strings.TrimSpace(deps.TailscaleDNSAddr)
	if !cfg.HomeDomain.IsTailscaleDNSEnabled() {
		rep.Checks = append(rep.Checks, VerifyCheck{
			ID:     "tailscale_split_dns",
			Title:  "Tailscale Split-DNS 应答器",
			Status: "warn",
			Detail: "已在设置中关闭内置 Tailscale Split-DNS 应答器（仅限局域网内解析）",
		})
	} else if tsAddr == "" {
		rep.Checks = append(rep.Checks, VerifyCheck{
			ID:      "tailscale_split_dns",
			Title:   "Tailscale Split-DNS 应答器",
			Status:  "warn",
			Detail:  "未检测到本机 Tailscale 虚拟 IP，请先在「Tailscale 组网」启动并登录节点",
			FixHint: "启动 Tailscale 后守护进程会自动在 <Tailscale_IP>:53 拉起专属应答器",
		})
	} else {
		tIPs, tRTT, tErr := probe(ctx, tsAddr, sampleFQDN, 2*time.Second)
		if tErr == nil && slices.Contains(tIPs, rep.ExpectedIP) {
			rep.Checks = append(rep.Checks, VerifyCheck{
				ID:     "tailscale_split_dns",
				Title:  "Tailscale Split-DNS 应答器",
				Status: "pass",
				Detail: fmt.Sprintf("%s 毫秒级应答 %s -> %s（仅放行 Tailscale 隧道来源）", tsAddr, sampleFQDN, rep.ExpectedIP),
				RTTMs:  tRTT.Milliseconds(),
			})
		} else {
			rep.Checks = append(rep.Checks, VerifyCheck{
				ID:      "tailscale_split_dns",
				Title:   "Tailscale Split-DNS 应答器",
				Status:  "fail",
				Detail:  fmt.Sprintf("%s 探测失败: %v（返回 %v）", tsAddr, tErr, tIPs),
				FixHint: "请确认 singctl 守护进程正在运行，且 OpenWrt dnsmasq 已放开 tailscale0 接口端口 53",
			})
		}
	}

	// 4. 外网可达性路由覆盖检查
	advPrefixes := ParseAdvertisedPrefixes(deps.AdvertisedSubnets)
	var lanOnlyNames []string
	for _, d := range cfg.HomeDomain.Devices {
		info := EvaluateReachability(d, advPrefixes, deps.TailscalePeers)
		if info.Status == "lan_only" {
			lanOnlyNames = append(lanOnlyNames, d.Alias+"."+suffix)
		}
	}
	if len(lanOnlyNames) == 0 {
		rep.Checks = append(rep.Checks, VerifyCheck{
			ID:     "remote_reachability",
			Title:  "外出跨网可达性检查",
			Status: "pass",
			Detail: fmt.Sprintf("全部 %d 台命名设备均已通过 Tailscale IP 或已广播子网覆盖，外出可直接访问", len(cfg.HomeDomain.Devices)),
		})
	} else {
		rep.Checks = append(rep.Checks, VerifyCheck{
			ID:      "remote_reachability",
			Title:   "外出跨网可达性检查",
			Status:  "warn",
			Detail:  fmt.Sprintf("以下设备当前仅局域网可达: %s", strings.Join(lanOnlyNames, ", ")),
			FixHint: "可在设备卡片上一键改用 Tailscale IP，或在 Tailscale 组网中补充对应网段广播",
		})
	}

	rep.OverallOK = true
	for _, c := range rep.Checks {
		if c.Status == "fail" {
			rep.OverallOK = false
			break
		}
	}
	return rep
}
