// 文件职责：负责嗅探监控的本机与舰队集群协同防火墙封禁/解封执行、防自锁防注入校验（validateSniffBlockTarget）及远端 nftables 自举修复脚本生成。
//
// 架构设计原则：
//   - 安全防自锁与防注入（Validate Before Enforcing）：封禁前强制汇聚操作者 IP、可信客户端白名单与 Fleet 节点 IP 并校验掩码下限（IPv4 >= /16，IPv6 >= /32），
//     所有进入远程 SSH 与 nftables 的目标字符串均由 net.ParseIP/ParseCIDR 规范化输出，彻底杜绝 Shell 注入。
//   - 复用公共编排单元：通过 validateSniffBlockTarget、selectScopeRemoteNodes 与 runRemoteNFTScripts 消除封禁/解封/全清之间的重复逻辑。
package serverweb

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/constant"
	"singctl/internal/firewall"
	"singctl/internal/fleet"
	"singctl/internal/logger"
)

type sniffBlockTargetSpec struct {
	canonical string
	isCIDR    bool
	isIPv4    bool
	parsedNet *net.IPNet
}

// validateSniffBlockTarget 解析并校验封禁/解封目标；enforceSafetyGuards=true 时额外阻断内网地址、宽泛网段与管理员/集群白名单 IP，防止误锁死。
func validateSniffBlockTarget(target string, protectedSet map[string]struct{}, enforceSafetyGuards bool) (sniffBlockTargetSpec, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return sniffBlockTargetSpec{}, fmt.Errorf("封禁目标不能为空")
	}

	if strings.Contains(target, "/") {
		ip, ipNet, err := net.ParseCIDR(target)
		if err != nil || ip == nil || ipNet == nil {
			return sniffBlockTargetSpec{}, fmt.Errorf("无效的 CIDR 网段格式: %s", target)
		}
		ones, bits := ipNet.Mask.Size()
		if enforceSafetyGuards {
			if bits == 32 && ones < 16 {
				return sniffBlockTargetSpec{}, fmt.Errorf("为防止误伤大面积网络，IPv4 网段掩码长度须在 /16 至 /32 之间")
			}
			if bits == 128 && ones < 32 {
				return sniffBlockTargetSpec{}, fmt.Errorf("IPv6 网段掩码长度须在 /32 至 /128 之间")
			}
			if isIgnoredInternalIP(ip.String()) {
				return sniffBlockTargetSpec{}, fmt.Errorf("安全防锁死保护：禁止封禁本地回环、局域网或内网保留网段 (%s)", target)
			}
			for protIPStr := range protectedSet {
				if protIP := net.ParseIP(protIPStr); protIP != nil && ipNet.Contains(protIP) {
					return sniffBlockTargetSpec{}, fmt.Errorf("安全防锁死保护：目标网段 (%s) 包含当前管理会话或受保护节点 IP (%s)，已拒绝执行", target, protIPStr)
				}
			}
		}
		return sniffBlockTargetSpec{
			canonical: ipNet.String(),
			isCIDR:    true,
			isIPv4:    bits == 32,
			parsedNet: ipNet,
		}, nil
	}

	ipStr := normalizeIPString(target)
	if ipStr == "" {
		return sniffBlockTargetSpec{}, fmt.Errorf("无效的 IP 地址格式: %s", target)
	}
	if enforceSafetyGuards {
		if isIgnoredInternalIP(ipStr) {
			return sniffBlockTargetSpec{}, fmt.Errorf("安全防锁死保护：禁止封禁本地回环或内网保留地址 (%s)", ipStr)
		}
		if _, isProtected := protectedSet[ipStr]; isProtected {
			return sniffBlockTargetSpec{}, fmt.Errorf("安全防锁死保护：禁止拉黑您当前所在的管理 IP 或集群受保护节点 (%s)", ipStr)
		}
	}
	parsedIP := net.ParseIP(ipStr)
	return sniffBlockTargetSpec{
		canonical: ipStr,
		isCIDR:    false,
		isIPv4:    parsedIP != nil && parsedIP.To4() != nil,
	}, nil
}

func (t *SniffTracker) collectProtectedIPSet(operatorIP string, extraProtectedIPs ...string) (map[string]struct{}, *fleet.Manager) {
	protectedSet := make(map[string]struct{})
	if opNorm := normalizeIPString(operatorIP); opNorm != "" {
		protectedSet[opNorm] = struct{}{}
	}
	for _, p := range extraProtectedIPs {
		if norm := normalizeIPString(p); norm != "" {
			protectedSet[norm] = struct{}{}
		}
	}

	t.mu.RLock()
	now := time.Now()
	for ip, exp := range t.trustedClients {
		if now.Before(exp) {
			protectedSet[ip] = struct{}{}
		}
	}
	fleetMgr := t.fleetMgr
	t.mu.RUnlock()

	if fleetMgr != nil && fleetMgr.Store != nil {
		if fNodes, err := fleetMgr.Store.ListPublic(); err == nil {
			for _, fn := range fNodes {
				if norm := normalizeIPString(fn.Host); norm != "" {
					protectedSet[norm] = struct{}{}
				}
			}
		}
	}
	return protectedSet, fleetMgr
}

func selectScopeRemoteNodes(fleetMgr *fleet.Manager, nodeScope string) []fleet.Node {
	if fleetMgr == nil || fleetMgr.Store == nil || (nodeScope != "all" && nodeScope == "local") {
		return nil
	}
	allNodes, err := fleetMgr.Store.List()
	if err != nil {
		return nil
	}
	var remoteNodes []fleet.Node
	for _, n := range allNodes {
		if !n.Enabled {
			continue
		}
		if nodeScope == "all" || n.ID == nodeScope {
			remoteNodes = append(remoteNodes, n)
		}
	}
	return remoteNodes
}

// BlockTarget 手动在本机拉黑单个嗅探 IP 或 /24 网段 (保持向后兼容)
func (t *SniffTracker) BlockTarget(target, operatorIP string, extraProtectedIPs ...string) (string, error) {
	canonical, _, err := t.BlockTargetForNode(context.Background(), target, "local", operatorIP, extraProtectedIPs...)
	return canonical, err
}

// BlockTargetForNode 手动在指定主机 ("local" | "<node_id>" | "all") 一键拉黑单个嗅探 IP 或 /24 网段
func (t *SniffTracker) BlockTargetForNode(ctx context.Context, target, nodeScope, operatorIP string, extraProtectedIPs ...string) (string, int, error) {
	nodeScope = cmp.Or(strings.TrimSpace(nodeScope), "all")
	protectedSet, fleetMgr := t.collectProtectedIPSet(operatorIP, extraProtectedIPs...)

	spec, err := validateSniffBlockTarget(target, protectedSet, true)
	if err != nil {
		return "", 0, err
	}

	applyLocal := nodeScope == "all" || nodeScope == "local"
	remoteNodes := selectScopeRemoteNodes(fleetMgr, nodeScope)

	now := time.Now()
	t.mu.Lock()
	t.applyBlockStateLocked(spec, nodeScope, applyLocal, remoteNodes, now)
	t.markDirtyLocked()
	raw, seq := t.snapshotPersistBytesLocked(now, true)
	t.mu.Unlock()
	t.persistSnapshot(raw, seq)

	appliedNodes := 0
	var localNFTErr error
	if applyLocal {
		if spec.isCIDR {
			localNFTErr = applyNFTBlockCIDR(spec.canonical, spec.isIPv4)
		} else {
			if t.limiter != nil {
				t.limiter.BanManual(spec.canonical, 7*24*time.Hour)
			}
			localNFTErr = applyNFTBlockIP(spec.canonical, spec.isIPv4)
		}
		if localNFTErr == nil || os.Geteuid() != 0 {
			appliedNodes++
		} else {
			logger.Warn("本机 nftables 写入封禁规则失败 (%s): %v", spec.canonical, localNFTErr)
		}
	}

	if len(remoteNodes) > 0 && fleetMgr != nil {
		if script := buildRemoteNFTBlockScript(spec.canonical, spec.isCIDR, spec.isIPv4); script != "" {
			appliedNodes += runRemoteNFTScripts(ctx, fleetMgr, remoteNodes, script, 5*time.Second)
		}
	}

	if nodeScope == "local" && localNFTErr != nil && os.Geteuid() == 0 {
		return spec.canonical, 0, fmt.Errorf("本机内核防火墙写入封禁规则失败: %w", localNFTErr)
	}

	return spec.canonical, appliedNodes, nil
}

func (t *SniffTracker) applyBlockStateLocked(spec sniffBlockTargetSpec, nodeScope string, applyLocal bool, remoteNodes []fleet.Node, now time.Time) {
	targetNodeIDs := make([]string, 0, 1+len(remoteNodes))
	if applyLocal {
		targetNodeIDs = append(targetNodeIDs, "local")
	}
	for _, rn := range remoteNodes {
		targetNodeIDs = append(targetNodeIDs, rn.ID)
	}
	if len(targetNodeIDs) == 0 && nodeScope != "local" {
		targetNodeIDs = append(targetNodeIDs, nodeScope)
	}

	if spec.isCIDR {
		if nodeScope == "all" || nodeScope == "local" {
			t.manualBlockedCIDRs[spec.canonical] = spec.parsedNet
		}
		for _, nid := range targetNodeIDs {
			if t.nodeBlockedCIDRs[nid] == nil {
				t.nodeBlockedCIDRs[nid] = make(map[string]*net.IPNet)
			}
			t.nodeBlockedCIDRs[nid][spec.canonical] = spec.parsedNet
			if nodeMap, ok := t.recordsByNode[nid]; ok {
				for _, rec := range nodeMap {
					if recIP := net.ParseIP(rec.ip); recIP != nil && spec.parsedNet.Contains(recIP) {
						rec.status = "banned"
					}
				}
			}
		}
		if nodeScope == "all" {
			for _, nodeMap := range t.recordsByNode {
				for _, rec := range nodeMap {
					if recIP := net.ParseIP(rec.ip); recIP != nil && spec.parsedNet.Contains(recIP) {
						rec.status = "banned"
					}
				}
			}
		}
		return
	}

	for _, nid := range targetNodeIDs {
		nodeName := resolveScopeNodeDisplayName(nid, remoteNodes)
		t.observeNodeAtLocked(nid, nodeName, spec.canonical, "管理员手动拉黑", "banned", 1, true, time.Time{}, now)
		if rec, ok := t.recordsByNode[nid][spec.canonical]; ok {
			rec.status = "banned"
		}
	}
	if nodeScope == "all" {
		for _, nodeMap := range t.recordsByNode {
			if rec, ok := nodeMap[spec.canonical]; ok {
				rec.status = "banned"
			}
		}
	}
}

func resolveScopeNodeDisplayName(nid string, remoteNodes []fleet.Node) string {
	if nid == "local" {
		return "本机网关"
	}
	for _, rn := range remoteNodes {
		if rn.ID == nid {
			return cmp.Or(rn.Name, rn.ID)
		}
	}
	return nid
}

const remoteEnsureSecurityNFTBlock = `if ! nft list table inet security >/dev/null 2>&1; then
  modprobe nf_tables 2>/dev/null || /sbin/modprobe nf_tables 2>/dev/null || true
  if [ -f /etc/sing-box/sec_block.nft ] && nft -c -f /etc/sing-box/sec_block.nft >/dev/null 2>&1; then
    nft -f /etc/sing-box/sec_block.nft >/dev/null 2>&1 || true
  fi
  if ! nft list table inet security >/dev/null 2>&1; then
    nft -f - <<'SINGCTL_NFT_EOF'
` + `table inet security {
    set blocklist_ip4_forever {
        type ipv4_addr
        flags interval
        auto-merge
        size 65535
    }
    set blocklist_ip4 {
        type ipv4_addr
        flags dynamic,timeout
        size 65535
        timeout 7d
    }
    set blocklist_ip6 {
        type ipv6_addr
        flags dynamic,timeout
        size 65535
        timeout 7d
    }
    set whitelist_ip {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }
    }
    chain input {
        type filter hook input priority 0; policy accept;
        ct state established,related counter accept
        iifname "lo" counter accept
        iifname "tailscale0" counter accept
        iifname "wg*" counter accept
        iifname "tun*" counter accept
        ip saddr @whitelist_ip counter accept
        ip saddr @blocklist_ip4_forever log prefix "[NFT] Ban Forever IPv4 (listed): " counter drop
        ip saddr @blocklist_ip4 log prefix "[NFT] Blocked IPv4 (listed): " counter drop
        ip6 saddr @blocklist_ip6 log prefix "[NFT] Blocked IPv6 (listed): " counter drop
    }
}
SINGCTL_NFT_EOF
  fi
  MASTER_IP=$(printf '%s' "${SSH_CLIENT:-}" | awk '{print $1}')
  if [ -n "$MASTER_IP" ]; then
    nft add element inet security whitelist_ip "{ $MASTER_IP }" 2>/dev/null || true
  fi
fi`

func buildRemoteNFTBlockScript(canonicalTarget string, isCIDR, isIPv4 bool) string {
	// canonicalTarget 已通过 net.ParseIP / net.ParseCIDR 严格校验，不含任何 Shell 元字符
	if isCIDR {
		if isIPv4 {
			return fmt.Sprintf("if command -v nft >/dev/null 2>&1; then\n%s\nnft add element inet security blocklist_ip4_forever '{ %s }' 2>/dev/null || nft get element inet security blocklist_ip4_forever '{ %s }' >/dev/null 2>&1\nfi\n",
				remoteEnsureSecurityNFTBlock, canonicalTarget, canonicalTarget)
		}
		return ""
	}
	setName := "blocklist_ip6"
	if isIPv4 {
		setName = "blocklist_ip4"
	}
	return fmt.Sprintf("if command -v nft >/dev/null 2>&1; then\n%s\nnft delete element inet security %s '{ %s }' 2>/dev/null || true\nnft add element inet security %s '{ %s timeout 7d }'\nfi\n",
		remoteEnsureSecurityNFTBlock, setName, canonicalTarget, setName, canonicalTarget)
}

func ensureLocalSecurityNFTTable(ctx context.Context) error {
	if exec.CommandContext(ctx, "nft", "list", "table", "inet", "security").Run() == nil {
		return nil
	}
	for _, bin := range []string{"modprobe", "/sbin/modprobe", "/usr/sbin/modprobe"} {
		if _, err := exec.LookPath(bin); err == nil {
			_ = exec.CommandContext(ctx, bin, "nf_tables").Run()
			break
		}
	}
	if _, err := os.Stat(constant.SingBoxNftablesFile); err == nil {
		if exec.CommandContext(ctx, "nft", "-c", "-f", constant.SingBoxNftablesFile).Run() == nil {
			if exec.CommandContext(ctx, "nft", "-f", constant.SingBoxNftablesFile).Run() == nil {
				return nil
			}
		}
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(firewall.BuildMinimalBlocklistNFT())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bootstrap inet security table: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func applyNFTBlockIP(ipStr string, isIPv4 bool) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := ensureLocalSecurityNFTTable(ctx); err != nil {
		return err
	}
	setName := "blocklist_ip6"
	if isIPv4 {
		setName = "blocklist_ip4"
	}
	_ = exec.CommandContext(ctx, "nft", "delete", "element", "inet", "security", setName, fmt.Sprintf("{ %s }", ipStr)).Run()
	elem := fmt.Sprintf("{ %s timeout 7d }", ipStr)
	if out, err := exec.CommandContext(ctx, "nft", "add", "element", "inet", "security", setName, elem).CombinedOutput(); err != nil {
		return fmt.Errorf("nft add element %s: %w (%s)", setName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func applyNFTBlockCIDR(cidr string, isIPv4 bool) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil
	}
	if !isIPv4 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := ensureLocalSecurityNFTTable(ctx); err != nil {
		return err
	}
	elem := fmt.Sprintf("{ %s }", cidr)
	if out, err := exec.CommandContext(ctx, "nft", "add", "element", "inet", "security", "blocklist_ip4_forever", elem).CombinedOutput(); err != nil {
		// auto-merge interval set 中若已包含该网段，get element 返回 0 视为幂等成功
		if exec.CommandContext(ctx, "nft", "get", "element", "inet", "security", "blocklist_ip4_forever", elem).Run() == nil {
			return nil
		}
		return fmt.Errorf("nft add element blocklist_ip4_forever: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// UnblockTargetForNode 在指定主机 ("local" | "<node_id>" | "all") 全链路解除单个 IP、/24 网段或全部 ("all") 封禁
func (t *SniffTracker) UnblockTargetForNode(ctx context.Context, target, nodeScope string) (string, int, error) {
	target = strings.TrimSpace(target)
	if target == "" || target == "*" {
		target = "all"
	}
	nodeScope = cmp.Or(strings.TrimSpace(nodeScope), "all")

	t.mu.RLock()
	fleetMgr := t.fleetMgr
	t.mu.RUnlock()

	applyLocal := nodeScope == "all" || nodeScope == "local"
	remoteNodes := selectScopeRemoteNodes(fleetMgr, nodeScope)

	if target == "all" {
		t.mu.Lock()
		t.unblockAllLocked(nodeScope)
		t.markDirtyLocked()
		raw, seq := t.snapshotPersistBytesLocked(time.Now(), true)
		t.mu.Unlock()
		t.persistSnapshot(raw, seq)

		appliedNodes := 0
		if applyLocal {
			appliedNodes++
			if t.limiter != nil {
				t.limiter.Unban("all")
			}
			applyNFTFlushAll()
		}
		if len(remoteNodes) > 0 && fleetMgr != nil {
			appliedNodes += runRemoteNFTScripts(ctx, fleetMgr, remoteNodes, buildRemoteNFTFlushScript(), 4*time.Second)
		}
		return "all", appliedNodes, nil
	}

	spec, err := validateSniffBlockTarget(target, nil, false)
	if err != nil {
		return "", 0, err
	}

	t.mu.Lock()
	t.unblockSpecLocked(spec, nodeScope)
	t.markDirtyLocked()
	raw, seq := t.snapshotPersistBytesLocked(time.Now(), true)
	t.mu.Unlock()
	t.persistSnapshot(raw, seq)

	appliedNodes := 0
	if applyLocal {
		appliedNodes++
		if spec.isCIDR {
			applyNFTUnblockCIDR(spec.canonical, spec.isIPv4)
		} else {
			if t.limiter != nil {
				t.limiter.Unban(spec.canonical)
			}
			applyNFTUnblockIP(spec.canonical, spec.isIPv4)
		}
	}

	if len(remoteNodes) > 0 && fleetMgr != nil {
		if script := buildRemoteNFTUnblockScript(spec.canonical, spec.isCIDR, spec.isIPv4); script != "" {
			appliedNodes += runRemoteNFTScripts(ctx, fleetMgr, remoteNodes, script, 4*time.Second)
		}
	}

	return spec.canonical, appliedNodes, nil
}

func (t *SniffTracker) unblockAllLocked(nodeScope string) {
	if nodeScope == "all" || nodeScope == "local" {
		clear(t.manualBlockedCIDRs)
	}
	if nodeScope == "all" {
		clear(t.nodeBlockedCIDRs)
		for _, nodeMap := range t.recordsByNode {
			for _, rec := range nodeMap {
				if rec.status == "banned" {
					rec.status = "observing"
				}
			}
		}
		return
	}
	delete(t.nodeBlockedCIDRs, nodeScope)
	if nodeMap, ok := t.recordsByNode[nodeScope]; ok {
		for _, rec := range nodeMap {
			if rec.status == "banned" {
				rec.status = "observing"
			}
		}
	}
}

func (t *SniffTracker) unblockSpecLocked(spec sniffBlockTargetSpec, nodeScope string) {
	if spec.isCIDR {
		if nodeScope == "all" || nodeScope == "local" {
			delete(t.manualBlockedCIDRs, spec.canonical)
		}
		if nodeScope == "all" {
			for nid := range t.nodeBlockedCIDRs {
				delete(t.nodeBlockedCIDRs[nid], spec.canonical)
			}
			for _, nodeMap := range t.recordsByNode {
				for _, rec := range nodeMap {
					if recIP := net.ParseIP(rec.ip); recIP != nil && spec.parsedNet.Contains(recIP) && rec.status == "banned" {
						rec.status = "observing"
					}
				}
			}
			return
		}
		if m, ok := t.nodeBlockedCIDRs[nodeScope]; ok {
			delete(m, spec.canonical)
		}
		if nodeMap, ok := t.recordsByNode[nodeScope]; ok {
			for _, rec := range nodeMap {
				if recIP := net.ParseIP(rec.ip); recIP != nil && spec.parsedNet.Contains(recIP) && rec.status == "banned" {
					rec.status = "observing"
				}
			}
		}
		return
	}

	if nodeScope == "all" {
		for _, nodeMap := range t.recordsByNode {
			if rec, ok := nodeMap[spec.canonical]; ok && rec.status == "banned" {
				rec.status = "observing"
			}
		}
		return
	}
	if nodeMap, ok := t.recordsByNode[nodeScope]; ok {
		if rec, ok := nodeMap[spec.canonical]; ok && rec.status == "banned" {
			rec.status = "observing"
		}
	}
}

func runRemoteNFTScripts(ctx context.Context, fleetMgr *fleet.Manager, remoteNodes []fleet.Node, script string, perNodeTimeout time.Duration) int {
	runner := fleetMgr.Runner
	if runner == nil {
		runner = fleet.DefaultSSHRunner
	}
	var wg sync.WaitGroup
	var remoteOK atomic.Int32
	for _, rn := range remoteNodes {
		node := rn
		wg.Go(func() {
			rCtx, cancel := context.WithTimeout(ctx, perNodeTimeout)
			defer cancel()
			if _, _, err := runner(rCtx, node, script); err == nil {
				remoteOK.Add(1)
			}
		})
	}
	wg.Wait()
	return int(remoteOK.Load())
}

func buildRemoteNFTUnblockScript(canonicalTarget string, isCIDR, isIPv4 bool) string {
	if isCIDR {
		if isIPv4 {
			return fmt.Sprintf("if command -v nft >/dev/null 2>&1; then nft delete element inet security blocklist_ip4_forever '{ %s }' 2>/dev/null || true; fi\n", canonicalTarget)
		}
		return ""
	}
	setName := "blocklist_ip6"
	if isIPv4 {
		setName = "blocklist_ip4"
	}
	return fmt.Sprintf("if command -v nft >/dev/null 2>&1; then nft delete element inet security %s '{ %s }' 2>/dev/null || true; fi\nif command -v fail2ban-client >/dev/null 2>&1; then fail2ban-client unban %s >/dev/null 2>&1 || true; fi\n", setName, canonicalTarget, canonicalTarget)
}

func buildRemoteNFTFlushScript() string {
	return "if command -v nft >/dev/null 2>&1; then nft flush set inet security blocklist_ip4 2>/dev/null || true; nft flush set inet security blocklist_ip6 2>/dev/null || true; nft flush set inet security blocklist_ip4_forever 2>/dev/null || true; fi\n"
}

func applyNFTUnblockIP(ipStr string, isIPv4 bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := exec.LookPath("nft"); err == nil {
		setName := "blocklist_ip6"
		if isIPv4 {
			setName = "blocklist_ip4"
		}
		elem := fmt.Sprintf("{ %s }", ipStr)
		_ = exec.CommandContext(ctx, "nft", "delete", "element", "inet", "security", setName, elem).Run()
	}
	if _, err := exec.LookPath("fail2ban-client"); err == nil {
		_ = exec.CommandContext(ctx, "fail2ban-client", "unban", ipStr).Run()
	}
}

func applyNFTUnblockCIDR(cidr string, isIPv4 bool) {
	if _, err := exec.LookPath("nft"); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if isIPv4 {
		elem := fmt.Sprintf("{ %s }", cidr)
		_ = exec.CommandContext(ctx, "nft", "delete", "element", "inet", "security", "blocklist_ip4_forever", elem).Run()
	}
}

func applyNFTFlushAll() {
	if _, err := exec.LookPath("nft"); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "nft", "flush", "set", "inet", "security", "blocklist_ip4").Run()
	_ = exec.CommandContext(ctx, "nft", "flush", "set", "inet", "security", "blocklist_ip6").Run()
	_ = exec.CommandContext(ctx, "nft", "flush", "set", "inet", "security", "blocklist_ip4_forever").Run()
}
