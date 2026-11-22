// 文件职责：负责嗅探监控的防自锁防注入校验、本机（复用 internal/firewall）与集群远端防火墙协同封禁/解封执行。
package sniff

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
	"singctl/internal/logger"
)

// BlockTargetSpec 描述通过安全校验并规范化后的单 IP 或 CIDR 封禁目标。
type BlockTargetSpec struct {
	Canonical string
	IsCIDR    bool
	IsIPv4    bool
	ParsedNet *net.IPNet
}

// ValidateBlockTarget 校验封禁/解封目标；enforceSafetyGuards=true 时阻断内网地址、宽泛掩码与管理员/集群受保护 IP。
func ValidateBlockTarget(target string, protectedSet map[string]struct{}, enforceSafetyGuards bool) (BlockTargetSpec, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return BlockTargetSpec{}, fmt.Errorf("封禁目标不能为空")
	}

	if strings.Contains(target, "/") {
		ip, ipNet, err := net.ParseCIDR(target)
		if err != nil || ip == nil || ipNet == nil {
			return BlockTargetSpec{}, fmt.Errorf("无效的 CIDR 网段格式: %s", target)
		}
		ones, bits := ipNet.Mask.Size()
		if enforceSafetyGuards {
			if bits == 32 && ones < 16 {
				return BlockTargetSpec{}, fmt.Errorf("为防止误伤大面积网络，IPv4 网段掩码长度须在 /16 至 /32 之间")
			}
			if bits == 128 && ones < 32 {
				return BlockTargetSpec{}, fmt.Errorf("IPv6 网段掩码长度须在 /32 至 /128 之间")
			}
			if IsIgnoredInternalIP(ip.String()) {
				return BlockTargetSpec{}, fmt.Errorf("安全防锁死保护：禁止封禁本地回环、局域网或内网保留网段 (%s)", target)
			}
			for protIPStr := range protectedSet {
				if protIP := net.ParseIP(protIPStr); protIP != nil && ipNet.Contains(protIP) {
					return BlockTargetSpec{}, fmt.Errorf("安全防锁死保护：目标网段 (%s) 包含当前管理会话或受保护节点 IP (%s)，已拒绝执行", target, protIPStr)
				}
			}
		}
		return BlockTargetSpec{
			Canonical: ipNet.String(),
			IsCIDR:    true,
			IsIPv4:    bits == 32,
			ParsedNet: ipNet,
		}, nil
	}

	ipStr := NormalizeIPString(target)
	if ipStr == "" {
		return BlockTargetSpec{}, fmt.Errorf("无效的 IP 地址格式: %s", target)
	}
	if enforceSafetyGuards {
		if IsIgnoredInternalIP(ipStr) {
			return BlockTargetSpec{}, fmt.Errorf("安全防锁死保护：禁止封禁本地回环或内网保留地址 (%s)", ipStr)
		}
		if _, isProtected := protectedSet[ipStr]; isProtected {
			return BlockTargetSpec{}, fmt.Errorf("安全防锁死保护：禁止拉黑您当前所在的管理 IP 或集群受保护节点 (%s)", ipStr)
		}
	}
	parsedIP := net.ParseIP(ipStr)
	return BlockTargetSpec{
		Canonical: ipStr,
		IsCIDR:    false,
		IsIPv4:    parsedIP != nil && parsedIP.To4() != nil,
	}, nil
}

func (t *Tracker) collectProtectedIPSet(operatorIP string, extraProtectedIPs ...string) (map[string]struct{}, *RemoteProvider) {
	protectedSet := make(map[string]struct{})
	if opNorm := NormalizeIPString(operatorIP); opNorm != "" {
		protectedSet[opNorm] = struct{}{}
	}
	for _, p := range extraProtectedIPs {
		if norm := NormalizeIPString(p); norm != "" {
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
	rp := t.remote
	t.mu.RUnlock()

	if rp != nil && rp.ListTargets != nil {
		if targets, err := rp.ListTargets(); err == nil {
			for _, fn := range targets {
				if norm := NormalizeIPString(fn.Host); norm != "" {
					protectedSet[norm] = struct{}{}
				}
			}
		}
	}
	return protectedSet, rp
}

func selectScopeRemoteTargets(rp *RemoteProvider, nodeScope string) []RemoteTarget {
	if rp == nil || rp.ListTargets == nil || nodeScope == "local" {
		return nil
	}
	allNodes, err := rp.ListTargets()
	if err != nil {
		return nil
	}
	var out []RemoteTarget
	for _, n := range allNodes {
		if n.Enabled && (nodeScope == "all" || n.ID == nodeScope) {
			out = append(out, n)
		}
	}
	return out
}

// BlockTarget 手动在本机拉黑单个嗅探 IP 或 /24 网段。
func (t *Tracker) BlockTarget(target, operatorIP string, extraProtectedIPs ...string) (string, error) {
	canonical, _, err := t.BlockTargetForNode(context.Background(), target, "local", operatorIP, extraProtectedIPs...)
	return canonical, err
}

// BlockTargetForNode 手动在指定主机 ("local" | "<node_id>" | "all") 一键拉黑单个嗅探 IP 或 /24 网段。
func (t *Tracker) BlockTargetForNode(ctx context.Context, target, nodeScope, operatorIP string, extraProtectedIPs ...string) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	nodeScope = cmp.Or(strings.TrimSpace(nodeScope), "all")
	protectedSet, rp := t.collectProtectedIPSet(operatorIP, extraProtectedIPs...)

	spec, err := ValidateBlockTarget(target, protectedSet, true)
	if err != nil {
		return "", 0, err
	}

	applyLocal := nodeScope == "all" || nodeScope == "local"
	remoteNodes := selectScopeRemoteTargets(rp, nodeScope)

	now := time.Now()
	t.mu.Lock()
	t.applyBlockStateLocked(spec, nodeScope, applyLocal, remoteNodes, now)
	t.markDirtyLocked()
	raw, seq := t.snapshotPersistBytesLocked(now, true)
	t.mu.Unlock()
	t.persistSnapshot(raw, seq, 25*time.Millisecond)

	appliedNodes := 0
	var localNFTErr error
	if applyLocal {
		if spec.IsCIDR {
			localNFTErr = applyNFTBlockCIDR(spec.Canonical, spec.IsIPv4)
		} else {
			if t.limiter != nil {
				t.limiter.BanManual(spec.Canonical, 7*24*time.Hour)
			}
			localNFTErr = ApplyNFTBlockIP(spec.Canonical, spec.IsIPv4)
		}
		if localNFTErr == nil || os.Geteuid() != 0 {
			appliedNodes++
		} else {
			logger.Warn("本机 nftables 写入封禁规则失败 (%s): %v", spec.Canonical, localNFTErr)
		}
	}

	if len(remoteNodes) > 0 && rp != nil && rp.Exec != nil {
		if script := BuildRemoteNFTBlockScript(spec.Canonical, spec.IsCIDR, spec.IsIPv4); script != "" {
			appliedNodes += runRemoteNFTScripts(ctx, rp.Exec, remoteNodes, script, 5*time.Second)
		}
	}

	if nodeScope == "local" && localNFTErr != nil && os.Geteuid() == 0 {
		return spec.Canonical, 0, fmt.Errorf("本机内核防火墙写入封禁规则失败: %w", localNFTErr)
	}
	return spec.Canonical, appliedNodes, nil
}

func (t *Tracker) applyBlockStateLocked(spec BlockTargetSpec, nodeScope string, applyLocal bool, remoteNodes []RemoteTarget, now time.Time) {
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

	if spec.IsCIDR {
		if nodeScope == "all" || nodeScope == "local" {
			t.manualBlockedCIDRs[spec.Canonical] = spec.ParsedNet
		}
		for _, nid := range targetNodeIDs {
			if t.nodeBlockedCIDRs[nid] == nil {
				t.nodeBlockedCIDRs[nid] = make(map[string]*net.IPNet)
			}
			t.nodeBlockedCIDRs[nid][spec.Canonical] = spec.ParsedNet
			markSubnetBannedInMap(t.recordsByNode[nid], spec.ParsedNet)
		}
		if nodeScope == "all" {
			for _, nodeMap := range t.recordsByNode {
				markSubnetBannedInMap(nodeMap, spec.ParsedNet)
			}
		}
		return
	}

	for _, nid := range targetNodeIDs {
		nodeName := resolveScopeNodeDisplayName(nid, remoteNodes)
		t.observeNodeAtLocked(nid, nodeName, spec.Canonical, "管理员手动拉黑", "banned", 1, true, time.Time{}, now)
		if rec, ok := t.recordsByNode[nid][spec.Canonical]; ok {
			rec.status = "banned"
		}
	}
	if nodeScope == "all" {
		for _, nodeMap := range t.recordsByNode {
			if rec, ok := nodeMap[spec.Canonical]; ok {
				rec.status = "banned"
			}
		}
	}
}

func markSubnetBannedInMap(nodeMap map[string]*sniffRecord, parsedNet *net.IPNet) {
	for _, rec := range nodeMap {
		if recIP := net.ParseIP(rec.ip); recIP != nil && parsedNet.Contains(recIP) {
			rec.status = "banned"
		}
	}
}

func resolveScopeNodeDisplayName(nid string, remoteNodes []RemoteTarget) string {
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

// BuildRemoteNFTBlockScript 生成带防自锁最小表自举的远端 nftables 封禁脚本。
func BuildRemoteNFTBlockScript(canonicalTarget string, isCIDR, isIPv4 bool) string {
	if isCIDR {
		if !isIPv4 {
			return ""
		}
		return fmt.Sprintf("if command -v nft >/dev/null 2>&1; then\n%s\nnft add element inet security blocklist_ip4_forever '{ %s }' 2>/dev/null || nft get element inet security blocklist_ip4_forever '{ %s }' >/dev/null 2>&1\nfi\n",
			remoteEnsureSecurityNFTBlock, canonicalTarget, canonicalTarget)
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

// ApplyNFTBlockIP 在本机 nftables `inet security` 表中封禁单个 IP（缺失表时复用 internal/firewall 最小安全表自举）。
func ApplyNFTBlockIP(ipStr string, isIPv4 bool) error {
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
	if !isIPv4 {
		return nil
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := ensureLocalSecurityNFTTable(ctx); err != nil {
		return err
	}
	elem := fmt.Sprintf("{ %s }", cidr)
	if out, err := exec.CommandContext(ctx, "nft", "add", "element", "inet", "security", "blocklist_ip4_forever", elem).CombinedOutput(); err != nil {
		if exec.CommandContext(ctx, "nft", "get", "element", "inet", "security", "blocklist_ip4_forever", elem).Run() == nil {
			return nil
		}
		return fmt.Errorf("nft add element blocklist_ip4_forever: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// UnblockTargetForNode 在指定主机 ("local" | "<node_id>" | "all") 全链路解除单个 IP、/24 网段或全部 ("all") 封禁。
func (t *Tracker) UnblockTargetForNode(ctx context.Context, target, nodeScope string) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	target = strings.TrimSpace(target)
	if target == "" || target == "*" {
		target = "all"
	}
	nodeScope = cmp.Or(strings.TrimSpace(nodeScope), "all")

	t.mu.RLock()
	rp := t.remote
	t.mu.RUnlock()

	applyLocal := nodeScope == "all" || nodeScope == "local"
	remoteNodes := selectScopeRemoteTargets(rp, nodeScope)

	if target == "all" {
		t.mu.Lock()
		t.unblockAllLocked(nodeScope)
		t.markDirtyLocked()
		raw, seq := t.snapshotPersistBytesLocked(time.Now(), true)
		t.mu.Unlock()
		t.persistSnapshot(raw, seq, 25*time.Millisecond)

		appliedNodes := 0
		if applyLocal {
			appliedNodes++
			if t.limiter != nil {
				t.limiter.Unban("all")
			}
			applyNFTFlushAll()
		}
		if len(remoteNodes) > 0 && rp != nil && rp.Exec != nil {
			appliedNodes += runRemoteNFTScripts(ctx, rp.Exec, remoteNodes, BuildRemoteNFTFlushScript(), 4*time.Second)
		}
		return "all", appliedNodes, nil
	}

	spec, err := ValidateBlockTarget(target, nil, false)
	if err != nil {
		return "", 0, err
	}

	t.mu.Lock()
	t.unblockSpecLocked(spec, nodeScope)
	t.markDirtyLocked()
	raw, seq := t.snapshotPersistBytesLocked(time.Now(), true)
	t.mu.Unlock()
	t.persistSnapshot(raw, seq, 25*time.Millisecond)

	appliedNodes := 0
	if applyLocal {
		appliedNodes++
		if spec.IsCIDR {
			applyNFTUnblockCIDR(spec.Canonical, spec.IsIPv4)
		} else {
			if t.limiter != nil {
				t.limiter.Unban(spec.Canonical)
			}
			applyNFTUnblockIP(spec.Canonical, spec.IsIPv4)
		}
	}
	if len(remoteNodes) > 0 && rp != nil && rp.Exec != nil {
		if script := BuildRemoteNFTUnblockScript(spec.Canonical, spec.IsCIDR, spec.IsIPv4); script != "" {
			appliedNodes += runRemoteNFTScripts(ctx, rp.Exec, remoteNodes, script, 4*time.Second)
		}
	}
	return spec.Canonical, appliedNodes, nil
}

func (t *Tracker) unblockAllLocked(nodeScope string) {
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
	for _, rec := range t.recordsByNode[nodeScope] {
		if rec.status == "banned" {
			rec.status = "observing"
		}
	}
}

func (t *Tracker) unblockSpecLocked(spec BlockTargetSpec, nodeScope string) {
	if spec.IsCIDR {
		if nodeScope == "all" || nodeScope == "local" {
			delete(t.manualBlockedCIDRs, spec.Canonical)
		}
		if nodeScope == "all" {
			for nid := range t.nodeBlockedCIDRs {
				delete(t.nodeBlockedCIDRs[nid], spec.Canonical)
			}
			for _, nodeMap := range t.recordsByNode {
				unmarkSubnetBannedInMap(nodeMap, spec.ParsedNet)
			}
			return
		}
		delete(t.nodeBlockedCIDRs[nodeScope], spec.Canonical)
		unmarkSubnetBannedInMap(t.recordsByNode[nodeScope], spec.ParsedNet)
		return
	}

	if nodeScope == "all" {
		for _, nodeMap := range t.recordsByNode {
			if rec, ok := nodeMap[spec.Canonical]; ok && rec.status == "banned" {
				rec.status = "observing"
			}
		}
		return
	}
	if rec, ok := t.recordsByNode[nodeScope][spec.Canonical]; ok && rec.status == "banned" {
		rec.status = "observing"
	}
}

func unmarkSubnetBannedInMap(nodeMap map[string]*sniffRecord, parsedNet *net.IPNet) {
	for _, rec := range nodeMap {
		if recIP := net.ParseIP(rec.ip); recIP != nil && parsedNet.Contains(recIP) && rec.status == "banned" {
			rec.status = "observing"
		}
	}
}

func runRemoteNFTScripts(ctx context.Context, execFn RemoteExecFunc, remoteNodes []RemoteTarget, script string, perNodeTimeout time.Duration) int {
	var wg sync.WaitGroup
	var remoteOK atomic.Int32
	for _, rn := range remoteNodes {
		node := rn
		wg.Go(func() {
			rCtx, cancel := context.WithTimeout(ctx, perNodeTimeout)
			defer cancel()
			if _, _, err := execFn(rCtx, node, script); err == nil {
				remoteOK.Add(1)
			}
		})
	}
	wg.Wait()
	return int(remoteOK.Load())
}

// BuildRemoteNFTUnblockScript 生成远端单 IP 或 CIDR 解封脚本。
func BuildRemoteNFTUnblockScript(canonicalTarget string, isCIDR, isIPv4 bool) string {
	if isCIDR {
		if !isIPv4 {
			return ""
		}
		return fmt.Sprintf("if command -v nft >/dev/null 2>&1; then nft delete element inet security blocklist_ip4_forever '{ %s }' 2>/dev/null || true; fi\n", canonicalTarget)
	}
	setName := "blocklist_ip6"
	if isIPv4 {
		setName = "blocklist_ip4"
	}
	return fmt.Sprintf("if command -v nft >/dev/null 2>&1; then nft delete element inet security %s '{ %s }' 2>/dev/null || true; fi\nif command -v fail2ban-client >/dev/null 2>&1; then fail2ban-client unban %s >/dev/null 2>&1 || true; fi\n", setName, canonicalTarget, canonicalTarget)
}

// BuildRemoteNFTFlushScript 生成远端防火墙封禁集合全清脚本。
func BuildRemoteNFTFlushScript() string {
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
		_ = exec.CommandContext(ctx, "nft", "delete", "element", "inet", "security", setName, fmt.Sprintf("{ %s }", ipStr)).Run()
	}
	if _, err := exec.LookPath("fail2ban-client"); err == nil {
		_ = exec.CommandContext(ctx, "fail2ban-client", "unban", ipStr).Run()
	}
}

func applyNFTUnblockCIDR(cidr string, isIPv4 bool) {
	if !isIPv4 {
		return
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "nft", "delete", "element", "inet", "security", "blocklist_ip4_forever", fmt.Sprintf("{ %s }", cidr)).Run()
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
