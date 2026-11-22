// 文件职责：协调 Tailscale LocalAPI 状态观测、fw4 JIT 瞬时打洞窗口与 3 态双向访问防火墙收敛。
package tailscale

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
)

// ErrNFTUnavailable 表示当前宿主机未安装 nftables (nft) 命令（例如 OpenWrt 21.02 纯 iptables 固件）。
var ErrNFTUnavailable = errors.New("nftables (nft) unavailable")

const (
	jitPollInterval     = 300 * time.Millisecond
	jitPostCloseGrace   = 1200 * time.Millisecond
	jitFailureThreshold = 2

	// DefaultNFTUnavailableBackoff 缺失 nft 时进入长退避静默的默认时长，避免每 3 秒反复 fork 与刷屏。
	DefaultNFTUnavailableBackoff = 30 * time.Minute

	// DefaultMinAutoJITBytes 限制仅当 DERP 会话窗口内实际产生 >= 4 KiB 真实流量增量时才自动开孔，
	// 过滤掉 Tailscale 长闲置后每 ~30 分钟偶发几百字节的 WireGuard 握手/保活噪声。
	DefaultMinAutoJITBytes int64 = 4096
)

// P2PPeerRuntimeState 记录单个纳管节点在内存/状态文件中的运行时状态。
type P2PPeerRuntimeState struct {
	Key                  string `json:"key"`
	InFlight             bool   `json:"inFlight"`
	PinholeOpen          bool   `json:"pinholeOpen"`
	ConsecutiveFails     int    `json:"consecutiveFails"`
	CooldownRemainingSec int    `json:"cooldownRemainingSec"`
	LastAttemptAt        string `json:"lastAttemptAt,omitempty"`
	LastUpgradeAt        string `json:"lastUpgradeAt,omitempty"`
	LastResult           string `json:"lastResult,omitempty"`
}

// P2PRuntimeSnapshot 描述 Daemon / WebUI 观测到的 Tailscale P2P 防线全局运行态。
type P2PRuntimeSnapshot struct {
	Enabled        bool                           `json:"enabled"`
	ApplyMode      string                         `json:"applyMode,omitempty"`
	OpenPinholes   int                            `json:"openPinholes"`
	OpenPinholeIPs []string                       `json:"openPinholeIPs,omitempty"`
	UpdatedAt      string                         `json:"updatedAt,omitempty"`
	LastError      string                         `json:"lastError,omitempty"`
	PeerStates     map[string]P2PPeerRuntimeState `json:"peerStates,omitempty"`
}

// PokeResult 表示 WebUI「测试瞬时打洞」操作的实时反馈结果。
type PokeResult struct {
	Direct         bool   `json:"direct"`
	CurAddr        string `json:"curAddr,omitempty"`
	Relay          string `json:"relay,omitempty"`
	LatencyMs      int64  `json:"latencyMs"`
	PinholeMs      int64  `json:"pinholeMs"`
	CandidateCount int    `json:"candidateCount"`
	Message        string `json:"message"`
}

type peerStateEntry struct {
	inFlight           bool
	pinholeOpen        bool
	consecutiveFails   int
	cooldownUntil      time.Time
	lastAttemptAt      time.Time
	lastUpgradeAt      time.Time
	lastResult         string
	trafficSeen        bool
	derpBurstActive    bool
	derpBurstBaseBytes int64
}

// P2PAssistController 协调 Tailscale LocalAPI 状态探测、fw4 JIT 瞬时打洞与 3 态防火墙收敛。
type P2PAssistController struct {
	BaseCtx               context.Context
	LocalAPI              LocalAPIClient
	FW4                   *FW4Manager
	LookPath              func(file string) (string, error)
	NFTUnavailableBackoff time.Duration
	Now                   func() time.Time
	Sleep                 func(ctx context.Context, d time.Duration) error
	DefaultLANCIDR        func() string
	HostSelfIPs           func() []netip.Addr
	MinAutoJITBytes       int64 // 0=默认 DefaultMinAutoJITBytes(4096); <0=禁用自动打洞流量门槛
	OnEvent               func(action string, healthy bool, summary string)

	mu                     sync.Mutex
	peers                  map[string]*peerStateEntry
	nftUnavailableUntil    time.Time
	nftUnavailableErr      string
	nftUnavailableReported bool
	wg                     sync.WaitGroup
}

// ResetNFTUnavailableBackoff 清除缺失 nft 的静默退避状态（用于配置热重载后重新探测）。
func (c *P2PAssistController) ResetNFTUnavailableBackoff() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.nftUnavailableUntil = time.Time{}
	c.nftUnavailableErr = ""
	c.nftUnavailableReported = false
	c.mu.Unlock()
}

func (c *P2PAssistController) effectiveNFTUnavailableBackoff() time.Duration {
	if c.NFTUnavailableBackoff > 0 {
		return c.NFTUnavailableBackoff
	}
	return DefaultNFTUnavailableBackoff
}

func (c *P2PAssistController) probeNFTBinary() error {
	if c.LookPath != nil {
		_, err := c.LookPath("nft")
		return err
	}
	// 当测试显式注入了自定义 FW4.Runner 时跳过宿主机 PATH 检查，避免非 Linux 测试机误判。
	if c.FW4 != nil && c.FW4.Runner != nil {
		return nil
	}
	_, err := exec.LookPath("nft")
	return err
}

func (c *P2PAssistController) recordNFTUnavailable(now time.Time, cause error) (msg string, firstReport bool) {
	backoff := c.effectiveNFTUnavailableBackoff()
	msg = fmt.Sprintf("当前宿主机未检测到 nftables (nft) 命令（可能为纯 iptables 固件），已跳过 fw4 P2P 防线并静默退避 %v: %v", backoff, cause)
	c.mu.Lock()
	defer c.mu.Unlock()
	firstReport = !c.nftUnavailableReported
	c.nftUnavailableReported = true
	c.nftUnavailableErr = msg
	c.nftUnavailableUntil = now.Add(backoff)
	return msg, firstReport
}

func (c *P2PAssistController) baseContext() context.Context {
	if c.BaseCtx != nil {
		return c.BaseCtx
	}
	return context.Background()
}

func (c *P2PAssistController) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *P2PAssistController) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *P2PAssistController) defaultLANCIDR() string {
	if c.DefaultLANCIDR != nil {
		return strings.TrimSpace(c.DefaultLANCIDR())
	}
	return ""
}

func (c *P2PAssistController) hostSelfIPs() []netip.Addr {
	if c.HostSelfIPs != nil {
		return c.HostSelfIPs()
	}
	return HostInterfaceAddrs()
}

func (c *P2PAssistController) fw4Manager() *FW4Manager {
	if c.FW4 != nil {
		return c.FW4
	}
	return &FW4Manager{}
}

// EffectiveLocalAPI 返回控制器当前绑定的 LocalAPI 客户端（未显式注入时回退默认连接池单例）。
func (c *P2PAssistController) EffectiveLocalAPI() LocalAPIClient {
	return c.localAPI()
}

// WaitBackground 等待当前已派发的异步打洞后台协程全部收敛结束。
func (c *P2PAssistController) WaitBackground() {
	if c != nil {
		c.wg.Wait()
	}
}

func (c *P2PAssistController) localAPI() LocalAPIClient {
	if c.LocalAPI != nil {
		return c.LocalAPI
	}
	return DefaultLocalAPIClient()
}

func (c *P2PAssistController) ensurePeerEntryLocked(key string) *peerStateEntry {
	if c.peers == nil {
		c.peers = make(map[string]*peerStateEntry)
	}
	st, ok := c.peers[key]
	if !ok {
		st = &peerStateEntry{}
		c.peers[key] = st
	}
	return st
}

// PeerStates 返回当前所有已观测对端的运行时状态只读副本。
func (c *P2PAssistController) PeerStates() map[string]P2PPeerRuntimeState {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]P2PPeerRuntimeState, len(c.peers))
	for k, st := range c.peers {
		coolRem := 0
		if !st.cooldownUntil.IsZero() && st.cooldownUntil.After(now) {
			coolRem = int(st.cooldownUntil.Sub(now).Seconds())
		}
		item := P2PPeerRuntimeState{
			Key:                  k,
			InFlight:             st.inFlight,
			PinholeOpen:          st.pinholeOpen,
			ConsecutiveFails:     st.consecutiveFails,
			CooldownRemainingSec: coolRem,
			LastResult:           st.lastResult,
		}
		if !st.lastAttemptAt.IsZero() {
			item.LastAttemptAt = st.lastAttemptAt.UTC().Format(time.RFC3339)
		}
		if !st.lastUpgradeAt.IsZero() {
			item.LastUpgradeAt = st.lastUpgradeAt.UTC().Format(time.RFC3339)
		}
		out[k] = item
	}
	return out
}

func peerRuntimeKey(rule config.TailscaleP2PPeerConfig, matched *PeerStatus) string {
	if matched != nil && matched.ID != "" {
		return matched.ID
	}
	return cmp.Or(strings.TrimSpace(rule.ID), strings.TrimSpace(rule.TailscaleIP), strings.ToLower(strings.TrimSpace(rule.Name)))
}

// Reconcile 周期性收敛 Layer 1/2/4 fw4 防火墙策略，并仅为满足条件（已授权 + Active + 走 DERP + 无冷却）的对端异步开启 JIT 瞬时打洞窗口。
func (c *P2PAssistController) Reconcile(ctx context.Context, cfg config.TailscaleP2PAssistConfig) (P2PRuntimeSnapshot, error) {
	now := c.now()
	fw4 := c.fw4Manager()

	if !cfg.Enabled {
		err := fw4.Remove(ctx)
		c.mu.Lock()
		for _, st := range c.peers {
			st.pinholeOpen = false
		}
		c.nftUnavailableUntil = time.Time{}
		c.nftUnavailableErr = ""
		c.nftUnavailableReported = false
		c.mu.Unlock()
		snap := P2PRuntimeSnapshot{
			Enabled:    false,
			UpdatedAt:  now.Format(time.DateTime),
			PeerStates: c.PeerStates(),
		}
		if err != nil {
			snap.LastError = err.Error()
		}
		return snap, err
	}

	c.mu.Lock()
	if !c.nftUnavailableUntil.IsZero() && now.Before(c.nftUnavailableUntil) {
		cachedErr := c.nftUnavailableErr
		c.mu.Unlock()
		return P2PRuntimeSnapshot{
			Enabled:    true,
			UpdatedAt:  now.Format(time.DateTime),
			LastError:  cachedErr,
			PeerStates: c.PeerStates(),
		}, nil
	}
	c.mu.Unlock()

	if lookErr := c.probeNFTBinary(); lookErr != nil {
		msg, firstReport := c.recordNFTUnavailable(now, lookErr)
		snap := P2PRuntimeSnapshot{
			Enabled:    true,
			UpdatedAt:  now.Format(time.DateTime),
			LastError:  msg,
			PeerStates: c.PeerStates(),
		}
		if firstReport {
			return snap, fmt.Errorf("%w: %w", ErrNFTUnavailable, lookErr)
		}
		return snap, nil
	}
	c.ResetNFTUnavailableBackoff()

	api := c.localAPI()
	statusSnap, statusErr := api.Status(ctx)

	var peers []PeerStatus
	selfID := ""
	if statusSnap != nil {
		peers = statusSnap.Peers
		selfID = statusSnap.Self.ID
	}

	resolved := make([]ResolvedPeerACL, 0, len(cfg.Peers))
	type jitCandidate struct {
		key  string
		rule config.TailscaleP2PPeerConfig
		peer PeerStatus
	}
	var candidates []jitCandidate

	for _, rule := range cfg.Peers {
		matched, ok := MatchConfiguredPeer(rule, peers, selfID)
		acl := ResolvedPeerACL{Config: rule}
		if ok && matched != nil {
			key := peerRuntimeKey(rule, matched)
			acl.TailscaleIPs = matched.TailscaleIPs
			acl.PrimaryRoutes = matched.PrimaryRoutes
			isActiveDERP := matched.CurAddr == "" && rule.JITEnabled && matched.Online && matched.Active && matched.Relay != ""
			allowJIT := c.observePeerTraffic(key, *matched, isActiveDERP)
			if matched.CurAddr != "" {
				c.clearStaleCooldown(key, now)
			} else if isActiveDERP && allowJIT {
				candidates = append(candidates, jitCandidate{
					key:  key,
					rule: rule,
					peer: *matched,
				})
			}
		}
		resolved = append(resolved, acl)
	}

	dropIns, err := RenderFW4DropIns(cfg, resolved, c.defaultLANCIDR(), now)
	if err != nil {
		return P2PRuntimeSnapshot{
			Enabled:    true,
			UpdatedAt:  now.Format(time.DateTime),
			LastError:  err.Error(),
			PeerStates: c.PeerStates(),
		}, err
	}

	applyMode, applyErr := fw4.Apply(ctx, dropIns)
	if applyErr != nil && errors.Is(applyErr, exec.ErrNotFound) {
		msg, firstReport := c.recordNFTUnavailable(now, applyErr)
		snap := P2PRuntimeSnapshot{
			Enabled:    true,
			UpdatedAt:  now.Format(time.DateTime),
			LastError:  msg,
			PeerStates: c.PeerStates(),
		}
		if firstReport {
			return snap, fmt.Errorf("%w: %w", ErrNFTUnavailable, applyErr)
		}
		return snap, nil
	}
	openCount, openIPs := fw4.CountOpenPinholes(ctx)

	if applyErr == nil {
		winTimeout := time.Duration(cfg.EffectiveJITWindowSec()+8) * time.Second
		for _, cand := range candidates {
			if c.tryStartJITLocked(cand.key, now) {
				c.wg.Add(1)
				go func(kc jitCandidate) {
					defer c.wg.Done()
					jitCtx, jitCancel := context.WithTimeout(c.baseContext(), winTimeout)
					defer jitCancel()
					_, _ = c.executeJITWindow(jitCtx, cfg, kc.key, kc.rule, kc.peer, false)
				}(cand)
			}
		}
	}

	snap := P2PRuntimeSnapshot{
		Enabled:        true,
		ApplyMode:      applyMode,
		OpenPinholes:   openCount,
		OpenPinholeIPs: openIPs,
		UpdatedAt:      now.Format(time.DateTime),
		PeerStates:     c.PeerStates(),
	}
	if applyErr != nil {
		snap.LastError = applyErr.Error()
		return snap, applyErr
	}
	if statusErr != nil {
		snap.LastError = statusErr.Error()
	}
	return snap, nil
}

func (c *P2PAssistController) effectiveMinAutoJITBytes() int64 {
	if c.MinAutoJITBytes < 0 {
		return -1
	}
	if c.MinAutoJITBytes > 0 {
		return c.MinAutoJITBytes
	}
	return DefaultMinAutoJITBytes
}

func (c *P2PAssistController) observePeerTraffic(key string, peer PeerStatus, activeDERP bool) bool {
	totalBytes := max(int64(0), peer.RxBytes) + max(int64(0), peer.TxBytes)
	minBytes := c.effectiveMinAutoJITBytes()

	c.mu.Lock()
	defer c.mu.Unlock()

	st := c.ensurePeerEntryLocked(key)
	if !activeDERP {
		st.trafficSeen = true
		st.derpBurstActive = false
		st.derpBurstBaseBytes = totalBytes
		return false
	}

	if minBytes < 0 {
		st.trafficSeen = true
		st.derpBurstActive = true
		return true
	}

	if !st.trafficSeen {
		st.trafficSeen = true
		st.derpBurstActive = true
		st.derpBurstBaseBytes = totalBytes
		return false
	}

	if !st.derpBurstActive {
		st.derpBurstActive = true
		if totalBytes < st.derpBurstBaseBytes {
			st.derpBurstBaseBytes = 0
		}
	} else if totalBytes < st.derpBurstBaseBytes {
		st.derpBurstBaseBytes = 0
	}

	return (totalBytes - st.derpBurstBaseBytes) >= minBytes
}

func (c *P2PAssistController) clearStaleCooldown(key string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peers == nil {
		return
	}
	st, ok := c.peers[key]
	if !ok || st.inFlight {
		return
	}
	st.consecutiveFails = 0
	st.cooldownUntil = time.Time{}
	if st.lastUpgradeAt.IsZero() {
		st.lastUpgradeAt = now
	}
	st.lastResult = "direct"
}

func (c *P2PAssistController) tryStartJITLocked(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.ensurePeerEntryLocked(key)
	if st.inFlight {
		return false
	}
	if !st.cooldownUntil.IsZero() {
		if now.Before(st.cooldownUntil) {
			return false
		}
		// Cooldown window has elapsed: grant a clean retry budget of jitFailureThreshold attempts.
		st.cooldownUntil = time.Time{}
		st.consecutiveFails = 0
	}
	st.inFlight = true
	st.lastAttemptAt = now
	return true
}

// PokePeer 由 WebUI 手动触发单次瞬时打洞窗口（忽略 Active 与冷却状态，但仍要求 P2P 防线开启且节点已授权 jit_enabled）。
func (c *P2PAssistController) PokePeer(ctx context.Context, cfg config.TailscaleP2PAssistConfig, targetKey string) (*PokeResult, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("请先启用 Tailscale P2P 直连防线")
	}
	statusSnap, err := c.localAPI().Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("读取 Tailscale 状态失败: %w", err)
	}

	targetTrim := strings.TrimSpace(targetKey)
	var foundRule *config.TailscaleP2PPeerConfig
	var matchedPeer *PeerStatus

	for i := range cfg.Peers {
		rule := cfg.Peers[i]
		m, ok := MatchConfiguredPeer(rule, statusSnap.Peers, statusSnap.Self.ID)
		matchesTarget := strings.EqualFold(rule.ID, targetTrim) ||
			strings.EqualFold(rule.Name, targetTrim) ||
			strings.EqualFold(rule.TailscaleIP, targetTrim) ||
			(ok && m != nil && (strings.EqualFold(m.ID, targetTrim) || strings.EqualFold(m.ShortName, targetTrim)))
		if matchesTarget {
			foundRule = &cfg.Peers[i]
			matchedPeer = m
			break
		}
	}
	if foundRule == nil {
		return nil, fmt.Errorf("未在 P2P 防线纳管列表中找到节点 %q", targetKey)
	}
	if !foundRule.JITEnabled {
		return nil, fmt.Errorf("节点 %s 未开启 JIT 瞬时打洞授权", foundRule.Name)
	}
	if matchedPeer == nil {
		return nil, fmt.Errorf("节点 %s 当前未在线或尚未加入 Tailnet", foundRule.Name)
	}
	if matchedPeer.CurAddr != "" {
		return &PokeResult{
			Direct:  true,
			CurAddr: matchedPeer.CurAddr,
			Relay:   matchedPeer.Relay,
			Message: "当前已是 P2P 直连通道，无需开孔",
		}, nil
	}

	key := peerRuntimeKey(*foundRule, matchedPeer)
	c.mu.Lock()
	st := c.ensurePeerEntryLocked(key)
	if st.inFlight {
		c.mu.Unlock()
		return nil, fmt.Errorf("节点 %s 正在执行瞬时打洞窗口，请数秒后重试", matchedPeer.ShortName)
	}
	st.inFlight = true
	st.lastAttemptAt = c.now()
	c.mu.Unlock()

	return c.executeJITWindow(ctx, cfg, key, *foundRule, *matchedPeer, true)
}

func (c *P2PAssistController) executeJITWindow(
	ctx context.Context,
	cfg config.TailscaleP2PAssistConfig,
	key string,
	rule config.TailscaleP2PPeerConfig,
	initialPeer PeerStatus,
	manual bool,
) (*PokeResult, error) {
	defer func() {
		c.mu.Lock()
		st := c.ensurePeerEntryLocked(key)
		st.inFlight = false
		st.pinholeOpen = false
		c.mu.Unlock()
	}()

	api := c.localAPI()
	fw4 := c.fw4Manager()

	netmapSnap, _ := api.NetMap(ctx)
	latestStatus, _ := api.Status(ctx)

	var endpoints []string
	endpoints = append(endpoints, initialPeer.Addrs...)
	if latestStatus != nil {
		if latestPeer, ok := MatchConfiguredPeer(rule, latestStatus.Peers, latestStatus.Self.ID); ok {
			endpoints = append(endpoints, latestPeer.Addrs...)
		}
	}
	if netmapSnap != nil && initialPeer.ID != "" {
		endpoints = append(endpoints, netmapSnap.PeerEndpoints[initialPeer.ID]...)
	}

	selfIPs := ExtractSelfIPs(latestStatus, netmapSnap, c.hostSelfIPs())
	v4, v6 := FilterPublicCandidateIPs(endpoints, selfIPs)
	candCount := len(v4) + len(v6)

	if candCount == 0 {
		res := &PokeResult{
			Direct:         false,
			Relay:          initialPeer.Relay,
			CandidateCount: 0,
			Message:        "未发现合法公网候选端点（或仅存在私网/CGNAT/本机地址），已跳过开孔并继续经 DERP 转发",
		}
		c.recordAttemptOutcome(cfg, key, initialPeer.ShortName, false, "", 0, manual, res.Message)
		return res, nil
	}

	winSec := cfg.EffectiveJITWindowSec()
	if err := fw4.OpenPinhole(ctx, v4, v6, winSec); err != nil {
		msg := fmt.Sprintf("开启内核瞬时放行集合失败: %v", err)
		c.recordAttemptOutcome(cfg, key, initialPeer.ShortName, false, "", 0, manual, msg)
		return &PokeResult{Direct: false, Relay: initialPeer.Relay, CandidateCount: candCount, Message: msg}, err
	}

	openedAt := c.now()
	c.mu.Lock()
	c.ensurePeerEntryLocked(key).pinholeOpen = true
	c.mu.Unlock()

	pinholeClosed := false
	closeOnce := func() {
		if pinholeClosed {
			return
		}
		pinholeClosed = true
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = fw4.ClosePinhole(closeCtx, v4, v6)
		c.mu.Lock()
		c.ensurePeerEntryLocked(key).pinholeOpen = false
		c.mu.Unlock()
	}
	defer closeOnce()

	peerTSIP := pickPeerTSIP(initialPeer.TailscaleIPs)
	discoCtx, discoCancel := context.WithCancel(ctx)
	var discoWg sync.WaitGroup
	defer func() {
		discoCancel()
		discoWg.Wait()
	}()
	sendDiscoAsync := func() {
		if peerTSIP == "" {
			return
		}
		discoWg.Go(func() {
			pCtx, pCancel := context.WithTimeout(discoCtx, 2500*time.Millisecond)
			defer pCancel()
			_, _ = api.PingDisco(pCtx, peerTSIP)
		})
	}

	// 异步触发 DISCO 探活，避免跨洋 DERP 延迟阻塞主观察循环与关孔定时器。
	sendDiscoAsync()
	deadline := openedAt.Add(time.Duration(winSec) * time.Second)
	direct := false
	curAddr := ""
	relay := initialPeer.Relay
	discoStage := 1

	for {
		if err := c.sleep(ctx, jitPollInterval); err != nil {
			break
		}
		now := c.now()
		stSnap, sErr := api.Status(ctx)
		if sErr == nil && stSnap != nil {
			if p, ok := MatchConfiguredPeer(rule, stSnap.Peers, stSnap.Self.ID); ok {
				relay = p.Relay
				if p.CurAddr != "" {
					direct = true
					curAddr = p.CurAddr
					break
				}
			}
		}
		if !now.Before(deadline) {
			break
		}
		elapsed := now.Sub(openedAt)
		if discoStage == 1 && elapsed >= 600*time.Millisecond {
			discoStage = 2
			sendDiscoAsync()
		} else if discoStage == 2 && elapsed >= 2000*time.Millisecond {
			discoStage = 3
			sendDiscoAsync()
		}
	}

	// 到点立即关孔以严格维持零常驻暴露；关孔后额外留 1.2s 宽限复查 conntrack 刚建成的直连状态。
	closeOnce()
	pinholeMs := max(int64(1), c.now().Sub(openedAt).Milliseconds())
	postCloseDirect := false

	if !direct {
		graceDeadline := c.now().Add(jitPostCloseGrace)
		for {
			if err := c.sleep(ctx, jitPollInterval); err != nil {
				break
			}
			stSnap, sErr := api.Status(ctx)
			if sErr == nil && stSnap != nil {
				if p, ok := MatchConfiguredPeer(rule, stSnap.Peers, stSnap.Self.ID); ok {
					relay = p.Relay
					if p.CurAddr != "" {
						direct = true
						curAddr = p.CurAddr
						postCloseDirect = true
						break
					}
				}
			}
			if !c.now().Before(graceDeadline) {
				break
			}
		}
	}

	discoCancel()
	discoWg.Wait()

	if direct {
		msg := fmt.Sprintf("P2P 直连升级成功（%dms 内自动关闭临时端口）", pinholeMs)
		if postCloseDirect {
			msg = fmt.Sprintf("P2P 直连升级成功（%dms 自动关孔，conntrack 握手已就绪）", pinholeMs)
		}
		c.recordAttemptOutcome(cfg, key, initialPeer.ShortName, true, curAddr, pinholeMs, manual, msg)
		return &PokeResult{
			Direct:         true,
			CurAddr:        curAddr,
			Relay:          relay,
			LatencyMs:      pinholeMs,
			PinholeMs:      pinholeMs,
			CandidateCount: candCount,
			Message:        msg,
		}, nil
	}

	msg := fmt.Sprintf("双端 NAT 阻塞未达成直连，已回收临时端口并维持 DERP (%s) 转发", cmp.Or(relay, "derp"))
	c.recordAttemptOutcome(cfg, key, initialPeer.ShortName, false, "", pinholeMs, manual, msg)
	return &PokeResult{
		Direct:         false,
		Relay:          relay,
		PinholeMs:      pinholeMs,
		CandidateCount: candCount,
		Message:        msg,
	}, nil
}

func (c *P2PAssistController) recordAttemptOutcome(
	cfg config.TailscaleP2PAssistConfig,
	key string,
	shortName string,
	direct bool,
	curAddr string,
	pinholeMs int64,
	manual bool,
	msg string,
) {
	now := c.now()
	c.mu.Lock()
	st := c.ensurePeerEntryLocked(key)
	enteredCooldown := false
	cooldownSec := cfg.EffectiveCooldownSec()
	if direct {
		st.consecutiveFails = 0
		st.cooldownUntil = time.Time{}
		st.lastUpgradeAt = now
		st.lastResult = "direct"
		st.trafficSeen = false
		st.derpBurstActive = false
	} else {
		st.consecutiveFails++
		if !manual && st.consecutiveFails >= jitFailureThreshold {
			st.cooldownUntil = now.Add(time.Duration(cooldownSec) * time.Second)
			st.lastResult = "cooldown_derp"
			enteredCooldown = true
		} else {
			st.lastResult = "derp_fallback"
		}
	}
	c.mu.Unlock()

	if c.OnEvent != nil {
		label := cmp.Or(shortName, key)
		switch {
		case direct:
			c.OnEvent("TS_P2P_DIRECT_OK", true, fmt.Sprintf("节点 %s 瞬时直连完成 (%dms 内关闭 WAN 窗口)", label, pinholeMs))
		case enteredCooldown:
			c.OnEvent("TS_P2P_COOLDOWN", true, fmt.Sprintf("节点 %s 连续 %d 次打洞未成，进入 %ds DERP 冷却退避", label, jitFailureThreshold, cooldownSec))
		case manual:
			c.OnEvent("TS_P2P_POKE", true, fmt.Sprintf("节点 %s 手动测试: %s", label, msg))
		}
	}
}

func pickPeerTSIP(ips []string) string {
	for _, raw := range ips {
		if addr, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil && addr.Is4() {
			return addr.String()
		}
	}
	if len(ips) > 0 {
		return strings.TrimSpace(ips[0])
	}
	return ""
}
