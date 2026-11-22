// 文件职责：负责本机系统级嗅探信号采集（扁平化子探针）与远端节点并发采集输出分段解包注入。
package sniff

import (
	"cmp"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

func (t *Tracker) triggerBackgroundSystemHarvestIfNeeded() {
	t.mu.RLock()
	enableProbe := t.EnableSystemProbe
	lastHarvest := t.lastSystemHarvest
	t.mu.RUnlock()
	if !enableProbe || (!lastHarvest.IsZero() && time.Since(lastHarvest) < systemHarvestMinDT) {
		return
	}
	if !t.systemBgRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer t.systemBgRunning.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		t.maybeHarvestSystemSources(ctx, false)
	}()
}

func (t *Tracker) triggerBackgroundRemoteHarvestIfNeeded() {
	t.mu.RLock()
	rp := t.remote
	enableProbe := t.EnableSystemProbe
	t.mu.RUnlock()
	if !enableProbe || rp == nil || rp.ListTargets == nil || rp.Exec == nil {
		return
	}
	if !t.remoteBgRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer t.remoteBgRunning.Store(false)
		nodes, err := rp.ListTargets()
		if err != nil || len(nodes) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t.maybeHarvestRemoteTargets(ctx, nodes, "all", false)
	}()
}

func (t *Tracker) maybeHarvestSystemSources(ctx context.Context, force bool) {
	now := time.Now()
	t.mu.Lock()
	if !t.EnableSystemProbe || (!force && !t.lastSystemHarvest.IsZero() && now.Sub(t.lastSystemHarvest) < systemHarvestMinDT) {
		t.mu.Unlock()
		return
	}
	t.lastSystemHarvest = now
	t.ensureNodeMetaLocked("local").lastHarvest = now
	t.bumpDataRevLocked()
	t.mu.Unlock()

	hCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	t.harvestLocalNFTSet(hCtx, now)
	harvestNFTKernelLogs(hCtx, t)
	t.harvestLocalFail2ban(hCtx, now)
	t.harvestLocalSSProbes(hCtx)
}

func (t *Tracker) harvestLocalNFTSet(ctx context.Context, now time.Time) {
	if _, err := exec.LookPath("nft"); err != nil {
		return
	}
	out, err := exec.CommandContext(ctx, "nft", "list", "set", "inet", "security", "blocklist_ip4").Output()
	if err != nil {
		return
	}
	entries := ParseNFTSetEntries(string(out), now)
	if len(entries) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ent := range entries {
		if !IsIgnoredInternalIP(ent.IP) {
			t.observeNodeAtLocked("local", "本机网关", ent.IP, "高危端口扫描拦截", "banned", 1, true, ent.ObservedAt, ent.ObservedAt)
		}
	}
}

func (t *Tracker) harvestLocalFail2ban(ctx context.Context, now time.Time) {
	if _, err := exec.LookPath("fail2ban-client"); err != nil {
		return
	}
	f2bTimeMap := harvestLocalFail2banLogTimes(now)
	for _, jail := range []string{"sshd", "recidive"} {
		out, err := exec.CommandContext(ctx, "fail2ban-client", "status", jail).Output()
		if err != nil {
			continue
		}
		ips := ParseFail2banBannedIPs(string(out))
		t.recordFail2banIPs("local", "本机网关", ips, f2bTimeMap)
	}
}

func (t *Tracker) recordFail2banIPs(nodeID, nodeName string, ips []string, f2bTimes map[string]Fail2banTimeInfo) {
	if len(ips) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ip := range ips {
		if IsIgnoredInternalIP(ip) {
			continue
		}
		ft, lt, hits := time.Time{}, time.Time{}, 3
		if info, ok := f2bTimes[ip]; ok {
			ft, lt = info.First, info.Last
			hits = max(hits, info.Hits)
		}
		t.observeNodeAtLocked(nodeID, nodeName, ip, "SSH 暴力破解", "banned", hits, true, ft, lt)
	}
}

func (t *Tracker) harvestLocalSSProbes(ctx context.Context) {
	if _, err := exec.LookPath("ss"); err != nil {
		return
	}
	out, err := exec.CommandContext(ctx, "ss", "-tan").Output()
	if err != nil {
		return
	}
	probes := ParseSSExternalProbes(string(out))
	if len(probes) == 0 {
		return
	}
	probeNow := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range probes {
		if !IsIgnoredInternalIP(p.IP) {
			t.observeNodeAtLocked("local", "本机网关", p.IP, p.Vector, p.Status, p.Hits, true, time.Time{}, probeNow)
		}
	}
}

func buildRemoteHarvestScript(telemetryAddr string) string {
	addr := cmp.Or(strings.TrimSpace(telemetryAddr), "127.0.0.1:"+fmt.Sprintf("%d", 9099))
	return fmt.Sprintf("TELEMETRY_ADDR=%q\n%s", addr, remoteHarvestScriptBody)
}

func (t *Tracker) maybeHarvestRemoteTargets(ctx context.Context, remoteNodes []RemoteTarget, nodeScope string, force bool) {
	t.mu.RLock()
	rp := t.remote
	t.mu.RUnlock()
	if rp == nil || rp.Exec == nil {
		return
	}

	now := time.Now()
	var targets []RemoteTarget
	t.mu.Lock()
	for _, fn := range remoteNodes {
		if !fn.Enabled || (nodeScope != "all" && fn.ID != nodeScope) {
			continue
		}
		meta := t.ensureNodeMetaLocked(fn.ID)
		if !force && !meta.lastHarvest.IsZero() && now.Sub(meta.lastHarvest) < fleetHarvestMinDT {
			continue
		}
		meta.lastHarvest = now
		targets = append(targets, fn)
	}
	if len(targets) > 0 {
		t.bumpDataRevLocked()
	}
	t.mu.Unlock()
	if len(targets) == 0 {
		return
	}

	script := buildRemoteHarvestScript(rp.TelemetryAddr)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, fn := range targets {
		node := fn
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()

			rCtx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
			defer cancel()
			out, _, err := rp.Exec(rCtx, node, script)
			if err != nil {
				t.mu.Lock()
				t.ensureNodeMetaLocked(node.ID).lastError = err.Error()
				t.bumpDataRevLocked()
				t.mu.Unlock()
				return
			}
			t.mu.Lock()
			meta := t.ensureNodeMetaLocked(node.ID)
			if meta.lastError != "" {
				meta.lastError = ""
				t.bumpDataRevLocked()
			}
			t.mu.Unlock()
			t.IngestRemoteSniffOutput(node.ID, cmp.Or(node.Name, node.ID), out)
		})
	}
	wg.Wait()
}

// IngestRemoteSniffOutput 解析远端子节点采集脚本返回的分段日志，兼容新旧分段标记。
func (t *Tracker) IngestRemoteSniffOutput(nodeID, nodeName, raw string) {
	var secTrusted, secNFT, secF2B, secKern, secSS strings.Builder
	currentSec := ""
	for line := range strings.SplitSeq(raw, "\n") {
		switch strings.TrimSpace(line) {
		case "===SINGCTL_TRUSTED===":
			currentSec = "trusted"
			continue
		case "===SINGCTL_NFT===", "===NFT_V4===":
			currentSec = "nft"
			continue
		case "===SINGCTL_F2B===", "===F2B===":
			currentSec = "f2b"
			continue
		case "===SINGCTL_KERN===":
			currentSec = "kern"
			continue
		case "===SINGCTL_SS===", "===SS===":
			currentSec = "ss"
			continue
		}
		switch currentSec {
		case "trusted":
			secTrusted.WriteString(line)
			secTrusted.WriteByte('\n')
		case "nft":
			secNFT.WriteString(line)
			secNFT.WriteByte('\n')
		case "f2b":
			secF2B.WriteString(line)
			secF2B.WriteByte('\n')
		case "kern":
			secKern.WriteString(line)
			secKern.WriteByte('\n')
		case "ss":
			secSS.WriteString(line)
			secSS.WriteByte('\n')
		}
	}

	if trustedStr := secTrusted.String(); trustedStr != "" {
		var clientIPs []string
		for _, m := range reSingBoxSourceIP.FindAllStringSubmatch(trustedStr, -1) {
			if len(m) == 2 && m[1] != "" {
				clientIPs = append(clientIPs, m[1])
			}
		}
		if len(clientIPs) > 0 {
			t.MarkTrustedClientIPs(clientIPs...)
		}
	}

	now := time.Now()
	nftEntries := ParseNFTSetEntries(secNFT.String(), now)
	f2bIPs := ParseFail2banBannedIPs(secF2B.String())
	f2bTimes := ParseFail2banLogTimestamps(secF2B.String(), now)
	ssProbes := ParseSSExternalProbes(secSS.String())

	t.mu.Lock()
	for _, ent := range nftEntries {
		if !IsIgnoredInternalIP(ent.IP) {
			t.observeNodeAtLocked(nodeID, nodeName, ent.IP, "高危端口扫描拦截", "banned", 1, true, ent.ObservedAt, ent.ObservedAt)
		}
	}
	for _, p := range ssProbes {
		if !IsIgnoredInternalIP(p.IP) {
			t.observeNodeAtLocked(nodeID, nodeName, p.IP, p.Vector, p.Status, p.Hits, true, time.Time{}, now)
		}
	}
	t.mu.Unlock()

	t.recordFail2banIPs(nodeID, nodeName, f2bIPs, f2bTimes)
	if kernStr := secKern.String(); kernStr != "" {
		ingestNFTKernelLogContent(t, nodeID, nodeName, kernStr, now)
	}
}
