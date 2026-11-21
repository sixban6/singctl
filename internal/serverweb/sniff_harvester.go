// 文件职责：负责本机系统级嗅探采集（nftables 封禁集、内核日志、fail2ban、ss 实时连接）与舰队远端节点并发 SSH 采集与分段解包注入。
//
// 架构设计原则：
//   - 异步不阻塞 UI：后台采集通过 atomic.Bool 单飞防抖触发，所有外部命令/SSH 执行严格绑定 context 超时（exec.CommandContext）。
//   - 解析器解耦：原始文本分段与正则提取委托给 sniff_parsers.go 与 sniff_fingerprints.go，本文件只负责采集调度与写入状态机。
package serverweb

import (
	"cmp"
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	"singctl/internal/fleet"
)

func (t *SniffTracker) triggerBackgroundSystemHarvestIfNeeded() {
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

func (t *SniffTracker) triggerBackgroundFleetHarvestIfNeeded() {
	t.mu.RLock()
	fleetMgr := t.fleetMgr
	enableProbe := t.EnableSystemProbe
	t.mu.RUnlock()
	if !enableProbe || fleetMgr == nil || fleetMgr.Store == nil {
		return
	}
	if !t.fleetBgRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer t.fleetBgRunning.Store(false)
		nodes, err := fleetMgr.Store.List()
		if err != nil || len(nodes) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t.maybeHarvestFleetNodes(ctx, nodes, "all", false)
	}()
}

func (t *SniffTracker) maybeHarvestSystemSources(ctx context.Context, force bool) {
	now := time.Now()
	t.mu.Lock()
	if !t.EnableSystemProbe || (!force && !t.lastSystemHarvest.IsZero() && now.Sub(t.lastSystemHarvest) < systemHarvestMinDT) {
		t.mu.Unlock()
		return
	}
	t.lastSystemHarvest = now
	t.ensureNodeMetaLocked("local").lastHarvest = now
	t.mu.Unlock()

	hCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	// 1. 采集 nftables 动态封禁集 (@blocklist_ip4，支持从 timeout/expires 反推真实封禁时间)
	if _, err := exec.LookPath("nft"); err == nil {
		if out, err := exec.CommandContext(hCtx, "nft", "list", "set", "inet", "security", "blocklist_ip4").Output(); err == nil {
			entries := parseNFTSetEntries(string(out), now)
			t.mu.Lock()
			for _, ent := range entries {
				if !isIgnoredInternalIP(ent.ip) {
					t.observeNodeAtLocked("local", "本机网关", ent.ip, "高危端口扫描拦截", "banned", 1, true, ent.observedAt, ent.observedAt)
				}
			}
			t.mu.Unlock()
		}
	}

	// 2. 采集内核日志中 [NFT] Blocked 的精确命中端口、次数与日志时间戳
	harvestNFTKernelLogs(hCtx, t)

	// 3. 采集 fail2ban (sshd / recidive) 封禁 IP 及 /var/log/fail2ban.log 时间戳
	f2bTimeMap := harvestLocalFail2banLogTimes(now)
	if _, err := exec.LookPath("fail2ban-client"); err == nil {
		for _, jail := range []string{"sshd", "recidive"} {
			if out, err := exec.CommandContext(hCtx, "fail2ban-client", "status", jail).Output(); err == nil {
				ips := parseFail2banBannedIPs(string(out))
				t.mu.Lock()
				for _, ip := range ips {
					if !isIgnoredInternalIP(ip) {
						ft, lt, hits := time.Time{}, time.Time{}, 3
						if info, ok := f2bTimeMap[ip]; ok {
							ft, lt = info.first, info.Last
							if info.hits > hits {
								hits = info.hits
							}
						}
						t.observeNodeAtLocked("local", "本机网关", ip, "SSH 暴力破解", "banned", hits, true, ft, lt)
					}
				}
				t.mu.Unlock()
			}
		}
	}

	// 4. 采集当前套接字 (ss -tan) 上的外部伪装回落与端口试探连接 (实时活跃连接更新 lastSeen=now)
	if _, err := exec.LookPath("ss"); err == nil {
		if out, err := exec.CommandContext(hCtx, "ss", "-tan").Output(); err == nil {
			probes := parseSSExternalProbes(string(out))
			probeNow := time.Now()
			t.mu.Lock()
			for _, p := range probes {
				if !isIgnoredInternalIP(p.ip) {
					t.observeNodeAtLocked("local", "本机网关", p.ip, p.vector, p.status, p.hits, true, time.Time{}, probeNow)
				}
			}
			t.mu.Unlock()
		}
	}
}

const remoteSniffHarvestScript = `
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
echo "===SINGCTL_TRUSTED==="
if command -v curl >/dev/null 2>&1 && [ -f /etc/sing-box/config.json ]; then
  SECRET=$(sed -n 's/.*"secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/sing-box/config.json | head -n 1)
  if [ -n "$SECRET" ]; then
    curl -fsS -m 1 -H "Authorization: Bearer $SECRET" http://127.0.0.1:9099/connections 2>/dev/null || true
  else
    curl -fsS -m 1 http://127.0.0.1:9099/connections 2>/dev/null || true
  fi
fi
echo ""
echo "===SINGCTL_NFT==="
if command -v nft >/dev/null 2>&1; then
  nft list set inet security blocklist_ip4 2>/dev/null || true
fi
echo "===SINGCTL_F2B==="
if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client status sshd 2>/dev/null || true
  fail2ban-client status recidive 2>/dev/null || true
fi
if [ -r /var/log/fail2ban.log ]; then
  tail -c 32768 /var/log/fail2ban.log 2>/dev/null | grep -E "Found |Ban " || true
fi
echo "===SINGCTL_KERN==="
for f in /var/log/kern.log /var/log/syslog /var/log/messages; do
  if [ -r "$f" ]; then
    tail -c 32768 "$f" 2>/dev/null | grep "\[NFT\]" || true
    break
  fi
done
echo "===SINGCTL_SS==="
if command -v ss >/dev/null 2>&1; then
  ss -tan 2>/dev/null || true
fi
`

func (t *SniffTracker) maybeHarvestFleetNodes(ctx context.Context, fleetNodes []fleet.Node, nodeScope string, force bool) {
	t.mu.RLock()
	fleetMgr := t.fleetMgr
	t.mu.RUnlock()
	if fleetMgr == nil {
		return
	}
	runner := fleetMgr.Runner
	if runner == nil {
		runner = fleet.DefaultSSHRunner
	}

	now := time.Now()
	var targets []fleet.Node
	t.mu.Lock()
	for _, fn := range fleetNodes {
		if !fn.Enabled {
			continue
		}
		if nodeScope != "all" && fn.ID != nodeScope {
			continue
		}
		meta := t.ensureNodeMetaLocked(fn.ID)
		if !force && !meta.lastHarvest.IsZero() && now.Sub(meta.lastHarvest) < fleetHarvestMinDT {
			continue
		}
		meta.lastHarvest = now
		targets = append(targets, fn)
	}
	t.mu.Unlock()

	if len(targets) == 0 {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, fn := range targets {
		wg.Add(1)
		go func(node fleet.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rCtx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
			defer cancel()
			out, _, err := runner(rCtx, node, remoteSniffHarvestScript)
			if err != nil {
				t.mu.Lock()
				t.ensureNodeMetaLocked(node.ID).lastError = err.Error()
				t.mu.Unlock()
				return
			}
			t.mu.Lock()
			t.ensureNodeMetaLocked(node.ID).lastError = ""
			t.mu.Unlock()
			t.IngestRemoteSniffOutput(node.ID, cmp.Or(node.Name, node.ID), out)
		}(fn)
	}
	wg.Wait()
}

// IngestRemoteSniffOutput 解析远端子节点采集脚本返回的分段日志，更新可信客户端白名单与各主机嗅探威胁记录。
func (t *SniffTracker) IngestRemoteSniffOutput(nodeID, nodeName, raw string) {
	var secTrusted, secNFT, secF2B, secKern, secSS strings.Builder
	currentSec := ""
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case "===SINGCTL_TRUSTED===":
			currentSec = "trusted"
			continue
		case "===SINGCTL_NFT===":
			currentSec = "nft"
			continue
		case "===SINGCTL_F2B===":
			currentSec = "f2b"
			continue
		case "===SINGCTL_KERN===":
			currentSec = "kern"
			continue
		case "===SINGCTL_SS===":
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

	// 1. 提取该子节点合法代理客户端 IP 并加入全局可信白名单
	if trustedStr := secTrusted.String(); trustedStr != "" {
		matches := reSingBoxSourceIP.FindAllStringSubmatch(trustedStr, -1)
		if len(matches) > 0 {
			var clientIPs []string
			for _, m := range matches {
				if len(m) == 2 && m[1] != "" {
					clientIPs = append(clientIPs, m[1])
				}
			}
			if len(clientIPs) > 0 {
				t.MarkTrustedClientIPs(clientIPs...)
			}
		}
	}

	now := time.Now()
	nftEntries := parseNFTSetEntries(secNFT.String(), now)
	f2bIPs := parseFail2banBannedIPs(secF2B.String())
	f2bTimes := parseFail2banLogTimestamps(secF2B.String(), now)
	ssProbes := parseSSExternalProbes(secSS.String())

	t.mu.Lock()
	for _, ent := range nftEntries {
		if !isIgnoredInternalIP(ent.ip) {
			t.observeNodeAtLocked(nodeID, nodeName, ent.ip, "高危端口扫描拦截", "banned", 1, true, ent.observedAt, ent.observedAt)
		}
	}
	for _, ip := range f2bIPs {
		if !isIgnoredInternalIP(ip) {
			ft, lt, hits := time.Time{}, time.Time{}, 3
			if info, ok := f2bTimes[ip]; ok {
				ft, lt = info.first, info.Last
				if info.hits > hits {
					hits = info.hits
				}
			}
			t.observeNodeAtLocked(nodeID, nodeName, ip, "SSH 暴力破解", "banned", hits, true, ft, lt)
		}
	}
	for _, p := range ssProbes {
		if !isIgnoredInternalIP(p.ip) {
			t.observeNodeAtLocked(nodeID, nodeName, p.ip, p.vector, p.status, p.hits, true, time.Time{}, now)
		}
	}
	t.mu.Unlock()

	if kernStr := secKern.String(); kernStr != "" {
		ingestNFTKernelLogContent(t, nodeID, nodeName, kernStr, now)
	}
}
