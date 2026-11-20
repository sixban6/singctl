package tailscale_p2p_e2e

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

const (
	e2eImageTag = "singctl-openwrt24-e2e:local"

	wanSubnet   = "198.51.100.0/24"
	wanGW       = "198.51.100.254"
	routerWANIP = "198.51.100.100"
	peerAWANIP  = "198.51.100.10"
	peerBWANIP  = "198.51.100.20"

	lanSubnet   = "192.168.180.0/24"
	lanGW       = "192.168.180.254"
	routerLANIP = "192.168.180.1"
	lanSrvIP    = "192.168.180.10"

	tsSubnet       = "100.64.200.0/24"
	tsGW           = "100.64.200.254"
	routerTSIP     = "100.64.200.1"
	remoteRtrTSIP  = "100.64.200.2"
	remoteLANIP    = "192.168.55.10"
	remoteSubnet   = "192.168.55.0/24"
	adminLaptopIP  = "100.64.200.99"
)

// TestTailscaleP2PDefenseOpenWrtE2E 使用真实 OpenWrt 24.10 容器镜像 (fw4 + nft + 内核 nf_conntrack + tailscale0 网卡)
// 验证 Tailscale P2P 防线 Layer 1 / Layer 2 / Layer 4 全套规则及坏第三方 /etc/nftables.d/*.nft 下 nft_direct 兜底与撤销。
func TestTailscaleP2PDefenseOpenWrtE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OpenWrt Tailscale P2P Defense Docker E2E in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed, skipping E2E test")
	}
	if out, err := exec.CommandContext(t.Context(), "docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	ctx := t.Context()
	workDir := t.TempDir()
	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	ensureOpenWrtE2EImage(t, ctx, repoRoot)
	targetArch := detectImageGoArch(t, ctx, e2eImageTag)
	probeBin := buildProbeHelperBinary(t, ctx, workDir, targetArch)

	nftDropInDir := filepath.Join(workDir, "nftables.d")
	if err := os.MkdirAll(nftDropInDir, 0755); err != nil {
		t.Fatalf("mkdir nftDropInDir: %v", err)
	}

	prefix := fmt.Sprintf("sc-tsp2p-%d", time.Now().UnixNano()%1000000)
	wanNet := prefix + "-wan"
	lanNet := prefix + "-lan"
	tsNet := prefix + "-ts"

	routerC := prefix + "-router"
	peerAC := prefix + "-peera"
	peerBC := prefix + "-peerb"
	lanSrvC := prefix + "-lansrv"
	tsPeersC := prefix + "-tspeers"

	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanCtx, "docker", "rm", "-f", tsPeersC, lanSrvC, peerBC, peerAC, routerC).Run()
		_ = exec.CommandContext(cleanCtx, "docker", "network", "rm", tsNet, lanNet, wanNet).Run()
	})

	mustRun(t, ctx, "docker", "network", "create", "--subnet="+wanSubnet, "--gateway="+wanGW, wanNet)
	mustRun(t, ctx, "docker", "network", "create", "--subnet="+lanSubnet, "--gateway="+lanGW, lanNet)
	mustRun(t, ctx, "docker", "network", "create", "--subnet="+tsSubnet, "--gateway="+tsGW, tsNet)

	startC := func(name, netName, ip string, extra ...string) {
		args := []string{
			"run", "-d", "--name", name,
			"--hostname", name,
			"--cap-add=NET_ADMIN",
			"--sysctl", "net.ipv4.ip_forward=1",
			"--network", netName, "--ip", ip,
		}
		args = append(args, extra...)
		args = append(args, e2eImageTag, "/bin/sh", "-c", "mkdir -p /var/run /var/lock /tmp/resolv.conf.d && exec sleep 3600")
		mustRun(t, ctx, "docker", args...)
	}

	startC(routerC, wanNet, routerWANIP,
		"-v", probeBin+":/usr/bin/p2p-probe:ro",
		"-v", nftDropInDir+":/usr/share/nftables.d",
	)
	mustRun(t, ctx, "docker", "network", "connect", "--ip", routerLANIP, lanNet, routerC)
	mustRun(t, ctx, "docker", "network", "connect", "--ip", routerTSIP, tsNet, routerC)

	startC(peerAC, wanNet, peerAWANIP, "-v", probeBin+":/usr/bin/p2p-probe:ro")
	startC(peerBC, wanNet, peerBWANIP, "-v", probeBin+":/usr/bin/p2p-probe:ro")
	startC(lanSrvC, lanNet, lanSrvIP, "-v", probeBin+":/usr/bin/p2p-probe:ro")
	startC(tsPeersC, tsNet, remoteRtrTSIP, "-v", probeBin+":/usr/bin/p2p-probe:ro")

	setupRouterFirewallAndListeners(t, ctx, routerC)
	setupLANAndTSPeers(t, ctx, lanSrvC, tsPeersC)

	fw4Mgr := &tailscale.FW4Manager{
		BaseDir: nftDropInDir,
		Runner:  dockerExecRunner(routerC),
	}

	now := time.Now().UTC()
	peerRule := config.TailscaleP2PPeerConfig{
		ID:          "nRemoteRouter",
		Name:        "router-remote",
		TailscaleIP: remoteRtrTSIP,
		JITEnabled:  true,
		AccessMode:  config.TailscaleAccessOutboundOnly,
	}
	resolved := []tailscale.ResolvedPeerACL{{
		Config:        peerRule,
		TailscaleIPs:  []string{remoteRtrTSIP},
		PrimaryRoutes: []string{remoteSubnet},
	}}
	p2pCfg := config.TailscaleP2PAssistConfig{
		Enabled:      true,
		JITWindowSec: 8,
		ListenPort:   41641,
	}

	// 1. Clean fw4 path: Render + Apply -> must select fw4_reload with 0 open pinholes
	dropIns, err := tailscale.RenderFW4DropIns(p2pCfg, resolved, lanSubnet, now)
	if err != nil {
		t.Fatalf("RenderFW4DropIns: %v", err)
	}
	applyMode, err := fw4Mgr.Apply(ctx, dropIns)
	if err != nil {
		t.Fatalf("FW4Manager.Apply failed: %v", err)
	}
	if applyMode != tailscale.ApplyModeFW4Reload {
		t.Fatalf("expected %q in clean OpenWrt container, got %q", tailscale.ApplyModeFW4Reload, applyMode)
	}
	if cnt, _ := fw4Mgr.CountOpenPinholes(ctx); cnt != 0 {
		t.Fatalf("expected 0 open pinholes at rest, got %d", cnt)
	}

	// 2. Idle Zero-Exposure: valid DISCO & WG1 from peerA to router WAN :41641 MUST be rejected/dropped
	beforeCount := readRouterUDPCount(t, ctx, routerC)
	mustExec(t, ctx, peerAC, fmt.Sprintf(`
set -e
p2p-probe udp-send %s:0 %s:41641 disco
p2p-probe udp-send %s:0 %s:41641 wg1
`, peerAWANIP, routerWANIP, peerAWANIP, routerWANIP))
	time.Sleep(250 * time.Millisecond)
	if after := readRouterUDPCount(t, ctx, routerC); after != beforeCount {
		t.Fatalf("idle zero-exposure violated! UDP listener received %d packets while @TS_JIT_ALLOW4 empty", after-beforeCount)
	}

	// 3. JIT Pinhole Open + Layer 2 Raw Payload Magic Filter
	if err := fw4Mgr.OpenPinhole(ctx, []netip.Addr{netip.MustParseAddr(peerAWANIP)}, nil, 8); err != nil {
		t.Fatalf("OpenPinhole failed: %v", err)
	}
	if cnt, ips := fw4Mgr.CountOpenPinholes(ctx); cnt != 1 || len(ips) != 1 || ips[0] != peerAWANIP {
		t.Fatalf("expected 1 open pinhole (%s), got cnt=%d ips=%v", peerAWANIP, cnt, ips)
	}

	// 3a. Unauthorized peerB even with valid DISCO/WG1 MUST be blocked
	c0 := readRouterUDPCount(t, ctx, routerC)
	mustExec(t, ctx, peerBC, fmt.Sprintf(`
set -e
p2p-probe udp-send %s:0 %s:41641 disco
p2p-probe udp-send %s:0 %s:41641 wg1
`, peerBWANIP, routerWANIP, peerBWANIP, routerWANIP))
	time.Sleep(200 * time.Millisecond)
	if c1 := readRouterUDPCount(t, ctx, routerC); c1 != c0 {
		t.Fatalf("unauthorized peerB penetrated pinhole (delta=%d)", c1-c0)
	}

	// 3b. Authorized peerA with garbage & malformed WG1 MUST be silently dropped by Layer 2 singctl_ts_jit_guard
	mustExec(t, ctx, peerAC, fmt.Sprintf(`
set -e
p2p-probe udp-send %s:0 %s:41641 garbage
p2p-probe udp-send %s:0 %s:41641 wg1bad
`, peerAWANIP, routerWANIP, peerAWANIP, routerWANIP))
	time.Sleep(200 * time.Millisecond)
	if c2 := readRouterUDPCount(t, ctx, routerC); c2 != c0 {
		t.Fatalf("Layer 2 payload filter failed to drop malformed UDP packets (delta=%d)", c2-c0)
	}
	guardDump := mustExec(t, ctx, routerC, "nft list chain inet fw4 singctl_ts_jit_guard")
	if !strings.Contains(guardDump, "packets 2") && !strings.Contains(guardDump, "counter packets") {
		t.Logf("guard chain dump:\n%s", guardDump)
	}

	// 3c. Authorized peerA with valid DISCO + WG1 + STUN MUST ALL PASS (expect +3 packets)
	mustExec(t, ctx, peerAC, fmt.Sprintf(`
set -e
p2p-probe udp-send %s:0 %s:41641 disco
p2p-probe udp-send %s:0 %s:41641 wg1
p2p-probe udp-send %s:0 %s:41641 stun
`, peerAWANIP, routerWANIP, peerAWANIP, routerWANIP, peerAWANIP, routerWANIP))
	time.Sleep(250 * time.Millisecond)
	if c3 := readRouterUDPCount(t, ctx, routerC); c3 != c0+3 {
		t.Fatalf("expected 3 valid DISCO/WG1/STUN packets accepted, got delta=%d\nChain:\n%s", c3-c0, mustExec(t, ctx, routerC, "nft list chain inet fw4 singctl_ts_jit_guard"))
	}

	// 4. Conntrack 5-Tuple Lock + CGNAT Neighbor Immunity:
	//    peerA sends DISCO from 51001 and waits for PONG reply (establishes conntrack);
	//    immediately ClosePinhole; verify 51001 STILL passes while 51002 (CGNAT neighbor) is BLOCKED!
	mustExec(t, ctx, peerAC, fmt.Sprintf("p2p-probe udp-exchange %s:51001 %s:41641 disco", peerAWANIP, routerWANIP))
	if err := fw4Mgr.ClosePinhole(ctx, []netip.Addr{netip.MustParseAddr(peerAWANIP)}, nil); err != nil {
		t.Fatalf("ClosePinhole failed: %v", err)
	}
	if cnt, _ := fw4Mgr.CountOpenPinholes(ctx); cnt != 0 {
		t.Fatalf("expected 0 open pinholes immediately after ClosePinhole, got %d", cnt)
	}
	// Established 5-tuple 51001 -> 41641 MUST STILL WORK
	mustExec(t, ctx, peerAC, fmt.Sprintf("p2p-probe udp-exchange %s:51001 %s:41641 data", peerAWANIP, routerWANIP))
	// Different srcPort 51002 from SAME peerA IP (CGNAT neighbor) MUST BE BLOCKED!
	c4 := readRouterUDPCount(t, ctx, routerC)
	mustExec(t, ctx, peerAC, fmt.Sprintf("p2p-probe udp-send %s:51002 %s:41641 disco", peerAWANIP, routerWANIP))
	time.Sleep(200 * time.Millisecond)
	if c5 := readRouterUDPCount(t, ctx, routerC); c5 != c4 {
		t.Fatalf("CGNAT neighbor on different srcPort 51002 was NOT blocked after ClosePinhole (delta=%d)", c5-c4)
	}

	// 5. Layer 4 State 1: outbound_only
	assertTCPBlocked(t, ctx, tsPeersC, remoteRtrTSIP, routerTSIP+":8090", "outbound_only peer->router mgmt")
	assertTCPBlocked(t, ctx, tsPeersC, remoteRtrTSIP, lanSrvIP+":8445", "outbound_only peer->lanSrv:8445")
	assertTCPBlocked(t, ctx, tsPeersC, remoteLANIP, lanSrvIP+":8445", "outbound_only remoteLAN->lanSrv:8445")
	// Outbound from LAN to remote router MUST succeed
	mustExec(t, ctx, lanSrvC, fmt.Sprintf("p2p-probe tcp-dial %s %s:9001", lanSrvIP, remoteRtrTSIP))
	// Unlisted admin device MUST access both router mgmt & LAN freely
	mustExec(t, ctx, tsPeersC, fmt.Sprintf("p2p-probe tcp-dial %s %s:8090", adminLaptopIP, routerTSIP))
	mustExec(t, ctx, tsPeersC, fmt.Sprintf("p2p-probe tcp-dial %s %s:8445", adminLaptopIP, lanSrvIP))

	// 6. Layer 4 State 2: bidirectional_timed (active -> expired)
	resolved[0].Config.AccessMode = config.TailscaleAccessBidirectionalTimed
	resolved[0].Config.BidirectionalUntil = now.Add(10 * time.Minute).Format(time.RFC3339)
	resolved[0].Config.AllowedLANTargets = []string{lanSrvIP + ":8445"}
	dropInsActive, err := tailscale.RenderFW4DropIns(p2pCfg, resolved, lanSubnet, now)
	if err != nil {
		t.Fatalf("render active timed: %v", err)
	}
	if mode, err := fw4Mgr.Apply(ctx, dropInsActive); err != nil || mode != tailscale.ApplyModeFW4Reload {
		t.Fatalf("apply active timed: mode=%q err=%v", mode, err)
	}
	mustExec(t, ctx, tsPeersC, fmt.Sprintf("p2p-probe tcp-dial %s %s:8445", remoteRtrTSIP, lanSrvIP))
	mustExec(t, ctx, tsPeersC, fmt.Sprintf("p2p-probe tcp-dial %s %s:8445", remoteLANIP, lanSrvIP))
	assertTCPBlocked(t, ctx, tsPeersC, remoteRtrTSIP, lanSrvIP+":8080", "bidirectional_timed non-allowed LAN port 8080")
	assertTCPBlocked(t, ctx, tsPeersC, remoteRtrTSIP, routerTSIP+":8090", "bidirectional_timed router mgmt stays blocked")

	// Expire timestamp and re-apply -> automatically locks down again
	resolved[0].Config.BidirectionalUntil = now.Add(-1 * time.Minute).Format(time.RFC3339)
	dropInsExpired, err := tailscale.RenderFW4DropIns(p2pCfg, resolved, lanSubnet, now)
	if err != nil {
		t.Fatalf("render expired timed: %v", err)
	}
	if _, err := fw4Mgr.Apply(ctx, dropInsExpired); err != nil {
		t.Fatalf("apply expired timed: %v", err)
	}
	assertTCPBlocked(t, ctx, tsPeersC, remoteRtrTSIP, lanSrvIP+":8445", "expired bidirectional_timed must revert to outbound_only")

	// 7. Hybrid Fallback Replication (n4120 scenario): corrupt unrelated /etc/nftables.d file so fw4 check FAILS,
	//    then re-enable bidirectional :8445 via Apply -> must seamlessly switch via nft_direct and enforce packets!
	mustExec(t, ctx, routerC, `mkdir -p /etc/nftables.d && printf 'broken_thirdparty_token {\n' > /etc/nftables.d/99-broken-thirdparty.nft`)
	resolved[0].Config.AccessMode = config.TailscaleAccessBidirectional
	resolved[0].Config.BidirectionalUntil = ""
	dropInsFallback, _ := tailscale.RenderFW4DropIns(p2pCfg, resolved, lanSubnet, now)
	fbMode, err := fw4Mgr.Apply(ctx, dropInsFallback)
	if err != nil {
		t.Fatalf("hybrid nft_direct Apply failed: %v", err)
	}
	if fbMode != tailscale.ApplyModeNFTDirect {
		t.Fatalf("expected %q when fw4 check broken by thirdparty file, got %q", tailscale.ApplyModeNFTDirect, fbMode)
	}
	mustExec(t, ctx, tsPeersC, fmt.Sprintf("p2p-probe tcp-dial %s %s:8445", remoteRtrTSIP, lanSrvIP))
	assertTCPBlocked(t, ctx, tsPeersC, remoteRtrTSIP, lanSrvIP+":8080", "nft_direct non-allowed LAN port 8080")

	// 8. Clean Teardown even while thirdparty /etc/nftables.d is broken, then confirm stock fw4 check is 0!
	if err := fw4Mgr.Remove(ctx); err != nil {
		t.Fatalf("FW4Manager.Remove failed under broken fw4: %v", err)
	}
	tblAfterRm := mustExec(t, ctx, routerC, "nft list table inet fw4")
	for _, gone := range []string{"TS_JIT_ALLOW4", "TS_JIT_ALLOW6", "singctl_ts_jit_guard", "singctl_ts_input_acl", "singctl_ts_forward_acl"} {
		if strings.Contains(tblAfterRm, gone) {
			t.Fatalf("expected %s cleaned from table inet fw4 after Remove:\n%s", gone, tblAfterRm)
		}
	}
	mustExec(t, ctx, routerC, "rm -f /etc/nftables.d/99-broken-thirdparty.nft && /sbin/fw4 -q check")
}
