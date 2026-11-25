// 文件职责：测试守护进程本地域名 Split-DNS 应答器与 DHCP MAC 自动跟随工作器的生命周期、热更新与状态落盘。
package daemon_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/homedomain"
)

func TestHomeDomainWorker_LifecycleHotReloadAndDHCPFollow(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	leasesPath := filepath.Join(dir, "dhcp.leases")
	arpPath := filepath.Join(dir, "arp")
	_ = os.WriteFile(leasesPath, []byte("1799999999 aa:bb:cc:dd:ee:01 192.0.2.10 MyNAS 01:aa\n"), 0644)
	_ = os.WriteFile(arpPath, []byte("IP address HW type Flags HW address Mask Device\n192.0.2.10 0x1 0x2 aa:bb:cc:dd:ee:01 * br-lan\n"), 0644)

	cfg := &config.Config{
		HomeDomain: config.HomeDomainConfig{
			Suffix: "home",
			Devices: []config.HomeDomainDevice{
				{Alias: "nas", DisplayName: "家庭NAS", IP: "192.0.2.10", MAC: "aa:bb:cc:dd:ee:01", Source: "lan"},
			},
		},
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	store := config.NewStore(cfgPath, config.WithInitialConfig(cfg))
	stateStore := daemon.NewStateStore(daemon.Paths{
		PidFile:   filepath.Join(dir, "dm.pid"),
		StateFile: filepath.Join(dir, "dm.state"),
		LogFile:   filepath.Join(dir, "dm.log"),
	})

	worker := daemon.NewHomeDomainWorker(daemon.HomeDomainWorkerDeps{
		ConfigStore:      store,
		StateStore:       stateStore,
		ListenAddrForTest: "127.0.0.1:0",
		DiscoveryDeps: homedomain.DiscoveryDeps{
			LeaseFiles:      []string{leasesPath},
			ARPFile:         arpPath,
			HostnameFunc:    func() (string, error) { return "n4120", nil },
			PrimaryLANIP:    func() string { return "192.0.2.1" },
			TailscaleStatus: func(context.Context) ([]byte, error) { return nil, os.ErrNotExist },
		},
		DnsmasqDeps: homedomain.DnsmasqDeps{
			IsOpenWrt: func() bool { return false },
		},
	})
	defer func() { _ = worker.Close() }()

	// Simulate short-lived reconcile timeout ctx cancelling immediately after Reconcile returns:
	// the persistent Split-DNS listener MUST remain alive until worker.Close()!
	shortCtx, cancelShort := context.WithTimeout(t.Context(), 5*time.Second)
	if err := worker.Reconcile(shortCtx, store.Get()); err != nil {
		cancelShort()
		t.Fatalf("Reconcile failed: %v", err)
	}
	cancelShort()
	time.Sleep(30 * time.Millisecond)

	snap := stateStore.Load()
	if snap.HomeDomainDNS == nil || !snap.HomeDomainDNS.Running || snap.HomeDomainDNS.ListenAddr == "" {
		t.Fatalf("expected running HomeDomainDNS in stateStore, got %+v", snap.HomeDomainDNS)
	}

	ips, _, err := homedomain.ProbeDNSRecord(t.Context(), snap.HomeDomainDNS.ListenAddr, "nas.home", 2*time.Second)
	if err != nil || len(ips) != 1 || ips[0] != "192.0.2.10" {
		t.Fatalf("ProbeDNSRecord after reconcile ctx cancel = (%v, %v), want [192.0.2.10]", ips, err)
	}

	// Simulate DHCP IP change and trigger ReconcileDHCP -> config + responder update automatically
	_ = os.WriteFile(leasesPath, []byte("1799999999 aa:bb:cc:dd:ee:01 192.0.2.55 MyNAS 01:aa\n"), 0644)
	_ = os.WriteFile(arpPath, []byte("IP address HW type Flags HW address Mask Device\n192.0.2.55 0x1 0x2 aa:bb:cc:dd:ee:01 * br-lan\n"), 0644)

	if updated := worker.ReconcileDHCP(t.Context()); !updated {
		t.Fatalf("expected ReconcileDHCP to detect MAC IP move 192.0.2.10 -> 192.0.2.55")
	}
	ips2, _, err := homedomain.ProbeDNSRecord(t.Context(), snap.HomeDomainDNS.ListenAddr, "nas.home", 2*time.Second)
	if err != nil || len(ips2) != 1 || ips2[0] != "192.0.2.55" {
		t.Fatalf("after DHCP move ProbeDNSRecord = (%v, %v), want [192.0.2.55]", ips2, err)
	}

	if err := worker.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	snapAfter := stateStore.Load()
	if snapAfter.HomeDomainDNS != nil && snapAfter.HomeDomainDNS.Running {
		t.Fatalf("expected Running=false after Close, got %+v", snapAfter.HomeDomainDNS)
	}
}
