// 文件职责：测试 Tailscale 专属 Split-DNS UDP/TCP 应答器的访问控制、无中断热更新、并发安全与生命周期停机。
package homedomain_test

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/homedomain"
)

func TestTailscaleDNSResponder_UDPAndTCPAndHotReload(t *testing.T) {
	srv := homedomain.NewResponder(homedomain.ResponderDeps{
		AllowSource: func(ip netip.Addr) bool {
			return ip.IsLoopback() || homedomain.IsTailscaleSourceIP(ip)
		},
	})
	srv.UpdateRecords("home", []config.DNSRewriteRule{
		{Domain: "nas.home", Answer: "192.0.2.10"},
	})

	if err := srv.Start(t.Context(), "127.0.0.1:0"); err != nil {
		t.Fatalf("Start responder failed: %v", err)
	}
	defer func() { _ = srv.Close() }()

	addr := srv.ListenAddr()
	if addr == "" {
		t.Fatalf("expected non-empty listen addr")
	}

	// 1. UDP probe resolves nas.home -> 192.0.2.10
	ips, rtt, err := homedomain.ProbeDNSRecord(t.Context(), addr, "nas.home", 2*time.Second)
	if err != nil || len(ips) != 1 || ips[0] != "192.0.2.10" {
		t.Fatalf("UDP ProbeDNSRecord = (%v, %v, %v), want [192.0.2.10]", ips, rtt, err)
	}

	// 2. TCP query works cleanly
	tcpConn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("TCP dial failed: %v", err)
	}
	_ = tcpConn.SetDeadline(time.Now().Add(2 * time.Second))
	q := buildTestDNSQuery(t, 0xabcd, "nas.home", homedomain.TypeA)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(q)))
	if _, err := tcpConn.Write(append(lenBuf, q...)); err != nil {
		t.Fatalf("TCP write failed: %v", err)
	}
	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, respLenBuf); err != nil {
		t.Fatalf("TCP read len failed: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(respLenBuf))
	if _, err := io.ReadFull(tcpConn, resp); err != nil {
		t.Fatalf("TCP read body failed: %v", err)
	}
	_ = tcpConn.Close()
	gotTCP, _ := netip.AddrFromSlice(resp[len(resp)-4:])
	if gotTCP.String() != "192.0.2.10" {
		t.Fatalf("TCP answer = %s, want 192.0.2.10", gotTCP)
	}

	// 3. Hot-reload records without socket restart + concurrent race stress
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 10 {
			srv.UpdateRecords("home", []config.DNSRewriteRule{
				{Domain: "nas.home", Answer: "192.0.2.20"},
			})
		}
	}()
	go func() {
		defer wg.Done()
		for range 10 {
			_, _, _ = homedomain.ProbeDNSRecord(t.Context(), addr, "nas.home", time.Second)
		}
	}()
	wg.Wait()

	ipsAfter, _, err := homedomain.ProbeDNSRecord(t.Context(), addr, "nas.home", 2*time.Second)
	if err != nil || len(ipsAfter) != 1 || ipsAfter[0] != "192.0.2.20" {
		t.Fatalf("after hot-reload expected 192.0.2.20, got %v err=%v", ipsAfter, err)
	}

	st := srv.Status()
	if !st.Running || st.Suffix != "home" || st.RecordCount != 1 || st.QueryCount < 2 {
		t.Fatalf("unexpected responder status: %+v", st)
	}

	// 4. Source IP allowlist redline: public IP rejected, Tailscale CGNAT/ULA allowed
	if homedomain.IsTailscaleSourceIP(netip.MustParseAddr("203.0.113.5")) {
		t.Fatalf("public IP must never pass Tailscale source check")
	}
	if !homedomain.IsTailscaleSourceIP(netip.MustParseAddr("100.64.1.2")) {
		t.Fatalf("Tailscale CGNAT IP must pass source check")
	}
}
