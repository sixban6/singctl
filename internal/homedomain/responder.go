// 文件职责：提供仅绑定 Tailscale 虚拟接口（100.x:53）的纯 Go Split-DNS UDP/TCP 权威应答器，支持源 IP 严格白名单与无中断热更新。
package homedomain

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

const (
	maxConcurrentTCPConns = 64
	tcpIOReadTimeout      = 3 * time.Second
)

// ResponderStatus 描述内置 Tailscale Split-DNS 应答器的运行态摘要。
type ResponderStatus struct {
	Running     bool   `json:"running"`
	ListenAddr  string `json:"listenAddr,omitempty"`
	Suffix      string `json:"suffix,omitempty"`
	RecordCount int    `json:"recordCount"`
	QueryCount  uint64 `json:"queryCount"`
	LastError   string `json:"lastError,omitempty"`
}

// ResponderDeps 显式注入应答器的源 IP 准入判定依赖（默认严格限定 Tailscale CGNAT/ULA + 本机回环自检）。
type ResponderDeps struct {
	AllowSource func(ip netip.Addr) bool
}

// IsTailscaleSourceIP 判断来源 IP 是否属于 Tailscale 虚拟网段（100.64.0.0/10 或 fd7a:115c:a1e0::/48）。
func IsTailscaleSourceIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	return tailscale.IsTailscaleAddr(ip.Unmap().String())
}

func defaultAllowSource(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	u := ip.Unmap()
	return u.IsLoopback() || IsTailscaleSourceIP(u)
}

// TailscaleDNSResponder 在 Tailscale 虚拟 IP:53 上直接响应受管 .home 域名查询（不依赖外部进程、零开放递归风险）。
type TailscaleDNSResponder struct {
	allowSource func(netip.Addr) bool
	index       atomic.Pointer[RecordIndex]
	queryCount  atomic.Uint64

	mu         sync.Mutex
	running    bool
	listenAddr string
	lastErr    string
	udpConn    net.PacketConn
	tcpLn      net.Listener
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	tcpSem     chan struct{}
}

// NewResponder 创建 Tailscale Split-DNS 应答器实例。
func NewResponder(deps ResponderDeps) *TailscaleDNSResponder {
	allow := deps.AllowSource
	if allow == nil {
		allow = defaultAllowSource
	}
	r := &TailscaleDNSResponder{
		allowSource: allow,
		tcpSem:      make(chan struct{}, maxConcurrentTCPConns),
	}
	r.index.Store(NewRecordIndex(config.DefaultHomeDomainSuffix, nil))
	return r
}

// UpdateRecords 原子切换内存域名索引（零锁竞争、无需重启监听套接字）。
func (r *TailscaleDNSResponder) UpdateRecords(suffix string, rules []config.DNSRewriteRule) {
	if r == nil {
		return
	}
	r.index.Store(NewRecordIndex(suffix, rules))
}

// Start 在指定地址（生产环境为 <tailscale_ip>:53，测试环境可为 127.0.0.1:0）启动 UDP + TCP 监听。
func (r *TailscaleDNSResponder) Start(ctx context.Context, listenAddr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		if r.listenAddr == listenAddr {
			return nil
		}
		r.stopLocked()
	}

	if ctx == nil {
		ctx = context.Background()
	}
	addr := strings.TrimSpace(listenAddr)
	if addr == "" {
		r.lastErr = "empty listen address"
		return errors.New(r.lastErr)
	}

	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		r.lastErr = err.Error()
		return err
	}
	actualAddr := udpConn.LocalAddr().String()
	tcpLn, err := net.Listen("tcp", actualAddr)
	if err != nil {
		_ = udpConn.Close()
		r.lastErr = err.Error()
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	r.udpConn = udpConn
	r.tcpLn = tcpLn
	r.listenAddr = actualAddr
	r.running = true
	r.lastErr = ""
	r.cancel = cancel

	r.wg.Add(2)
	go r.serveUDP(runCtx, udpConn)
	go r.serveTCP(runCtx, tcpLn)

	// 外部 ctx 取消时确保监听句柄及时关闭并同步运行态
	go func() {
		<-runCtx.Done()
		_ = udpConn.Close()
		_ = tcpLn.Close()
		r.mu.Lock()
		if r.udpConn == udpConn {
			r.running = false
			r.listenAddr = ""
			r.udpConn = nil
			r.tcpLn = nil
		}
		r.mu.Unlock()
	}()
	return nil
}

// Close 优雅停止 UDP + TCP 监听并等待全部协程退出。
func (r *TailscaleDNSResponder) Close() error {
	r.mu.Lock()
	r.stopLocked()
	r.mu.Unlock()
	return nil
}

func (r *TailscaleDNSResponder) stopLocked() {
	if !r.running {
		return
	}
	if r.cancel != nil {
		r.cancel()
	}
	if r.udpConn != nil {
		_ = r.udpConn.Close()
		r.udpConn = nil
	}
	if r.tcpLn != nil {
		_ = r.tcpLn.Close()
		r.tcpLn = nil
	}
	r.running = false
	r.listenAddr = ""
	// 释放锁等待协程退出后再重新拿锁，避免潜在死锁
	r.mu.Unlock()
	r.wg.Wait()
	r.mu.Lock()
}

// ListenAddr 返回当前实际监听地址。
func (r *TailscaleDNSResponder) ListenAddr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listenAddr
}

// Status 返回当前应答器快照状态。
func (r *TailscaleDNSResponder) Status() ResponderStatus {
	r.mu.Lock()
	running := r.running
	addr := r.listenAddr
	lastErr := r.lastErr
	r.mu.Unlock()

	idx := r.index.Load()
	return ResponderStatus{
		Running:     running,
		ListenAddr:  addr,
		Suffix:      idx.Suffix(),
		RecordCount: idx.Count(),
		QueryCount:  r.queryCount.Load(),
		LastError:   lastErr,
	}
}

func (r *TailscaleDNSResponder) isAllowedAddr(remote net.Addr) bool {
	if remote == nil {
		return false
	}
	var ip net.IP
	switch v := remote.(type) {
	case *net.UDPAddr:
		ip = v.IP
	case *net.TCPAddr:
		ip = v.IP
	default:
		host, _, err := net.SplitHostPort(remote.String())
		if err != nil {
			return false
		}
		ip = net.ParseIP(host)
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return r.allowSource(addr.Unmap())
}

func (r *TailscaleDNSResponder) serveUDP(ctx context.Context, conn net.PacketConn) {
	defer r.wg.Done()
	buf := make([]byte, 1500)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if !r.isAllowedAddr(remote) {
			continue
		}
		idx := r.index.Load()
		resp, ok := idx.AnswerPacket(buf[:n])
		if !ok {
			continue
		}
		r.queryCount.Add(1)
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = conn.WriteTo(resp, remote)
	}
}

func (r *TailscaleDNSResponder) serveTCP(ctx context.Context, ln net.Listener) {
	defer r.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if !r.isAllowedAddr(conn.RemoteAddr()) {
			_ = conn.Close()
			continue
		}
		select {
		case r.tcpSem <- struct{}{}:
			r.wg.Add(1)
			go func(c net.Conn) {
				defer r.wg.Done()
				defer func() { <-r.tcpSem }()
				r.handleTCPConn(c)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
}

func (r *TailscaleDNSResponder) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(tcpIOReadTimeout))

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	qLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if qLen < 12 || qLen > 4096 {
		return
	}
	req := make([]byte, qLen)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	idx := r.index.Load()
	resp, ok := idx.AnswerPacket(req)
	if !ok {
		return
	}
	r.queryCount.Add(1)
	var respLen [2]byte
	binary.BigEndian.PutUint16(respLen[:], uint16(len(resp)))
	_, _ = conn.Write(respLen[:])
	_, _ = conn.Write(resp)
}
