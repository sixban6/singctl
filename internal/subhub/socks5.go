package subhub

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

const DefaultWarpProxyAddr = "127.0.0.1:40000"

// dialSOCKS5Context dials targetAddr ("host:port") through a local SOCKS5 proxy using RFC 1928
// domain-name addressing (socks5h) so DNS resolution occurs on the proxy exit without leaking locally.
func dialSOCKS5Context(ctx context.Context, proxyAddr, targetAddr string, allowLoopbackTarget bool) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || portNum == 0 {
		return nil, fmt.Errorf("invalid target port %q", portStr)
	}

	if !allowLoopbackTarget {
		if addr, parseErr := netip.ParseAddr(host); parseErr == nil && isBlockedRemoteAddr(addr) {
			return nil, fmt.Errorf("blocked SSRF connection via SOCKS5 to non-public IP %s", addr)
		}
	}

	var d net.Dialer
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		d.Timeout = 5 * time.Second
	}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect SOCKS5 proxy %s: %w", proxyAddr, err)
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	}

	cleanupOnErr := true
	defer func() {
		if cleanupOnErr {
			_ = conn.Close()
		}
	}()

	// 1. Greeting: VER=5, NMETHODS=1, METHOD=0 (No authentication)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, fmt.Errorf("socks5 write greeting: %w", err)
	}
	var greetResp [2]byte
	if _, err := io.ReadFull(conn, greetResp[:]); err != nil {
		return nil, fmt.Errorf("socks5 read greeting: %w", err)
	}
	if greetResp[0] != 0x05 || greetResp[1] != 0x00 {
		return nil, fmt.Errorf("socks5 auth rejected (ver=%d method=%d)", greetResp[0], greetResp[1])
	}

	// 2. CONNECT request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP, DST.ADDR, DST.PORT
	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00)
	if ip, ipErr := netip.ParseAddr(host); ipErr == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b4 := ip.As4()
			req = append(req, 0x01)
			req = append(req, b4[:]...)
		} else {
			b16 := ip.As16()
			req = append(req, 0x04)
			req = append(req, b16[:]...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("socks5 invalid domain length")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portNum))
	req = append(req, portBytes[:]...)

	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("socks5 write connect: %w", err)
	}

	// 3. Read reply header: VER, REP, RSV, ATYP
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("socks5 read connect reply: %w", err)
	}
	if hdr[0] != 0x05 {
		return nil, fmt.Errorf("socks5 invalid reply version %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		return nil, fmt.Errorf("socks5 connect failed with code 0x%02x", hdr[1])
	}

	var drainLen int
	switch hdr[3] {
	case 0x01:
		drainLen = 4 + 2
	case 0x04:
		drainLen = 16 + 2
	case 0x03:
		var domLen [1]byte
		if _, err := io.ReadFull(conn, domLen[:]); err != nil {
			return nil, fmt.Errorf("socks5 read bound domain len: %w", err)
		}
		drainLen = int(domLen[0]) + 2
	default:
		return nil, fmt.Errorf("socks5 unsupported reply atyp %d", hdr[3])
	}
	if drainLen > 0 {
		buf := make([]byte, drainLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, fmt.Errorf("socks5 read bound addr: %w", err)
		}
	}

	_ = conn.SetDeadline(time.Time{})
	cleanupOnErr = false
	return conn, nil
}

func isTCPPortListening(addr string, timeout time.Duration) bool {
	if addr == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
