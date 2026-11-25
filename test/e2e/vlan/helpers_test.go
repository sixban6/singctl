// 文件职责：提供 OpenWrt VLAN Docker 多容器集群 E2E 测试的镜像探测、交叉编译、独立 netns 探针程序与容器命令辅助函数。
package vlan_e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	openWrt24Image = "openwrt/rootfs:aarch64_generic"
	openWrt21Image = "immortalwrt/rootfs:armvirt-64-openwrt-21.02"
	openWrtIptImg  = "singctl-openwrt24-e2e:local"
)

func detectImageGoArch(t *testing.T, ctx context.Context, image string) string {
	t.Helper()
	if unameOut, err := exec.CommandContext(ctx, "docker", "run", "--rm", image, "uname", "-m").CombinedOutput(); err == nil {
		u := strings.ToLower(strings.TrimSpace(string(unameOut)))
		if strings.Contains(u, "aarch64") || strings.Contains(u, "arm64") {
			return "arm64"
		}
		if strings.Contains(u, "x86_64") || strings.Contains(u, "amd64") {
			return "amd64"
		}
	}
	out := strings.ToLower(strings.TrimSpace(mustRun(t, ctx, "docker", "image", "inspect", "--format", "{{.Architecture}}", image)))
	switch {
	case strings.Contains(out, "arm64"), strings.Contains(out, "aarch64"):
		return "arm64"
	case strings.Contains(out, "amd64"), strings.Contains(out, "x86_64"):
		return "amd64"
	default:
		return runtime.GOARCH
	}
}

func imageExists(ctx context.Context, image string) bool {
	return exec.CommandContext(ctx, "docker", "image", "inspect", image).Run() == nil
}

func crossCompileSingCtl(t *testing.T, ctx context.Context, repoRoot, workDir, targetArch string) string {
	return crossCompileSingCtlWithTags(t, ctx, repoRoot, workDir, targetArch, "lite")
}

func crossCompileSingCtlFull(t *testing.T, ctx context.Context, repoRoot, workDir, targetArch string) string {
	return crossCompileSingCtlWithTags(t, ctx, repoRoot, workDir, targetArch, "")
}

func crossCompileSingCtlWithTags(t *testing.T, ctx context.Context, repoRoot, workDir, targetArch, buildTags string) string {
	t.Helper()
	suffix := "full"
	if buildTags != "" {
		suffix = buildTags
	}
	outBin := filepath.Join(workDir, "singctl-"+suffix+"-"+targetArch)
	args := []string{"build"}
	if buildTags != "" {
		args = append(args, "-tags", buildTags)
	}
	args = append(args, "-o", outBin, "./cmd/singctl")
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+targetArch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-compile singctl (%s) linux/%s failed: %v\n%s", suffix, targetArch, err, string(out))
	}
	return outBin
}

// buildProbeHelper 构建极简静态 Linux 探针，支持：
//   - serve <addr> <tag>：HTTP 探测服务端（/ 返回标签，/hold 保持长连接供审计与强断验证）
//   - dns-serve <udpAddr> <domain=ip,...>：极简权威 UDP DNS 应答器
//   - sing-box (argv[0] 为 sing-box 或 singbox-shim)：check -c 校验 JSON + run 监听 :7895 IP_TRANSPARENT TProxy 与 127.0.0.1:9090 Clash API
//   - http <method> <url> [localIP|-] [jsonBody]：HTTP 客户端
//   - netns-spawn <pidFile> <sockPath>：启动独立 CLONE_NEWNET 网络命名空间进程，通过 Unix Socket 执行网内配置/HTTP/DNS/服务
//   - netns-ctl <sockPath> <op> [args...]：向指定独立网络命名空间发送 sh / http / dns / serve 指令
func buildProbeHelper(t *testing.T, ctx context.Context, workDir, targetArch string) string {
	t.Helper()
	dir := filepath.Join(workDir, "probe-"+targetArch)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir probe dir: %v", err)
	}
	src := `package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

type nsReq struct {
	Op      string ` + "`json:\"op\"`" + `
	Cmd     string ` + "`json:\"cmd,omitempty\"`" + `
	Method  string ` + "`json:\"method,omitempty\"`" + `
	URL     string ` + "`json:\"url,omitempty\"`" + `
	LocalIP string ` + "`json:\"localIp,omitempty\"`" + `
	Body    string ` + "`json:\"body,omitempty\"`" + `
	Addr    string ` + "`json:\"addr,omitempty\"`" + `
	Tag     string ` + "`json:\"tag,omitempty\"`" + `
}

type nsResp struct {
	OK     bool   ` + "`json:\"ok\"`" + `
	Status int    ` + "`json:\"status,omitempty\"`" + `
	Output string ` + "`json:\"output,omitempty\"`" + `
	Error  string ` + "`json:\"error,omitempty\"`" + `
}

func doHTTP(method, url, localIP, jsonBody string) (int, string, error) {
	var body io.Reader
	if jsonBody != "" {
		body = bytes.NewBufferString(jsonBody)
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	if localIP != "" && localIP != "-" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
	}
	cli := &http.Client{
		Timeout: 35 * time.Second,
		Transport: &http.Transport{
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return 0, "", err
	}
	if body != nil || (method != "GET" && method != "HEAD") {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cli.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(raw)), nil
}

func runServe(listenAddr, tag string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "HOLD:%s:from=%s\n", tag, r.RemoteAddr)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
		case <-timer.C:
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "OK:%s:from=%s\n", tag, r.RemoteAddr)
	})
	return http.ListenAndServe(listenAddr, mux)
}

func decodeDNSName(pkt []byte, off int) (string, int, bool) {
	var labels []string
	cur := off
	jumped := false
	nextOff := 0
	for steps := 0; steps < 64 && cur < len(pkt); steps++ {
		l := int(pkt[cur])
		if l == 0 {
			if !jumped {
				nextOff = cur + 1
			}
			return strings.Join(labels, "."), nextOff, true
		}
		if l&0xC0 == 0xC0 {
			if cur+1 >= len(pkt) {
				return "", 0, false
			}
			ptr := int(l&0x3F)<<8 | int(pkt[cur+1])
			if !jumped {
				nextOff = cur + 2
				jumped = true
			}
			cur = ptr
			continue
		}
		cur++
		if cur+l > len(pkt) {
			return "", 0, false
		}
		labels = append(labels, string(pkt[cur:cur+l]))
		cur += l
	}
	return "", 0, false
}

func encodeDNSName(name string) []byte {
	var buf bytes.Buffer
	for _, part := range strings.Split(strings.Trim(strings.ToLower(name), "."), ".") {
		if part == "" || len(part) > 63 {
			continue
		}
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0)
	return buf.Bytes()
}

func runDNSServe(listenAddr, spec string) error {
	records := make(map[string]net.IP)
	for _, entry := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok {
			continue
		}
		if ip := net.ParseIP(strings.TrimSpace(v)).To4(); ip != nil {
			records[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(k)), ".")] = ip
		}
	}
	pc, err := net.ListenPacket("udp4", listenAddr)
	if err != nil {
		return err
	}
	defer pc.Close()
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n < 12 {
			continue
		}
		req := buf[:n]
		qName, qEnd, ok := decodeDNSName(req, 12)
		if !ok || qEnd+4 > n {
			continue
		}
		qType := binary.BigEndian.Uint16(req[qEnd : qEnd+2])
		qClass := binary.BigEndian.Uint16(req[qEnd+2 : qEnd+4])
		key := strings.ToLower(strings.TrimSuffix(qName, "."))
		ip, found := records[key]

		var resp bytes.Buffer
		hdr := make([]byte, 12)
		copy(hdr[0:2], req[0:2])
		flags := uint16(0x8400) | (binary.BigEndian.Uint16(req[2:4]) & 0x0100)
		if qType == 1 && qClass == 1 && found {
			binary.BigEndian.PutUint16(hdr[2:4], flags)
			binary.BigEndian.PutUint16(hdr[4:6], 1)
			binary.BigEndian.PutUint16(hdr[6:8], 1)
		} else {
			binary.BigEndian.PutUint16(hdr[2:4], flags|3)
			binary.BigEndian.PutUint16(hdr[4:6], 1)
		}
		resp.Write(hdr)
		resp.Write(req[12 : qEnd+4])
		if qType == 1 && qClass == 1 && found {
			resp.Write([]byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04})
			resp.Write(ip.To4())
		}
		_, _ = pc.WriteTo(resp.Bytes(), addr)
	}
}

func doDNSQuery(serverAddr, domain string) (string, error) {
	if !strings.Contains(serverAddr, ":") {
		serverAddr += ":53"
	}
	conn, err := net.DialTimeout("udp4", serverAddr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	var req bytes.Buffer
	req.Write([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	req.Write(encodeDNSName(domain))
	req.Write([]byte{0x00, 0x01, 0x00, 0x01})
	if _, err := conn.Write(req.Bytes()); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return "", fmt.Errorf("read dns response failed: %v (n=%d)", err, n)
	}
	anCount := int(binary.BigEndian.Uint16(buf[6:8]))
	rcode := buf[3] & 0x0F
	if rcode != 0 || anCount == 0 {
		return "", fmt.Errorf("dns rcode=%d answers=%d", rcode, anCount)
	}
	_, off, ok := decodeDNSName(buf[:n], 12)
	if !ok || off+4 > n {
		return "", fmt.Errorf("malformed dns question")
	}
	off += 4
	var ips []string
	for i := 0; i < anCount && off < n; i++ {
		_, nextOff, ok := decodeDNSName(buf[:n], off)
		if !ok || nextOff+10 > n {
			break
		}
		rrType := binary.BigEndian.Uint16(buf[nextOff : nextOff+2])
		rdLen := int(binary.BigEndian.Uint16(buf[nextOff+8 : nextOff+10]))
		rdataOff := nextOff + 10
		if rdataOff+rdLen > n {
			break
		}
		if rrType == 1 && rdLen == 4 {
			ips = append(ips, net.IP(buf[rdataOff:rdataOff+4]).String())
		}
		off = rdataOff + rdLen
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no A record returned")
	}
	return strings.Join(ips, ","), nil
}

type shimConn struct {
	id       string
	srcIP    string
	srcPort  string
	dstIP    string
	dstPort  string
	start    string
	upload   atomic.Int64
	download atomic.Int64
	left     net.Conn
	right    net.Conn
}

func (sc *shimConn) closeBoth() {
	if sc.left != nil {
		_ = sc.left.Close()
	}
	if sc.right != nil {
		_ = sc.right.Close()
	}
}

func lookupOriginalDst(c net.Conn) (net.IP, int, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil, 0, false
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return nil, 0, false
	}
	const (
		solIP         = 0
		soOriginalDst = 80
	)
	var sa [16]byte
	saLen := uint32(len(sa))
	var errno syscall.Errno
	if cErr := rc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solIP, soOriginalDst, uintptr(unsafe.Pointer(&sa[0])), uintptr(unsafe.Pointer(&saLen)), 0)
	}); cErr != nil || errno != 0 {
		return nil, 0, false
	}
	port := int(binary.BigEndian.Uint16(sa[2:4]))
	ip := net.IPv4(sa[4], sa[5], sa[6], sa[7])
	if port <= 0 || ip.IsUnspecified() {
		return nil, 0, false
	}
	return ip, port, true
}

func runSingBoxShim(args []string) int {
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "check":
		cfgPath := "/etc/sing-box/config.json"
		for i := 1; i < len(args)-1; i++ {
			if args[i] == "-c" {
				cfgPath = args[i+1]
			}
		}
		raw, err := os.ReadFile(cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", cfgPath, err)
			return 1
		}
		if !json.Valid(raw) {
			fmt.Fprintf(os.Stderr, "invalid json in %s\n", cfgPath)
			return 1
		}
		return 0
	case "run":
		sigCh := make(chan os.Signal, 2)
		signal.Notify(sigCh, syscall.SIGHUP)
		go func() {
			for range sigCh {
			}
		}()

		var mu sync.Mutex
		conns := make(map[string]*shimConn)
		var nextID atomic.Uint64

		mux := http.NewServeMux()
		mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{\"version\":\"1.12.0-e2e-shim\"}"))
		})
		mux.HandleFunc("/proxies", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{\"proxies\":{\"Proxy\":{\"type\":\"Selector\",\"now\":\"node-a\",\"all\":[\"node-a\"]}}}"))
		})
		mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				mu.Lock()
				for id, sc := range conns {
					sc.closeBoth()
					delete(conns, id)
				}
				mu.Unlock()
				w.WriteHeader(http.StatusNoContent)
				return
			}
			mu.Lock()
			list := make([]map[string]any, 0, len(conns))
			var upTotal, downTotal int64
			for _, sc := range conns {
				up := sc.upload.Load()
				down := sc.download.Load()
				upTotal += up
				downTotal += down
				list = append(list, map[string]any{
					"id":       sc.id,
					"upload":   up,
					"download": down,
					"start":    sc.start,
					"chains":   []string{"Proxy", "node-a"},
					"rule":     "final",
					"metadata": map[string]any{
						"network":         "tcp",
						"type":            "tproxy",
						"sourceIP":        sc.srcIP,
						"sourcePort":      sc.srcPort,
						"destinationIP":   sc.dstIP,
						"destinationPort": sc.dstPort,
						"host":            "",
						"sniffHost":       "",
					},
				})
			}
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"downloadTotal": downTotal,
				"uploadTotal":   upTotal,
				"memory":        1024,
				"connections":   list,
			})
		})
		mux.HandleFunc("/connections/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/connections/")
			mu.Lock()
			sc, ok := conns[id]
			if ok {
				delete(conns, id)
			}
			mu.Unlock()
			if ok && sc != nil {
				sc.closeBoth()
			}
			w.WriteHeader(http.StatusNoContent)
		})

		go func() {
			if err := http.ListenAndServe("127.0.0.1:9090", mux); err != nil {
				fmt.Fprintf(os.Stderr, "clash api listen: %v\n", err)
				os.Exit(1)
			}
		}()

		const (
			solIP         = 0
			ipTransparent = 19
			outBypassMark = 0xff
		)
		lc := net.ListenConfig{
			Control: func(_, _ string, c syscall.RawConn) error {
				var sockErr error
				_ = c.Control(func(fd uintptr) {
					sockErr = syscall.SetsockoptInt(int(fd), solIP, ipTransparent, 1)
				})
				return sockErr
			},
		}
		ln, err := lc.Listen(context.Background(), "tcp4", ":7895")
		if err != nil {
			fmt.Fprintf(os.Stderr, "tproxy listen :7895: %v\n", err)
			return 1
		}
		defer ln.Close()

		upDialer := &net.Dialer{
			Timeout: 5 * time.Second,
			Control: func(_, _ string, c syscall.RawConn) error {
				var sockErr error
				_ = c.Control(func(fd uintptr) {
					sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, outBypassMark)
				})
				return sockErr
			},
		}

		for {
			clientConn, err := ln.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				remoteTCP, _ := c.RemoteAddr().(*net.TCPAddr)
				localTCP, _ := c.LocalAddr().(*net.TCPAddr)
				if remoteTCP == nil || localTCP == nil {
					return
				}
				dstIP := localTCP.IP
				dstPort := localTCP.Port
				if dstPort == 7895 {
					if origIP, origPort, ok := lookupOriginalDst(c); ok && origPort != 7895 {
						dstIP = origIP
						dstPort = origPort
					}
				}
				dstAddr := net.JoinHostPort(dstIP.String(), strconv.Itoa(dstPort))
				upstream, err := upDialer.Dial("tcp4", dstAddr)
				if err != nil {
					return
				}
				defer upstream.Close()

				id := fmt.Sprintf("conn-%d", nextID.Add(1))
				sc := &shimConn{
					id:      id,
					srcIP:   remoteTCP.IP.String(),
					srcPort: strconv.Itoa(remoteTCP.Port),
					dstIP:   dstIP.String(),
					dstPort: strconv.Itoa(dstPort),
					start:   time.Now().UTC().Format(time.RFC3339Nano),
					left:    c,
					right:   upstream,
				}
				mu.Lock()
				conns[id] = sc
				mu.Unlock()
				defer func() {
					mu.Lock()
					delete(conns, id)
					mu.Unlock()
				}()

				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					buf := make([]byte, 32*1024)
					for {
						nr, er := c.Read(buf)
						if nr > 0 {
							sc.upload.Add(int64(nr))
							if _, ew := upstream.Write(buf[:nr]); ew != nil {
								break
							}
						}
						if er != nil {
							break
						}
					}
					if tc, ok := upstream.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
				}()
				go func() {
					defer wg.Done()
					buf := make([]byte, 32*1024)
					for {
						nr, er := upstream.Read(buf)
						if nr > 0 {
							sc.download.Add(int64(nr))
							if _, ew := c.Write(buf[:nr]); ew != nil {
								break
							}
						}
						if er != nil {
							break
						}
					}
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
				}()
				wg.Wait()
			}(clientConn)
		}
	default:
		return 0
	}
}

func runNetNSAgent(pidFile, sockPath string) {
	_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen unix %s: %v\n", sockPath, err)
		os.Exit(1)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			var req nsReq
			if err := json.NewDecoder(c).Decode(&req); err != nil {
				_ = json.NewEncoder(c).Encode(nsResp{OK: false, Error: err.Error()})
				return
			}
			switch req.Op {
			case "sh":
				cmd := exec.Command("/bin/sh", "-c", "export PATH=/usr/sbin:/usr/bin:/sbin:/bin; "+req.Cmd)
				out, err := cmd.CombinedOutput()
				resp := nsResp{OK: err == nil, Output: strings.TrimSpace(string(out))}
				if err != nil {
					resp.Error = err.Error()
				}
				_ = json.NewEncoder(c).Encode(resp)
			case "http":
				code, body, err := doHTTP(req.Method, req.URL, req.LocalIP, req.Body)
				resp := nsResp{OK: err == nil, Status: code, Output: body}
				if err != nil {
					resp.Error = err.Error()
				}
				_ = json.NewEncoder(c).Encode(resp)
			case "dns":
				out, err := doDNSQuery(req.Addr, req.Tag)
				resp := nsResp{OK: err == nil, Output: out}
				if err != nil {
					resp.Error = err.Error()
				}
				_ = json.NewEncoder(c).Encode(resp)
			case "serve":
				go func(addr, tag string) { _ = runServe(addr, tag) }(req.Addr, req.Tag)
				time.Sleep(100 * time.Millisecond)
				_ = json.NewEncoder(c).Encode(nsResp{OK: true})
			default:
				_ = json.NewEncoder(c).Encode(nsResp{OK: false, Error: "unknown op"})
			}
		}(conn)
	}
}

func main() {
	if len(os.Args) > 0 && filepath.Base(os.Args[0]) == "sing-box" {
		os.Exit(runSingBoxShim(os.Args[1:]))
	}
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "singbox-shim":
		os.Exit(runSingBoxShim(os.Args[2:]))
	case "serve":
		if err := runServe(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "serve: %v\n", err)
			os.Exit(1)
		}
	case "dns-serve":
		if err := runDNSServe(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "dns-serve: %v\n", err)
			os.Exit(1)
		}
	case "dns-query":
		out, err := doDNSQuery(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERR:%v\n", err)
			os.Exit(1)
		}
		fmt.Println(out)
	case "http":
		localIP := "-"
		body := ""
		if len(os.Args) >= 5 {
			localIP = os.Args[4]
		}
		if len(os.Args) >= 6 {
			body = os.Args[5]
		}
		code, out, err := doHTTP(os.Args[2], os.Args[3], localIP, body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERR:%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("STATUS=%d\n%s", code, out)
	case "netns-spawn":
		// Re-exec self in a brand new isolated Linux network namespace (CLONE_NEWNET) with detached stdio.
		cmd := exec.Command(os.Args[0], "netns-agent", os.Args[2], os.Args[3])
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWNET,
			Setsid:     true,
		}
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "spawn netns: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(cmd.Process.Pid)
	case "netns-agent":
		runNetNSAgent(os.Args[2], os.Args[3])
	case "netns-ctl":
		sock := os.Args[2]
		op := os.Args[3]
		req := nsReq{Op: op}
		switch op {
		case "sh":
			req.Cmd = os.Args[4]
		case "http":
			req.Method = os.Args[4]
			req.URL = os.Args[5]
			if len(os.Args) >= 7 {
				req.LocalIP = os.Args[6]
			}
			if len(os.Args) >= 8 {
				req.Body = os.Args[7]
			}
		case "dns":
			req.Addr = os.Args[4]
			req.Tag = os.Args[5]
		case "serve":
			req.Addr = os.Args[4]
			req.Tag = os.Args[5]
		}
		conn, err := net.DialTimeout("unix", sock, 35*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dial %s: %v\n", sock, err)
			os.Exit(1)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(40 * time.Second))
		_ = json.NewEncoder(conn).Encode(req)
		var resp nsResp
		if err := json.NewDecoder(conn).Decode(&resp); err != nil {
			fmt.Fprintf(os.Stderr, "decode: %v\n", err)
			os.Exit(1)
		}
		if !resp.OK {
			fmt.Fprintf(os.Stderr, "ERR:%s\n%s\n", resp.Error, resp.Output)
			os.Exit(1)
		}
		if op == "http" {
			fmt.Printf("STATUS=%d\n%s", resp.Status, resp.Output)
		} else if resp.Output != "" {
			fmt.Print(resp.Output)
		}
	default:
		os.Exit(2)
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatalf("write probe main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module vlanprobe\n\ngo 1.24\n"), 0644); err != nil {
		t.Fatalf("write probe go.mod: %v", err)
	}
	outBin := filepath.Join(workDir, "vlan-probe-"+targetArch)
	cmd := exec.CommandContext(ctx, "go", "build", "-o", outBin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+targetArch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build probe helper linux/%s failed: %v\n%s", targetArch, err, string(out))
	}
	return outBin
}

func mustRun(t *testing.T, ctx context.Context, name string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %s\nerr: %v\noutput:\n%s", name, strings.Join(args, " "), err, string(out))
	}
	return string(out)
}

func dockerExec(ctx context.Context, container, shCmd string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", container, "/bin/sh", "-c",
		`export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; `+shCmd)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustDockerExec(t *testing.T, ctx context.Context, container, shCmd string) string {
	t.Helper()
	out, err := dockerExec(ctx, container, shCmd)
	if err != nil {
		t.Fatalf("docker exec %s failed: %v\ncmd:\n%s\noutput:\n%s", container, err, shCmd, out)
	}
	return out
}

func probeHTTP(ctx context.Context, container, method, url, localIP, jsonBody string) (int, string, error) {
	if localIP == "" {
		localIP = "-"
	}
	args := []string{"exec", container, "/usr/bin/vlan-probe", "http", method, url, localIP}
	if jsonBody != "" {
		args = append(args, jsonBody)
	}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return parseProbeHTTPOut(string(out), err)
}

func probeNetNSHTTP(ctx context.Context, container, sockPath, method, url, localIP, jsonBody string) (int, string, error) {
	if localIP == "" {
		localIP = "-"
	}
	args := []string{"exec", container, "/usr/bin/vlan-probe", "netns-ctl", sockPath, "http", method, url, localIP}
	if jsonBody != "" {
		args = append(args, jsonBody)
	}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return parseProbeHTTPOut(string(out), err)
}

func probeNetNSDNS(ctx context.Context, container, sockPath, serverAddr, domain string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "exec", container, "/usr/bin/vlan-probe", "netns-ctl", sockPath, "dns", serverAddr, domain).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func mustNetNSSh(t *testing.T, ctx context.Context, container, sockPath, shCmd string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", "exec", container, "/usr/bin/vlan-probe", "netns-ctl", sockPath, "sh", shCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("netns sh (%s) failed: %v\ncmd:\n%s\nout:\n%s", sockPath, err, shCmd, string(out))
	}
	return string(out)
}

func mustNetNSJSON(t *testing.T, ctx context.Context, container, sockPath, method, url string, payload any) (int, string) {
	t.Helper()
	bodyStr := ""
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		bodyStr = string(raw)
	}
	code, body, err := probeNetNSHTTP(ctx, container, sockPath, method, url, "-", bodyStr)
	if err != nil {
		t.Fatalf("netns HTTP %s %s (%s) failed: %v (output=%s)", method, url, sockPath, err, body)
	}
	return code, body
}

func parseProbeHTTPOut(text string, err error) (int, string, error) {
	if err != nil {
		return 0, text, err
	}
	firstLine, body, _ := strings.Cut(text, "\n")
	var code int
	if _, scanErr := fmt.Sscanf(strings.TrimSpace(firstLine), "STATUS=%d", &code); scanErr != nil {
		return 0, text, fmt.Errorf("parse status from %q: %w", firstLine, scanErr)
	}
	return code, strings.TrimSpace(body), nil
}

func waitUntil(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", desc)
}

func wireContainerVeth(t *testing.T, ctx context.Context, c1, if1, c2, if2 string) {
	t.Helper()
	p1 := strings.TrimSpace(mustRun(t, ctx, "docker", "inspect", "-f", "{{.State.Pid}}", c1))
	p2 := strings.TrimSpace(mustRun(t, ctx, "docker", "inspect", "-f", "{{.State.Pid}}", c2))
	mustRun(t, ctx, "docker", "run", "--rm", "--privileged", "--pid=host", "--network=host",
		openWrt24Image, "/bin/sh", "-c",
		fmt.Sprintf("ip link add vx type veth && ip link set vx netns %s && ip link set veth0 netns %s", p1, p2),
	)
	mustDockerExec(t, ctx, c1, fmt.Sprintf("ip link set vx name %s && ip link set %s up", if1, if1))
	mustDockerExec(t, ctx, c2, fmt.Sprintf("ip link set veth0 name %s && ip link set %s up", if2, if2))
}
