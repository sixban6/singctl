// 文件职责：负责 WARP SOCKS5 隧道健康探测、Cloudflare trace 查询、临时隔离端口离网预探测（Staging Probe）与 systemd 路径解析。
//
// 架构设计原则：
//   - 零中断离网预验证：stageSelectWorkingEndpoint 先串行探测首节点，失败后再并发竞速备选池并在首胜时立刻取消落败 goroutine，
//     在现网配置切换前确认新隧道可达。
//   - 路径解耦与可测性：通过 WireproxyPathEnv 与 customProbe 函数参数注入隔离路径与探测桩，避免单测污染真实 /etc。
package deploy

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func isWarpSocksRunning() bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:40000", 1*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func hasGlobalIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return true
			}
		}
	}
	return false
}

// newWarpSocksHTTPClientAt 构建经过指定 SOCKS5 地址的短连接 HTTP 客户端。
func newWarpSocksHTTPClientAt(socksAddr string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	proxyURL, err := url.Parse("socks5://" + cmp.Or(strings.TrimSpace(socksAddr), "127.0.0.1:40000"))
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// newWarpSocksHTTPClient 构建经过本地 wireproxy SOCKS5 (127.0.0.1:40000) 的短连接 HTTP 客户端。
func newWarpSocksHTTPClient(timeout time.Duration) (*http.Client, error) {
	return newWarpSocksHTTPClientAt("127.0.0.1:40000", timeout)
}

func fetchCloudflareTraceURL(ctx context.Context, client *http.Client, traceURL string) (ip, loc, warpState string, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	if err != nil {
		return "", "", "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", "", "", false
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "ip":
			ip = v
		case "loc":
			loc = v
		case "warp":
			warpState = v
		}
	}
	ok = (warpState == "on" || warpState == "plus") && ip != ""
	return ip, loc, warpState, ok
}

// IsWarpTunnelHealthy 通过本地 SOCKS5 (127.0.0.1:40000) 探测 Cloudflare trace，确认底层 WireGuard 隧道已真实连通
func IsWarpTunnelHealthy(timeout time.Duration) bool {
	_, _, _, ok := FetchWarpExitInfo(timeout)
	return ok
}

// FetchWarpExitInfo 通过本地 SOCKS5 (127.0.0.1:40000) 查询当前 WARP 出口 IP、地区代码及 warp 状态
func FetchWarpExitInfo(timeout time.Duration) (ip, loc, warpState string, ok bool) {
	client, err := newWarpSocksHTTPClient(timeout)
	if err != nil {
		return "", "", "", false
	}
	defer client.CloseIdleConnections()
	return fetchCloudflareTraceURL(context.Background(), client, "https://cloudflare.com/cdn-cgi/trace")
}

// fetchWarpTraceViaProxy 使用直连 IP 的 Cloudflare trace 端点探测指定 SOCKS5 代理的 WARP 出口状态。
func fetchWarpTraceViaProxy(ctx context.Context, socksAddr string, preferIPv6 bool, timeout time.Duration) (ip, loc, warpState string, ok bool) {
	client, err := newWarpSocksHTTPClientAt(socksAddr, timeout)
	if err != nil {
		return "", "", "", false
	}
	defer client.CloseIdleConnections()

	urls := []string{"https://1.1.1.1/cdn-cgi/trace"}
	if preferIPv6 {
		urls = []string{"https://[2606:4700:4700::1111]/cdn-cgi/trace", "https://1.1.1.1/cdn-cgi/trace"}
	}
	for _, traceURL := range urls {
		if ctx.Err() != nil {
			return "", "", "", false
		}
		if ip, loc, state, ok := fetchCloudflareTraceURL(ctx, client, traceURL); ok {
			return ip, loc, state, true
		}
	}
	return "", "", "", false
}

// probeWireproxyEndpointStaging 启动隔离的临时端口 wireproxy 进程，离网预验证指定配置文件的握手与出口连通性。
func probeWireproxyEndpointStaging(ctx context.Context, wireproxyBin, confContent string) (ip, loc string, ok bool) {
	if ctx.Err() != nil {
		return "", "", false
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", false
	}
	socksAddr := ln.Addr().String()
	_ = ln.Close()

	stagedConf := strings.ReplaceAll(confContent, "BindAddress = 127.0.0.1:40000", "BindAddress = "+socksAddr)
	f, err := os.CreateTemp("", "singctl-warp-stage-*.conf")
	if err != nil {
		return "", "", false
	}
	tmpPath := f.Name()
	_ = f.Chmod(0600)
	_, writeErr := f.WriteString(stagedConf)
	closeErr := f.Close()
	defer os.Remove(tmpPath)
	if writeErr != nil || closeErr != nil {
		return "", "", false
	}

	procCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(procCtx, wireproxyBin, "-s", "-c", tmpPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		return "", "", false
	}
	defer func() {
		cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	listening := false
	for range 15 {
		if ctx.Err() != nil {
			return "", "", false
		}
		conn, dialErr := net.DialTimeout("tcp", socksAddr, 120*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			listening = true
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !listening {
		return "", "", false
	}

	preferIPv6 := strings.Contains(stagedConf, "ResolveStrategy = ipv6")
	for attempt := range 2 {
		if ctx.Err() != nil {
			return "", "", false
		}
		if ip, loc, _, ok := fetchWarpTraceViaProxy(procCtx, socksAddr, preferIPv6, 1600*time.Millisecond); ok && ip != "" {
			return ip, loc, true
		}
		if attempt == 0 {
			time.Sleep(150 * time.Millisecond)
		}
	}
	return "", "", false
}

// stageSelectWorkingEndpoint 优先串行验证首节点，若失败则并发竞速探测其余备选 Endpoint 并立刻取消落败者。
func stageSelectWorkingEndpoint(
	ctx context.Context,
	wireproxyBin, privKey string,
	reg *warpRegResponse,
	hasIPv6 bool,
	endpoints []string,
	customProbe func(ep, conf string) (string, string, bool),
) (winEP, winConf, ip, loc string, ok bool) {
	if len(endpoints) == 0 {
		return "", "", "", "", false
	}

	runOne := func(probeCtx context.Context, ep string) (string, string, string, string, bool) {
		conf := renderWireproxyConfigFromReg(privKey, reg, hasIPv6, ep)
		if customProbe != nil {
			pIP, pLoc, pOK := customProbe(ep, conf)
			return ep, conf, pIP, pLoc, pOK
		}
		pIP, pLoc, pOK := probeWireproxyEndpointStaging(probeCtx, wireproxyBin, conf)
		return ep, conf, pIP, pLoc, pOK
	}

	firstCtx, firstCancel := context.WithTimeout(ctx, 2200*time.Millisecond)
	ep0, conf0, ip0, loc0, ok0 := runOne(firstCtx, endpoints[0])
	firstCancel()
	if ok0 && ip0 != "" {
		return ep0, conf0, ip0, loc0, true
	}

	if len(endpoints) <= 1 || ctx.Err() != nil {
		return "", "", "", "", false
	}

	raceCtx, raceCancel := context.WithTimeout(ctx, 2800*time.Millisecond)
	defer raceCancel()

	var (
		mu     sync.Mutex
		won    bool
		winIP  string
		winLoc string
		wg     sync.WaitGroup
	)
	for _, ep := range endpoints[1:] {
		wg.Add(1)
		go func(candidate string) {
			defer wg.Done()
			cEP, cConf, cIP, cLoc, cOK := runOne(raceCtx, candidate)
			if !cOK || cIP == "" {
				return
			}
			mu.Lock()
			if !won {
				won = true
				winEP = cEP
				winConf = cConf
				winIP = cIP
				winLoc = cLoc
				raceCancel()
			}
			mu.Unlock()
		}(ep)
	}
	wg.Wait()

	if won {
		return winEP, winConf, winIP, winLoc, true
	}
	return "", "", "", "", false
}

// ProbeWarpRealTargets 校验 WARP 隧道真实可用性：不仅检查 cloudflare trace (warp=on|plus)，
// 同时发起真实 HTTPS HEAD 探测 (x.com / api.x.com) 验证 1280 MTU 下外网 TLS 大包握手无黑洞。
func ProbeWarpRealTargets(timeout time.Duration) (ip, loc string, err error) {
	if !isWarpSocksRunning() {
		return "", "", fmt.Errorf("WARP SOCKS5 (127.0.0.1:40000) 未监听")
	}
	ip, loc, _, ok := FetchWarpExitInfo(timeout)
	if !ok || ip == "" {
		return "", "", fmt.Errorf("WARP Cloudflare trace 握手未就绪")
	}

	client, err := newWarpSocksHTTPClient(timeout)
	if err != nil {
		return "", "", err
	}
	defer client.CloseIdleConnections()

	var lastErr error
	for _, targetURL := range []string{"https://x.com/robots.txt", "https://api.x.com/robots.txt"} {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodHead, targetURL, nil)
		if reqErr != nil {
			lastErr = reqErr
			continue
		}
		req.Header.Set("User-Agent", "curl/8.5.0")
		resp, doErr := client.Do(req)
		if doErr == nil && resp != nil && resp.StatusCode > 0 {
			_ = resp.Body.Close()
			return ip, loc, nil
		}
		lastErr = doErr
	}
	return ip, loc, fmt.Errorf("WARP 出口 (%s) 访问外部目标 TLS/连接超时: %v", ip, lastErr)
}

// WireproxyPathEnv 允许测试注入隔离的配置文件与 systemd unit 搜索路径。
type WireproxyPathEnv struct {
	PrimaryConf string
	CompatConf  string
	UnitFiles   []string
}

// ParseWireproxyConfFromUnit 从 systemd unit 内容中提取 ExecStart 的 -c / --config 参数路径。
func ParseWireproxyConfFromUnit(unitContent string) string {
	for line := range strings.SplitSeq(unitContent, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		rest, ok := strings.CutPrefix(trimmed, "ExecStart=")
		if !ok {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(rest))
		for i := 0; i < len(fields); i++ {
			tok := strings.Trim(fields[i], `"'`)
			if (tok == "-c" || tok == "--config") && i+1 < len(fields) {
				cand := strings.Trim(fields[i+1], `"'`)
				if strings.HasPrefix(cand, "/") {
					return filepath.Clean(cand)
				}
			}
			for _, prefix := range []string{"-c=", "--config="} {
				if val, has := strings.CutPrefix(tok, prefix); has {
					cand := strings.Trim(val, `"'`)
					if strings.HasPrefix(cand, "/") {
						return filepath.Clean(cand)
					}
				}
			}
		}
	}
	return ""
}

// ResolveWireproxyConfigPaths 解析内置纯 Go wireproxy 单一事实配置文件路径与存在状态。
// 老版 fscarmen 的 /etc/wireguard/proxy.conf 不再作为有效配置（检测到时由清理/部署流程自动迁出）。
func ResolveWireproxyConfigPaths() (activePath string, mirrorPaths []string, exists bool) {
	return ResolveWireproxyConfigPathsWithEnv(WireproxyPathEnv{})
}

func ResolveWireproxyConfigPathsWithEnv(env WireproxyPathEnv) (activePath string, mirrorPaths []string, exists bool) {
	primary := cmp.Or(strings.TrimSpace(env.PrimaryConf), DefaultWireproxyConf)
	compat := filepath.Clean(cmp.Or(strings.TrimSpace(env.CompatConf), LegacyWireproxyConf))
	unitFiles := env.UnitFiles
	if unitFiles == nil {
		unitFiles = []string{
			DefaultWireproxyService,
			"/lib/systemd/system/wireproxy.service",
			"/usr/lib/systemd/system/wireproxy.service",
		}
	}

	unitTarget := ""
	for _, uf := range unitFiles {
		raw, err := os.ReadFile(uf)
		if err != nil {
			continue
		}
		if parsed := ParseWireproxyConfFromUnit(string(raw)); parsed != "" && filepath.Clean(parsed) != compat {
			unitTarget = parsed
			if st, stErr := os.Stat(parsed); stErr == nil && !st.IsDir() {
				return parsed, nil, true
			}
			break
		}
	}

	if st, err := os.Stat(primary); err == nil && !st.IsDir() {
		return primary, nil, true
	}
	return cmp.Or(unitTarget, primary), nil, false
}
