package deploy

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/util/netinfo"
)

type warpRegRequest struct {
	Key          string `json:"key"`
	InstallID    string `json:"install_id"`
	FCMToken     string `json:"fcm_token"`
	TOS          string `json:"tos"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	Locale       string `json:"locale"`
}

type warpRegResponse struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Token  string `json:"token"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4   string `json:"v4"`
				V6   string `json:"v6"`
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

const (
	DefaultWireproxyBin     = "/usr/local/bin/wireproxy"
	DefaultWireproxyConf    = "/etc/wireproxy/wireproxy.conf"
	DefaultWireproxyService = "/etc/systemd/system/wireproxy.service"
	LegacyWireproxyConf     = "/etc/wireguard/proxy.conf"
)

// WarpCandidateEndpoints 定义 Cloudflare WARP 多端口/多 Anycast Endpoint 备选池（IPv4 直连防 DNS 解析死锁）
var WarpCandidateEndpoints = []string{
	"162.159.192.1:2408",
	"162.159.195.1:500",
	"188.114.96.1:4500",
	"162.159.193.10:1701",
}

func isValidIPv4Endpoint(ep string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(ep))
	if err != nil || host == "" || port == "" || port == "0" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
}

// UninstallWarp uninstalls WARP (wireproxy) and any legacy fscarmen WARP leftovers.
func UninstallWarp() error {
	logger.Info("Uninstalling WARP (wireproxy)...")
	_ = runCmd("systemctl", "stop", "wireproxy")
	_ = runCmd("systemctl", "disable", "wireproxy")
	_, _ = PurgeLegacyFscarmenWarp()
	_ = os.Remove(DefaultWireproxyService)
	_ = runCmd("systemctl", "daemon-reload")
	_ = os.Remove(DefaultWireproxyBin)
	_ = os.RemoveAll("/etc/wireproxy")
	logger.Success("WARP uninstallation completed.")
	return nil
}

// IsWindtfWireproxyBinary 检测指定路径是否为内置纯 Go 支持 [Resolve]/ResolveStrategy 的 windtf/wireproxy 二进制。
// 老旧 fscarmen 预编译版基于 upstream wireproxy，不支持 ResolveStrategy 且会导致配置解析报错崩溃。
func IsWindtfWireproxyBinary(binPath string) bool {
	info, err := os.Stat(binPath)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return false
	}
	f, err := os.Open(binPath)
	if err != nil {
		return false
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, 32*1024*1024))
	if err != nil {
		return false
	}
	return bytes.Contains(buf, []byte("ResolveStrategy"))
}

// LegacyWarpPurgeEnv 允许测试注入隔离的文件系统与 systemd 路径以验证 fscarmen 残留清理逻辑。
type LegacyWarpPurgeEnv struct {
	LegacyFiles      []string
	LegacyGlobs      []string
	LegacyDirs       []string
	UnitFiles        []string
	StopServices     []string
	StandardUnitPath string
	PrimaryBin       string
	PrimaryConf      string
	RunSystemctl     func(args ...string) error
}

func defaultLegacyWarpPurgeEnv(env *LegacyWarpPurgeEnv) LegacyWarpPurgeEnv {
	var e LegacyWarpPurgeEnv
	customFilesProvided := env != nil && (env.LegacyFiles != nil || env.LegacyGlobs != nil)
	if env != nil {
		e = *env
	}
	if !customFilesProvided {
		e.LegacyFiles = []string{
			"/usr/bin/warp",
			"/usr/local/bin/warp",
			"/usr/bin/wireproxy",
			"/usr/bin/warp-go",
			"/usr/local/bin/warp-go",
			"/etc/systemd/system/warp-go.service",
			LegacyWireproxyConf,
			"/etc/wireguard/wgcf.conf",
			"/etc/wireguard/wgcf-account.toml",
		}
		e.LegacyGlobs = []string{
			"/etc/wireguard/proxy.conf*",
			"/etc/wireguard/wgcf*",
			"/etc/wireguard/warp*",
		}
	}
	if e.LegacyDirs == nil {
		if env == nil {
			e.LegacyDirs = []string{"/opt/warp-go"}
		} else {
			e.LegacyDirs = []string{}
		}
	}
	if e.UnitFiles == nil {
		if env == nil {
			e.UnitFiles = []string{
				DefaultWireproxyService,
				"/lib/systemd/system/wireproxy.service",
				"/usr/lib/systemd/system/wireproxy.service",
			}
		} else {
			e.UnitFiles = []string{}
		}
	}
	if e.StopServices == nil {
		if env == nil {
			e.StopServices = []string{"wg-quick@wgcf", "warp-go", "warp-svc"}
		} else {
			e.StopServices = []string{}
		}
	}
	e.StandardUnitPath = cmp.Or(strings.TrimSpace(e.StandardUnitPath), DefaultWireproxyService)
	e.PrimaryBin = cmp.Or(strings.TrimSpace(e.PrimaryBin), DefaultWireproxyBin)
	e.PrimaryConf = cmp.Or(strings.TrimSpace(e.PrimaryConf), DefaultWireproxyConf)
	if e.RunSystemctl == nil {
		e.RunSystemctl = func(args ...string) error {
			return runCmd("systemctl", args...)
		}
	}
	return e
}

func isLegacyWireproxyUnitContent(content string) bool {
	return strings.Contains(content, "/usr/bin/wireproxy") || strings.Contains(content, LegacyWireproxyConf)
}

func collectLegacyFilesToCheck(e LegacyWarpPurgeEnv) []string {
	files := slices.Clone(e.LegacyFiles)
	for _, pattern := range e.LegacyGlobs {
		if matches, err := filepath.Glob(pattern); err == nil {
			for _, m := range matches {
				if !slices.Contains(files, m) {
					files = append(files, m)
				}
			}
		}
	}
	return files
}

// HasLegacyFscarmenWarp 检测宿主机是否存在旧版 fscarmen / warp-go / /etc/wireguard/proxy.conf 等非内置纯 Go WARP 残留。
func HasLegacyFscarmenWarp() bool {
	return HasLegacyFscarmenWarpWithEnv(nil)
}

func HasLegacyFscarmenWarpWithEnv(env *LegacyWarpPurgeEnv) bool {
	e := defaultLegacyWarpPurgeEnv(env)
	for _, p := range collectLegacyFilesToCheck(e) {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	for _, d := range e.LegacyDirs {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return true
		}
	}
	for _, uf := range e.UnitFiles {
		if raw, err := os.ReadFile(uf); err == nil && isLegacyWireproxyUnitContent(string(raw)) {
			return true
		}
	}
	if _, err := os.Stat(e.PrimaryBin); err == nil && !IsWindtfWireproxyBinary(e.PrimaryBin) {
		return true
	}
	return false
}

// PurgeLegacyFscarmenWarp 彻底清理旧版 fscarmen 脚本产物、旧版 /usr/bin/wireproxy 与 /etc/wireguard/proxy.conf，
// 并统一收敛至纯 Go 版本 (/usr/local/bin/wireproxy + /etc/wireproxy/wireproxy.conf)。
func PurgeLegacyFscarmenWarp() (bool, error) {
	return PurgeLegacyFscarmenWarpWithEnv(nil)
}

func PurgeLegacyFscarmenWarpWithEnv(env *LegacyWarpPurgeEnv) (bool, error) {
	e := defaultLegacyWarpPurgeEnv(env)
	changed := false

	for _, svc := range e.StopServices {
		_ = e.RunSystemctl("stop", svc)
		_ = e.RunSystemctl("disable", svc)
	}

	legacyUnitDetected := false
	for _, uf := range e.UnitFiles {
		raw, err := os.ReadFile(uf)
		if err != nil {
			continue
		}
		if isLegacyWireproxyUnitContent(string(raw)) {
			legacyUnitDetected = true
			if uf != e.StandardUnitPath {
				if rmErr := os.Remove(uf); rmErr == nil {
					changed = true
				}
			}
		}
	}
	if legacyUnitDetected {
		_ = e.RunSystemctl("stop", "wireproxy")
		if err := writeWireproxySystemdUnit(e.StandardUnitPath, e.PrimaryBin, e.PrimaryConf); err != nil {
			return changed, fmt.Errorf("重写标准 wireproxy.service 失败: %w", err)
		}
		changed = true
	}

	for _, p := range collectLegacyFilesToCheck(e) {
		if _, err := os.Stat(p); err == nil {
			if rmErr := os.Remove(p); rmErr == nil {
				changed = true
			}
		}
	}
	for _, d := range e.LegacyDirs {
		if _, err := os.Stat(d); err == nil {
			if rmErr := os.RemoveAll(d); rmErr == nil {
				changed = true
			}
		}
	}

	if _, err := os.Stat(e.PrimaryBin); err == nil && !IsWindtfWireproxyBinary(e.PrimaryBin) {
		if rmErr := os.Remove(e.PrimaryBin); rmErr == nil {
			changed = true
		}
	}

	if changed {
		_ = e.RunSystemctl("daemon-reload")
	}
	return changed, nil
}

func writeWireproxySystemdUnit(unitPath, wireproxyBin, confPath string) error {
	if dir := filepath.Dir(unitPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	serviceContent := fmt.Sprintf(`[Unit]
Description=WireProxy for WARP
After=network.target

[Service]
Type=simple
ExecStart=%s -s -c %s
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, wireproxyBin, confPath)
	return os.WriteFile(unitPath, []byte(serviceContent), 0644)
}

// DeployWarp installs wireproxy using Cloudflare WARP API in pure Go
func DeployWarp() error {
	return DeployWarpWithConfig(nil)
}

// DeployWarpWithConfig installs and configures wireproxy with Cloudflare WARP in pure Go
func DeployWarpWithConfig(cfg *config.Config) error {
	logger.Info("Starting WARP (wireproxy) pure-Go deployment...")

	// 0. 优先清理遗留的 fscarmen / warp-go / /etc/wireguard/proxy.conf 产物
	if purged, err := PurgeLegacyFscarmenWarp(); err != nil {
		logger.Warn("清理旧版 fscarmen WARP 残留警告: %v", err)
	} else if purged {
		logger.Info("已自动清理旧版 fscarmen WARP 残留并切换至纯 Go 架构")
	}

	// 1. Check if pure-Go windtf/wireproxy is already running and healthy on /etc/wireproxy/wireproxy.conf
	if IsWindtfWireproxyBinary(DefaultWireproxyBin) {
		if raw, err := os.ReadFile(DefaultWireproxyConf); err == nil {
			if normalized, changed := NormalizeWireproxyConfigContent(string(raw)); changed {
				_ = writeFileAtomic0600(DefaultWireproxyConf, []byte(normalized))
				_ = writeWireproxySystemdUnit(DefaultWireproxyService, DefaultWireproxyBin, DefaultWireproxyConf)
				_ = runCmd("systemctl", "daemon-reload")
				_ = runCmd("systemctl", "restart", "wireproxy")
				time.Sleep(1500 * time.Millisecond)
			}
			if isWarpSocksRunning() && IsWarpTunnelHealthy(3*time.Second) {
				logger.Success("WARP (wireproxy) is already running cleanly on 127.0.0.1:40000")
				return nil
			}
		}
	}

	// 2. Ensure pure-Go windtf/wireproxy binary is installed
	wireproxyBin, err := ensureWireproxyBinary(cfg)
	if err != nil {
		return fmt.Errorf("failed to ensure wireproxy binary: %w", err)
	}

	// 3. Generate WireGuard X25519 keypair
	privKey, pubKey, err := GenerateWireguardKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate WireGuard keypair: %w", err)
	}

	// 4. Register with Cloudflare WARP API
	logger.Info("Registering Cloudflare WARP account via API...")
	reg, err := registerCloudflareWarp(pubKey)
	if err != nil {
		return fmt.Errorf("failed to register Cloudflare WARP account: %w", err)
	}

	// 5. Render /etc/wireproxy/wireproxy.conf (pure-Go single source of truth)
	if err := os.MkdirAll(filepath.Dir(DefaultWireproxyConf), 0700); err != nil {
		return fmt.Errorf("failed to create /etc/wireproxy: %w", err)
	}
	hasV6 := hasGlobalIPv6()
	candidates := slices.Clone(WarpCandidateEndpoints)
	if regEP := extractRegV4Endpoint(reg); regEP != "" && !slices.Contains(candidates, regEP) {
		candidates = append(candidates, regEP)
	}
	confContent := renderWireproxyConfigFromReg(privKey, reg, hasV6, WarpCandidateEndpoints[0])
	if IsWindtfWireproxyBinary(wireproxyBin) {
		stageCtx, stageCancel := context.WithTimeout(context.Background(), 6*time.Second)
		winEP, winConf, _, _, ok := stageSelectWorkingEndpoint(stageCtx, wireproxyBin, privKey, reg, hasV6, candidates, nil)
		stageCancel()
		if ok && winConf != "" {
			confContent = winConf
			logger.Info("WARP 预探测选定可用 Endpoint: %s", winEP)
		}
	}
	if err := writeFileAtomic0600(DefaultWireproxyConf, []byte(confContent)); err != nil {
		return fmt.Errorf("failed to write %s: %w", DefaultWireproxyConf, err)
	}

	// 6. Create standardized systemd unit pointing strictly to /usr/local/bin/wireproxy and /etc/wireproxy/wireproxy.conf
	if err := writeWireproxySystemdUnit(DefaultWireproxyService, wireproxyBin, DefaultWireproxyConf); err != nil {
		return fmt.Errorf("failed to write %s: %w", DefaultWireproxyService, err)
	}

	// 7. Enable and restart service
	_ = runCmd("systemctl", "daemon-reload")
	if err := runCmd("systemctl", "enable", "--now", "wireproxy"); err != nil {
		return fmt.Errorf("failed to enable and start wireproxy service: %w", err)
	}
	_ = runCmd("systemctl", "restart", "wireproxy")

	// 8. Wait for port 40000 to listen & verify tunnel handshake (auto-fallback endpoints if needed)
	logger.Info("Verifying WARP SOCKS5 proxy on 127.0.0.1:40000...")
	var success bool
	for range 5 {
		time.Sleep(600 * time.Millisecond)
		if isWarpSocksRunning() && IsWarpTunnelHealthy(2*time.Second) {
			success = true
			break
		}
	}

	if !success && isWarpSocksRunning() {
		logger.Warn("当前 Endpoint 握手未就绪，尝试自动轮换备选 Endpoint...")
		if ep, _, _, swErr := SwitchWarpEndpoint(); swErr == nil {
			logger.Success("已自动切换至可用 Endpoint (%s)", ep)
			success = true
		}
	}

	if !success {
		logger.Warn("WARP service started, waiting for tunnel readiness. Verify with: systemctl status wireproxy")
	} else {
		logger.Success("WARP (wireproxy) deployed successfully on 127.0.0.1:40000")
	}

	return nil
}

func isWarpSocksRunning() bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:40000", 1*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// BuildWireproxyConfig 渲染标准纯 Go wireproxy 配置（MTU=1280，IPv4 直连 Endpoint）。
// 注意：
//  1. 绝不使用 ResolveStrategy = auto；若 [Interface] Address 包含虚拟 IPv6 地址则设为 ipv6（优先使用每次注册都会轮换的 WARP IPv6 出口，并对纯 IPv4 目标自动回退至 IPv4），纯 IPv4 配置则设为 ipv4。
//  2. wireproxy 在启动阶段若配置了 PersistentKeepalive，会在 Routine: receive incoming v4 启动前抢先触发握手导致死锁。
//  3. MTU 固定 1280，消除外层 Hysteria2/VLESS 与内层 WireGuard 叠加封装触发 PMTU 黑洞导致大包 TLS 握手超时（如 x.com）。
func BuildWireproxyConfig(addressLine, privKey, peerPubKey string, hasIPv6 bool) string {
	return BuildWireproxyConfigWithEndpoint(addressLine, privKey, peerPubKey, WarpCandidateEndpoints[0], hasIPv6)
}

// BuildWireproxyConfigWithEndpoint 使用指定 IPv4 Endpoint 渲染 wireproxy 配置。
func BuildWireproxyConfigWithEndpoint(addressLine, privKey, peerPubKey, endpoint string, hasIPv6 bool) string {
	ep := cmp.Or(strings.TrimSpace(endpoint), WarpCandidateEndpoints[0])
	dnsLine := "1.1.1.1,8.8.8.8,8.8.4.4"
	if hasIPv6 {
		dnsLine = "1.1.1.1,8.8.8.8,8.8.4.4,2606:4700:4700::1111,2001:4860:4860::8888,2001:4860:4860::8844"
	}
	resolveStrategy := "ipv4"
	if strings.Contains(addressLine, ":") {
		resolveStrategy = "ipv6"
	}
	return fmt.Sprintf(`[Interface]
Address = %s
MTU = 1280
PrivateKey = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s

[Socks5]
BindAddress = 127.0.0.1:40000

[Resolve]
ResolveStrategy = %s
`, addressLine, privKey, dnsLine, peerPubKey, ep, resolveStrategy)
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
		mu      sync.Mutex
		won     bool
		winIP   string
		winLoc  string
		wg      sync.WaitGroup
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

// WarpRotateDeps 定义更换 WARP IP 时的可注入外部依赖（用于离线单元测试与模拟回滚）。
type WarpRotateDeps struct {
	PathEnv            WireproxyPathEnv
	PurgeLegacy        func() (bool, error)
	CandidateEndpoints []string
	PreviousIP         string
	GenerateKeypair    func() (privKey, pubKey string, err error)
	RegisterWarp       func(pubKey string) (*warpRegResponse, error)
	HasIPv6            func() bool
	RestartService     func() error
	FetchExitInfo      func(timeout time.Duration) (ip, loc, state string, ok bool)
	StageProbe         func(endpoint, confContent string) (ip, loc string, ok bool)
	DeployFallback     func() error
	PollAttempts       int
	PollInterval       time.Duration
}

func renderWireproxyConfigFromReg(privKey string, reg *warpRegResponse, hasIPv6 bool, endpoint string) string {
	var v4Addr, v6Addr, peerPubKey string
	if reg != nil {
		v4Addr = reg.Config.Interface.Addresses.V4
		if !strings.Contains(v4Addr, "/") && v4Addr != "" {
			v4Addr += "/32"
		}
		v6Addr = reg.Config.Interface.Addresses.V6
		if !strings.Contains(v6Addr, "/") && v6Addr != "" {
			v6Addr += "/128"
		}
		if len(reg.Config.Peers) > 0 && reg.Config.Peers[0].PublicKey != "" {
			peerPubKey = reg.Config.Peers[0].PublicKey
		}
	}
	addressLine := v4Addr
	if v6Addr != "" {
		if addressLine != "" {
			addressLine += ", " + v6Addr
		} else {
			addressLine = v6Addr
		}
	}
	addressLine = cmp.Or(addressLine, "172.16.0.2/32")
	peerPubKey = cmp.Or(peerPubKey, "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
	return BuildWireproxyConfigWithEndpoint(addressLine, privKey, peerPubKey, endpoint, hasIPv6)
}

func extractRegV4Endpoint(reg *warpRegResponse) string {
	if reg == nil || len(reg.Config.Peers) == 0 {
		return ""
	}
	v4 := strings.TrimSpace(reg.Config.Peers[0].Endpoint.V4)
	if v4 == "" || strings.HasSuffix(v4, ":0") {
		return ""
	}
	host, port, err := net.SplitHostPort(v4)
	if err != nil || host == "" || port == "" || port == "0" {
		return ""
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return v4
}

// RotateWarpIdentity 重新注册 Cloudflare WARP 设备密钥并热切换本地 wireproxy 出口 IP（带离网预验证、多 Endpoint 自动回退、0600 备份与失败自动回滚）
func RotateWarpIdentity() (newIP, newLoc string, err error) {
	return RotateWarpIdentityFrom("")
}

// RotateWarpIdentityFrom 尝试换取与 previousIP 不同的全新 WARP 出口身份并热切换本地 wireproxy。
func RotateWarpIdentityFrom(previousIP string) (newIP, newLoc string, err error) {
	return RotateWarpIdentityWithDeps(&WarpRotateDeps{
		PurgeLegacy:        PurgeLegacyFscarmenWarp,
		CandidateEndpoints: WarpCandidateEndpoints,
		PreviousIP:         strings.TrimSpace(previousIP),
	})
}

func RotateWarpIdentityWithDeps(deps *WarpRotateDeps) (newIP, newLoc string, err error) {
	var d WarpRotateDeps
	if deps != nil {
		d = *deps
	}
	if d.PurgeLegacy != nil {
		_, _ = d.PurgeLegacy()
	} else if d.PathEnv.PrimaryConf == "" && len(d.PathEnv.UnitFiles) == 0 {
		_, _ = PurgeLegacyFscarmenWarp()
	}
	if d.GenerateKeypair == nil {
		d.GenerateKeypair = GenerateWireguardKeypair
	}
	if d.RegisterWarp == nil {
		d.RegisterWarp = registerCloudflareWarp
	}
	if d.HasIPv6 == nil {
		d.HasIPv6 = hasGlobalIPv6
	}
	if d.RestartService == nil {
		d.RestartService = func() error {
			return runCmd("systemctl", "restart", "wireproxy")
		}
	}
	if d.FetchExitInfo == nil {
		d.FetchExitInfo = func(timeout time.Duration) (string, string, string, bool) {
			if !isWarpSocksRunning() {
				return "", "", "", false
			}
			return FetchWarpExitInfo(timeout)
		}
	}
	if d.DeployFallback == nil {
		d.DeployFallback = func() error {
			return DeployWarpWithConfig(nil)
		}
	}
	if d.PollAttempts <= 0 {
		d.PollAttempts = 2
	}
	if d.PollInterval <= 0 {
		d.PollInterval = 350 * time.Millisecond
	}

	activePath, mirrorPaths, exists := ResolveWireproxyConfigPathsWithEnv(d.PathEnv)
	if !exists {
		// 若尚未生成标准纯 Go WARP 配置（含首次从 fscarmen 迁移清理后），自动初始化部署并直接探测新出口 IP
		if err := d.DeployFallback(); err != nil {
			return "", "", fmt.Errorf("未检测到已部署的 WARP 配置 (%s)，且自动初始化失败: %w", activePath, err)
		}
		for range d.PollAttempts {
			if ip, loc, _, ok := d.FetchExitInfo(2 * time.Second); ok && ip != "" {
				return ip, loc, nil
			}
			time.Sleep(d.PollInterval)
		}
		return "", "", fmt.Errorf("WARP 已完成自动初始化，但暂未探测到出口 IP，请稍后刷新查看")
	}

	oldActive, errRead := os.ReadFile(activePath)
	if errRead != nil {
		return "", "", fmt.Errorf("读取现网 WARP 配置 (%s) 失败: %w", activePath, errRead)
	}
	_ = os.Chmod(activePath, 0600)

	// 1. 以 0600 备份现网生效配置（保留最近 3 份备份）
	bakPath := fmt.Sprintf("%s.%d.bak", activePath, time.Now().UnixNano())
	_ = os.WriteFile(bakPath, oldActive, 0600)
	_ = os.Chmod(bakPath, 0600)
	pruneWireproxyBackups(activePath, 3)

	existingMirrors := make(map[string][]byte, len(mirrorPaths))
	var createdMirrors []string
	for _, mp := range mirrorPaths {
		if b, mErr := os.ReadFile(mp); mErr == nil {
			existingMirrors[mp] = b
		} else {
			createdMirrors = append(createdMirrors, mp)
		}
	}

	currentEP := ExtractWireproxyEndpoint(string(oldActive))
	buildCandidateEndpoints := func(reg *warpRegResponse) []string {
		var endpoints []string
		addUnique := func(ep string) {
			ep = strings.TrimSpace(ep)
			if ep != "" && !slices.Contains(endpoints, ep) {
				endpoints = append(endpoints, ep)
			}
		}
		regEP := extractRegV4Endpoint(reg)
		if len(d.CandidateEndpoints) == 0 {
			if isValidIPv4Endpoint(currentEP) {
				addUnique(currentEP)
			} else {
				addUnique(WarpCandidateEndpoints[0])
			}
			addUnique(regEP)
			return endpoints
		}
		if isValidIPv4Endpoint(currentEP) {
			addUnique(currentEP)
		}
		for _, ep := range d.CandidateEndpoints {
			addUnique(ep)
		}
		addUnique(regEP)
		return endpoints
	}

	rollback := func() {
		_ = writeFileAtomic0600(activePath, oldActive)
		for mp, oldBytes := range existingMirrors {
			_ = writeFileAtomic0600(mp, oldBytes)
		}
		for _, mp := range createdMirrors {
			_ = os.Remove(mp)
		}
		_ = d.RestartService()
	}

	useStaging := d.StageProbe != nil || ((deps == nil || (deps.RestartService == nil && deps.FetchExitInfo == nil)) && IsWindtfWireproxyBinary(DefaultWireproxyBin))
	if useStaging {
		hasV6 := d.HasIPv6()
		prevIP := strings.TrimSpace(d.PreviousIP)
		maxReg := 1
		if prevIP != "" {
			maxReg = 2
		}

		var chosenConf, stageIP, stageLoc string
		for attempt := range maxReg {
			privKey, pubKey, kErr := d.GenerateKeypair()
			if kErr != nil {
				if attempt == 0 || chosenConf == "" {
					_ = os.Remove(bakPath)
					return "", "", fmt.Errorf("生成 WireGuard 密钥对失败: %w", kErr)
				}
				break
			}
			reg, rErr := d.RegisterWarp(pubKey)
			if rErr != nil {
				if attempt == 0 || chosenConf == "" {
					_ = os.Remove(bakPath)
					return "", "", fmt.Errorf("注册 Cloudflare WARP 新身份失败: %w", rErr)
				}
				break
			}

			endpoints := buildCandidateEndpoints(reg)
			stageCtx, stageCancel := context.WithTimeout(context.Background(), 5500*time.Millisecond)
			_, winConf, sIP, sLoc, ok := stageSelectWorkingEndpoint(stageCtx, DefaultWireproxyBin, privKey, reg, hasV6, endpoints, d.StageProbe)
			stageCancel()
			if !ok || winConf == "" {
				if attempt == 0 || chosenConf == "" {
					_ = os.Remove(bakPath)
					return "", "", fmt.Errorf("新 WARP 身份在备选 Endpoint 握手超时，已保留原隧道不断流")
				}
				break
			}

			chosenConf = winConf
			stageIP = sIP
			stageLoc = sLoc
			if prevIP == "" || stageIP != prevIP || attempt == maxReg-1 {
				break
			}
		}

		if err := writeFileAtomic0600(activePath, []byte(chosenConf)); err != nil {
			return "", "", fmt.Errorf("写入新 wireproxy 配置 (%s) 失败: %w", activePath, err)
		}
		for _, mp := range mirrorPaths {
			_ = writeFileAtomic0600(mp, []byte(chosenConf))
		}

		if err := d.RestartService(); err != nil {
			rollback()
			return "", "", fmt.Errorf("重启 wireproxy 失败，已回滚原配置: %w", err)
		}

		// 若单元测试仅注入 StageProbe 而未模拟本地 127.0.0.1:40000，则直接采信离网探测结果
		if deps != nil && deps.StageProbe != nil && deps.FetchExitInfo == nil {
			return stageIP, stageLoc, nil
		}

		preferIPv6 := strings.Contains(chosenConf, "ResolveStrategy = ipv6")
		for attempt := range 4 {
			if attempt == 0 {
				time.Sleep(250 * time.Millisecond)
			} else {
				time.Sleep(300 * time.Millisecond)
			}
			if deps != nil && deps.FetchExitInfo != nil {
				if liveIP, liveLoc, _, ok := d.FetchExitInfo(1800 * time.Millisecond); ok && liveIP != "" {
					return liveIP, cmp.Or(liveLoc, stageLoc), nil
				}
				continue
			}
			if isWarpSocksRunning() {
				if liveIP, liveLoc, _, ok := fetchWarpTraceViaProxy(context.Background(), "127.0.0.1:40000", preferIPv6, 1800*time.Millisecond); ok && liveIP != "" {
					return liveIP, cmp.Or(liveLoc, stageLoc), nil
				}
				if liveIP, liveLoc, _, ok := d.FetchExitInfo(1800 * time.Millisecond); ok && liveIP != "" {
					return liveIP, cmp.Or(liveLoc, stageLoc), nil
				}
			}
		}

		rollback()
		return "", "", fmt.Errorf("新 WARP 身份加载后本地隧道未就绪，已自动回滚保留原有出口隧道")
	}

	// 2. 生成新 X25519 密钥对并向 Cloudflare 注册新身份（无本地 wireproxy 进程时的直接回退模式）
	privKey, pubKey, kErr := d.GenerateKeypair()
	if kErr != nil {
		return "", "", fmt.Errorf("生成 WireGuard 密钥对失败: %w", kErr)
	}
	reg, rErr := d.RegisterWarp(pubKey)
	if rErr != nil {
		return "", "", fmt.Errorf("注册 Cloudflare WARP 新身份失败: %w", rErr)
	}

	endpoints := buildCandidateEndpoints(reg)

	// 3. 按序尝试各 Endpoint：写入 0600 配置、重启 wireproxy 并验证握手成功
	var lastRestartErr error
	hasV6 := d.HasIPv6()
	for _, ep := range endpoints {
		freshConf := renderWireproxyConfigFromReg(privKey, reg, hasV6, ep)
		if err := writeFileAtomic0600(activePath, []byte(freshConf)); err != nil {
			return "", "", fmt.Errorf("写入新 wireproxy 配置 (%s) 失败: %w", activePath, err)
		}
		for _, mp := range mirrorPaths {
			_ = writeFileAtomic0600(mp, []byte(freshConf))
		}

		if err := d.RestartService(); err != nil {
			lastRestartErr = err
			continue
		}

		for range d.PollAttempts {
			time.Sleep(d.PollInterval)
			if ip, loc, _, ok := d.FetchExitInfo(1800 * time.Millisecond); ok && ip != "" {
				return ip, loc, nil
			}
		}
	}

	rollback()
	if lastRestartErr != nil && len(endpoints) == 1 {
		return "", "", fmt.Errorf("重启 wireproxy 失败，已回滚原配置: %w", lastRestartErr)
	}
	return "", "", fmt.Errorf("新 WARP 身份握手超时，已自动回滚保留原有出口隧道")
}

func pruneWireproxyBackups(path string, keep int) {
	if keep < 1 {
		keep = 1
	}
	matches, err := filepath.Glob(path + ".*.bak")
	if err != nil || len(matches) <= keep {
		return
	}
	slices.Sort(matches)
	slices.Reverse(matches)
	for i := keep; i < len(matches); i++ {
		_ = os.Remove(matches[i])
	}
}

// NormalizeWireproxyConfigContent 修正既有 wireproxy 配置中的 MTU=1280、双栈可轮换 ResolveStrategy、域名 Endpoint 与启动死锁 PersistentKeepalive
func NormalizeWireproxyConfigContent(content string) (string, bool) {
	lines := strings.Split(content, "\n")

	targetStrategy := "ipv4"
	inInterfaceScan := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inInterfaceScan = strings.EqualFold(trimmed, "[Interface]")
			continue
		}
		if inInterfaceScan && strings.HasPrefix(trimmed, "Address") && !strings.HasPrefix(trimmed, "#") {
			if k, v, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(k) == "Address" && strings.Contains(v, ":") {
				targetStrategy = "ipv6"
			}
		}
	}

	changed := false
	inInterface := false
	sawMTU := false
	inPeer := false
	hasResolveSection := false
	out := make([]string, 0, len(lines)+4)

	flushMissingMTU := func() {
		if inInterface && !sawMTU {
			out = append(out, "MTU = 1280")
			changed = true
			sawMTU = true
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if !strings.EqualFold(trimmed, "[Interface]") {
				flushMissingMTU()
			}
			inInterface = strings.EqualFold(trimmed, "[Interface]")
			inPeer = strings.EqualFold(trimmed, "[Peer]")
			if strings.EqualFold(trimmed, "[Resolve]") {
				hasResolveSection = true
			}
		}
		if inInterface && strings.HasPrefix(trimmed, "MTU") && !strings.HasPrefix(trimmed, "#") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[0]) == "MTU" {
				sawMTU = true
				if strings.TrimSpace(parts[1]) != "1280" {
					line = "MTU = 1280"
					changed = true
				}
			}
		}
		if strings.HasPrefix(trimmed, "ResolveStrategy") && !strings.HasPrefix(trimmed, "#") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[1]) != targetStrategy {
				line = "ResolveStrategy = " + targetStrategy
				changed = true
			}
		}
		if inPeer && strings.HasPrefix(trimmed, "Endpoint") && !strings.HasPrefix(trimmed, "#") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 && strings.Contains(parts[1], "engage.cloudflareclient.com") {
				line = "Endpoint = " + WarpCandidateEndpoints[0]
				changed = true
			}
		}
		if inPeer && strings.HasPrefix(trimmed, "PersistentKeepalive") {
			changed = true
			continue
		}
		out = append(out, line)
	}
	flushMissingMTU()

	if !hasResolveSection {
		for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
			out = out[:len(out)-1]
		}
		out = append(out, "", "[Resolve]", "ResolveStrategy = "+targetStrategy, "")
		changed = true
	}

	return strings.Join(out, "\n"), changed
}

// ExtractWireproxyEndpoint 读取配置文件中的 [Peer] Endpoint 值。
func ExtractWireproxyEndpoint(content string) string {
	inPeer := false
	for line := range strings.SplitSeq(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inPeer = strings.EqualFold(trimmed, "[Peer]")
			continue
		}
		if inPeer && strings.HasPrefix(trimmed, "Endpoint") && !strings.HasPrefix(trimmed, "#") {
			if k, v, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(k) == "Endpoint" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

// ReplaceWireproxyEndpoint 替换配置文件中 [Peer] 段内的 Endpoint。
func ReplaceWireproxyEndpoint(content, newEndpoint string) string {
	lines := strings.Split(content, "\n")
	inPeer := false
	replaced := false
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inPeer = strings.EqualFold(trimmed, "[Peer]")
		} else if inPeer && strings.HasPrefix(trimmed, "Endpoint") && !strings.HasPrefix(trimmed, "#") {
			if k, _, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(k) == "Endpoint" {
				line = "Endpoint = " + strings.TrimSpace(newEndpoint)
				replaced = true
			}
		}
		out = append(out, line)
	}
	if !replaced {
		return content
	}
	return strings.Join(out, "\n")
}

// WarpEndpointSwitchDeps 允许测试注入 Endpoint 切换流程的外部依赖。
type WarpEndpointSwitchDeps struct {
	ConfPath           string
	CandidateEndpoints []string
	RestartService     func() error
	ProbeTargets       func(timeout time.Duration) (ip, loc string, err error)
	PollAttempts       int
	PollInterval       time.Duration
}

// SwitchWarpEndpoint 轮换 wireproxy Endpoint 节点并重启隧道，直至真实外网探测连通（全部失败自动恢复原配置）。
func SwitchWarpEndpoint() (endpoint, ip, loc string, err error) {
	return SwitchWarpEndpointWithDeps(nil)
}

func SwitchWarpEndpointWithDeps(deps *WarpEndpointSwitchDeps) (endpoint, ip, loc string, err error) {
	var d WarpEndpointSwitchDeps
	if deps != nil {
		d = *deps
	}
	confPath := cmp.Or(strings.TrimSpace(d.ConfPath), DefaultWireproxyConf)
	if len(d.CandidateEndpoints) == 0 {
		d.CandidateEndpoints = WarpCandidateEndpoints
	}
	if d.RestartService == nil {
		d.RestartService = func() error {
			return runCmd("systemctl", "restart", "wireproxy")
		}
	}
	if d.ProbeTargets == nil {
		d.ProbeTargets = ProbeWarpRealTargets
	}
	if d.PollAttempts <= 0 {
		d.PollAttempts = 2
	}
	if d.PollInterval <= 0 {
		d.PollInterval = 350 * time.Millisecond
	}

	origBytes, readErr := os.ReadFile(confPath)
	if readErr != nil {
		return "", "", "", fmt.Errorf("读取 wireproxy 配置失败: %w", readErr)
	}
	origContent := string(origBytes)
	currentEP := ExtractWireproxyEndpoint(origContent)
	ordered := orderCandidateEndpointsAfterCurrent(d.CandidateEndpoints, currentEP)

	var lastErr error
	for _, cand := range ordered {
		updated := ReplaceWireproxyEndpoint(origContent, cand)
		if normalized, changed := NormalizeWireproxyConfigContent(updated); changed {
			updated = normalized
		}
		if wErr := writeFileAtomic0600(confPath, []byte(updated)); wErr != nil {
			lastErr = wErr
			continue
		}
		if rErr := d.RestartService(); rErr != nil {
			lastErr = rErr
			continue
		}
		for range d.PollAttempts {
			time.Sleep(d.PollInterval)
			if probeIP, probeLoc, pErr := d.ProbeTargets(2500 * time.Millisecond); pErr == nil && probeIP != "" {
				return cand, probeIP, probeLoc, nil
			} else if pErr != nil {
				lastErr = pErr
			}
		}
	}

	_ = writeFileAtomic0600(confPath, origBytes)
	_ = d.RestartService()
	return "", "", "", fmt.Errorf("所有备选 WARP Endpoint (%d 个) 均不可达: %v", len(ordered), lastErr)
}

func orderCandidateEndpointsAfterCurrent(candidates []string, current string) []string {
	idx := slices.Index(candidates, strings.TrimSpace(current))
	if idx < 0 || idx+1 >= len(candidates) {
		return slices.Clone(candidates)
	}
	ordered := make([]string, 0, len(candidates))
	ordered = append(ordered, candidates[idx+1:]...)
	ordered = append(ordered, candidates[:idx+1]...)
	return ordered
}

// SyncWarpConfigIfNeeded 检查并自愈本机 WARP (wireproxy) 配置与隧道握手状态（同时自动清理遗留的 fscarmen 脚本产物）
func SyncWarpConfigIfNeeded() (healed bool, msg string, err error) {
	purged, _ := PurgeLegacyFscarmenWarp()

	activePath, _, exists := ResolveWireproxyConfigPaths()
	if purged && (!exists || !IsWindtfWireproxyBinary(DefaultWireproxyBin)) {
		if dErr := DeployWarpWithConfig(nil); dErr != nil {
			return false, "", fmt.Errorf("已清理旧版 fscarmen WARP，但重建纯 Go wireproxy 失败: %w", dErr)
		}
		return true, "已清理旧版 fscarmen WARP 并迁移至内置纯 Go wireproxy (MTU=1280)", nil
	}

	if !exists {
		return false, "", nil
	}
	if !IsWindtfWireproxyBinary(DefaultWireproxyBin) {
		if dErr := DeployWarpWithConfig(nil); dErr != nil {
			return false, "", fmt.Errorf("升级为纯 Go wireproxy 失败: %w", dErr)
		}
		return true, "已替换升级为内置纯 Go windtf/wireproxy 引擎", nil
	}

	raw, rErr := os.ReadFile(activePath)
	if rErr != nil {
		return false, "", nil
	}
	anyChanged := purged
	if normalized, changed := NormalizeWireproxyConfigContent(string(raw)); changed {
		if wErr := writeFileAtomic0600(activePath, []byte(normalized)); wErr != nil {
			return false, "", fmt.Errorf("写入 %s 失败: %w", activePath, wErr)
		}
		anyChanged = true
	}

	if !anyChanged && isWarpSocksRunning() {
		if _, _, pErr := ProbeWarpRealTargets(3 * time.Second); pErr == nil {
			return false, "", nil
		}
	}

	_ = writeWireproxySystemdUnit(DefaultWireproxyService, DefaultWireproxyBin, activePath)
	_ = runCmd("systemctl", "daemon-reload")
	_ = runCmd("systemctl", "restart", "wireproxy")
	for range 4 {
		time.Sleep(800 * time.Millisecond)
		if _, _, pErr := ProbeWarpRealTargets(3 * time.Second); pErr == nil {
			return true, "WARP (wireproxy) 已规范化 MTU=1280/IPv4 策略并恢复真实出口连通", nil
		}
	}

	if ep, _, _, swErr := SwitchWarpEndpoint(); swErr == nil {
		return true, fmt.Sprintf("WARP (wireproxy) 已自动切换至可用 Endpoint (%s)", ep), nil
	}

	if newIP, _, rErr := RotateWarpIdentity(); rErr == nil {
		return true, fmt.Sprintf("WARP (wireproxy) 已自动重新注册身份并切换出口 IP (%s)", newIP), nil
	} else {
		return false, "", rErr
	}
}

func GenerateWireguardKeypair() (string, string, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privKey := base64.StdEncoding.EncodeToString(priv.Bytes())
	pubKey := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	return privKey, pubKey, nil
}

func registerCloudflareWarp(publicKey string) (*warpRegResponse, error) {
	reqBody := warpRegRequest{
		Key:          publicKey,
		InstallID:    "",
		FCMToken:     "",
		TOS:          time.Now().UTC().Format(time.RFC3339Nano),
		Model:        "PC",
		SerialNumber: "",
		Locale:       "en_US",
	}
	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	regURL := "https://api.cloudflareclient.com/v0a3922/reg"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, regURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cloudflare API error (%s): %s", resp.Status, string(body))
	}

	var reg warpRegResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return nil, fmt.Errorf("failed to decode cloudflare registration response: %w", err)
	}

	return &reg, nil
}

func ensureWireproxyBinary(cfg *config.Config) (string, error) {
	if IsWindtfWireproxyBinary(DefaultWireproxyBin) {
		return DefaultWireproxyBin, nil
	}

	arch := runtime.GOARCH
	switch arch {
	case "amd64", "arm64", "386", "arm", "mipsle":
	default:
		return "", fmt.Errorf("unsupported architecture for wireproxy: %s", arch)
	}

	mirror := ""
	if cfg != nil {
		mirror = cfg.GitHub.MirrorURL
	}

	downloadURL := fmt.Sprintf("https://github.com/windtf/wireproxy/releases/latest/download/wireproxy_linux_%s.tar.gz", arch)
	reachableURL := netinfo.GetReachableURL(downloadURL, mirror)

	logger.Info("Downloading windtf/wireproxy binary from: %s", reachableURL)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(reachableURL)
	if err != nil {
		return "", fmt.Errorf("failed to download wireproxy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download wireproxy (status %s)", resp.Status)
	}

	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to gunzip wireproxy: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	targetPath := DefaultWireproxyBin
	found := false

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("reading tar entry: %w", err)
		}
		baseName := filepath.Base(hdr.Name)
		if baseName == "wireproxy" {
			_ = os.MkdirAll(filepath.Dir(targetPath), 0755)
			tmpBin := fmt.Sprintf("%s.%d.tmp", targetPath, time.Now().UnixNano())
			outFile, err := os.OpenFile(tmpBin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return "", fmt.Errorf("failed to create %s: %w", tmpBin, err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				_ = os.Remove(tmpBin)
				return "", fmt.Errorf("failed to write %s: %w", tmpBin, err)
			}
			outFile.Close()
			if !IsWindtfWireproxyBinary(tmpBin) {
				_ = os.Remove(tmpBin)
				return "", fmt.Errorf("downloaded wireproxy binary failed compatibility check (missing ResolveStrategy)")
			}
			if err := os.Rename(tmpBin, targetPath); err != nil {
				_ = os.Remove(tmpBin)
				return "", fmt.Errorf("failed to install %s: %w", targetPath, err)
			}
			_ = os.Chmod(targetPath, 0755)
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("wireproxy binary not found inside archive")
	}

	logger.Success("Installed windtf/wireproxy binary to %s", targetPath)
	return targetPath, nil
}
