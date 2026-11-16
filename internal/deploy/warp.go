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

// UninstallWarp uninstalls WARP (wireproxy)
func UninstallWarp() error {
	logger.Info("Uninstalling WARP (wireproxy)...")
	_ = runCmd("systemctl", "stop", "wireproxy")
	_ = runCmd("systemctl", "disable", "wireproxy")
	_ = os.Remove("/etc/systemd/system/wireproxy.service")
	_ = runCmd("systemctl", "daemon-reload")
	_ = os.Remove("/usr/local/bin/wireproxy")
	_ = os.Remove("/usr/bin/wireproxy")
	_ = os.RemoveAll("/etc/wireproxy")
	_ = os.RemoveAll("/etc/wireguard")
	logger.Success("WARP uninstallation completed.")
	return nil
}

// DeployWarp installs wireproxy using Cloudflare WARP API in pure Go
func DeployWarp() error {
	return DeployWarpWithConfig(nil)
}

// DeployWarpWithConfig installs and configures wireproxy with Cloudflare WARP in pure Go
func DeployWarpWithConfig(cfg *config.Config) error {
	logger.Info("Starting WARP (wireproxy) native deployment...")

	// 1. Check if WARP SOCKS5 is already running and tunnel is healthy on port 40000
	if isWarpSocksRunning() && IsWarpTunnelHealthy(3*time.Second) {
		logger.Success("WARP (wireproxy) is already running on 127.0.0.1:40000")
		return nil
	}

	// 2. Ensure wireproxy binary is installed
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

	// 5. Render /etc/wireproxy/wireproxy.conf
	if err := os.MkdirAll("/etc/wireproxy", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/wireproxy: %w", err)
	}

	v4Addr := reg.Config.Interface.Addresses.V4
	if !strings.Contains(v4Addr, "/") && v4Addr != "" {
		v4Addr += "/32"
	}
	v6Addr := reg.Config.Interface.Addresses.V6
	if !strings.Contains(v6Addr, "/") && v6Addr != "" {
		v6Addr += "/128"
	}

	addressLine := v4Addr
	if v6Addr != "" {
		if addressLine != "" {
			addressLine += ", " + v6Addr
		} else {
			addressLine = v6Addr
		}
	}
	if addressLine == "" {
		addressLine = "172.16.0.2/32"
	}

	peerPubKey := "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	if len(reg.Config.Peers) > 0 && reg.Config.Peers[0].PublicKey != "" {
		peerPubKey = reg.Config.Peers[0].PublicKey
	}

	confContent := BuildWireproxyConfig(addressLine, privKey, peerPubKey, hasGlobalIPv6())

	confPath := "/etc/wireproxy/wireproxy.conf"
	if err := os.WriteFile(confPath, []byte(confContent), 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", confPath, err)
	}

	// Also symlink / write /etc/wireguard/proxy.conf for backward compatibility
	if err := os.MkdirAll("/etc/wireguard", 0755); err == nil {
		_ = os.WriteFile("/etc/wireguard/proxy.conf", []byte(confContent), 0600)
	}

	// 6. Create systemd unit
	serviceContent := fmt.Sprintf(`[Unit]
Description=WireProxy for WARP
After=network.target

[Service]
Type=simple
ExecStart=%s -c %s
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, wireproxyBin, confPath)

	servicePath := "/etc/systemd/system/wireproxy.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", servicePath, err)
	}

	// 7. Enable and restart service
	_ = runCmd("systemctl", "daemon-reload")
	if err := runCmd("systemctl", "enable", "--now", "wireproxy"); err != nil {
		return fmt.Errorf("failed to enable and start wireproxy service: %w", err)
	}
	_ = runCmd("systemctl", "restart", "wireproxy")

	// 8. Wait for port 40000 to listen
	logger.Info("Verifying WARP SOCKS5 proxy on 127.0.0.1:40000...")
	var success bool
	for range 10 {
		time.Sleep(1 * time.Second)
		if isWarpSocksRunning() {
			success = true
			break
		}
	}

	if !success {
		logger.Warn("WARP service started, waiting for port 40000. Verify with: systemctl status wireproxy")
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

// buildWireproxyConfig 渲染 wireproxy 配置。
// 注意：
//  1. wireproxy 的 ResolveStrategy = auto 只要检测到 [Interface] Address 含虚拟 IPv6 地址就会强制转为 ipv6，
//     在纯 IPv4 VPS 上会导致 engage.cloudflareclient.com 解析为 AAAA 记录并引发 WireGuard 握手 100% 超时黑洞。
//  2. wireproxy 在启动阶段若配置了 PersistentKeepalive，会在 Routine: receive incoming v4 启动前抢先触发握手导致死锁。
//
// 因此固定使用 IPv4 Endpoint (162.159.192.1:2408) 与 ResolveStrategy = ipv4，且不启用 PersistentKeepalive。
func BuildWireproxyConfig(addressLine, privKey, peerPubKey string, hasIPv6 bool) string {
	dnsLine := "1.1.1.1,8.8.8.8,8.8.4.4"
	if hasIPv6 {
		dnsLine = "1.1.1.1,8.8.8.8,8.8.4.4,2606:4700:4700::1111,2001:4860:4860::8888,2001:4860:4860::8844"
	}
	return fmt.Sprintf(`[Interface]
Address = %s
MTU = 1420
PrivateKey = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = 162.159.192.1:2408

[Socks5]
BindAddress = 127.0.0.1:40000

[Resolve]
ResolveStrategy = ipv4
`, addressLine, privKey, dnsLine, peerPubKey)
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

// IsWarpTunnelHealthy 通过本地 SOCKS5 (127.0.0.1:40000) 探测 Cloudflare trace，确认底层 WireGuard 隧道已真实连通
func IsWarpTunnelHealthy(timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	proxyURL, err := url.Parse("socks5://127.0.0.1:40000")
	if err != nil {
		return false
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false
	}
	trace := string(body)
	return strings.Contains(trace, "warp=on") || strings.Contains(trace, "warp=plus")
}

// FetchWarpExitInfo 通过本地 SOCKS5 (127.0.0.1:40000) 查询当前 WARP 出口 IP、地区代码及 warp 状态
func FetchWarpExitInfo(timeout time.Duration) (ip, loc, warpState string, ok bool) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	proxyURL, err := url.Parse("socks5://127.0.0.1:40000")
	if err != nil {
		return "", "", "", false
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
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
	ok = warpState == "on" || warpState == "plus"
	return ip, loc, warpState, ok
}

const (
	DefaultWireproxyConf = "/etc/wireproxy/wireproxy.conf"
	LegacyWireproxyConf  = "/etc/wireguard/proxy.conf"
)

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

// ResolveWireproxyConfigPaths 解析当前宿主 wireproxy 真实生效的主配置文件路径、需同步的兼容镜像路径及文件是否已存在。
func ResolveWireproxyConfigPaths() (activePath string, mirrorPaths []string, exists bool) {
	return ResolveWireproxyConfigPathsWithEnv(WireproxyPathEnv{})
}

func ResolveWireproxyConfigPathsWithEnv(env WireproxyPathEnv) (activePath string, mirrorPaths []string, exists bool) {
	primary := cmp.Or(strings.TrimSpace(env.PrimaryConf), DefaultWireproxyConf)
	compat := cmp.Or(strings.TrimSpace(env.CompatConf), LegacyWireproxyConf)
	unitFiles := env.UnitFiles
	if unitFiles == nil {
		unitFiles = []string{
			"/etc/systemd/system/wireproxy.service",
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
		if parsed := ParseWireproxyConfFromUnit(string(raw)); parsed != "" {
			unitTarget = parsed
			if st, stErr := os.Stat(parsed); stErr == nil && !st.IsDir() {
				activePath = parsed
				exists = true
			}
			break
		}
	}

	if activePath == "" {
		if st, err := os.Stat(primary); err == nil && !st.IsDir() {
			activePath = primary
			exists = true
		} else if st, err := os.Stat(compat); err == nil && !st.IsDir() {
			activePath = compat
			exists = true
		} else {
			activePath = cmp.Or(unitTarget, primary)
			exists = false
		}
	}

	addMirror := func(p string) {
		if p != "" && p != activePath && !slices.Contains(mirrorPaths, p) {
			mirrorPaths = append(mirrorPaths, p)
		}
	}
	// 始终将标准主配置路径纳入同步镜像（老节点仅有 /etc/wireguard/proxy.conf 时可自动补齐 /etc/wireproxy/wireproxy.conf）
	addMirror(primary)
	if st, err := os.Stat(compat); err == nil && !st.IsDir() {
		addMirror(compat)
	}
	return activePath, mirrorPaths, exists
}

// WarpRotateDeps 定义更换 WARP IP 时的可注入外部依赖（用于离线单元测试与模拟回滚）。
type WarpRotateDeps struct {
	PathEnv         WireproxyPathEnv
	GenerateKeypair func() (privKey, pubKey string, err error)
	RegisterWarp    func(pubKey string) (*warpRegResponse, error)
	HasIPv6         func() bool
	RestartService  func() error
	FetchExitInfo   func(timeout time.Duration) (ip, loc, state string, ok bool)
	DeployFallback  func() error
	PollAttempts    int
	PollInterval    time.Duration
}

func renderWireproxyConfigFromReg(privKey string, reg *warpRegResponse, hasIPv6 bool) string {
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
	return BuildWireproxyConfig(addressLine, privKey, peerPubKey, hasIPv6)
}

// RotateWarpIdentity 重新注册 Cloudflare WARP 设备密钥并热切换本地 wireproxy 出口 IP（带 0600 备份与失败自动回滚）
func RotateWarpIdentity() (newIP, newLoc string, err error) {
	return RotateWarpIdentityWithDeps(nil)
}

func RotateWarpIdentityWithDeps(deps *WarpRotateDeps) (newIP, newLoc string, err error) {
	var d WarpRotateDeps
	if deps != nil {
		d = *deps
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
		d.PollAttempts = 6
	}
	if d.PollInterval <= 0 {
		d.PollInterval = 800 * time.Millisecond
	}

	activePath, mirrorPaths, exists := ResolveWireproxyConfigPathsWithEnv(d.PathEnv)
	if !exists {
		// 若尚未生成任何 WARP 配置文件，自动初始化部署并直接探测新出口 IP
		if err := d.DeployFallback(); err != nil {
			return "", "", fmt.Errorf("未检测到已部署的 WARP 配置 (%s)，且自动初始化失败: %w", activePath, err)
		}
		for range d.PollAttempts {
			if ip, loc, _, ok := d.FetchExitInfo(3 * time.Second); ok && ip != "" {
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

	// 2. 生成新 X25519 密钥对并向 Cloudflare 注册新身份
	privKey, pubKey, kErr := d.GenerateKeypair()
	if kErr != nil {
		return "", "", fmt.Errorf("生成 WireGuard 密钥对失败: %w", kErr)
	}
	reg, rErr := d.RegisterWarp(pubKey)
	if rErr != nil {
		return "", "", fmt.Errorf("注册 Cloudflare WARP 新身份失败: %w", rErr)
	}

	freshConf := renderWireproxyConfigFromReg(privKey, reg, d.HasIPv6())

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

	// 3. 以 0600 原子写入生效配置及兼容镜像，并重启 wireproxy
	if err := writeFileAtomic0600(activePath, []byte(freshConf)); err != nil {
		return "", "", fmt.Errorf("写入新 wireproxy 配置 (%s) 失败: %w", activePath, err)
	}
	for _, mp := range mirrorPaths {
		_ = writeFileAtomic0600(mp, []byte(freshConf))
	}

	if err := d.RestartService(); err != nil {
		rollback()
		return "", "", fmt.Errorf("重启 wireproxy 失败，已回滚原配置: %w", err)
	}

	// 4. 轮询验证新隧道握手就绪并读取新出口 IP
	for range d.PollAttempts {
		time.Sleep(d.PollInterval)
		if ip, loc, _, ok := d.FetchExitInfo(3 * time.Second); ok && ip != "" {
			return ip, loc, nil
		}
	}

	rollback()
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

// NormalizeWireproxyConfigContent 修正既有 wireproxy 配置中的 ResolveStrategy=auto、域名 Endpoint 与会导致启动抢跑死锁的 PersistentKeepalive
func NormalizeWireproxyConfigContent(content string) (string, bool) {
	lines := strings.Split(content, "\n")
	changed := false
	inPeer := false
	out := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inPeer = strings.EqualFold(trimmed, "[Peer]")
		}
		if strings.HasPrefix(trimmed, "ResolveStrategy") && !strings.HasPrefix(trimmed, "#") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[1]) != "ipv4" {
				line = "ResolveStrategy = ipv4"
				changed = true
			}
		}
		if inPeer && strings.HasPrefix(trimmed, "Endpoint") && !strings.HasPrefix(trimmed, "#") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 && strings.Contains(parts[1], "engage.cloudflareclient.com") {
				line = "Endpoint = 162.159.192.1:2408"
				changed = true
			}
		}
		if inPeer && strings.HasPrefix(trimmed, "PersistentKeepalive") {
			changed = true
			continue
		}
		out = append(out, line)
	}

	return strings.Join(out, "\n"), changed
}

// SyncWarpConfigIfNeeded 检查并自愈本机 WARP (wireproxy) 配置与隧道握手状态
func SyncWarpConfigIfNeeded() (healed bool, msg string, err error) {
	activePath, mirrorPaths, _ := ResolveWireproxyConfigPaths()
	confPaths := make([]string, 0, 3+len(mirrorPaths))
	for _, p := range append([]string{activePath, DefaultWireproxyConf, LegacyWireproxyConf}, mirrorPaths...) {
		if p != "" && !slices.Contains(confPaths, p) {
			confPaths = append(confPaths, p)
		}
	}
	var existingPaths []string
	for _, p := range confPaths {
		if st, stErr := os.Stat(p); stErr == nil && !st.IsDir() {
			existingPaths = append(existingPaths, p)
		}
	}
	if len(existingPaths) == 0 {
		return false, "", nil
	}

	anyChanged := false
	for _, p := range existingPaths {
		raw, rErr := os.ReadFile(p)
		if rErr != nil {
			continue
		}
		normalized, changed := NormalizeWireproxyConfigContent(string(raw))
		if changed {
			if wErr := writeFileAtomic0600(p, []byte(normalized)); wErr != nil {
				return false, "", fmt.Errorf("写入 %s 失败: %w", p, wErr)
			}
			anyChanged = true
		}
	}

	tunnelOK := isWarpSocksRunning() && IsWarpTunnelHealthy(3*time.Second)
	if !anyChanged && tunnelOK {
		return false, "", nil
	}

	_ = runCmd("systemctl", "restart", "wireproxy")
	for range 4 {
		time.Sleep(800 * time.Millisecond)
		if isWarpSocksRunning() && IsWarpTunnelHealthy(3*time.Second) {
			return true, "WARP (wireproxy) 已修正 IPv4 解析策略并恢复隧道握手连通", nil
		}
	}

	// 若规范化配置重启后仍无法完成 WireGuard 握手（例如旧设备密钥已被 Cloudflare 注销），则自动重新注册密钥对
	privKey, pubKey, kErr := GenerateWireguardKeypair()
	if kErr != nil {
		return false, "", fmt.Errorf("WARP 隧道未连通且生成新密钥对失败: %w", kErr)
	}
	reg, rErr := registerCloudflareWarp(pubKey)
	if rErr != nil {
		return false, "", fmt.Errorf("WARP 隧道未连通且重新注册 Cloudflare WARP 失败: %w", rErr)
	}
	freshConf := renderWireproxyConfigFromReg(privKey, reg, hasGlobalIPv6())
	for _, p := range existingPaths {
		_ = writeFileAtomic0600(p, []byte(freshConf))
	}
	_ = runCmd("systemctl", "restart", "wireproxy")
	for range 4 {
		time.Sleep(800 * time.Millisecond)
		if isWarpSocksRunning() && IsWarpTunnelHealthy(3*time.Second) {
			return true, "WARP (wireproxy) 已自动重新注册设备密钥并恢复隧道连通", nil
		}
	}
	return false, "", fmt.Errorf("WARP (wireproxy) 重启后隧道握手仍未就绪，请检查 UDP 2408 出口连通性")
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

	url := "https://api.cloudflareclient.com/v0a3922/reg"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(jsonBytes))
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
	for _, p := range []string{"/usr/local/bin/wireproxy", "/usr/bin/wireproxy"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if path, err := exec.LookPath("wireproxy"); err == nil {
		return path, nil
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

	logger.Info("Downloading wireproxy binary from: %s", reachableURL)
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
	targetPath := "/usr/local/bin/wireproxy"
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
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return "", fmt.Errorf("failed to create %s: %w", targetPath, err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return "", fmt.Errorf("failed to write %s: %w", targetPath, err)
			}
			outFile.Close()
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("wireproxy binary not found inside archive")
	}

	logger.Success("Installed wireproxy binary to %s", targetPath)
	return targetPath, nil
}
