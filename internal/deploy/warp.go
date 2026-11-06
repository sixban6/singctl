package deploy

import (
	"archive/tar"
	"bytes"
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
	privKey, pubKey, err := generateWireguardKeypair()
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

	confContent := buildWireproxyConfig(addressLine, privKey, peerPubKey, hasGlobalIPv6())

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
// 1. wireproxy 的 ResolveStrategy = auto 只要检测到 [Interface] Address 含虚拟 IPv6 地址就会强制转为 ipv6，
//    在纯 IPv4 VPS 上会导致 engage.cloudflareclient.com 解析为 AAAA 记录并引发 WireGuard 握手 100% 超时黑洞。
// 2. wireproxy 在启动阶段若配置了 PersistentKeepalive，会在 Routine: receive incoming v4 启动前抢先触发握手导致死锁。
// 因此固定使用 IPv4 Endpoint (162.159.192.1:2408) 与 ResolveStrategy = ipv4，且不启用 PersistentKeepalive。
func buildWireproxyConfig(addressLine, privKey, peerPubKey string, hasIPv6 bool) string {
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
	confPaths := []string{"/etc/wireproxy/wireproxy.conf", "/etc/wireguard/proxy.conf"}
	var existingPaths []string
	for _, p := range confPaths {
		if _, stErr := os.Stat(p); stErr == nil {
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
			if wErr := os.WriteFile(p, []byte(normalized), 0600); wErr != nil {
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
	privKey, pubKey, kErr := generateWireguardKeypair()
	if kErr != nil {
		return false, "", fmt.Errorf("WARP 隧道未连通且生成新密钥对失败: %w", kErr)
	}
	reg, rErr := registerCloudflareWarp(pubKey)
	if rErr != nil {
		return false, "", fmt.Errorf("WARP 隧道未连通且重新注册 Cloudflare WARP 失败: %w", rErr)
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
	freshConf := buildWireproxyConfig(addressLine, privKey, peerPubKey, hasGlobalIPv6())
	for _, p := range existingPaths {
		_ = os.WriteFile(p, []byte(freshConf), 0600)
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

func generateWireguardKeypair() (string, string, error) {
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
