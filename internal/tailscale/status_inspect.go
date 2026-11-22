// 文件职责：提供 Tailscale 虚拟网段来源识别、LocalAPI 路由偏好查询及宿主机运行状态聚合。
package tailscale

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	tsCGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")
	tsULA6Prefix  = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// BackendStatus 描述 `tailscale status --json` 与 LocalAPI prefs 解析出的运行态快照。
type BackendStatus struct {
	Running      bool
	State        string
	Mode         string
	AcceptRoutes bool
	LiveSubnets  string
}

// HostStatusOptions 控制宿主机 Tailscale 综合状态聚合所需的可选输入。
type HostStatusOptions struct {
	BinPath           string
	LocalAPI          *UnixLocalAPIClient
	AuthKeyConfigured bool
	ConfiguredSubnets string
	DaemonProcProbe   func() bool
}

// IsTailscaleAddr 判断 IP 字符串是否属于 Tailscale CGNAT (100.64.0.0/10) 或 ULA (fd7a:115c:a1e0::/48) 网段。
func IsTailscaleAddr(rawIP string) bool {
	s := strings.TrimSpace(rawIP)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if i := strings.LastIndexByte(s, '%'); i > 0 {
		s = s[:i]
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return tsCGNATPrefix.Contains(addr) || tsULA6Prefix.Contains(addr)
}

// IsTailscaleRequest 判断 HTTP 请求来源是否来自 Tailscale 虚拟隧道（含本机回环反代透传头安全校验）。
func IsTailscaleRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	remote := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	if IsTailscaleAddr(remote) {
		return true
	}
	if addr, err := netip.ParseAddr(remote); err == nil && addr.Unmap().IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if IsTailscaleAddr(first) {
				return true
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" && IsTailscaleAddr(xri) {
			return true
		}
	}
	return false
}

// RouteAllPrefs 通过 tailscaled Unix Socket LocalAPI 读取当前 RouteAll (--accept-routes) 状态。
func (c *UnixLocalAPIClient) RouteAllPrefs(ctx context.Context) (bool, error) {
	pCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(pCtx, http.MethodGet, "http://local-tailscaled.sock/localapi/v0/prefs", nil)
	if err != nil {
		return false, err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))
		return false, fmt.Errorf("localapi prefs http %d", resp.StatusCode)
	}
	var prefs struct {
		RouteAll bool `json:"RouteAll"`
	}
	decErr := json.NewDecoder(resp.Body).Decode(&prefs)
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))
	if decErr != nil {
		return false, decErr
	}
	return prefs.RouteAll, nil
}

// QueryAcceptRoutes 优先通过 LocalAPI 查询 RouteAll，失败时回退 `tailscale debug prefs`。
func QueryAcceptRoutes(ctx context.Context, localAPI *UnixLocalAPIClient, binPath string) bool {
	if localAPI == nil {
		localAPI = defaultUnixLocalAPIClient
	}
	if routeAll, err := localAPI.RouteAllPrefs(ctx); err == nil {
		return routeAll
	}
	if strings.TrimSpace(binPath) == "" {
		return false
	}
	out, err := exec.CommandContext(ctx, binPath, "debug", "prefs").Output()
	if err != nil {
		return false
	}
	var prefs struct {
		RouteAll bool `json:"RouteAll"`
	}
	if json.Unmarshal(out, &prefs) == nil {
		return prefs.RouteAll
	}
	return false
}

// QueryBackendStatus 通过 `tailscale status --json` 与 LocalAPI 解析后端状态、启动模式及广播子网。
func QueryBackendStatus(ctx context.Context, binPath string, localAPI *UnixLocalAPIClient) BackendStatus {
	if strings.TrimSpace(binPath) == "" {
		return BackendStatus{}
	}
	qCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(qCtx, binPath, "status", "--json").Output()
	if err != nil {
		return BackendStatus{}
	}
	var st struct {
		BackendState string `json:"BackendState"`
		Self         struct {
			AdvertisedRoutes []string `json:"AdvertisedRoutes"`
			ExitNodeOption   bool     `json:"ExitNodeOption"`
		} `json:"Self"`
	}
	if json.Unmarshal(out, &st) != nil || st.BackendState == "" {
		return BackendStatus{}
	}

	var lanRoutes []string
	for _, r := range st.Self.AdvertisedRoutes {
		trimmed := strings.TrimSpace(r)
		if trimmed == "" || trimmed == "0.0.0.0/0" || trimmed == "::/0" {
			continue
		}
		lanRoutes = append(lanRoutes, trimmed)
	}

	mode := ""
	hasRoutes := len(lanRoutes) > 0
	switch {
	case st.Self.ExitNodeOption && hasRoutes:
		mode = "gateway"
	case st.Self.ExitNodeOption:
		mode = "exit"
	case hasRoutes:
		mode = "router"
	}

	return BackendStatus{
		Running:      true,
		State:        st.BackendState,
		Mode:         mode,
		AcceptRoutes: QueryAcceptRoutes(qCtx, localAPI, binPath),
		LiveSubnets:  strings.Join(lanRoutes, ", "),
	}
}

// FindInstalledTailscaleBin 查找本机已安装的 tailscale CLI 可执行文件路径。
func FindInstalledTailscaleBin() string {
	for _, c := range []string{"/usr/sbin/tailscale", "/usr/bin/tailscale", "/usr/local/bin/tailscale"} {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p
	}
	return ""
}

// InspectHostStatus 聚合宿主机 Tailscale 安装状态、版本号、运行态、模式与子网配置。
func InspectHostStatus(ctx context.Context, opts HostStatusOptions) map[string]any {
	binPath := strings.TrimSpace(opts.BinPath)
	if binPath == "" {
		binPath = FindInstalledTailscaleBin()
	}

	version := ""
	if binPath != "" {
		vCtx, vCancel := context.WithTimeout(ctx, 3*time.Second)
		if out, err := exec.CommandContext(vCtx, binPath, "version").CombinedOutput(); err == nil {
			if v, err := ParseVersionOutput(string(out)); err == nil {
				version = v
			}
		}
		vCancel()
	}

	bs := QueryBackendStatus(ctx, binPath, opts.LocalAPI)
	daemonUp := bs.Running
	if !daemonUp && binPath == "" && opts.DaemonProcProbe != nil {
		daemonUp = opts.DaemonProcProbe()
	}

	subnets := cmp.Or(strings.TrimSpace(opts.ConfiguredSubnets), bs.LiveSubnets)
	return map[string]any{
		"installed":    binPath != "",
		"running":      daemonUp,
		"state":        bs.State,
		"mode":         bs.Mode,
		"acceptRoutes": bs.AcceptRoutes,
		"subnets":      subnets,
		"version":      version,
		"authKeySet":   opts.AuthKeyConfigured,
	}
}
