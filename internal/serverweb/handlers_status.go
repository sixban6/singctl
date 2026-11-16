package serverweb

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/subhub"
)

const statusCmdTimeout = 1200 * time.Millisecond

func runCommandWithTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	if timeout <= 0 {
		timeout = statusCmdTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

type serviceProbeSnapshot struct {
	running bool
	pid     string
	uptime  string
}

func probeSystemdService(unit string) serviceProbeSnapshot {
	var snap serviceProbeSnapshot
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		snap.running = checkServiceRunning(unit)
	}()
	go func() {
		defer wg.Done()
		snap.pid = getServicePID(unit)
	}()
	go func() {
		defer wg.Done()
		snap.uptime = getServiceUptime(unit)
	}()
	wg.Wait()
	return snap
}

func (s *Server) getCachedServiceVersions() (caddyVer, singboxVer, subhubVer, warpVer string) {
	s.versionCacheMu.Lock()
	if len(s.cachedVersions) > 0 && time.Since(s.cachedVersionsAt) < 60*time.Second {
		caddyVer = s.cachedVersions["caddy"]
		singboxVer = s.cachedVersions["singbox"]
		subhubVer = s.cachedVersions["subhub"]
		warpVer = s.cachedVersions["warp"]
		s.versionCacheMu.Unlock()
		return
	}
	s.versionCacheMu.Unlock()

	fetchWithTimeout := func(fn func() string) string {
		ch := make(chan string, 1)
		go func() {
			ch <- fn()
		}()
		select {
		case v := <-ch:
			return v
		case <-time.After(1500 * time.Millisecond):
			return ""
		}
	}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); caddyVer = fetchWithTimeout(deploy.GetInstalledCaddyVersion) }()
	go func() { defer wg.Done(); singboxVer = fetchWithTimeout(deploy.GetInstalledSingBoxVersion) }()
	go func() { defer wg.Done(); subhubVer = fetchWithTimeout(deploy.GetInstalledSubhubVersion) }()
	go func() { defer wg.Done(); warpVer = fetchWithTimeout(deploy.GetInstalledWarpVersion) }()
	wg.Wait()

	s.versionCacheMu.Lock()
	s.cachedVersions = map[string]string{
		"caddy":   caddyVer,
		"singbox": singboxVer,
		"subhub":  subhubVer,
		"warp":    warpVer,
	}
	s.cachedVersionsAt = time.Now()
	s.versionCacheMu.Unlock()
	return
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}

	subDomain := cfg.Server.GetSubstoreDomain()
	if subDomain == "" {
		subDomain = cfg.Server.GetNodeDomain()
	}
	adminPath := cfg.Server.GetWebAdminPath()
	httpsURL := ""
	if subDomain != "" && adminPath != "" {
		httpsURL = fmt.Sprintf("https://%s%s/", subDomain, adminPath)
	}

	var caddyProbe, singboxProbe, subhubProbe, warpProbe serviceProbeSnapshot
	var caddyVer, singboxVer, subhubVer, warpVer string
	var sysMetrics map[string]any
	var certs []CertHealth

	var wg sync.WaitGroup
	wg.Add(7)
	go func() { defer wg.Done(); caddyProbe = probeSystemdService("caddy") }()
	go func() { defer wg.Done(); singboxProbe = probeSystemdService("sing-box") }()
	go func() { defer wg.Done(); subhubProbe = probeSystemdService("singctl-sub") }()
	go func() { defer wg.Done(); warpProbe = probeSystemdService("wireproxy") }()
	go func() {
		defer wg.Done()
		caddyVer, singboxVer, subhubVer, warpVer = s.getCachedServiceVersions()
	}()
	go func() { defer wg.Done(); sysMetrics = getSystemMetrics() }()
	go func() { defer wg.Done(); certs = InspectServerCerts(cfg, false) }()
	wg.Wait()

	subhubRunning := subhubProbe.running || subhub.IsRunning()

	substoreAdminURL := ""
	sbt := deploy.NewSubstore(cfg, "")
	if adminURL, err := sbt.GetAdminURL(); err == nil && adminURL != "" {
		substoreAdminURL = adminURL
	}

	status := map[string]any{
		"version":     s.opts.Version,
		"authEnabled": s.GetPassword() != "",
		"system":      sysMetrics,
		"admin": map[string]any{
			"username": s.GetUsername(),
			"path":     adminPath,
			"httpsUrl": httpsURL,
			"port":     cfg.Server.GetWebAdminPort(),
		},
		"services": map[string]any{
			"caddy": map[string]any{
				"running": caddyProbe.running,
				"version": caddyVer,
				"pid":     caddyProbe.pid,
				"uptime":  caddyProbe.uptime,
			},
			"singbox": map[string]any{
				"running": singboxProbe.running,
				"version": singboxVer,
				"pid":     singboxProbe.pid,
				"uptime":  singboxProbe.uptime,
			},
			"subhub": map[string]any{
				"running": subhubRunning,
				"version": subhubVer,
				"pid":     subhubProbe.pid,
				"uptime":  subhubProbe.uptime,
				"engine":  "native-go",
			},
			"warp": map[string]any{
				"running":   warpProbe.running,
				"version":   warpVer,
				"pid":       warpProbe.pid,
				"socksPort": 40000,
			},
		},
		"config": map[string]any{
			"nodeDomain":       cfg.Server.GetNodeDomain(),
			"substoreDomain":   cfg.Server.GetSubstoreDomain(),
			"substoreAdminUrl": substoreAdminURL,
			"nodeTag":          cfg.Server.NodeTag,
			"sni":              cfg.Server.Sni,
			"hasCFToken":       cfg.Server.CFDNSKey != "",
		},
		"certs": certs,
	}
	if s.audit != nil {
		rawLogs := s.audit.List()
		enriched := make([]map[string]any, 0, len(rawLogs))
		for _, entry := range rawLogs {
			item := map[string]any{
				"time":     entry.Time,
				"action":   entry.Action,
				"ip":       entry.IP,
				"category": ClassifyAuditCategory(entry.Action),
			}
			if s.geo != nil {
				geo := s.geo.Resolve(entry.IP)
				item["geo"] = geo.Geo
				item["isp"] = geo.ISP
				item["country"] = geo.Country
				item["countryCode"] = geo.CountryCode
				item["flag"] = geo.Flag
			}
			enriched = append(enriched, item)
		}
		status["auditLogs"] = enriched
	}
	if s.pendingAck() && !config.IsHashedPassword(s.GetPassword()) {
		status["initialCredentials"] = map[string]any{
			"pending":  true,
			"username": s.GetUsername(),
			"password": s.GetPassword(),
		}
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败: "+err.Error())
		return
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "初始化服务端实例失败: "+err.Error())
		return
	}
	_ = sbs.LoadExistingCredentials()

	sbt := deploy.NewSubstore(cfg, "")
	adminURL, _ := sbt.GetAdminURL()

	res := map[string]any{
		"hy2": map[string]any{
			"link":     sbs.ShareLinkHy2,
			"port":     sbs.Hy2Port(),
			"protocol": "hysteria2",
			"domain":   cfg.Server.GetNodeDomain(),
		},
		"vless": map[string]any{
			"link":     sbs.ShareLinkVless,
			"port":     sbs.VlessPort(),
			"protocol": "vless",
			"sni":      cfg.Server.Sni,
		},
		"substore": map[string]any{
			"adminUrl": adminURL,
		},
	}
	writeJSON(w, http.StatusOK, res)
}

func getSystemMetrics() map[string]any {
	m := map[string]any{
		"bbr":    isBBREnabled(),
		"uptime": getSystemUptime(),
	}

	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, available uint64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				switch fields[0] {
				case "MemTotal:":
					total, _ = strconv.ParseUint(fields[1], 10, 64)
				case "MemAvailable:":
					available, _ = strconv.ParseUint(fields[1], 10, 64)
				}
			}
		}
		if total > 0 {
			used := total - available
			m["memTotalMB"] = total / 1024
			m["memUsedMB"] = used / 1024
			m["memUsagePercent"] = fmt.Sprintf("%.1f%%", float64(used)/float64(total)*100)
		}
	}

	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			m["loadAvg"] = fmt.Sprintf("%s, %s, %s", fields[0], fields[1], fields[2])
			m["load1"] = fields[0]
			m["load5"] = fields[1]
			m["load15"] = fields[2]
		}
	}

	out, err := runCommandWithTimeout(statusCmdTimeout, "df", "-h", "/")
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 5 {
				m["diskUsed"] = fields[2]
				m["diskTotal"] = fields[1]
				m["diskPercent"] = fields[4]
			}
		}
	}

	return m
}

func getSystemUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	if len(fields) > 0 {
		secs, _ := strconv.ParseFloat(fields[0], 64)
		dur := (time.Duration(secs) * time.Second).Round(time.Minute)
		return dur.String()
	}
	return ""
}

func getServicePID(name string) string {
	out, err := runCommandWithTimeout(statusCmdTimeout, "systemctl", "show", "--property", "MainPID", "--value", name)
	if err != nil {
		return ""
	}
	pid := strings.TrimSpace(string(out))
	if pid == "0" {
		return ""
	}
	return pid
}

func getServiceUptime(name string) string {
	out, err := runCommandWithTimeout(statusCmdTimeout, "systemctl", "show", "--property", "ActiveEnterTimestamp", "--value", name)
	if err != nil {
		return ""
	}
	val := strings.TrimSpace(string(out))
	if val == "" {
		return ""
	}
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", val)
	if err != nil {
		return val
	}
	return time.Since(t).Round(time.Second).String()
}

func checkServiceRunning(name string) bool {
	out, err := runCommandWithTimeout(statusCmdTimeout, "systemctl", "is-active", name)
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

func isBBREnabled() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(string(data)), "bbr")
}

func diagnoseWARP() map[string]any {
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("socks5://127.0.0.1:40000")
			},
		},
	}
	start := time.Now()
	resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return map[string]any{
			"connected": false,
			"error":     err.Error(),
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	trace := string(body)

	res := map[string]any{
		"connected": true,
		"latencyMs": latency,
		"warp":      "off",
	}
	for _, line := range strings.Split(trace, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch k {
			case "ip":
				res["ip"] = v
			case "loc":
				res["loc"] = v
			case "warp":
				res["warp"] = v
			}
		}
	}
	return res
}
