package serverweb

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/component"
	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/subhub"
	"singctl/internal/telemetry"
)

const (
	statusCmdTimeout        = 1200 * time.Millisecond
	statusSelectMaxWait     = 600 * time.Millisecond
	configSelectMaxWait     = 150 * time.Millisecond
	configCacheTTL          = 5 * time.Second
	serviceProbeCacheTTL    = 5 * time.Second
	serviceVersionCacheTTL  = 5 * time.Minute
	certProbeCacheTTL       = 3 * time.Minute
	rootDiskMetricsCacheTTL = 15 * time.Second
)

func runCommandWithTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	if timeout <= 0 {
		timeout = statusCmdTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func probeLoopbackTCP(addr string, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func probeServicesByLoopbackPorts() map[string]serviceProbeSnapshot {
	return map[string]serviceProbeSnapshot{
		"caddy":       {running: probeLoopbackTCP("127.0.0.1:443", 80*time.Millisecond)},
		"sing-box":    {running: probeLoopbackTCP(telemetry.DefaultControllerAddr, 80*time.Millisecond)},
		"singctl-sub": {running: probeLoopbackTCP(subhub.DefaultListenAddr, 80*time.Millisecond)},
		"wireproxy":   {running: probeLoopbackTCP("127.0.0.1:40000", 80*time.Millisecond)},
	}
}

func (s *Server) resolveSubstoreAdminURLFast(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	sbt := deploy.NewSubstore(cfg, "")
	if adminURL, err := sbt.GetAdminURL(); err == nil {
		return adminURL
	}
	return ""
}

// loadConfigBounded 以单飞 + 硬超时读取最新配置；当底层磁盘发生 D 状态假死时立即回退不可变快照，绝不卡死请求或巡检。
func (s *Server) loadConfigBounded(maxWait time.Duration) (*config.Config, error) {
	var fallbackCfg *config.Config
	if s.cfgStore != nil && s.cfgStore.Revision() > 0 {
		fallbackCfg = s.cfgStore.Get()
	}

	if strings.TrimSpace(s.opts.ConfigPath) == "" {
		if fallbackCfg != nil {
			return fallbackCfg, nil
		}
		return &config.Config{}, nil
	}
	if maxWait <= 0 {
		maxWait = configSelectMaxWait
	}

	if !s.configRefreshRunning.CompareAndSwap(false, true) {
		if fallbackCfg != nil {
			return fallbackCfg, nil
		}
		return &config.Config{}, os.ErrDeadlineExceeded
	}

	type cfgRes struct {
		cfg *config.Config
		err error
	}
	doneCh := make(chan cfgRes, 1)
	loader := func(p string) (*config.Config, error) {
		if s.configLoaderOverride != nil {
			return s.configLoaderOverride(p)
		}
		if s.cfgStore != nil {
			return s.cfgStore.LoadLatest()
		}
		return config.Load(p)
	}
	cfgPath := s.opts.ConfigPath
	go func() {
		defer s.configRefreshRunning.Store(false)
		loaded, err := loader(cfgPath)
		if err == nil && loaded != nil {
			s.updateConfigCache(loaded)
		}
		doneCh <- cfgRes{cfg: loaded, err: err}
	}()

	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	select {
	case res := <-doneCh:
		if res.err == nil && res.cfg != nil {
			return res.cfg, nil
		}
		if fallbackCfg != nil {
			return fallbackCfg, nil
		}
		return &config.Config{}, res.err
	case <-timer.C:
		if fallbackCfg != nil {
			return fallbackCfg, nil
		}
		return &config.Config{}, os.ErrDeadlineExceeded
	}
}

func (s *Server) getConfigSnapshot(maxWait time.Duration) (*config.Config, string) {
	s.configCacheMu.RLock()
	cacheFresh := !s.cachedConfigAt.IsZero() && time.Since(s.cachedConfigAt) < configCacheTTL
	subURL := s.cachedSubAdminURL
	s.configCacheMu.RUnlock()
	if cacheFresh && s.cfgStore != nil && s.cfgStore.Revision() > 0 {
		return s.cfgStore.Get(), subURL
	}

	cfg, _ := s.loadConfigBounded(maxWait)
	if cfg == nil {
		cfg = &config.Config{}
	}
	s.configCacheMu.RLock()
	subURL = s.cachedSubAdminURL
	s.configCacheMu.RUnlock()
	if subURL == "" {
		subURL = s.resolveSubstoreAdminURLFast(cfg)
	}
	return cfg, subURL
}

type serviceProbeSnapshot struct {
	running bool
	pid     string
	uptime  string
}

func formatServiceUptime(val string) string {
	val = strings.TrimSpace(val)
	if val == "" || val == "n/a" {
		return ""
	}
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", val)
	if err != nil {
		return val
	}
	return time.Since(t).Round(time.Second).String()
}

func parseSystemdShowBatchOutput(raw string) map[string]serviceProbeSnapshot {
	out := make(map[string]serviceProbeSnapshot)
	var curUnit string
	var curSnap serviceProbeSnapshot

	flush := func() {
		if curUnit != "" {
			out[curUnit] = curSnap
		}
		curUnit = ""
		curSnap = serviceProbeSnapshot{}
	}

	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "Id":
			curUnit = strings.TrimSuffix(v, ".service")
		case "ActiveState":
			curSnap.running = v == "active"
		case "MainPID":
			if v != "" && v != "0" {
				curSnap.pid = v
			}
		case "ActiveEnterTimestamp":
			curSnap.uptime = formatServiceUptime(v)
		}
	}
	flush()
	return out
}

func probeSystemdServicesBatch(units ...string) map[string]serviceProbeSnapshot {
	args := []string{"show", "--property=Id,ActiveState,MainPID,ActiveEnterTimestamp"}
	args = append(args, units...)
	out, err := runCommandWithTimeout(statusCmdTimeout, "systemctl", args...)
	if err != nil && len(out) == 0 {
		return map[string]serviceProbeSnapshot{}
	}
	return parseSystemdShowBatchOutput(string(out))
}

func (s *Server) getCachedServiceProbes() map[string]serviceProbeSnapshot {
	s.serviceProbeMu.Lock()
	if s.cachedServiceProbes != nil && time.Since(s.cachedServiceProbesAt) < serviceProbeCacheTTL {
		cached := maps.Clone(s.cachedServiceProbes)
		s.serviceProbeMu.Unlock()
		return cached
	}
	fallback := maps.Clone(s.cachedServiceProbes)
	s.serviceProbeMu.Unlock()

	if !s.serviceProbeRunning.CompareAndSwap(false, true) {
		if len(fallback) > 0 {
			return fallback
		}
		return probeServicesByLoopbackPorts()
	}

	doneCh := make(chan map[string]serviceProbeSnapshot, 1)
	prober := s.statusProberOverride
	go func() {
		defer s.serviceProbeRunning.Store(false)
		var probes map[string]serviceProbeSnapshot
		if prober != nil {
			probes = prober()
		} else {
			probes = probeSystemdServicesBatch("caddy", "sing-box", "singctl-sub", "wireproxy")
		}
		if len(probes) > 0 {
			s.serviceProbeMu.Lock()
			s.cachedServiceProbes = maps.Clone(probes)
			s.cachedServiceProbesAt = time.Now()
			s.serviceProbeMu.Unlock()
		}
		doneCh <- probes
	}()

	timer := time.NewTimer(statusSelectMaxWait)
	defer timer.Stop()
	select {
	case probes := <-doneCh:
		if len(probes) > 0 {
			return probes
		}
		if len(fallback) > 0 {
			return fallback
		}
		return probeServicesByLoopbackPorts()
	case <-timer.C:
		if len(fallback) > 0 {
			return fallback
		}
		return probeServicesByLoopbackPorts()
	}
}

func (s *Server) getCachedServiceVersions() (caddyVer, singboxVer, subhubVer, warpVer string) {
	s.versionCacheMu.Lock()
	if len(s.cachedVersions) > 0 && time.Since(s.cachedVersionsAt) < serviceVersionCacheTTL {
		caddyVer = s.cachedVersions["caddy"]
		singboxVer = s.cachedVersions["singbox"]
		subhubVer = s.cachedVersions["subhub"]
		warpVer = s.cachedVersions["warp"]
		s.versionCacheMu.Unlock()
		return
	}
	fallback := maps.Clone(s.cachedVersions)
	s.versionCacheMu.Unlock()

	applyMap := func(m map[string]string) (string, string, string, string) {
		return m["caddy"], m["singbox"], m["subhub"], m["warp"]
	}

	if !s.versionProbeRunning.CompareAndSwap(false, true) {
		return applyMap(fallback)
	}

	doneCh := make(chan map[string]string, 1)
	go func() {
		defer s.versionProbeRunning.Store(false)
		fetchWithTimeout := func(fn func() string) string {
			ch := make(chan string, 1)
			go func() {
				ch <- fn()
			}()
			t := time.NewTimer(1500 * time.Millisecond)
			defer t.Stop()
			select {
			case v := <-ch:
				return v
			case <-t.C:
				return ""
			}
		}

		type verEntry struct {
			id  string
			ver string
		}
		var targets []component.Component
		for _, comp := range deploy.ServerRegistry().All() {
			if _, ok := comp.(component.Versioned); ok {
				targets = append(targets, comp)
			}
		}

		resCh := make(chan verEntry, len(targets))
		var wg sync.WaitGroup
		for _, comp := range targets {
			verComp := comp.(component.Versioned)
			id := comp.ID()
			wg.Add(1)
			go func() {
				defer wg.Done()
				resCh <- verEntry{id: id, ver: fetchWithTimeout(verComp.InstalledVersion)}
			}()
		}
		wg.Wait()
		close(resCh)

		res := make(map[string]string, len(targets))
		for entry := range resCh {
			res[entry.id] = cmp.Or(entry.ver, fallback[entry.id])
		}
		s.versionCacheMu.Lock()
		s.cachedVersions = maps.Clone(res)
		s.cachedVersionsAt = time.Now()
		s.versionCacheMu.Unlock()
		doneCh <- res
	}()

	timer := time.NewTimer(statusSelectMaxWait)
	defer timer.Stop()
	select {
	case res := <-doneCh:
		return applyMap(res)
	case <-timer.C:
		return applyMap(fallback)
	}
}

func (s *Server) getCachedCerts(cfg *config.Config) []CertHealth {
	s.certProbeMu.Lock()
	if s.cachedCerts != nil && time.Since(s.cachedCertsAt) < certProbeCacheTTL {
		cached := slices.Clone(s.cachedCerts)
		s.certProbeMu.Unlock()
		return cached
	}
	fallback := slices.Clone(s.cachedCerts)
	s.certProbeMu.Unlock()

	if !s.certProbeRunning.CompareAndSwap(false, true) {
		if fallback != nil {
			return fallback
		}
		return []CertHealth{}
	}

	doneCh := make(chan []CertHealth, 1)
	go func() {
		defer s.certProbeRunning.Store(false)
		certs := InspectServerCerts(cfg, false)
		s.certProbeMu.Lock()
		s.cachedCerts = slices.Clone(certs)
		s.cachedCertsAt = time.Now()
		s.certProbeMu.Unlock()
		doneCh <- certs
	}()

	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case certs := <-doneCh:
		return certs
	case <-timer.C:
		if fallback != nil {
			return fallback
		}
		return []CertHealth{}
	}
}

func (s *Server) getCachedRootDiskUsage() (used, total, pct string, ok bool) {
	s.diskMetricsMu.Lock()
	if !s.cachedDiskAt.IsZero() && time.Since(s.cachedDiskAt) < rootDiskMetricsCacheTTL {
		used, total, pct, ok = s.cachedDiskUsed, s.cachedDiskTotal, s.cachedDiskPercent, s.cachedDiskOK
		s.diskMetricsMu.Unlock()
		return
	}
	fbUsed, fbTotal, fbPct, fbOK := s.cachedDiskUsed, s.cachedDiskTotal, s.cachedDiskPercent, s.cachedDiskOK
	s.diskMetricsMu.Unlock()

	if !s.diskProbeRunning.CompareAndSwap(false, true) {
		return fbUsed, fbTotal, fbPct, fbOK
	}

	type diskSnap struct {
		u, t, p string
		ok      bool
	}
	doneCh := make(chan diskSnap, 1)
	go func() {
		defer s.diskProbeRunning.Store(false)
		u, t, p, okVal := getRootDiskUsage()
		if okVal {
			s.diskMetricsMu.Lock()
			s.cachedDiskUsed = u
			s.cachedDiskTotal = t
			s.cachedDiskPercent = p
			s.cachedDiskOK = true
			s.cachedDiskAt = time.Now()
			s.diskMetricsMu.Unlock()
		}
		doneCh <- diskSnap{u: u, t: t, p: p, ok: okVal}
	}()

	timer := time.NewTimer(configSelectMaxWait)
	defer timer.Stop()
	select {
	case d := <-doneCh:
		if d.ok {
			return d.u, d.t, d.p, true
		}
		return fbUsed, fbTotal, fbPct, fbOK
	case <-timer.C:
		return fbUsed, fbTotal, fbPct, fbOK
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg, substoreAdminURL := s.getConfigSnapshot(configSelectMaxWait)

	subDomain := cfg.Server.GetSubstoreDomain()
	if subDomain == "" {
		subDomain = cfg.Server.GetNodeDomain()
	}
	adminPath := cfg.Server.GetWebAdminPath()
	httpsURL := ""
	if subDomain != "" && adminPath != "" {
		httpsURL = fmt.Sprintf("https://%s%s/", subDomain, adminPath)
	}

	var probes map[string]serviceProbeSnapshot
	var caddyVer, singboxVer, subhubVer, warpVer string
	var sysMetrics map[string]any
	var certs []CertHealth

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); probes = s.getCachedServiceProbes() }()
	go func() {
		defer wg.Done()
		caddyVer, singboxVer, subhubVer, warpVer = s.getCachedServiceVersions()
	}()
	go func() { defer wg.Done(); sysMetrics = s.getSystemMetricsBounded() }()
	go func() { defer wg.Done(); certs = s.getCachedCerts(cfg) }()
	wg.Wait()

	caddyProbe := probes["caddy"]
	singboxProbe := probes["sing-box"]
	subhubProbe := probes["singctl-sub"]
	warpProbe := probes["wireproxy"]

	subhubRunning := subhubProbe.running || probeLoopbackTCP(subhub.DefaultListenAddr, 80*time.Millisecond)

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

func (s *Server) getSystemMetricsBounded() map[string]any {
	m := readProcSystemMetrics()
	if used, total, pct, ok := s.getCachedRootDiskUsage(); ok {
		m["diskUsed"] = used
		m["diskTotal"] = total
		m["diskPercent"] = pct
	}
	return m
}

func readProcSystemMetrics() map[string]any {
	m := map[string]any{
		"bbr":    isBBREnabled(),
		"uptime": getSystemUptime(),
	}

	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, available uint64
		for line := range strings.SplitSeq(string(data), "\n") {
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
