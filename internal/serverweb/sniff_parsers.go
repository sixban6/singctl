package serverweb

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ssPortProbeRule declaratively maps a local listener port and TCP socket state
// to a human-readable probe vector and defensive classification status.
type ssPortProbeRule struct {
	Port        int
	OnlyStates  []string // Optional allowed TCP states (e.g. "SYN-RECV", "TIME-WAIT"); empty matches all non-LISTEN states.
	Vector      string
	StateVector map[string]string // Optional per-state vector override.
	Status      string
}

var defaultSSPortProbeRules = []ssPortProbeRule{
	{Port: 80, Vector: "HTTP/80 端口嗅探", Status: "masqueraded"},
	{Port: 9445, Vector: "TLS/443 伪装回落嗅探", Status: "masqueraded"},
	{
		Port:   443,
		Vector: "TLS/443 伪装回落嗅探",
		StateVector: map[string]string{
			"SYN-RECV":  "TLS/443 握手探测",
			"TIME-WAIT": "TLS/443 握手探测",
		},
		Status: "masqueraded",
	},
	{Port: 22, OnlyStates: []string{"SYN-RECV", "TIME-WAIT"}, Vector: "SSH/:22 端口试探", Status: "observing"},
	{Port: 2222, OnlyStates: []string{"SYN-RECV", "TIME-WAIT"}, Vector: "SSH/:2222 端口试探", Status: "observing"},
}

type nftSetEntry struct {
	ip         string
	observedAt time.Time
}

func parseNFTDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "-") {
		return 0
	}
	const maxNFTDays = 3650
	var total time.Duration
	if before, after, hasDay := strings.Cut(s, "d"); hasDay {
		days, err := strconv.Atoi(before)
		if err != nil || days <= 0 {
			return 0
		}
		if days > maxNFTDays {
			days = maxNFTDays
		}
		total += time.Duration(days) * 24 * time.Hour
		s = after
	}
	if s != "" {
		if strings.HasPrefix(s, "-") {
			return 0
		}
		if rem, err := time.ParseDuration(s); err == nil && rem > 0 {
			if rem > maxNFTDays*24*time.Hour {
				rem = maxNFTDays * 24 * time.Hour
			}
			total += rem
		}
	}
	if total < 0 {
		return 0
	}
	return total
}

func parseNFTSetEntries(raw string, refNow time.Time) []nftSetEntry {
	idx := strings.Index(raw, "elements = {")
	if idx < 0 {
		return nil
	}
	sub := raw[idx+len("elements = {"):]
	if endIdx := strings.IndexByte(sub, '}'); endIdx >= 0 {
		sub = sub[:endIdx]
	}

	seen := make(map[string]struct{})
	out := make([]nftSetEntry, 0, 32)
	for part := range strings.SplitSeq(sub, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tok := reIPv4Token.FindString(part)
		if tok == "" {
			continue
		}
		// 跳过 CIDR 网段前缀 (如 198.51.100.0/24)，避免将网段基址误判为单点活跃 IP
		if strings.Contains(part, tok+"/") {
			continue
		}
		ip := normalizeIPString(tok)
		if ip == "" {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}

		var observedAt time.Time
		timeoutDur := 7 * 24 * time.Hour
		if tm := reNFTTimeout.FindStringSubmatch(part); len(tm) == 2 {
			if d := parseNFTDuration(tm[1]); d > 0 {
				timeoutDur = d
			}
		}
		if em := reNFTExpires.FindStringSubmatch(part); len(em) == 2 {
			if expDur := parseNFTDuration(em[1]); expDur > 0 && timeoutDur >= expDur {
				age := timeoutDur - expDur
				if age > sniffEntryTTL {
					continue
				}
				observedAt = refNow.Add(-age)
			}
		}
		out = append(out, nftSetEntry{
			ip:         ip,
			observedAt: observedAt,
		})
	}
	return out
}

type fail2banTimeInfo struct {
	first time.Time
	Last  time.Time
	hits  int
}

func harvestLocalFail2banLogTimes(refNow time.Time) map[string]fail2banTimeInfo {
	raw, err := readTailBytes("/var/log/fail2ban.log", 64*1024)
	if err != nil || len(raw) == 0 {
		return nil
	}
	return parseFail2banLogTimestamps(string(raw), refNow)
}

func parseFail2banLogTimestamps(raw string, refNow time.Time) map[string]fail2banTimeInfo {
	out := make(map[string]fail2banTimeInfo)
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) < 20 {
			continue
		}
		m := reFail2banLogIP.FindStringSubmatch(trimmed)
		if len(m) != 2 {
			continue
		}
		ip := normalizeIPString(m[1])
		if ip == "" || isIgnoredInternalIP(ip) {
			continue
		}
		ts, err := time.ParseInLocation(SniffTimeLayout, trimmed[:19], refNow.Location())
		if err != nil {
			continue
		}
		info := out[ip]
		info.hits++
		if info.first.IsZero() || ts.Before(info.first) {
			info.first = ts
		}
		if info.Last.IsZero() || ts.After(info.Last) {
			info.Last = ts
		}
		out[ip] = info
	}
	return out
}

func parseLogLineTimestamp(line string, refNow time.Time) time.Time {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) < 15 {
		return time.Time{}
	}
	// 格式 1: ISO8601 / RFC3339 (如 2026-03-30T10:15:22.123456+08:00 ...)
	if firstSpace := strings.IndexByte(trimmed, ' '); firstSpace > 18 {
		tok := trimmed[:firstSpace]
		if ts, err := time.Parse(time.RFC3339Nano, tok); err == nil {
			return ts
		}
		if ts, err := time.Parse(time.RFC3339, tok); err == nil {
			return ts
		}
	}
	// 格式 2: 传统 Syslog (如 "Mar 30 10:15:22" 或 "Mar  7 10:15:22")
	prefix := trimmed[:15]
	if ts, err := time.ParseInLocation(time.Stamp, prefix, refNow.Location()); err == nil {
		withYear := time.Date(refNow.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, refNow.Location())
		if withYear.After(refNow.Add(24 * time.Hour)) {
			withYear = withYear.AddDate(-1, 0, 0)
		}
		return withYear
	}
	return time.Time{}
}

func harvestNFTKernelLogs(ctx context.Context, t *SniffTracker) {
	var content string
	for _, logPath := range []string{"/var/log/kern.log", "/var/log/syslog", "/var/log/messages"} {
		if raw, err := readTailBytes(logPath, 64*1024); err == nil && len(raw) > 0 {
			content = string(raw)
			break
		}
	}
	if content == "" {
		if out, err := exec.CommandContext(ctx, "dmesg").Output(); err == nil && len(out) > 0 {
			if len(out) > 64*1024 {
				out = out[len(out)-64*1024:]
				if nl := bytes.IndexByte(out, '\n'); nl >= 0 {
					out = out[nl+1:]
				} else {
					out = nil
				}
			}
			content = string(out)
		}
	}
	if content == "" {
		return
	}
	ingestNFTKernelLogContent(t, "local", "本机网关", content, time.Now())
}

func ingestNFTKernelLogContent(t *SniffTracker, nodeID, nodeName, content string, refNow time.Time) {
	type nftHitAgg struct {
		hits      int
		port      string
		firstTime time.Time
		lastTime  time.Time
	}
	aggByIP := make(map[string]*nftHitAgg)
	for line := range strings.SplitSeq(content, "\n") {
		if !strings.Contains(line, "[NFT]") {
			continue
		}
		m := reNFTLogLine.FindStringSubmatch(line)
		if len(m) == 3 {
			ip := normalizeIPString(m[1])
			port := m[2]
			if ip != "" && !isIgnoredInternalIP(ip) {
				ts := parseLogLineTimestamp(line, refNow)
				agg, exists := aggByIP[ip]
				if !exists {
					agg = &nftHitAgg{
						port:      port,
						firstTime: ts,
						lastTime:  ts,
					}
					aggByIP[ip] = agg
				}
				agg.hits++
				if port != "" {
					agg.port = port
				}
				if !ts.IsZero() {
					if agg.firstTime.IsZero() || ts.Before(agg.firstTime) {
						agg.firstTime = ts
					}
					if agg.lastTime.IsZero() || ts.After(agg.lastTime) {
						agg.lastTime = ts
					}
				}
			}
		}
	}
	if len(aggByIP) == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	for ip, agg := range aggByIP {
		vec := "高危端口扫描"
		if agg.port != "" {
			vec = fmt.Sprintf("高危端口扫描 (:%s)", agg.port)
		}
		t.observeNodeAtLocked(nodeID, nodeName, ip, vec, "banned", agg.hits, true, agg.firstTime, agg.lastTime)
	}
}

func readTailBytes(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size <= 0 {
		return nil, nil
	}
	offset := int64(0)
	if size > maxBytes {
		offset = size - maxBytes
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, size-offset)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF && n == 0 {
		return nil, err
	}
	res := buf[:n]
	if offset > 0 {
		if nl := bytes.IndexByte(res, '\n'); nl >= 0 {
			res = res[nl+1:]
		} else {
			return nil, nil
		}
	}
	return res, nil
}

func parseFail2banBannedIPs(raw string) []string {
	var out []string
	seen := make(map[string]struct{})
	for line := range strings.SplitSeq(raw, "\n") {
		if !strings.Contains(line, "Banned IP list:") {
			continue
		}
		parts := strings.SplitN(line, "Banned IP list:", 2)
		if len(parts) != 2 {
			continue
		}
		for tok := range strings.FieldsSeq(parts[1]) {
			if ip := normalizeIPString(tok); ip != "" {
				if _, ok := seen[ip]; !ok {
					seen[ip] = struct{}{}
					out = append(out, ip)
				}
			}
		}
	}
	return out
}

type ssProbeItem struct {
	ip     string
	vector string
	status string
	hits   int
}

func matchSSPortProbeRule(rulesByPort map[int]ssPortProbeRule, port int, state string) (string, string, bool) {
	rule, ok := rulesByPort[port]
	if !ok {
		return "", "", false
	}
	if len(rule.OnlyStates) > 0 && !slices.Contains(rule.OnlyStates, state) {
		return "", "", false
	}
	vec := rule.Vector
	if override, hasOverride := rule.StateVector[state]; hasOverride && override != "" {
		vec = override
	}
	if vec == "" {
		return "", "", false
	}
	return vec, rule.Status, true
}

func parseSSExternalProbes(raw string) []ssProbeItem {
	return parseSSExternalProbesWithRules(raw, defaultSSPortProbeRules)
}

func parseSSExternalProbesWithRules(raw string, rules []ssPortProbeRule) []ssProbeItem {
	rulesByPort := make(map[int]ssPortProbeRule, len(rules))
	for _, r := range rules {
		rulesByPort[r.Port] = r
	}

	byIP := make(map[string]*ssProbeItem)
	for line := range strings.SplitSeq(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		state := fields[0]
		if state == "LISTEN" || state == "State" {
			continue
		}
		localPort := extractPortNumber(fields[3])
		peerIP := normalizeIPString(fields[4])
		if peerIP == "" || isIgnoredInternalIP(peerIP) {
			continue
		}

		vec, st, matched := matchSSPortProbeRule(rulesByPort, localPort, state)
		if !matched {
			continue
		}
		if existing, ok := byIP[peerIP]; ok {
			existing.hits++
		} else {
			byIP[peerIP] = &ssProbeItem{
				ip:     peerIP,
				vector: vec,
				status: st,
				hits:   1,
			}
		}
	}
	out := make([]ssProbeItem, 0, len(byIP))
	for _, v := range byIP {
		out = append(out, *v)
	}
	return out
}

func extractPortNumber(addr string) int {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 || idx+1 >= len(addr) {
		return 0
	}
	p, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return 0
	}
	return p
}
