// 文件职责：负责多源嗅探日志纯函数解析（nftables 集合、内核日志、fail2ban、ss 实时探测套接字）与防撕裂尾部文件读取。
package sniff

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

// SSPortProbeRule 声明式映射本地监听端口和 TCP 套接字状态到探测向量与防御状态。
type SSPortProbeRule struct {
	Port        int
	OnlyStates  []string
	Vector      string
	StateVector map[string]string
	Status      string
}

var defaultSSPortProbeRules = []SSPortProbeRule{
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

// DefaultSSPortProbeRules 返回默认端口嗅探分类规则表副本。
func DefaultSSPortProbeRules() []SSPortProbeRule {
	return slices.Clone(defaultSSPortProbeRules)
}

type SSProbeItem struct {
	IP     string
	Vector string
	Status string
	Hits   int
}

type NFTSetEntry struct {
	IP         string
	ObservedAt time.Time
}

type Fail2banTimeInfo struct {
	First time.Time
	Last  time.Time
	Hits  int
}

// ParseNFTDuration 解析 nftables 的 timeout/expires 文本（如 6d23h59m），带负数与溢出护栏。
func ParseNFTDuration(s string) time.Duration {
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
		days = min(days, maxNFTDays)
		total += time.Duration(days) * 24 * time.Hour
		s = after
	}
	if s != "" {
		if strings.HasPrefix(s, "-") {
			return 0
		}
		if rem, err := time.ParseDuration(s); err == nil && rem > 0 {
			total += min(rem, maxNFTDays*24*time.Hour)
		}
	}
	if total < 0 {
		return 0
	}
	return total
}

// ParseNFTSetEntries 解析 `nft list set` 输出中的活跃单点 IP 与反推首次封禁时间。
func ParseNFTSetEntries(raw string, refNow time.Time) []NFTSetEntry {
	idx := strings.Index(raw, "elements = {")
	if idx < 0 {
		return nil
	}
	sub := raw[idx+len("elements = {"):]
	if endIdx := strings.IndexByte(sub, '}'); endIdx >= 0 {
		sub = sub[:endIdx]
	}

	seen := make(map[string]struct{})
	out := make([]NFTSetEntry, 0, 32)
	for part := range strings.SplitSeq(sub, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tok := reIPv4Token.FindString(part)
		if tok == "" || strings.Contains(part, tok+"/") {
			continue
		}
		ip := NormalizeIPString(tok)
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
			if d := ParseNFTDuration(tm[1]); d > 0 {
				timeoutDur = d
			}
		}
		if em := reNFTExpires.FindStringSubmatch(part); len(em) == 2 {
			if expDur := ParseNFTDuration(em[1]); expDur > 0 && timeoutDur >= expDur {
				age := timeoutDur - expDur
				if age > sniffEntryTTL {
					continue
				}
				observedAt = refNow.Add(-age)
			}
		}
		out = append(out, NFTSetEntry{IP: ip, ObservedAt: observedAt})
	}
	return out
}

func harvestLocalFail2banLogTimes(refNow time.Time) map[string]Fail2banTimeInfo {
	raw, err := ReadTailBytes("/var/log/fail2ban.log", 64*1024)
	if err != nil || len(raw) == 0 {
		return nil
	}
	return ParseFail2banLogTimestamps(string(raw), refNow)
}

// ParseFail2banLogTimestamps 提取 fail2ban 日志中的 Found/Ban 时间范围与命中次数。
func ParseFail2banLogTimestamps(raw string, refNow time.Time) map[string]Fail2banTimeInfo {
	out := make(map[string]Fail2banTimeInfo)
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) < 20 {
			continue
		}
		m := reFail2banLogIP.FindStringSubmatch(trimmed)
		if len(m) != 2 {
			continue
		}
		ip := NormalizeIPString(m[1])
		if ip == "" || IsIgnoredInternalIP(ip) {
			continue
		}
		ts, err := time.ParseInLocation(TimeLayout, trimmed[:19], refNow.Location())
		if err != nil {
			continue
		}
		info := out[ip]
		info.Hits++
		if info.First.IsZero() || ts.Before(info.First) {
			info.First = ts
		}
		if info.Last.IsZero() || ts.After(info.Last) {
			info.Last = ts
		}
		out[ip] = info
	}
	return out
}

// ParseLogLineTimestamp 解析内核/系统日志首部的 RFC3339 或传统 Syslog 时间戳。
func ParseLogLineTimestamp(line string, refNow time.Time) time.Time {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) < 15 {
		return time.Time{}
	}
	if firstSpace := strings.IndexByte(trimmed, ' '); firstSpace > 18 {
		tok := trimmed[:firstSpace]
		if ts, err := time.Parse(time.RFC3339Nano, tok); err == nil {
			return ts
		}
		if ts, err := time.Parse(time.RFC3339, tok); err == nil {
			return ts
		}
	}
	ts, err := time.ParseInLocation(time.Stamp, trimmed[:15], refNow.Location())
	if err != nil {
		return time.Time{}
	}
	withYear := time.Date(refNow.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, refNow.Location())
	if withYear.After(refNow.Add(24 * time.Hour)) {
		withYear = withYear.AddDate(-1, 0, 0)
	}
	return withYear
}

func harvestNFTKernelLogs(ctx context.Context, t *Tracker) {
	var content string
	for _, logPath := range []string{"/var/log/kern.log", "/var/log/syslog", "/var/log/messages"} {
		if raw, err := ReadTailBytes(logPath, 64*1024); err == nil && len(raw) > 0 {
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
	if content != "" {
		ingestNFTKernelLogContent(t, "local", "本机网关", content, time.Now())
	}
}

func ingestNFTKernelLogContent(t *Tracker, nodeID, nodeName, content string, refNow time.Time) {
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
		if len(m) != 3 {
			continue
		}
		ip := NormalizeIPString(m[1])
		if ip == "" || IsIgnoredInternalIP(ip) {
			continue
		}
		ts := ParseLogLineTimestamp(line, refNow)
		agg, exists := aggByIP[ip]
		if !exists {
			agg = &nftHitAgg{port: m[2], firstTime: ts, lastTime: ts}
			aggByIP[ip] = agg
		}
		agg.hits++
		if m[2] != "" {
			agg.port = m[2]
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

// ReadTailBytes 从文件末尾读取最多 maxBytes 字节，并丢弃截断产生的首行残片。
func ReadTailBytes(path string, maxBytes int64) ([]byte, error) {
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
	var offset int64
	if size > maxBytes {
		offset = size - maxBytes
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
		nl := bytes.IndexByte(res, '\n')
		if nl < 0 {
			return nil, nil
		}
		res = res[nl+1:]
	}
	return res, nil
}

// ParseFail2banBannedIPs 提取 `fail2ban-client status <jail>` 中的封禁 IP 列表。
func ParseFail2banBannedIPs(raw string) []string {
	var out []string
	seen := make(map[string]struct{})
	for line := range strings.SplitSeq(raw, "\n") {
		_, rest, found := strings.Cut(line, "Banned IP list:")
		if !found {
			continue
		}
		for tok := range strings.FieldsSeq(rest) {
			ip := NormalizeIPString(tok)
			if ip == "" {
				continue
			}
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				out = append(out, ip)
			}
		}
	}
	return out
}

func matchSSPortProbeRule(rulesByPort map[int]SSPortProbeRule, port int, state string) (string, string, bool) {
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

// ParseSSExternalProbes 使用默认端口规则表提取 `ss -tan` 中的外部探测套接字。
func ParseSSExternalProbes(raw string) []SSProbeItem {
	return ParseSSExternalProbesWithRules(raw, defaultSSPortProbeRules)
}

// ParseSSExternalProbesWithRules 按声明式端口规则表提取外部嗅探与试探连接。
func ParseSSExternalProbesWithRules(raw string, rules []SSPortProbeRule) []SSProbeItem {
	rulesByPort := make(map[int]SSPortProbeRule, len(rules))
	for _, r := range rules {
		rulesByPort[r.Port] = r
	}

	byIP := make(map[string]*SSProbeItem)
	for line := range strings.SplitSeq(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] == "LISTEN" || fields[0] == "State" {
			continue
		}
		localPort := extractPortNumber(fields[3])
		peerIP := NormalizeIPString(fields[4])
		if peerIP == "" || IsIgnoredInternalIP(peerIP) {
			continue
		}
		vec, st, matched := matchSSPortProbeRule(rulesByPort, localPort, fields[0])
		if !matched {
			continue
		}
		if existing, ok := byIP[peerIP]; ok {
			existing.Hits++
		} else {
			byIP[peerIP] = &SSProbeItem{IP: peerIP, Vector: vec, Status: st, Hits: 1}
		}
	}
	out := make([]SSProbeItem, 0, len(byIP))
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
