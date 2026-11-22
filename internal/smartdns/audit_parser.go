// 文件职责：负责 SmartDNS tmpfs 审计日志单行解析与并发安全增量轮转追踪读取。
package smartdns

import (
	"cmp"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxAuditReadBytes    = 2 * 1024 * 1024
	maxAuditPartialBytes = 8 * 1024
)

var dnsTypeNames = map[int]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	64:  "SVCB",
	65:  "HTTPS",
	255: "ANY",
}

// AuditEntry 表示从 SmartDNS 审计日志解析出的单条查询记录。
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Domain    string    `json:"domain"`
	QueryType string    `json:"queryType"`
	LatencyMs float64   `json:"latencyMs"`
	Blocked   bool      `json:"blocked"`
}

// AuditLogTailer 并发安全地增量追踪 SmartDNS tmpfs 审计日志并自动处理 128k 轮转截断。
type AuditLogTailer struct {
	mu       sync.Mutex
	path     string
	offset   int64
	lastSize int64
	lastInfo os.FileInfo
	partial  string
}

// NewAuditLogTailer 创建指向指定审计日志路径的增量追踪器（路径为空时默认使用 DefaultAuditLogPath）。
func NewAuditLogTailer(path string) *AuditLogTailer {
	return &AuditLogTailer{
		path: cmp.Or(strings.TrimSpace(path), DefaultAuditLogPath),
	}
}

// Reset 重置读取偏移与半行缓冲以从头重新解析。
func (t *AuditLogTailer) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.offset = 0
	t.lastSize = 0
	t.lastInfo = nil
	t.partial = ""
}

// Offset 返回当前已消费的文件字节偏移量。
func (t *AuditLogTailer) Offset() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.offset
}

// ReadNew 增量读取自上次偏移之后的新增审计记录（自动适配文件缺失、截断与 inode 轮转重建）。
func (t *AuditLogTailer) ReadNew() ([]AuditEntry, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	f, err := os.Open(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			t.offset = 0
			t.lastSize = 0
			t.lastInfo = nil
			t.partial = ""
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	// 检测轮转（新 inode）或原地截断（文件变小）
	if (t.lastInfo != nil && !os.SameFile(t.lastInfo, info)) || info.Size() < t.offset {
		t.offset = 0
		t.partial = ""
	}
	if info.Size() == t.offset {
		t.lastSize = info.Size()
		t.lastInfo = info
		return nil, nil
	}

	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return nil, err
	}
	chunk, err := io.ReadAll(io.LimitReader(f, maxAuditReadBytes))
	if err != nil {
		return nil, err
	}
	t.offset += int64(len(chunk))
	t.lastSize = info.Size()
	t.lastInfo = info

	if len(chunk) == 0 {
		return nil, nil
	}

	combined := t.partial + string(chunk)
	t.partial = ""

	lastNL := strings.LastIndexByte(combined, '\n')
	if lastNL < 0 {
		if len(combined) <= maxAuditPartialBytes {
			t.partial = combined
		}
		return nil, nil
	}
	if lastNL+1 < len(combined) {
		rem := combined[lastNL+1:]
		if len(rem) <= maxAuditPartialBytes {
			t.partial = rem
		}
	}

	var entries []AuditEntry
	for line := range strings.SplitSeq(combined[:lastNL], "\n") {
		if entry, ok := ParseAuditLine(line); ok {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// ParseAuditLine 解析单行 SmartDNS 审计日志，兼容经典 query 格式与 dns_server.c/group/result 变体。
func ParseAuditLine(line string) (AuditEntry, bool) {
	s := strings.TrimSpace(line)
	if s == "" || !strings.HasPrefix(s, "[") {
		return AuditEntry{}, false
	}

	endBracket := strings.IndexByte(s, ']')
	if endBracket <= 1 {
		return AuditEntry{}, false
	}
	ts, ok := parseAuditTimestamp(s[1:endBracket])
	if !ok {
		return AuditEntry{}, false
	}

	rest := strings.TrimSpace(s[endBracket+1:])
	// 跳过可选的 `[ INFO][ dns_server.c:2390]` 头部标签块
	for strings.HasPrefix(rest, "[") {
		idx := strings.IndexByte(rest, ']')
		if idx < 0 {
			break
		}
		rest = strings.TrimSpace(rest[idx+1:])
	}

	// 格式 A: `<client> query <domain>, type <t>, time <ms>, [speed: <ms>,] [group <g>,] result <ans>`
	if _, afterQuery, hasQuery := strings.Cut(rest, " query "); hasQuery {
		return parseClassicQueryAudit(ts, afterQuery)
	}
	if afterQuery, hasPrefix := strings.CutPrefix(rest, "query "); hasPrefix {
		return parseClassicQueryAudit(ts, afterQuery)
	}

	// 格式 B: `result: <domain>, client: ..., qtype: <t>, ..., time: <ms>[, ...]`
	if afterResult, hasPrefix := strings.CutPrefix(rest, "result:"); hasPrefix {
		return parseColonResultAudit(ts, afterResult)
	}

	return AuditEntry{}, false
}

func parseClassicQueryAudit(ts time.Time, body string) (AuditEntry, bool) {
	domainPart, remainder, hasComma := strings.Cut(body, ",")
	domain := normalizeAuditDomain(domainPart)
	if domain == "" {
		return AuditEntry{}, false
	}

	entry := AuditEntry{
		Timestamp: ts,
		Domain:    domain,
		QueryType: "A",
	}
	if !hasComma {
		return entry, true
	}

	var (
		hasTime        bool
		speedFallback  float64
		hasSpeed       bool
		hasResultField bool
		resultValue    string
	)

	// result 字段内部可能包含多个逗号分隔 IP（如 `result 2001:db8::1, 2001:db8::2`），
	// 先截取出 result 字段，再按逗号解析前置键值对。
	beforeResult := remainder
	if idx := findResultFieldIndex(remainder); idx >= 0 {
		beforeResult = remainder[:idx]
		rawRes := strings.TrimSpace(remainder[idx:])
		rawRes = strings.TrimPrefix(rawRes, "result:")
		rawRes = strings.TrimPrefix(rawRes, "result")
		resultValue = strings.TrimSpace(rawRes)
		hasResultField = true
	}

	for seg := range strings.SplitSeq(beforeResult, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		k, v := splitAuditKeyValue(seg)
		switch k {
		case "type", "qtype":
			entry.QueryType = normalizeQueryType(v)
		case "time":
			if ms, ok := parseDurationMs(v); ok {
				entry.LatencyMs = ms
				hasTime = true
			}
		case "speed":
			if ms, ok := parseDurationMs(v); ok {
				speedFallback = ms
				hasSpeed = true
			}
		}
	}

	if !hasTime && hasSpeed {
		entry.LatencyMs = speedFallback
	}
	if hasResultField {
		entry.Blocked = classifyAuditBlocked(resultValue, entry.QueryType, entry.LatencyMs, hasTime)
	}
	return entry, true
}

func parseColonResultAudit(ts time.Time, body string) (AuditEntry, bool) {
	domainPart, remainder, _ := strings.Cut(body, ",")
	domain := normalizeAuditDomain(domainPart)
	if domain == "" {
		return AuditEntry{}, false
	}
	entry := AuditEntry{
		Timestamp: ts,
		Domain:    domain,
		QueryType: "A",
	}
	var (
		hasTime        bool
		hasResultField bool
		resultValue    string
	)
	for seg := range strings.SplitSeq(remainder, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		k, v := splitAuditKeyValue(seg)
		switch k {
		case "type", "qtype":
			entry.QueryType = normalizeQueryType(v)
		case "time":
			if ms, ok := parseDurationMs(v); ok {
				entry.LatencyMs = ms
				hasTime = true
			}
		case "answer", "result":
			resultValue = v
			hasResultField = true
		}
	}
	if hasResultField {
		entry.Blocked = classifyAuditBlocked(resultValue, entry.QueryType, entry.LatencyMs, hasTime)
	}
	return entry, true
}

func findResultFieldIndex(s string) int {
	lower := strings.ToLower(s)
	for _, token := range []string{", result:", ", result ", ", result"} {
		if idx := strings.Index(lower, token); idx >= 0 {
			return idx + 2 // skip ", "
		}
	}
	trimmed := strings.TrimSpace(lower)
	if strings.HasPrefix(trimmed, "result:") || strings.HasPrefix(trimmed, "result ") || trimmed == "result" {
		return strings.Index(lower, "result")
	}
	return -1
}

func splitAuditKeyValue(seg string) (string, string) {
	if k, v, ok := strings.Cut(seg, ":"); ok {
		return strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
	}
	if k, v, ok := strings.Cut(seg, " "); ok {
		return strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
	}
	return strings.ToLower(strings.TrimSpace(seg)), ""
}

func parseAuditTimestamp(raw string) (time.Time, bool) {
	norm := strings.ReplaceAll(strings.TrimSpace(raw), ",", ".")
	for _, layout := range []string{
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05.000000",
		"2006-01-02 15:04:05",
	} {
		if ts, err := time.ParseInLocation(layout, norm, time.Local); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

func normalizeAuditDomain(raw string) string {
	d := strings.TrimSpace(raw)
	d = strings.TrimSuffix(strings.ToLower(d), ".")
	if d == "" || strings.ContainsAny(d, " \t\r\n") {
		return ""
	}
	return d
}

func normalizeQueryType(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "A"
	}
	if n, err := strconv.Atoi(v); err == nil {
		if name, ok := dnsTypeNames[n]; ok {
			return name
		}
		return "TYPE" + strconv.Itoa(n)
	}
	return strings.ToUpper(v)
}

func parseDurationMs(raw string) (float64, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	v = strings.TrimSuffix(v, "ms")
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		return 0, false
	}
	return f, true
}

// localInstantBlockMaxMs 区分本地规则瞬时拦截 (0-2ms) 与真实上游 NODATA/NXDOMAIN/超时 (>2ms)。
const localInstantBlockMaxMs = 2.0

func classifyAuditBlocked(raw, queryType string, latencyMs float64, hasTime bool) bool {
	trimmed := strings.TrimSpace(raw)
	isLocalInstant := !hasTime || latencyMs <= localInstantBlockMaxMs
	if trimmed == "" {
		return queryType != "AAAA" && isLocalInstant
	}

	hasValidAnswer := false
	hasExplicitBlock := false
	hasSOALike := false

	for token := range strings.SplitSeq(trimmed, ",") {
		tok := strings.TrimSpace(token)
		if tok == "" {
			continue
		}
		upper := strings.ToUpper(tok)
		switch {
		case upper == "SERVFAIL":
			return false
		case upper == "NXDOMAIN", upper == "REFUSED":
			hasExplicitBlock = true
			continue
		case upper == "SOA", strings.HasPrefix(upper, "SOA "), upper == "NONE", upper == "-":
			hasSOALike = true
			continue
		}
		if ip := net.ParseIP(tok); ip != nil {
			if ip.IsUnspecified() {
				hasExplicitBlock = true
				continue
			}
			hasValidAnswer = true
			continue
		}
		// 非零 IP 且非拦截状态码（例如合法 CNAME 目标）视为正常解析放行。
		hasValidAnswer = true
	}

	if hasValidAnswer {
		return false
	}
	if hasExplicitBlock {
		return true
	}
	if hasSOALike {
		// IPv4-only 站点、内网 A 重写与 force-AAAA-SOA 均会对 AAAA 返回 soa，绝不能误计为广告拦截；
		// 仅将非 AAAA 查询的本地瞬时 SOA（0-2ms）判定为 address /domain/# 拦截。
		return queryType != "AAAA" && isLocalInstant
	}
	return false
}
