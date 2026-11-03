package subhub

import (
	"cmp"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	accessAuditFileName = ".access_audit.json"
	maxAccessAuditLogs  = 100
)

// AccessLogEntry records a single client subscription pull or unauthorized key probe.
type AccessLogEntry struct {
	Timestamp   string `json:"timestamp"`
	IP          string `json:"ip"`
	CountryCode string `json:"countryCode,omitempty"`
	Geo         string `json:"geo,omitempty"`
	Flag        string `json:"flag,omitempty"`
	ClientApp   string `json:"clientApp"`
	UserAgent   string `json:"userAgent,omitempty"`
	Target      string `json:"target"`
	Collection  string `json:"collection,omitempty"`
	NodeCount   int    `json:"nodeCount"`
	Status      string `json:"status"` // "ok" | "denied"
}

func (s *Store) accessAuditPath() string {
	return filepath.Join(s.DataDir, accessAuditFileName)
}

// RecordAccess appends a subscription access event to the bounded audit log on disk.
func (s *Store) RecordAccess(entry AccessLogEntry) {
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().Format(time.RFC3339)
	}
	if len(entry.UserAgent) > 96 {
		entry.UserAgent = entry.UserAgent[:96]
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.accessAuditPath()
	var list []AccessLogEntry
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &list)
	}

	// Prepend newest first
	list = slices.Insert(list, 0, entry)
	if len(list) > maxAccessAuditLogs {
		list = list[:maxAccessAuditLogs]
	}

	if err := os.MkdirAll(s.DataDir, 0755); err != nil {
		return
	}
	out, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// ListAccessLogs returns the recent subscription access audit entries (newest first).
func (s *Store) ListAccessLogs() ([]AccessLogEntry, error) {
	s.mu.Lock()
	path := s.accessAuditPath()
	raw, err := os.ReadFile(path)
	s.mu.Unlock()

	if err != nil {
		if os.IsNotExist(err) {
			return []AccessLogEntry{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return []AccessLogEntry{}, nil
	}
	var list []AccessLogEntry
	if err := json.Unmarshal(raw, &list); err != nil {
		return []AccessLogEntry{}, nil
	}
	return list, nil
}

// ClearAccessLogs clears all stored subscription access audit entries.
func (s *Store) ClearAccessLogs() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.accessAuditPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func extractRequestIPAndCountry(r *http.Request) (ip string, country string) {
	country = strings.ToUpper(strings.TrimSpace(cmp.Or(
		r.Header.Get("X-Geo-Country"),
		r.Header.Get("CF-IPCountry"),
	)))
	if country == "XX" || country == "T1" {
		country = ""
	}

	for _, hdr := range []string{"X-Real-IP", "CF-Connecting-IP", "X-Forwarded-For"} {
		val := strings.TrimSpace(r.Header.Get(hdr))
		if val == "" {
			continue
		}
		first := strings.TrimSpace(strings.Split(val, ",")[0])
		if parsed := net.ParseIP(first); parsed != nil {
			return parsed.String(), country
		}
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	return host, country
}

// IdentifyClientApp classifies a client's User-Agent into a concise human-readable app label.
func IdentifyClientApp(ua string) string {
	lower := strings.ToLower(strings.TrimSpace(ua))
	switch {
	case lower == "":
		return "Unknown"
	case strings.Contains(lower, "shadowrocket"):
		return "Shadowrocket"
	case strings.Contains(lower, "flclash"):
		return "FlClash"
	case strings.Contains(lower, "clash-verge") || strings.Contains(lower, "clashverge"):
		return "Clash Verge"
	case strings.Contains(lower, "stash"):
		return "Stash"
	case strings.Contains(lower, "mihomo") || strings.Contains(lower, "clash.meta") || strings.Contains(lower, "metacubex"):
		return "Clash.Meta"
	case strings.Contains(lower, "clash"):
		return "Clash"
	case strings.Contains(lower, "sfi/"):
		return "Sing-box iOS"
	case strings.Contains(lower, "sfa/"):
		return "Sing-box Android"
	case strings.Contains(lower, "sfm/"):
		return "Sing-box macOS"
	case strings.Contains(lower, "sing-box"):
		return "Sing-box"
	case strings.Contains(lower, "surge"):
		return "Surge"
	case strings.Contains(lower, "loon"):
		return "Loon"
	case strings.Contains(lower, "quantumult"):
		return "Quantumult X"
	case strings.Contains(lower, "v2ray") || strings.Contains(lower, "hiddify") || strings.Contains(lower, "nekobox"):
		return "V2Ray / Hiddify"
	case strings.Contains(lower, "singctl"):
		return "SingCtl"
	case strings.Contains(lower, "curl/"):
		return "curl"
	case strings.Contains(lower, "mozilla/"):
		return "Browser"
	default:
		if idx := strings.IndexByte(ua, '/'); idx > 0 && idx <= 24 {
			return strings.TrimSpace(ua[:idx])
		}
		if len(ua) > 20 {
			return strings.TrimSpace(ua[:20])
		}
		return strings.TrimSpace(ua)
	}
}
