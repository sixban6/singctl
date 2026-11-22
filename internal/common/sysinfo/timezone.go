// 文件职责：提供精简 Linux / OpenWrt（无 /usr/share/zoneinfo）环境下的本地时区初始化与 POSIX TZ 字符串解析。
package sysinfo

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// InitLocalTimezone 在 Go 默认回退为 UTC 的精简固件（如 OpenWrt）上自动读取 /etc/TZ 与 /etc/config/system 修正 time.Local。
func InitLocalTimezone() {
	if time.Local != nil && time.Local.String() != "UTC" {
		return
	}
	if loc := ResolveLocalLocationFromFiles("/etc/TZ", "/etc/config/system"); loc != nil && loc.String() != "UTC" {
		time.Local = loc
	}
}

// ResolveLocalLocationFromFiles 按 TZ 环境变量 -> /etc/TZ -> UCI /etc/config/system -> time.Local 顺序解析本地时区。
func ResolveLocalLocationFromFiles(tzFile, uciSystemFile string) *time.Location {
	if envTZ := strings.TrimSpace(os.Getenv("TZ")); envTZ != "" {
		if loc := ParsePOSIXTZLocation(envTZ); loc != nil {
			return loc
		}
	}
	if tzFile != "" {
		if raw, err := os.ReadFile(tzFile); err == nil {
			for line := range strings.SplitSeq(string(raw), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					if loc := ParsePOSIXTZLocation(line); loc != nil {
						return loc
					}
				}
			}
		}
	}
	if uciSystemFile != "" {
		if raw, err := os.ReadFile(uciSystemFile); err == nil {
			var zoneName, posixTZ string
			for line := range strings.SplitSeq(string(raw), "\n") {
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) >= 3 && fields[0] == "option" {
					val := strings.Trim(fields[2], "'\"")
					switch fields[1] {
					case "zonename":
						zoneName = val
					case "timezone":
						posixTZ = val
					}
				}
			}
			for _, candidate := range []string{zoneName, posixTZ} {
				if loc := ParsePOSIXTZLocation(candidate); loc != nil {
					return loc
				}
			}
		}
	}
	return time.Local
}

// ParsePOSIXTZLocation 解析 IANA 时区名或 OpenWrt / musl POSIX TZ 字符串（如 "CST-8", "<+08>-8", "IST-5:30"）。
func ParsePOSIXTZLocation(spec string) *time.Location {
	s := strings.TrimSpace(spec)
	if s == "" {
		return nil
	}
	if loc, err := time.LoadLocation(s); err == nil && loc != nil {
		return loc
	}

	switch strings.ToLower(strings.ReplaceAll(s, " ", "_")) {
	case "asia/shanghai", "asia/chongqing", "asia/harbin", "asia/urumqi", "asia/hong_kong", "asia/macau", "asia/taipei", "asia/singapore", "prc":
		return time.FixedZone("CST", 8*3600)
	case "asia/tokyo", "asia/seoul":
		return time.FixedZone("JST", 9*3600)
	}

	var tzName, rest string
	if strings.HasPrefix(s, "<") {
		end := strings.IndexByte(s, '>')
		if end <= 1 {
			return nil
		}
		tzName = s[1:end]
		rest = s[end+1:]
	} else {
		i := 0
		for i < len(s) && ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) {
			i++
		}
		if i == 0 {
			return nil
		}
		tzName = s[:i]
		rest = s[i:]
	}

	if rest == "" {
		if strings.EqualFold(tzName, "UTC") || strings.EqualFold(tzName, "GMT") {
			return time.UTC
		}
		return nil
	}

	westSign := 1
	switch rest[0] {
	case '-':
		westSign = -1
		rest = rest[1:]
	case '+':
		westSign = 1
		rest = rest[1:]
	}

	numEnd := 0
	for numEnd < len(rest) && ((rest[numEnd] >= '0' && rest[numEnd] <= '9') || rest[numEnd] == ':') {
		numEnd++
	}
	if numEnd == 0 {
		return nil
	}
	parts := strings.Split(rest[:numEnd], ":")
	if len(parts) > 3 {
		return nil
	}
	hh, err := strconv.Atoi(parts[0])
	if err != nil || hh > 14 {
		return nil
	}
	mm, ss := 0, 0
	if len(parts) >= 2 {
		mm, err = strconv.Atoi(parts[1])
		if err != nil || mm < 0 || mm >= 60 {
			return nil
		}
	}
	if len(parts) == 3 {
		ss, err = strconv.Atoi(parts[2])
		if err != nil || ss < 0 || ss >= 60 {
			return nil
		}
	}

	westSeconds := westSign * (hh*3600 + mm*60 + ss)
	eastSeconds := -westSeconds
	if eastSeconds == 0 && (strings.EqualFold(tzName, "UTC") || strings.EqualFold(tzName, "GMT")) {
		return time.UTC
	}
	return time.FixedZone(tzName, eastSeconds)
}
