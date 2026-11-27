// 文件职责：实现 OpenWrt Wi-Fi 调优服务的显式依赖注入基础设施、UCI 解析器、输入白名单校验与纯无线重载函数。
package wifiopt

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/fsx"
)

const (
	defaultWirelessFile     = "/etc/config/wireless"
	defaultSysctlFile       = "/etc/sysctl.conf"
	defaultLowMemSysctlFile = "/etc/sysctl.d/99-singctl-lowmem.conf"
	defaultRCLocalFile      = "/etc/rc.local"
	defaultPollInterval     = 1 * time.Second
	defaultVerifyTimeout    = 25 * time.Second
	defaultRetestWindow     = 3 * time.Second
)

var (
	validUCISectionRe = regexp.MustCompile(`^[A-Za-z0-9_@\[\]-]{1,64}$`)
	validHTModes2G    = map[string]bool{"HT20": true, "HT40": true, "HE20": true, "HE40": true, "EHT20": true, "EHT40": true}
	validHTModes5G    = map[string]bool{"HT20": true, "HT40": true, "VHT20": true, "VHT40": true, "VHT80": true, "VHT160": true, "HE20": true, "HE40": true, "HE80": true, "HE160": true, "EHT80": true, "EHT160": true}
	valid2GChannels   = map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true, 10: true, 11: true, 12: true, 13: true}
	valid5GChannels   = map[int]bool{36: true, 40: true, 44: true, 48: true, 52: true, 56: true, 60: true, 64: true, 100: true, 104: true, 108: true, 112: true, 116: true, 120: true, 124: true, 128: true, 132: true, 136: true, 140: true, 144: true, 149: true, 153: true, 157: true, 161: true, 165: true}
)

// Env 封装全部外部系统副作用（命令执行、文件读写、时钟），测试时显式注入替身，绝不读写宿主机真实配置。
type Env struct {
	RunCmd        func(ctx context.Context, name string, args ...string) ([]byte, error)
	LookPath      func(file string) (string, error)
	ReadFile         func(path string) ([]byte, error)
	WriteFile0600    func(path string, data []byte) error
	WriteSysfs       func(path string, data []byte) error
	ReadDir          func(path string) ([]string, error)
	Glob             func(pattern string) ([]string, error)
	Now              func() time.Time
	Sleep            func(ctx context.Context, d time.Duration) error
	ReloadWifi       func(ctx context.Context) error
	WirelessFile     string
	SysctlFile       string
	LowMemSysctlFile string
	RCLocalFile      string
	PollInterval     time.Duration
	VerifyTimeout    time.Duration
	RetestWindow     time.Duration
	CPUCount         int
}

// Service 提供 Wi-Fi 体检、周边信道扫描、安全应用与高并发底盘加速能力。
type Service struct {
	env Env

	statsMu         sync.Mutex
	statsBaseline   map[string]netDevStat
	statsBaselineAt time.Time
	statsScope      string
}

// NewService 创建 Wi-Fi 调优领域服务（未注入字段自动回退生产默认实现）。
func NewService(env Env) *Service {
	return &Service{env: env}
}

func (s *Service) runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.env.RunCmd != nil {
		return s.env.RunCmd(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (s *Service) lookPath(file string) (string, error) {
	if s.env.LookPath != nil {
		return s.env.LookPath(file)
	}
	return exec.LookPath(file)
}

func (s *Service) readFile(path string) ([]byte, error) {
	if s.env.ReadFile != nil {
		return s.env.ReadFile(path)
	}
	return os.ReadFile(path)
}

func (s *Service) writeFile0600(path string, data []byte) error {
	if s.env.WriteFile0600 != nil {
		return s.env.WriteFile0600(path, data)
	}
	return fsx.WriteAtomic0600(path, data)
}

func (s *Service) writeSysfs(path string, data []byte) error {
	if s.env.WriteSysfs != nil {
		return s.env.WriteSysfs(path, data)
	}
	if s.env.WriteFile0600 != nil {
		return s.env.WriteFile0600(path, data)
	}
	// sysfs 虚拟文件不支持同目录临时文件原子 rename，必须直接写入
	return os.WriteFile(path, data, 0644)
}

func (s *Service) writeSystemFile(path string, data []byte, perm os.FileMode) error {
	if s.env.WriteFile0600 != nil {
		return s.env.WriteFile0600(path, data)
	}
	return fsx.WriteAtomic(path, data, perm)
}

func (s *Service) glob(pattern string) ([]string, error) {
	if s.env.Glob != nil {
		return s.env.Glob(pattern)
	}
	return filepath.Glob(pattern)
}

func (s *Service) now() time.Time {
	if s.env.Now != nil {
		return s.env.Now()
	}
	return time.Now()
}

func (s *Service) sleep(ctx context.Context, d time.Duration) error {
	if s.env.Sleep != nil {
		return s.env.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (s *Service) wirelessFile() string {
	return cmp.Or(strings.TrimSpace(s.env.WirelessFile), defaultWirelessFile)
}

func (s *Service) sysctlFile() string {
	return cmp.Or(strings.TrimSpace(s.env.SysctlFile), defaultSysctlFile)
}

func (s *Service) lowMemSysctlFile() string {
	return cmp.Or(strings.TrimSpace(s.env.LowMemSysctlFile), defaultLowMemSysctlFile)
}

func (s *Service) rcLocalFile() string {
	return cmp.Or(strings.TrimSpace(s.env.RCLocalFile), defaultRCLocalFile)
}

func (s *Service) retestWindow() time.Duration {
	if s.env.RetestWindow > 0 {
		return s.env.RetestWindow
	}
	return defaultRetestWindow
}

func (s *Service) pollInterval() time.Duration {
	if s.env.PollInterval > 0 {
		return s.env.PollInterval
	}
	return defaultPollInterval
}

func (s *Service) verifyTimeout() time.Duration {
	if s.env.VerifyTimeout > 0 {
		return s.env.VerifyTimeout
	}
	return defaultVerifyTimeout
}

func (s *Service) cpuCount() int {
	if s.env.CPUCount > 0 {
		return s.env.CPUCount
	}
	return max(1, runtime.NumCPU())
}

func (s *Service) reloadWifi(ctx context.Context) error {
	if s.env.ReloadWifi != nil {
		return s.env.ReloadWifi(ctx)
	}
	return ReloadOpenWrtWireless(ctx)
}

// ReloadOpenWrtWireless 仅安全重载 OpenWrt 无线子系统（供 SafeCommit 纯无线回滚复用，严禁触碰有线/WAN/network）。
func ReloadOpenWrtWireless(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	wifiPath, err := exec.LookPath("wifi")
	if err != nil {
		return fmt.Errorf("未找到 OpenWrt wifi 命令: %w", err)
	}
	if out, err := exec.CommandContext(cctx, wifiPath, "reload").CombinedOutput(); err != nil {
		return fmt.Errorf("wifi reload failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// uciSection / uciDoc 为轻量纯 Go UCI `uci show` 解析器，保留原始节声明顺序。
type uciSection struct {
	Name    string
	Type    string
	Options map[string]string
}

func (s *uciSection) opt(k string) string {
	if s == nil {
		return ""
	}
	return s.Options[k]
}

type uciDoc struct {
	Order    []string
	Sections map[string]*uciSection
}

func parseUCIShow(pkg string, raw string) *uciDoc {
	doc := &uciDoc{Sections: make(map[string]*uciSection)}
	prefix := pkg + "."
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := strings.TrimPrefix(line, prefix)
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			continue
		}
		lhs, rhs := rest[:eq], unquoteUCI(rest[eq+1:])
		if dot := strings.IndexByte(lhs, '.'); dot < 0 {
			sec := doc.ensure(lhs)
			sec.Type = rhs
		} else {
			secName, optName := lhs[:dot], lhs[dot+1:]
			sec := doc.ensure(secName)
			sec.Options[optName] = rhs
		}
	}
	return doc
}

func (d *uciDoc) ensure(name string) *uciSection {
	if sec, ok := d.Sections[name]; ok {
		return sec
	}
	sec := &uciSection{Name: name, Options: make(map[string]string)}
	d.Sections[name] = sec
	d.Order = append(d.Order, name)
	return sec
}

func (d *uciDoc) byType(typ string) []*uciSection {
	var out []*uciSection
	for _, name := range d.Order {
		if sec := d.Sections[name]; sec != nil && sec.Type == typ {
			out = append(out, sec)
		}
	}
	return out
}

func unquoteUCI(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && ((v[0] == '\'' && v[len(v)-1] == '\'') || (v[0] == '"' && v[len(v)-1] == '"')) {
		return v[1 : len(v)-1]
	}
	return v
}

func hasShellMetaOrControl(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
		switch c {
		case ';', '&', '|', '$', '`', '(', ')', '<', '>', '\\', '\'', '"':
			return true
		}
	}
	return false
}

func isValidUCISectionName(s string) bool {
	return s != "" && !hasShellMetaOrControl(s) && validUCISectionRe.MatchString(s)
}

func isDFSChannel(ch int) bool {
	return ch >= 52 && ch <= 144
}

func isNonOverlapping2GChannel(ch int) bool {
	return ch == 1 || ch == 6 || ch == 11
}

func normalizeBand(raw, htmode string, ch int) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "2g", "2.4g", "2.4ghz":
		return "2g"
	case "5g", "5ghz":
		return "5g"
	case "6g", "6ghz":
		return "6g"
	}
	if ch >= 36 {
		return "5g"
	}
	if ch >= 1 && ch <= 14 {
		return "2g"
	}
	upper := strings.ToUpper(htmode)
	if strings.Contains(upper, "80") || strings.Contains(upper, "160") || strings.HasPrefix(upper, "VHT") {
		return "5g"
	}
	return "2g"
}
