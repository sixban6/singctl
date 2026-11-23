//go:build !lite

// 文件职责：定义全链路健康体检模型、声明式检查项注册表（Registry）、可注入宿主/网络探针契约（Deps）与报告输出。
package doctor

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/subhub"
)

// Scope 标识体检项适用的运行模式。
type Scope string

const (
	ScopeServer Scope = "server"
	ScopeClient Scope = "client"
)

// DoctorItem 单个体检检查项。
type DoctorItem struct {
	Name     string `json:"name"`
	Category string `json:"category"` // "system" | "network" | "services" | "security"
	Status   string `json:"status"`   // "ok" | "warn" | "fail"
	Summary  string `json:"summary"`
	Detail   string `json:"detail,omitempty"`
}

// DoctorReport 整体体检报告。
type DoctorReport struct {
	Score     int          `json:"score"`
	CheckedAt string       `json:"checkedAt"`
	Items     []DoctorItem `json:"items"`
	Summary   string       `json:"summary"`
}

// TLSPeerInfo 描述服务端网关 TLS 握手对端证书摘要。
type TLSPeerInfo struct {
	NotAfter   time.Time
	TLSVersion string
}

// Deps 封装体检检查项所需的全部宿主文件、进程与网络探针依赖；零值字段自动回退生产默认实现。
type Deps struct {
	GOOS                 string
	GOARCH               string
	NumCPU               int
	Now                  func() time.Time
	ReadFile             func(path string) ([]byte, error)
	FileExists           func(path string) bool
	FileNonEmpty         func(path string) bool
	DialTCP              func(addr string, timeout time.Duration) error
	HTTPGetStatus        func(url string, timeout time.Duration) (statusCode int, latency time.Duration, err error)
	ProbeServerTLS       func(domain string, port int) (TLSPeerInfo, error)
	ProbeRealitySNI      func(sni string) (latency time.Duration, tlsVer string, err error)
	LookupValidCaddyCert func(domain string) (crtPath, keyPath string)
	IsServiceActive      func(serviceName string) bool
	CheckMediaUnlock     func() *MediaUnlockReport
}

// DefaultDeps 返回生产环境默认探针依赖集合。
func DefaultDeps() Deps {
	return Deps{}.withDefaults()
}

func (d Deps) withDefaults() Deps {
	d.GOOS = cmp.Or(d.GOOS, runtime.GOOS)
	d.GOARCH = cmp.Or(d.GOARCH, runtime.GOARCH)
	if d.NumCPU <= 0 {
		d.NumCPU = runtime.NumCPU()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.ReadFile == nil {
		d.ReadFile = os.ReadFile
	}
	if d.FileExists == nil {
		d.FileExists = func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		}
	}
	if d.FileNonEmpty == nil {
		d.FileNonEmpty = fileNonEmpty
	}
	if d.DialTCP == nil {
		d.DialTCP = defaultDialTCP
	}
	if d.HTTPGetStatus == nil {
		d.HTTPGetStatus = defaultHTTPGetStatus
	}
	if d.ProbeServerTLS == nil {
		d.ProbeServerTLS = defaultProbeServerTLS
	}
	if d.ProbeRealitySNI == nil {
		d.ProbeRealitySNI = defaultProbeRealitySNI
	}
	if d.LookupValidCaddyCert == nil {
		d.LookupValidCaddyCert = deploy.LookupValidCaddyCert
	}
	if d.IsServiceActive == nil {
		d.IsServiceActive = defaultIsServiceActive
	}
	if d.CheckMediaUnlock == nil {
		d.CheckMediaUnlock = CheckMediaUnlock
	}
	return d
}

// Check 描述一个声明式健康体检算子。
type Check struct {
	ID    string
	Scope Scope
	Run   func(ctx context.Context, cfg *config.Config, deps Deps) []DoctorItem
}

// Registry 维护有序、并发安全的声明式体检算子集合。
type Registry struct {
	mu     sync.RWMutex
	checks []Check
}

// NewRegistry 创建空的声明式体检注册表。
func NewRegistry() *Registry {
	return &Registry{}
}

// Register 按传入顺序追加一个或多个体检检查项。
func (r *Registry) Register(checks ...Check) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks = append(r.checks, checks...)
}

// RunScope 执行指定 Scope 的全部体检项并汇总评分报告。
func (r *Registry) RunScope(ctx context.Context, scope Scope, cfg *config.Config, deps Deps, healthyMsg string) *DoctorReport {
	if ctx == nil {
		ctx = context.Background()
	}
	deps = deps.withDefaults()

	r.mu.RLock()
	snapshot := make([]Check, 0, len(r.checks))
	for _, c := range r.checks {
		if c.Scope == scope && c.Run != nil {
			snapshot = append(snapshot, c)
		}
	}
	r.mu.RUnlock()

	report := &DoctorReport{
		Score:     100,
		CheckedAt: deps.Now().Format("2006-01-02 15:04:05"),
		Items:     make([]DoctorItem, 0, len(snapshot)),
	}
	for _, c := range snapshot {
		if err := ctx.Err(); err != nil {
			break
		}
		report.Items = append(report.Items, c.Run(ctx, cfg, deps)...)
	}
	FinalizeReport(report, healthyMsg)
	return report
}

var defaultRegistry = sync.OnceValue(func() *Registry {
	reg := NewRegistry()
	reg.Register(defaultServerChecks()...)
	reg.Register(defaultClientChecks()...)
	return reg
})

// DefaultRegistry 返回包含内置服务端与客户端全部检查项的只读全局注册表。
func DefaultRegistry() *Registry {
	return defaultRegistry()
}

// IsServerEnvironment 判断当前主机/配置是否处于服务端部署模式。
func IsServerEnvironment(cfg *config.Config) bool {
	return IsServerEnvironmentWithDeps(cfg, DefaultDeps())
}

// IsServerEnvironmentWithDeps 基于可注入宿主文件探针判断是否为服务端部署模式。
func IsServerEnvironmentWithDeps(cfg *config.Config, deps Deps) bool {
	deps = deps.withDefaults()
	if deps.FileExists("/etc/caddy/Caddyfile") || deps.FileExists("/etc/sub-store") {
		return true
	}
	if cfg != nil {
		domain := cfg.Server.GetNodeDomain()
		if domain != "" && domain != "node.yourdomain.com" && domain != "node.example.com" {
			return true
		}
		if cfg.Server.GetWebAdminPath() != "" {
			return true
		}
	}
	return false
}

// RunDoctor 根据当前环境自动识别服务端或客户端模式并执行体检。
func RunDoctor(cfg *config.Config) *DoctorReport {
	if IsServerEnvironment(cfg) {
		return RunServerDoctor(cfg)
	}
	return RunClientDoctor(cfg)
}

// RunServerDoctor 执行服务端全链路体检。
func RunServerDoctor(cfg *config.Config) *DoctorReport {
	return RunServerDoctorWithDeps(context.Background(), cfg, DefaultDeps())
}

// RunServerDoctorWithDeps 使用显式注入的依赖执行服务端全链路体检。
func RunServerDoctorWithDeps(ctx context.Context, cfg *config.Config, deps Deps) *DoctorReport {
	const healthyMsg = "🎉 系统运行状态极佳！所有核心组件、TLS 证书与高可用链路均处于健康状态。"
	return DefaultRegistry().RunScope(ctx, ScopeServer, cfg, deps, healthyMsg)
}

// RunClientDoctor 执行客户端透明代理/桌面网关模式体检。
func RunClientDoctor(cfg *config.Config) *DoctorReport {
	return RunClientDoctorWithDeps(context.Background(), cfg, DefaultDeps())
}

// RunClientDoctorWithDeps 使用显式注入的依赖执行客户端模式体检。
func RunClientDoctorWithDeps(ctx context.Context, cfg *config.Config, deps Deps) *DoctorReport {
	const healthyMsg = "🎉 客户端运行环境健康，代理与网络组件状态良好。"
	return DefaultRegistry().RunScope(ctx, ScopeClient, cfg, deps, healthyMsg)
}

// FinalizeReport 根据体检项中的 fail/warn 数量汇总综合评分与总结结论。
func FinalizeReport(report *DoctorReport, healthyMsg string) {
	var fails, warns int
	for _, item := range report.Items {
		switch item.Status {
		case "fail":
			fails++
		case "warn":
			warns++
		}
	}
	report.Score = max(0, 100-(fails*20)-(warns*5))

	switch {
	case fails == 0 && warns == 0:
		report.Summary = healthyMsg
	case fails == 0:
		report.Summary = fmt.Sprintf("⚠️ 系统整体可用，但发现 %d 项次要警告，建议排查优化。", warns)
	default:
		report.Summary = fmt.Sprintf("❌ 检测到 %d 项严重异常与 %d 项警告，部分代理或网关链路可能受阻，请根据下方详情排查！", fails, warns)
	}
}

func defaultDialTCP(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func defaultHTTPGetStatus(url string, timeout time.Duration) (int, time.Duration, error) {
	client := &http.Client{Timeout: timeout}
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, time.Since(start), nil
}

func defaultProbeServerTLS(domain string, vlessPort int) (TLSPeerInfo, error) {
	targetAddr := fmt.Sprintf("%s:%d", domain, vlessPort)
	tlsCfg := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", targetAddr, tlsCfg)
	if err != nil {
		// NAT 共享 IP 小鸡内部往往不支持 Hairpin NAT，回退通过本地回环验证同一网关与真实 ACME 证书链
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", vlessPort), tlsCfg)
	}
	if err != nil {
		return TLSPeerInfo{}, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return TLSPeerInfo{}, errors.New("no peer certificates presented")
	}
	return TLSPeerInfo{
		NotAfter:   state.PeerCertificates[0].NotAfter,
		TLSVersion: tlsVersionToString(state.Version),
	}, nil
}

func defaultProbeRealitySNI(sni string) (time.Duration, string, error) {
	start := time.Now()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", sni+":443", &tls.Config{
		ServerName: sni,
	})
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	return time.Since(start), tlsVersionToString(conn.ConnectionState().Version), nil
}

func defaultIsServiceActive(serviceName string) bool {
	ctx := context.Background()
	mgr := servicemgr.Detect(nil)

	// 针对 SubHub 原生订阅引擎: 优先检查 singctl-sub 服务及本地 3001 端口
	if serviceName == "singctl-sub" || serviceName == "substore" || serviceName == "sub-store" {
		if mgr.IsActive(ctx, "singctl-sub") {
			return true
		}
		if defaultDialTCP(subhub.DefaultListenAddr, 300*time.Millisecond) == nil {
			return true
		}
	}

	// 针对 WARP: 检查 wireproxy 或 warp-svc 或 40000 端口
	if serviceName == "wireproxy" {
		if defaultDialTCP("127.0.0.1:40000", 300*time.Millisecond) == nil {
			return true
		}
		if mgr.IsActive(ctx, "warp-svc") {
			return true
		}
	}

	// 优先通过 servicemgr 检查宿主服务状态
	if mgr.IsActive(ctx, serviceName) {
		return true
	}
	// 回退检查进程名称
	out, err := exec.Command("pgrep", "-f", serviceName).Output()
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	default:
		return "未知"
	}
}

func joinInts(ints []int) string {
	s := make([]string, 0, len(ints))
	for _, i := range ints {
		s = append(s, fmt.Sprintf("%d", i))
	}
	return strings.Join(s, ", ")
}

func fileNonEmpty(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// PrintDoctorReport 终端美化输出。
func PrintDoctorReport(r *DoctorReport) {
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Success("                 🩺 SINGCTL 全链路健康体检报告")
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Info("体检时间: %s  |  综合健康指数: %d / 100", r.CheckedAt, r.Score)
	logger.Info("───────────────────────────────────────────────────────────")

	for _, item := range r.Items {
		switch item.Status {
		case "ok":
			logger.Success("  [✓] %-18s : %s", item.Name, item.Summary)
		case "warn":
			logger.Warn("  [!] %-18s : %s", item.Name, item.Summary)
			if item.Detail != "" {
				logger.Info("      ➜ 说明: %s", item.Detail)
			}
		case "fail":
			logger.Error("  [✗] %-18s : %s", item.Name, item.Summary)
			if item.Detail != "" {
				logger.Info("      ➜ 修复建议: %s", item.Detail)
			}
		}
	}

	logger.Info("───────────────────────────────────────────────────────────")
	hasFail := false
	for _, item := range r.Items {
		if item.Status == "fail" {
			hasFail = true
			break
		}
	}

	if r.Score >= 90 {
		logger.Success("结论: %s", r.Summary)
	} else if !hasFail {
		logger.Warn("结论: %s", r.Summary)
	} else {
		logger.Error("结论: %s", r.Summary)
	}
	logger.Info("═══════════════════════════════════════════════════════════\n")
}
