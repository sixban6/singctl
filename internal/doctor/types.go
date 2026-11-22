// 文件职责：定义新一代网关全链路深度体检引擎的状态枚举、检查结果、综合报告、OCP Checker 契约与全可注入 Env。
package doctor

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
)

const (
	defaultSmartDNSConfPath = "/etc/singctl/smartdns.conf"
	defaultAdGuardConfPath  = "/etc/AdGuardHome/AdGuardHome.yaml"
	defaultSingBoxConfPath  = "/etc/sing-box/config.json"
)

// Status 表示单项深度体检或总体报告的健康状态。
type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

// CheckResult 描述单项深度体检算子的结构化诊断结论与一键修复建议。
type CheckResult struct {
	ID         string `json:"id"`
	Category   string `json:"category"`
	Title      string `json:"title"`
	Status     Status `json:"status"`
	Summary    string `json:"summary"`
	Detail     string `json:"detail,omitzero"`
	Advice     string `json:"advice,omitzero"`
	FixAction  string `json:"fixAction,omitzero"`
	FixLabel   string `json:"fixLabel,omitzero"`
	DurationMs int64  `json:"durationMs"`
}

// Report 汇总全部深度体检算子的评分、状态分布、耗时与按注册顺序排列的结果列表。
type Report struct {
	Score      int           `json:"score"`
	Overall    Status        `json:"overall"`
	Passed     int           `json:"passed"`
	Warnings   int           `json:"warnings"`
	Failed     int           `json:"failed"`
	Skipped    int           `json:"skipped"`
	DurationMs int64         `json:"durationMs"`
	CheckedAt  string        `json:"checkedAt"`
	Checks     []CheckResult `json:"checks"`
}

// Checker 定义 OCP 声明式深度体检算子接口，新增检查项无需修改调度主干。
type Checker interface {
	ID() string
	Run(ctx context.Context, env *Env) CheckResult
}

// Env 封装深度体检所需的全部外部 I/O、命令执行、网络探针与快捷修复依赖；零值自动回退生产默认实现。
type Env struct {
	Config            *config.Config
	ConfigPath        string
	SingBoxConfigPath string
	SmartDNSConfPath  string
	AdGuardConfPath   string
	ProcRoot          string
	NowFunc           func() time.Time
	RunCmd            func(ctx context.Context, name string, args ...string) ([]byte, error)
	LookPath          func(file string) (string, error)
	HTTPProbe         func(ctx context.Context, url string) (statusCode int, latencyMs int64, err error)
	DialTCP           func(ctx context.Context, addr string) error
	ReadFile          func(path string) ([]byte, error)
	Statfs            func(path string) (sysinfo.DiskSpace, error)
	ReadMemInfo       func() (sysinfo.MemInfo, error)
	IsOpenWrt         func() bool
	QuickFixHandlers  map[string]func(ctx context.Context) (string, error)
}

func (e *Env) withDefaults() *Env {
	var out Env
	if e != nil {
		out = *e
		if e.QuickFixHandlers != nil {
			out.QuickFixHandlers = maps.Clone(e.QuickFixHandlers)
		}
	}
	out.SingBoxConfigPath = cmp.Or(strings.TrimSpace(out.SingBoxConfigPath), constant.SingBoxConfigFile, defaultSingBoxConfPath)
	out.SmartDNSConfPath = cmp.Or(strings.TrimSpace(out.SmartDNSConfPath), defaultSmartDNSConfPath)
	out.AdGuardConfPath = cmp.Or(strings.TrimSpace(out.AdGuardConfPath), constant.AdGuardConfigFile, defaultAdGuardConfPath)
	out.ProcRoot = strings.TrimSpace(out.ProcRoot)

	if out.NowFunc == nil {
		out.NowFunc = time.Now
	}
	if out.RunCmd == nil {
		out.RunCmd = defaultRunCmd
	}
	if out.LookPath == nil {
		out.LookPath = exec.LookPath
	}
	if out.HTTPProbe == nil {
		out.HTTPProbe = defaultHTTPProbe
	}
	if out.DialTCP == nil {
		out.DialTCP = defaultDialTCPCtx
	}
	if out.ReadFile == nil {
		out.ReadFile = os.ReadFile
	}
	if out.Statfs == nil {
		out.Statfs = sysinfo.Statfs
	}
	if out.ReadMemInfo == nil {
		out.ReadMemInfo = sysinfo.ReadMemInfo
	}
	if out.IsOpenWrt == nil {
		out.IsOpenWrt = sysinfo.IsOpenWrt
	}
	return &out
}

func (e *Env) lookPathOK(file string) bool {
	if e == nil || e.LookPath == nil {
		return false
	}
	p, err := e.LookPath(file)
	return err == nil && strings.TrimSpace(p) != ""
}

func (e *Env) effectiveIPv6Mode() string {
	if e != nil && e.Config != nil {
		return e.Config.Gateway.EffectiveIPv6Mode()
	}
	return config.GatewayIPv6Off
}

func defaultRunCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func defaultDialTCPCtx(ctx context.Context, addr string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	d := &net.Dialer{Timeout: 800 * time.Millisecond}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func defaultHTTPProbe(ctx context.Context, targetURL string) (int, int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "singctl-doctor/1.0")
	client := &http.Client{Timeout: 4 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	latencyMs := max(1, time.Since(start).Milliseconds())
	if err != nil {
		return 0, latencyMs, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return resp.StatusCode, latencyMs, nil
}

func worstStatus(a, b Status) Status {
	rank := func(s Status) int {
		switch s {
		case StatusFail:
			return 4
		case StatusWarn:
			return 3
		case StatusPass:
			return 2
		case StatusSkip:
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

func formatMiB(bytes uint64) string {
	return fmt.Sprintf("%.1fMB", float64(bytes)/(1024.0*1024.0))
}
