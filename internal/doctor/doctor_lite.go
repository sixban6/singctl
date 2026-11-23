//go:build lite

// 文件职责：为 -tags lite 客户端精简版提供零服务端重依赖的最小环境识别与旧服务端体检报告兼容层。
package doctor

import (
	"os"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
)

// DoctorItem 单个旧版体检检查项。
type DoctorItem struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Summary  string `json:"summary"`
	Detail   string `json:"detail,omitempty"`
}

// DoctorReport 旧版整体体检报告。
type DoctorReport struct {
	Score     int          `json:"score"`
	CheckedAt string       `json:"checkedAt"`
	Items     []DoctorItem `json:"items"`
	Summary   string       `json:"summary"`
}

// IsServerEnvironment 判断当前主机/配置是否处于服务端部署模式（纯本地文件与配置判定，零服务端重包依赖）。
func IsServerEnvironment(cfg *config.Config) bool {
	if _, err := os.Stat("/etc/caddy/Caddyfile"); err == nil {
		return true
	}
	if _, err := os.Stat("/etc/sub-store"); err == nil {
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

// RunDoctor 在 -tags lite 纯客户端精简版中返回轻量兼容体检报告，零服务端重包依赖。
func RunDoctor(cfg *config.Config) *DoctorReport {
	return RunServerDoctor(cfg)
}

// RunServerDoctor 在 -tags lite 纯客户端精简版中返回友好提示，避免拉入 deploy/subhub 等服务端重包。
func RunServerDoctor(_ *config.Config) *DoctorReport {
	const msg = "当前为 SingCtl -lite 路由器客户端精简版，不含服务端体检模块；请运行 'singctl doctor --mode client' 或使用标准完整版。"
	return &DoctorReport{
		Score:     0,
		CheckedAt: time.Now().Format("2006-01-02 15:04:05"),
		Items: []DoctorItem{{
			Name:     "服务端体检模块",
			Category: "system",
			Status:   "warn",
			Summary:  "当前 -lite 精简版仅包含客户端 8 项深度体检",
			Detail:   msg,
		}},
		Summary: msg,
	}
}

// PrintDoctorReport 终端输出兼容报告。
func PrintDoctorReport(r *DoctorReport) {
	if r == nil {
		return
	}
	logger.Warn("%s", r.Summary)
	for _, item := range r.Items {
		logger.Info("  [%s] %s: %s", item.Status, item.Name, item.Summary)
		if item.Detail != "" {
			logger.Info("      ➜ %s", item.Detail)
		}
	}
}
