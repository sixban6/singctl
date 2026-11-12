package serverweb

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const MaxAuditLogs = 200

// ClassifyAuditCategory 根据操作描述自动归类审计记录，便于前端筛选定位
func ClassifyAuditCategory(action string) string {
	switch {
	case strings.Contains(action, "登录") || strings.Contains(action, "密码") || strings.Contains(action, "凭证") || strings.Contains(action, "路径"):
		return "login"
	case strings.Contains(action, "拉黑") || strings.Contains(action, "封禁") || strings.Contains(action, "解封") || strings.Contains(action, "自愈") || strings.Contains(action, "抗探测") || strings.Contains(action, "备份") || strings.Contains(action, "灾备") || strings.Contains(action, "快照") || strings.Contains(action, "恢复"):
		return "security"
	case strings.Contains(action, "舰队") || strings.Contains(action, "子节点"):
		return "fleet"
	case strings.Contains(action, "订阅"):
		return "subscription"
	default:
		return "service"
	}
}

// AuditEntry 最近管理操作审计记录 (绝对不记录任何密码、会话令牌或敏感秘钥)
type AuditEntry struct {
	Time   string `json:"time"`
	Action string `json:"action"`
	IP     string `json:"ip"`
}

// AuditManager 管理操作审计日志管理器 (支持 0600 小文件持久化)
type AuditManager struct {
	mu       sync.RWMutex
	logs     []AuditEntry
	filePath string
}

// NewAuditManager 创建审计日志管理器实例
func NewAuditManager(filePath ...string) *AuditManager {
	fp := ""
	if len(filePath) > 0 {
		fp = strings.TrimSpace(filePath[0])
	}
	m := &AuditManager{
		logs:     make([]AuditEntry, 0, MaxAuditLogs),
		filePath: fp,
	}
	m.loadLocked()
	return m
}

// Record 记录一条管理操作 (自动生成时间，严格禁止写入密码/令牌)
func (m *AuditManager) Record(ip, action string) {
	if m == nil {
		return
	}
	if ip == "" {
		ip = "127.0.0.1"
	}
	entry := AuditEntry{
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Action: action,
		IP:     ip,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 最新记录插入切片头部
	m.logs = append([]AuditEntry{entry}, m.logs...)
	if len(m.logs) > MaxAuditLogs {
		m.logs = m.logs[:MaxAuditLogs]
	}
	m.SaveLocked()
}

// List 获取最近管理操作列表 (最新的在前)
func (m *AuditManager) List() []AuditEntry {
	if m == nil {
		return []AuditEntry{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]AuditEntry, len(m.logs))
	copy(res, m.logs)
	return res
}

func (m *AuditManager) loadLocked() {
	if m.filePath == "" {
		return
	}
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		return
	}
	var loaded []AuditEntry
	if err := json.Unmarshal(data, &loaded); err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(loaded) > MaxAuditLogs {
		loaded = loaded[:MaxAuditLogs]
	}
	m.logs = loaded
}

func (m *AuditManager) SaveLocked() {
	if m.filePath == "" {
		return
	}
	data, err := json.MarshalIndent(m.logs, "", "  ")
	if err != nil {
		return
	}
	dir := filepath.Dir(m.filePath)
	_ = os.MkdirAll(dir, 0700)

	tmp := fmt.Sprintf("%s.%d.tmp", m.filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Chmod(tmp, 0600)
	if err := os.Rename(tmp, m.filePath); err != nil {
		_ = os.Remove(tmp)
		_ = os.WriteFile(m.filePath, data, 0600)
		_ = os.Chmod(m.filePath, 0600)
	}
}
