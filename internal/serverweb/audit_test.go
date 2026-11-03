package serverweb

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditManager_RecordAndCap(t *testing.T) {
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.json")

	am := NewAuditManager(auditFile)

	am.Record("1.1.1.1", "登录成功")
	am.Record("2.2.2.2", "更新配置")

	list := am.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(list))
	}

	// 最新的记录在前面
	if list[0].Action != "更新配置" || list[0].IP != "2.2.2.2" {
		t.Errorf("unexpected first entry: %+v", list[0])
	}
	if list[1].Action != "登录成功" || list[1].IP != "1.1.1.1" {
		t.Errorf("unexpected second entry: %+v", list[1])
	}

	// 检查文件权限是否为 0600
	st, err := os.Stat(auditFile)
	if err != nil {
		t.Fatalf("stat audit file failed: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected audit file perm 0600, got %o", perm)
	}

	// 插入超过 maxAuditLogs (50) 条记录，验证截断上限
	for i := 0; i < maxAuditLogs+10; i++ {
		am.Record("3.3.3.3", "操作测试")
	}

	listAfter := am.List()
	if len(listAfter) != maxAuditLogs {
		t.Fatalf("expected capped at %d, got %d", maxAuditLogs, len(listAfter))
	}
}

func TestAuditManager_PersistenceAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.json")

	// 实例 1：记录操作并持久化
	am1 := NewAuditManager(auditFile)
	am1.Record("203.0.113.1", "管理员登录成功")
	am1.Record("203.0.113.1", "修改管理账号为 [superadmin] 并更新管理密码")

	// 模拟重启：创建新实例 2 并读取同一文件
	am2 := NewAuditManager(auditFile)
	list := am2.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 reloaded entries, got %d", len(list))
	}

	if list[0].Action != "修改管理账号为 [superadmin] 并更新管理密码" {
		t.Errorf("unexpected entry 0: %+v", list[0])
	}
	if list[1].Action != "管理员登录成功" {
		t.Errorf("unexpected entry 1: %+v", list[1])
	}
}
