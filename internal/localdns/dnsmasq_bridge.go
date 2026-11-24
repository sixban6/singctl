// 文件职责：提供历史基础模式遗留 OpenWrt dnsmasq 桥接快照（/etc/singctl/dnsmasq-bridge-backup.json）的无痕幂等还原清理。
package localdns

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/platform/servicemgr"
)

const defaultDnsmasqBridgeBackupPath = "/etc/singctl/dnsmasq-bridge-backup.json"

// DnsmasqBridgeDeps 封装 OpenWrt dnsmasq 历史桥接还原操作的可替换宿主机 I/O 依赖（零值回退生产默认）。
type DnsmasqBridgeDeps struct {
	IsOpenWrt     func() bool
	RunUCI        func(ctx context.Context, args ...string) (string, error)
	ReloadDnsmasq func(ctx context.Context) error
	BackupPath    string
}

type dnsmasqBridgeBackup struct {
	NoResolv string   `json:"noresolv"`
	Servers  []string `json:"servers,omitempty"`
}

func (d DnsmasqBridgeDeps) isOpenWrt() bool {
	if d.IsOpenWrt != nil {
		return d.IsOpenWrt()
	}
	if runtime.GOOS != "linux" || !sysinfo.IsOpenWrt() {
		return false
	}
	_, err := exec.LookPath("uci")
	return err == nil
}

func (d DnsmasqBridgeDeps) runUCI(ctx context.Context, args ...string) (string, error) {
	if d.RunUCI != nil {
		return d.RunUCI(ctx, args...)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "uci", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (d DnsmasqBridgeDeps) reloadDnsmasq(ctx context.Context) error {
	if d.ReloadDnsmasq != nil {
		return d.ReloadDnsmasq(ctx)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	mgr := servicemgr.Detect(nil)
	if mgr.Kind() == servicemgr.InitProcd {
		return mgr.Reload(ctx, "dnsmasq")
	}
	return nil
}

func (d DnsmasqBridgeDeps) backupPath() string {
	return cmp.Or(strings.TrimSpace(d.BackupPath), defaultDnsmasqBridgeBackupPath)
}

func targetBridgeServer(dnsPort int) string {
	if dnsPort <= 0 || dnsPort > 65535 {
		dnsPort = 5353
	}
	return "127.0.0.1#" + strconv.Itoa(dnsPort)
}

func isLegacyBridged(ctx context.Context, dnsPort int, deps DnsmasqBridgeDeps) bool {
	noResolv, _ := deps.runUCI(ctx, "-q", "get", "dhcp.@dnsmasq[0].noresolv")
	if strings.TrimSpace(noResolv) != "1" {
		return false
	}
	serversRaw, _ := deps.runUCI(ctx, "-q", "get", "dhcp.@dnsmasq[0].server")
	want := targetBridgeServer(dnsPort)
	for field := range strings.FieldsSeq(serversRaw) {
		if strings.Trim(field, "'\"") == want {
			return true
		}
	}
	return false
}

// RestoreLegacyOpenWrtDnsmasqBridge 幂等清理早期版本基础模式遗留的 OpenWrt dnsmasq 桥接配置与 0600 备份快照；
// 无遗留快照且未处于桥接状态时直接返回 (false, nil)。
func RestoreLegacyOpenWrtDnsmasqBridge(ctx context.Context, dnsPort int, deps DnsmasqBridgeDeps) (bool, error) {
	if !deps.isOpenWrt() {
		return false, nil
	}
	backupFile := deps.backupPath()
	rawBackup, readErr := os.ReadFile(backupFile)
	hasBackup := readErr == nil && len(rawBackup) > 0
	isBridged := isLegacyBridged(ctx, dnsPort, deps)
	if !hasBackup && !isBridged {
		return false, nil
	}

	if hasBackup {
		var snap dnsmasqBridgeBackup
		if err := json.Unmarshal(rawBackup, &snap); err == nil {
			if snap.NoResolv != "" {
				_, _ = deps.runUCI(ctx, "set", "dhcp.@dnsmasq[0].noresolv="+snap.NoResolv)
			} else {
				_, _ = deps.runUCI(ctx, "delete", "dhcp.@dnsmasq[0].noresolv")
			}
			_, _ = deps.runUCI(ctx, "delete", "dhcp.@dnsmasq[0].server")
			for _, srv := range snap.Servers {
				if strings.TrimSpace(srv) != "" {
					_, _ = deps.runUCI(ctx, "add_list", "dhcp.@dnsmasq[0].server="+srv)
				}
			}
		}
		_ = os.Remove(backupFile)
	} else {
		_, _ = deps.runUCI(ctx, "delete", "dhcp.@dnsmasq[0].noresolv")
		_, _ = deps.runUCI(ctx, "delete", "dhcp.@dnsmasq[0].server")
	}
	if _, err := deps.runUCI(ctx, "commit", "dhcp"); err != nil {
		return false, fmt.Errorf("uci commit dhcp restore: %w", err)
	}
	if err := deps.reloadDnsmasq(ctx); err != nil {
		return true, fmt.Errorf("reload dnsmasq restore: %w", err)
	}
	return true, nil
}
