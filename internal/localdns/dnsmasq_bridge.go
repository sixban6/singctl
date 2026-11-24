// 文件职责：实现「基础模式」（零 sing-box）下 OpenWrt dnsmasq 接管至本地 SmartDNS/AdGuard 的 0600 备份、原子切换与无痕还原。
package localdns

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/common/sysinfo"
	"singctl/internal/platform/servicemgr"
)

const defaultDnsmasqBridgeBackupPath = "/etc/singctl/dnsmasq-bridge-backup.json"

// DnsmasqBridgeDeps 封装 OpenWrt dnsmasq 桥接操作的可替换宿主机 I/O 依赖（零值回退生产默认）。
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

// InspectOpenWrtDnsmasqBridge 检测 OpenWrt dnsmasq 当前是否已接管指向本地防劫持 DNS (127.0.0.1#<port>)。
func InspectOpenWrtDnsmasqBridge(ctx context.Context, dnsPort int, deps DnsmasqBridgeDeps) bool {
	if !deps.isOpenWrt() {
		return false
	}
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

// SyncOpenWrtDnsmasqBridge 在「基础模式」下将 OpenWrt dnsmasq 安全桥接至 127.0.0.1#<dnsPort>，
// 或在切入 sing-box 审计/代理模式时从 0600 快照无痕恢复原上游配置（幂等）。
func SyncOpenWrtDnsmasqBridge(ctx context.Context, enable bool, dnsPort int, deps DnsmasqBridgeDeps) (bool, error) {
	if !deps.isOpenWrt() {
		return false, nil
	}
	wantServer := targetBridgeServer(dnsPort)
	backupFile := deps.backupPath()

	if enable {
		if InspectOpenWrtDnsmasqBridge(ctx, dnsPort, deps) {
			return false, nil
		}
		// 首次接管前备份原有 dnsmasq 上游配置至 0600 文件
		if _, err := os.Stat(backupFile); errors.Is(err, os.ErrNotExist) {
			origNoResolv, _ := deps.runUCI(ctx, "-q", "get", "dhcp.@dnsmasq[0].noresolv")
			origServersRaw, _ := deps.runUCI(ctx, "-q", "get", "dhcp.@dnsmasq[0].server")
			var origServers []string
			for s := range strings.FieldsSeq(origServersRaw) {
				clean := strings.Trim(s, "'\"")
				if clean != "" && !strings.HasPrefix(clean, "127.0.0.1#") {
					origServers = append(origServers, clean)
				}
			}
			snap := dnsmasqBridgeBackup{
				NoResolv: strings.TrimSpace(origNoResolv),
				Servers:  origServers,
			}
			if raw, mErr := json.MarshalIndent(snap, "", "  "); mErr == nil {
				_ = os.MkdirAll(filepath.Dir(backupFile), 0700)
				_ = fsx.WriteAtomic0600(backupFile, append(raw, '\n'))
			}
		}

		if _, err := deps.runUCI(ctx, "set", "dhcp.@dnsmasq[0].noresolv=1"); err != nil {
			return false, fmt.Errorf("uci set dnsmasq noresolv: %w", err)
		}
		_, _ = deps.runUCI(ctx, "delete", "dhcp.@dnsmasq[0].server")
		if _, err := deps.runUCI(ctx, "add_list", "dhcp.@dnsmasq[0].server="+wantServer); err != nil {
			return false, fmt.Errorf("uci add_list dnsmasq server: %w", err)
		}
		if _, err := deps.runUCI(ctx, "commit", "dhcp"); err != nil {
			return false, fmt.Errorf("uci commit dhcp: %w", err)
		}
		if err := deps.reloadDnsmasq(ctx); err != nil {
			return true, fmt.Errorf("reload dnsmasq: %w", err)
		}
		return true, nil
	}

	// Disable / restore
	rawBackup, readErr := os.ReadFile(backupFile)
	hasBackup := readErr == nil && len(rawBackup) > 0
	isBridged := InspectOpenWrtDnsmasqBridge(ctx, dnsPort, deps)
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
