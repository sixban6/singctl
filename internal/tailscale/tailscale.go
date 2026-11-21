package tailscale

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"

	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/util/file"
	"singctl/internal/util/netinfo"
	releasepkg "singctl/internal/util/release"
)

const (
	installDir = "/usr/sbin"
)

type Tailscale struct {
	httpClient   *http.Client
	OpenWrtCheck func() bool
	DownloadURL  string
	config       *config.TailscaleConfig
}

func New(downloadURL string, config *config.TailscaleConfig) *Tailscale {
	return &Tailscale{
		httpClient:   http.DefaultClient,
		OpenWrtCheck: netinfo.IsOpenWrt,
		DownloadURL:  downloadURL,
		config:       config,
	}
}

// SelectTailscaleAsset 过滤合适的 Tailscale 发布包
func (t *Tailscale) SelectTailscaleAsset(assetName string) bool {
	arch, err := t.GetSystemArchitecture()
	if err != nil {
		arch = "amd64" // fallback
	}
	return selectTailscaleAssetForArch(assetName, arch)
}

// GetSystemArchitecture 检测系统架构并映射到 Tailscale 的架构命名
func (t *Tailscale) GetSystemArchitecture() (string, error) {
	out, err := exec.Command("uname", "-m").Output()
	if err != nil {
		return "", fmt.Errorf("failed to detect architecture: %w", err)
	}

	arch := strings.TrimSpace(string(out))

	// 映射系统架构到 Tailscale 的架构命名
	switch arch {
	case "x86_64", "amd64":
		return "amd64", nil
	case "aarch64", "arm64":
		return "arm64", nil
	case "armv7l", "armv7":
		return "arm", nil
	case "i386", "i686":
		return "386", nil
	default:
		return "", fmt.Errorf("unsupported architecture: %s", arch)
	}
}

func (t *Tailscale) Install() error {
	logger.Info("Starting Tailscale installation...")

	ctx := context.Background()

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "tailscale-install-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// 直连获取发布元数据（信任锚，不走镜像）；压缩包按连通性选择直连/镜像
	mirror := ""
	if !netinfo.CheckGoogleConnectivity() {
		mirror = t.DownloadURL
		logger.Info("Google appears unreachable, applying mirror config: %s", mirror)
	}
	client := releasepkg.NewClient(mirror)
	client.DirectFirst = netinfo.CheckGoogleConnectivity()
	info, sourceRepo, _, err := fetchTailscaleReleaseInfo(ctx, client)
	if err != nil {
		return fmt.Errorf("无法直连 GitHub API 获取 tailscale 发布信息（为保证供应链安全，元数据不走镜像）: %w", err)
	}

	var asset *releasepkg.Asset
	for i := range info.Assets {
		if t.SelectTailscaleAsset(info.Assets[i].Name) {
			asset = &info.Assets[i]
			break
		}
	}
	if asset == nil {
		return fmt.Errorf("no suitable asset found for OS: %s, Arch: %s", runtime.GOOS, runtime.GOARCH)
	}

	// 若 GitHub API 资产对象暂未附带内联 sha256 digest，回填校验清单 checksums.txt 确保强校验。
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(asset.Digest)), "sha256:") {
		if sums, err := client.FetchChecksums(ctx, sourceRepo, info.TagName, nil, info); err == nil {
			if sum, ok := sums[asset.Name]; ok && sum != "" {
				asset.Digest = "sha256:" + sum
			}
		}
	}

	res, err := client.Download(ctx, *asset, tempDir)
	if err != nil {
		return fmt.Errorf("download tailscale failed: %w", err)
	}
	if res.SHA256Verified {
		logger.Success("✅ sha256 校验通过，与 GitHub 官方 digest 一致 (%s)", asset.Name)
	} else if res.ViaMirror {
		logger.Warn("⚠️ tailscale 经镜像下载；官方元数据无 digest，仅按大小校验（%d 字节），无法进行加密校验", asset.Size)
	}

	extractDir := filepath.Join(tempDir, "extracted")
	if err := releasepkg.Extract(res.Path, extractDir); err != nil {
		return fmt.Errorf("extract tailscale archive failed: %w", err)
	}
	_ = os.Remove(res.Path)

	// 从下载的解压文件中查找二进制文件
	tsBin, err := file.FindExecutable(extractDir, "tailscale")
	if err != nil {
		return fmt.Errorf("tailscale binary not found: %w", err)
	}

	tsdBin, err := file.FindExecutable(extractDir, "tailscaled")
	if err != nil {
		return fmt.Errorf("tailscaled binary not found: %w", err)
	}

	// 拷贝/链接文件（精简合体版保留 tailscale -> tailscaled 软链接以节省一半空间）
	if err := installTailscaleBinaries(tsBin, tsdBin, installDir); err != nil {
		return err
	}

	// 3. Create Init Script
	isOpenWrt := t.OpenWrtCheck()
	logger.Info("Checking for kmod-tun...")
	hasTun := CheckTunModule()
	if hasTun {
		logger.Info("kmod-tun detected, using Scheme 2 (Kernel Mode)")
	} else {
		logger.Info("kmod-tun NOT detected, using Scheme 1 (Userspace Mode)")
	}

	if isOpenWrt {
		logger.Info("Creating procd init script...")
		if err := CreateInitScript(hasTun); err != nil {
			return err
		}
		mgr := servicemgr.NewProcd(nil, filepath.Dir(constant.TailscaleInitdScript))
		svcName := filepath.Base(constant.TailscaleInitdScript)
		logger.Info("Enabling and starting service...")
		if err := mgr.Enable(ctx, svcName); err != nil {
			return fmt.Errorf("enable service failed: %w", err)
		}
		if err := mgr.Start(ctx, svcName); err != nil {
			return fmt.Errorf("start service failed: %w", err)
		}
	} else {
		logger.Info("Creating systemd service script...")
		if err := createSystemdScript(hasTun); err != nil {
			return err
		}
		mgr := servicemgr.NewSystemd(nil)
		logger.Info("Enabling and starting service via servicemgr...")
		if err := mgr.DaemonReload(ctx); err != nil {
			logger.Warn("systemctl daemon-reload failed: %v", err)
		}
		if err := mgr.Enable(ctx, "tailscaled.service"); err != nil {
			return fmt.Errorf("enable tailscaled service failed: %w", err)
		}
		if err := mgr.Start(ctx, "tailscaled.service"); err != nil {
			return fmt.Errorf("start tailscaled service failed: %w", err)
		}
	}

	logger.Success("Tailscale installed successfully")
	logger.Info("Run 'singctl start tailscale' to configure and authenticate your device")
	return nil
}

// StartOptions 控制 Tailscale 启动或在线热重配行为。
type StartOptions struct {
	AdvertiseExitNode    bool
	IsMainRouter         bool
	AcceptRoutesOverride *bool
	Reconfigure          bool // 运行中时强制执行 tailscale up --reset 热切换模式/路由参数
}

// StartWithOptions 按给定选项启动 Tailscale；当 Reconfigure=true 时，允许在已 Running 状态在线热切换模式。
func (t *Tailscale) StartWithOptions(opts StartOptions) error {
	advertiseExitNode := opts.AdvertiseExitNode
	IsMainRouter := opts.IsMainRouter
	acceptRoutesOverride := opts.AcceptRoutesOverride

	logger.Info("Starting Tailscale configuration...")

	hasTun := CheckTunModule()
	if hasTun {
		logger.Info("kmod-tun detected, configuring for Kernel Mode")
	} else {
		logger.Info("kmod-tun NOT detected, configuring for Userspace Mode")
	}

	isOpenWrt := t.OpenWrtCheck()

	// 0. Ensure tailscaled service is running
	logger.Info("Ensuring tailscaled service is running...")
	svcCtx := context.Background()
	if isOpenWrt {
		mgr := servicemgr.NewProcd(nil, filepath.Dir(constant.TailscaleInitdScript))
		if err := mgr.Start(svcCtx, filepath.Base(constant.TailscaleInitdScript)); err != nil {
			logger.Warn("Failed to start tailscaled service: %v", err)
		}
	} else {
		if err := servicemgr.NewSystemd(nil).Start(svcCtx, "tailscaled.service"); err != nil {
			logger.Warn("Failed to start tailscaled service: %v", err)
		}
	}
	// Give it a moment to start and wait for socket
	logger.Info("Waiting for tailscaled socket to initialize...")
	socketPath := "/var/run/tailscale/tailscaled.sock"
	for range 20 {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Ensure the socket exists before 'up'
	if _, err := os.Stat(socketPath); err != nil {
		out, _ := exec.Command("logread", "-e", "tailscale").Output()
		logSnippet := string(out)
		if len(logSnippet) > 1000 {
			logSnippet = logSnippet[len(logSnippet)-1000:]
		}
		logger.Warn("tailscaled logs before crash:\n%s", logSnippet)
		return fmt.Errorf("tailscaled socket didn't become available at %s within timeout", socketPath)
	}

	// 2. Check current status for idempotency / online reconfigure
	statusOut, statusErr := exec.Command(filepath.Join(installDir, "tailscale"), "status", "--json").Output()
	var tsStatus struct {
		BackendState string `json:"BackendState"`
	}
	alreadyRunning := statusErr == nil && json.Unmarshal(statusOut, &tsStatus) == nil && tsStatus.BackendState == "Running"
	shouldRunUp := !alreadyRunning || opts.Reconfigure
	if alreadyRunning {
		if opts.Reconfigure {
			logger.Info("🔄 正在在线热切换 Tailscale 启动模式与路由参数（无需重启服务）...")
		} else {
			logger.Success("Tailscale is already Running, skipping authorization step.")
		}
	}

	// 3. Tailscale Up (Config and Online)
	if shouldRunUp {
		args := []string{"up", "--reset", "--accept-dns=false"}
		if acceptRoutesOverride != nil {
			args = append(args, fmt.Sprintf("--accept-routes=%t", *acceptRoutesOverride))
		} else if IsMainRouter || advertiseExitNode {
			// Router/ExitNode mode should not import foreign routes by default.
			// This avoids route conflicts when local TProxy rules are active.
			args = append(args, "--accept-routes=false")
		} else {
			args = append(args, "--accept-routes=true")
		}

		// Get LAN subnet to advertise (if it's a private network)
		var lanSubnet string
		if t.config != nil {
			lanSubnet = strings.TrimSpace(t.config.Subnets)
		}
		var err error
		if IsMainRouter && lanSubnet == "" {
			logger.Warn("subnets not config will auto detect")
			lanSubnet, err = netinfo.GetLANSubnet()
		}
		if IsMainRouter && err == nil && lanSubnet != "" {
			logger.Info("Detected private LAN subnet: %s, adding to advertise-routes", lanSubnet)
			args = append(args, "--advertise-routes="+lanSubnet)
			if isOpenWrt {
				args = append(args, "--snat-subnet-routes=false")
			}
		} else if IsMainRouter && err != nil {
			logger.Warn("Failed to detect LAN subnet: %v", err)
		} else if IsMainRouter {
			logger.Info("Detected subnet %s is not a private LAN, skipping advertise-routes", lanSubnet)
		}
		//if hasTun {
		//	logger.Info("Open netfilter-mode")
		args = append(args, "--netfilter-mode=off")
		//}
		if advertiseExitNode {
			args = append(args, "--advertise-exit-node")
			logger.Info("Exit node advertisement enabled")
		}

		// Auth Key 改用环境变量传递，避免出现在命令行参数中被 ps aux 泄露；
		// 仅首次/未认证时注入 TS_AUTHKEY，避免在线热切模式时重复提交可能已过期的一次性密钥。
		cmdEnv := os.Environ()
		if !alreadyRunning && t.config != nil && strings.TrimSpace(t.config.AuthKey) != "" {
			cmdEnv = append(cmdEnv, "TS_AUTHKEY="+strings.TrimSpace(t.config.AuthKey))
			logger.Info("Using configured Auth Key for automatic authorization (via TS_AUTHKEY env)")
		}

		cmd := exec.Command(filepath.Join(installDir, "tailscale"), args...)
		cmd.Env = cmdEnv
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("tailscale up failed: %w", err)
		}
	}

	// 3. Optimize UDP GRO for better performance (Tailscale recommendation)
	logger.Info("Optimizing UDP GRO settings for better performance...")
	if err := OptimizeUDPGRO(); err != nil {
		logger.Warn("Failed to optimize UDP GRO (non-critical): %v", err)
	}

	if isOpenWrt {
		// 3. Configure Firewall and Network
		logger.Info("Configuring firewall and network for OpenWrt...")

		// 先清理历史上用 uci add 产生的重复匿名条目
		CleanupTailscaleFirewall()

		// Network interface（命名 section，uci set 天然幂等）
		exec.Command("uci", "set", "network.tailscale=interface").Run()
		exec.Command("uci", "set", "network.tailscale.device=tailscale0").Run()
		exec.Command("uci", "set", "network.tailscale.proto=unmanaged").Run()

		// Firewall zone（改用命名 section "tailscale_zone"，多次运行只写入一次）
		exec.Command("uci", "set", "firewall.tailscale_zone=zone").Run()
		exec.Command("uci", "set", "firewall.tailscale_zone.name=tailscale").Run()
		exec.Command("uci", "set", "firewall.tailscale_zone.network=tailscale").Run()
		exec.Command("uci", "set", "firewall.tailscale_zone.input=ACCEPT").Run()
		exec.Command("uci", "set", "firewall.tailscale_zone.output=ACCEPT").Run()
		exec.Command("uci", "set", "firewall.tailscale_zone.forward=ACCEPT").Run()
		exec.Command("uci", "set", "firewall.tailscale_zone.masq=1").Run()

		// Forwarding rules（同样用命名 section，幂等）
		exec.Command("uci", "set", "firewall.ts_fwd_to_lan=forwarding").Run()
		exec.Command("uci", "set", "firewall.ts_fwd_to_lan.src=tailscale").Run()
		exec.Command("uci", "set", "firewall.ts_fwd_to_lan.dest=lan").Run()

		exec.Command("uci", "set", "firewall.ts_fwd_from_lan=forwarding").Run()
		exec.Command("uci", "set", "firewall.ts_fwd_from_lan.src=lan").Run()
		exec.Command("uci", "set", "firewall.ts_fwd_from_lan.dest=tailscale").Run()

		exec.Command("uci", "set", "firewall.ts_fwd_to_wan=forwarding").Run()
		exec.Command("uci", "set", "firewall.ts_fwd_to_wan.src=tailscale").Run()
		exec.Command("uci", "set", "firewall.ts_fwd_to_wan.dest=wan").Run()

		// Commit and Reload
		exec.Command("uci", "commit", "network").Run()
		exec.Command("uci", "commit", "firewall").Run()
		exec.Command("/etc/init.d/network", "reload").Run()
		exec.Command("/etc/init.d/firewall", "reload").Run()
	}

	logger.Success("Tailscale configured and started")
	return nil
}

// CleanupTailscaleFirewall 删除历史上用 "uci add" 产生的匿名重复 zone/forwarding 条目。
// 匹配规则：zone.name==tailscale 或 forwarding.src/dest==tailscale 的匿名 section。
func CleanupTailscaleFirewall() {
	// 删除所有 name==tailscale 的匿名 zone
	RemoveAnonymousUCISections("firewall", "zone", "name", "tailscale")
	// 删除所有 src==tailscale 或 dest==tailscale 的匿名 forwarding
	RemoveAnonymousUCISections("firewall", "forwarding", "src", "tailscale")
	RemoveAnonymousUCISections("firewall", "forwarding", "dest", "tailscale")
}

// RemoveAnonymousUCISections 找出 config 中类型为 sectionType、且 key==value 的所有匿名
// section，逐一删除。匿名 section 的 ID 格式为 @type[N]。
func RemoveAnonymousUCISections(config, sectionType, key, value string) {
	// uci show <config> 输出所有配置；逐行找匿名 section 中匹配的条目
	out, err := exec.Command("uci", "show", config).Output()
	if err != nil {
		return
	}

	// 收集需要删除的匿名 section index（倒序删除，避免 index 偏移）
	// 行格式示例：firewall.@zone[2].name='tailscale'
	targetPrefix := config + ".@" + sectionType + "["
	matchSuffix := "." + key + "='" + value + "'"

	indexSet := map[int]struct{}{}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, targetPrefix) {
			continue
		}
		if !strings.HasSuffix(strings.TrimRight(line, "\r"), matchSuffix) {
			continue
		}
		// 解析 index：firewall.@zone[2].name=... → 2
		rest := strings.TrimPrefix(line, targetPrefix)
		closeBracket := strings.Index(rest, "]")
		if closeBracket < 0 {
			continue
		}
		var idx int
		if _, err := fmt.Sscanf(rest[:closeBracket], "%d", &idx); err == nil {
			indexSet[idx] = struct{}{}
		}
	}

	// 倒序删除，防止删除后 index 错位
	indices := make([]int, 0, len(indexSet))
	for idx := range indexSet {
		indices = append(indices, idx)
	}
	// 简单冒泡降序 -> 改为使用 slices.SortFunc
	slices.SortFunc(indices, func(a, b int) int {
		return cmp.Compare(b, a)
	})

	for _, idx := range indices {
		section := fmt.Sprintf("%s.@%s[%d]", config, sectionType, idx)
		exec.Command("uci", "delete", section).Run()
		logger.Info("Removed duplicate anonymous section: %s", section)
	}
	if len(indices) > 0 {
		exec.Command("uci", "commit", config).Run()
	}
}

func (t *Tailscale) Stop() error {
	logger.Info("Stopping Tailscale...")

	// 1. Bring down Tailscale connection
	if err := exec.Command(filepath.Join(installDir, "tailscale"), "down").Run(); err != nil {
		logger.Warn("tailscale down failed: %v", err)
	}

	// 2. Stop the service
	stopCtx := context.Background()
	if t.OpenWrtCheck() {
		mgr := servicemgr.NewProcd(nil, filepath.Dir(constant.TailscaleInitdScript))
		if err := mgr.Stop(stopCtx, filepath.Base(constant.TailscaleInitdScript)); err != nil {
			return fmt.Errorf("stop service failed: %w", err)
		}
	} else {
		if err := servicemgr.NewSystemd(nil).Stop(stopCtx, "tailscaled.service"); err != nil {
			return fmt.Errorf("stop systemd service failed: %w", err)
		}
	}

	// 3. Restore UDP GRO settings to default
	logger.Info("Restoring UDP GRO settings to default...")
	if err := RestoreUDPGRO(); err != nil {
		logger.Warn("Failed to restore UDP GRO (non-critical): %v", err)
	}

	logger.Success("Tailscale stopped successfully")
	return nil
}

// ParseVersionOutput 从 "tailscale version" 输出中提取版本号（首行）
func ParseVersionOutput(out string) (string, error) {
	lines := strings.SplitN(strings.TrimSpace(out), "\n", 2)
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", fmt.Errorf("unexpected tailscale version output: %s", out)
	}
	return strings.TrimSpace(lines[0]), nil
}

// getInstalledVersionOf 运行指定二进制文件的版本命令（tailscaled 用 --version，tailscale CLI 用 version）。
func (t *Tailscale) getInstalledVersionOf(binPath string) (string, error) {
	arg := "version"
	if strings.Contains(filepath.Base(binPath), "tailscaled") {
		arg = "--version"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, arg).Output()
	if err != nil {
		return "", fmt.Errorf("failed to run %s %s: %w", binPath, arg, err)
	}
	return ParseVersionOutput(string(out))
}

// installTailscaleBinaries 安装或替换 tailscaled 与 tailscale；若包内 tailscale 为指向 tailscaled 的合体软链接，
// 则保留相对软链接（避免把单二进制重复复制两份导致双倍 Flash 占用）。
func installTailscaleBinaries(tsBin, tsdBin, targetDir string) error {
	targetTSD := filepath.Join(targetDir, "tailscaled")
	targetTS := filepath.Join(targetDir, "tailscale")

	if err := file.InstallOrReplace(tsdBin, targetTSD); err != nil {
		return fmt.Errorf("install tailscaled binary failed: %w", err)
	}

	linfo, lErr := os.Lstat(tsBin)
	tsStat, sErr := os.Stat(tsBin)
	tsdStat, dErr := os.Stat(tsdBin)
	isCombined := (lErr == nil && linfo.Mode()&os.ModeSymlink != 0) ||
		(sErr == nil && dErr == nil && os.SameFile(tsStat, tsdStat))

	if isCombined {
		tmpLink := filepath.Join(targetDir, ".tailscale.tmp-link")
		_ = os.Remove(tmpLink)
		if err := os.Symlink("tailscaled", tmpLink); err != nil {
			return fmt.Errorf("create tailscale symlink: %w", err)
		}
		if err := os.Rename(tmpLink, targetTS); err != nil {
			_ = os.Remove(tmpLink)
			return fmt.Errorf("replace tailscale symlink: %w", err)
		}
		return nil
	}

	if err := file.InstallOrReplace(tsBin, targetTS); err != nil {
		return fmt.Errorf("install tailscale binary failed: %w", err)
	}
	return nil
}

// OptimizeUDPGRO configures UDP GRO settings for better Tailscale performance
// Reference: https://tailscale.com/s/ethtool-config-udp-gro
func OptimizeUDPGRO() error {
	// Check if ethtool is available
	if _, err := exec.LookPath("ethtool"); err != nil {
		return fmt.Errorf("ethtool not found (install with: apk add ethtool or opkg install ethtool)")
	}

	// Get the default route network interface
	out, err := exec.Command("ip", "-o", "route", "get", "8.8.8.8").Output()
	if err != nil {
		return fmt.Errorf("failed to get default route: %w", err)
	}

	// Parse interface name from output (typically field 5)
	fields := strings.Fields(string(out))
	var netdev string
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			netdev = fields[i+1]
			break
		}
	}

	if netdev == "" {
		return fmt.Errorf("could not determine network interface")
	}

	logger.Info("Configuring UDP GRO on interface: %s", netdev)

	// Configure rx-udp-gro-forwarding and rx-gro-list
	cmd := exec.Command("ethtool", "-K", netdev, "rx-udp-gro-forwarding", "on", "rx-gro-list", "off")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ethtool command failed: %w", err)
	}

	logger.Success("UDP GRO optimization applied")
	return nil
}

// RestoreUDPGRO restores UDP GRO settings to default values
func RestoreUDPGRO() error {
	// Check if ethtool is available
	if _, err := exec.LookPath("ethtool"); err != nil {
		return fmt.Errorf("ethtool not found")
	}

	// Get the default route network interface
	out, err := exec.Command("ip", "-o", "route", "get", "8.8.8.8").Output()
	if err != nil {
		return fmt.Errorf("failed to get default route: %w", err)
	}

	// Parse interface name from output
	fields := strings.Fields(string(out))
	var netdev string
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			netdev = fields[i+1]
			break
		}
	}

	if netdev == "" {
		return fmt.Errorf("could not determine network interface")
	}

	logger.Info("Restoring UDP GRO on interface: %s", netdev)

	// Restore to default settings (rx-udp-gro-forwarding off)
	cmd := exec.Command("ethtool", "-K", netdev, "rx-udp-gro-forwarding", "off", "rx-gro-list", "on")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ethtool command failed: %w", err)
	}

	logger.Success("UDP GRO settings restored to default")
	return nil
}

func CheckTunModule() bool {
	// 1. Try to load the tun module. If modprobe succeeds, the module is available.
	if err := exec.Command("modprobe", "tun").Run(); err == nil {
		return true
	}

	// 2. Fallback: exact match "tun" in lsmod (module might already be loaded)
	out, err := exec.Command("lsmod").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) > 0 && parts[0] == "tun" {
				return true
			}
		}
	}

	// NOTE: Do NOT check /dev/net/tun file existence here!
	// A previous "mknod /dev/net/tun" in the init script can create the device node
	// even when the kernel module is not loaded, causing a false positive.
	return false
}

func CreateInitScript(hasTun bool) error {
	scriptPath := constant.TailscaleInitdScript

	content := `#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
STOP=10

start_service() {
`
	if hasTun {
		content += `    # 加载 tun 模块以防未开机加载
    modprobe tun > /dev/null 2>&1

    # 确保 TUN 设备存在
    if [ ! -c /dev/net/tun ]; then
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200
        chmod 0666 /dev/net/tun
    fi

    # 开启转发
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    mkdir -p %s
    mkdir -p /var/run/tailscale

    procd_open_instance
    procd_set_param command /usr/sbin/tailscaled
    
    # 核心差异：移除 userspace-networking，默认使用 tun
    procd_append_param command --state=%s/tailscaled.state
    procd_append_param command --socket=/var/run/tailscale/tailscaled.sock
    procd_append_param command --port=41641
    
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`
	} else {
		content += `    # 开启内核转发(虽然是用户态，但为了路由功能最好开启)
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    mkdir -p %s
    mkdir -p /var/run/tailscale

    procd_open_instance
    procd_set_param command /usr/sbin/tailscaled
    
    # 核心差异：用户态网络模式
    procd_append_param command --tun=userspace-networking
    procd_append_param command --state=%s/tailscaled.state
    procd_append_param command --socket=/var/run/tailscale/tailscaled.sock
    procd_append_param command --port=41641
    
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`
	}

	finalContent := fmt.Sprintf(content, constant.TailscaleStateDir, constant.TailscaleStateDir)
	if err := os.WriteFile(scriptPath, []byte(finalContent), 0755); err != nil {
		return fmt.Errorf("write init script failed: %w", err)
	}
	return nil
}

func createSystemdScript(hasTun bool) error {
	scriptPath := constant.TailscaleSystemdService

	content := `[Unit]
Description=Tailscale node agent
Documentation=https://tailscale.com/kb/
Wants=network-pre.target
After=network-pre.target NetworkManager.service systemd-resolved.service

[Service]
ExecStartPre=/usr/sbin/tailscaled --cleanup
`
	if hasTun {
		content += `ExecStart=/usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock --port=41641
`
	} else {
		content += `ExecStart=/usr/sbin/tailscaled --tun=userspace-networking --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock --port=41641
`
	}
	content += `ExecStopPost=/usr/sbin/tailscaled --cleanup
Restart=on-failure
RuntimeDirectory=tailscale
RuntimeDirectoryMode=0755
StateDirectory=tailscale
StateDirectoryMode=0700
CacheDirectory=tailscale
CacheDirectoryMode=0750
Type=notify

[Install]
WantedBy=multi-user.target
`

	// Ensure directories exist
	os.MkdirAll("/var/lib/tailscale", 0700)
	os.MkdirAll("/var/run/tailscale", 0755)

	if err := os.WriteFile(scriptPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write systemd script failed: %w", err)
	}
	return nil
}
