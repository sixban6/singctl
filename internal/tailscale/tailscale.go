package tailscale

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	"singctl/internal/util/file"
	"singctl/internal/util/netinfo"

	"github.com/sixban6/ghinstall"
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
	name := strings.ToLower(assetName)

	if !strings.Contains(name, "tailscale") {
		return false
	}

	arch, err := t.GetSystemArchitecture()
	if err != nil {
		arch = "amd64" // fallback
	}

	if !strings.Contains(name, arch) {
		return false
	}

	if !strings.Contains(name, ".tgz") && !strings.Contains(name, ".tar.gz") {
		return false
	}

	return true
}

// isPrivateSubnet 检查给定 CIDR 是否属于私有网络
func isPrivateSubnet(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	if ip.To4() != nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}
	return false
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
	logger.Info("Starting Tailscale installation via ghinstall...")

	ctx := context.Background()

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "tailscale-install-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	mirror := ""
	if !netinfo.CheckGoogleConnectivity() {
		mirror = t.DownloadURL
		logger.Info("Google appears unreachable, applying mirror config: %s", mirror)
	} else {
		logger.Info("Google is reachable, skipping mirror config.")
	}

	cfg := &ghinstall.Config{
		Github: []ghinstall.Repo{
			{
				URL:       "https://github.com/sixban6/auto_fetch_tailscale",
				OutputDir: tempDir,
			},
		},
		MirrorURL: mirror,
	}

	filter := ghinstall.CustomFilter(func(assets []ghinstall.Asset) (*ghinstall.Asset, error) {
		for _, asset := range assets {
			if t.SelectTailscaleAsset(asset.Name) {
				return &asset, nil
			}
		}
		return nil, fmt.Errorf("no suitable asset found for OS: %s, Arch: %s", runtime.GOOS, runtime.GOARCH)
	})

	if err := ghinstall.InstallWithConfigAndFilter(ctx, cfg, filter); err != nil {
		return fmt.Errorf("install tailscale failed: %w", err)
	}

	// 从下载的解压文件中查找二进制文件
	tsBin, err := file.FindExecutable(tempDir, "tailscale")
	if err != nil {
		return fmt.Errorf("tailscale binary not found: %w", err)
	}

	tsdBin, err := file.FindExecutable(tempDir, "tailscaled")
	if err != nil {
		return fmt.Errorf("tailscaled binary not found: %w", err)
	}

	// 拷贝文件
	if err := file.InstallOrReplace(tsBin, filepath.Join(installDir, "tailscale")); err != nil {
		return err
	}
	if err := file.InstallOrReplace(tsdBin, filepath.Join(installDir, "tailscaled")); err != nil {
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
		// 4. Enable and Start Service
		logger.Info("Enabling and starting service...")
		if err := exec.Command(constant.TailscaleInitdScript, "enable").Run(); err != nil {
			return fmt.Errorf("enable service failed: %w", err)
		}
		if err := exec.Command(constant.TailscaleInitdScript, "start").Run(); err != nil {
			return fmt.Errorf("start service failed: %w", err)
		}
	} else {
		logger.Info("Creating systemd service script...")
		if err := createSystemdScript(hasTun); err != nil {
			return err
		}
		// 4. Enable and Start Service
		logger.Info("Enabling and starting service via systemctl...")
		if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
			logger.Warn("systemctl daemon-reload failed: %v", err)
		}
		if err := exec.Command("systemctl", "enable", "--now", "tailscaled.service").Run(); err != nil {
			return fmt.Errorf("systemctl enable and start service failed: %w", err)
		}
	}

	logger.Success("Tailscale installed successfully")
	logger.Info("Run 'singctl start tailscale' to configure and authenticate your device")
	return nil
}

// Start brings up Tailscale and configures firewall/network rules.
// advertiseExitNode=true also advertises this device as a Tailscale exit node.
func (t *Tailscale) Start(advertiseExitNode bool) error {
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
	if isOpenWrt {
		if err := exec.Command(constant.TailscaleInitdScript, "start").Run(); err != nil {
			logger.Warn("Failed to start tailscaled service: %v", err)
		}
	} else {
		if err := exec.Command("systemctl", "start", "tailscaled.service").Run(); err != nil {
			logger.Warn("Failed to start tailscaled service via systemctl: %v", err)
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

	// 2. Check current status for idempotency
	statusOut, statusErr := exec.Command(filepath.Join(installDir, "tailscale"), "status", "--json").Output()
	var tsStatus struct {
		BackendState string `json:"BackendState"`
	}
	isNeedsAuth := true
	if statusErr == nil {
		if err := json.Unmarshal(statusOut, &tsStatus); err == nil {
			if tsStatus.BackendState == "Running" {
				// 已经 Running 则无需重新 up
				isNeedsAuth = false
				logger.Success("Tailscale is already Running, skipping authorization step.")
			}
		}
	}

	// 3. Tailscale Up (Config and Online)
	if isNeedsAuth {
		args := []string{"up", "--reset", "--accept-dns=false", "--accept-routes=true"}

		// Get LAN subnet to advertise (if it's a private network)
		lanSubnet := t.config.LanIPICDR
		err := errors.New("")
		if t.config.LanIPICDR == "" {
			lanSubnet, err = netinfo.GetLANSubnet()
		}
		if err == nil && lanSubnet != "" && isPrivateSubnet(lanSubnet) {
			logger.Info("Detected private LAN subnet: %s, adding to advertise-routes", lanSubnet)
			args = append(args, "--advertise-routes="+lanSubnet)
			if isOpenWrt {
				args = append(args, "--snat-subnet-routes=false")
			}
		} else if err != nil {
			logger.Warn("Failed to detect LAN subnet: %v", err)
		} else {
			logger.Info("Detected subnet %s is not a private LAN, skipping advertise-routes", lanSubnet)
		}
		if hasTun {
			args = append(args, "--netfilter-mode=on")
		}
		if advertiseExitNode {
			args = append(args, "--advertise-exit-node")
			logger.Info("Exit node advertisement enabled")
		}

		if t.config.AuthKey != "" {
			args = append(args, "--authkey="+t.config.AuthKey)
			logger.Info("Using configured Auth Key for automatic authorization")
		}

		cmd := exec.Command(filepath.Join(installDir, "tailscale"), args...)
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
	if t.OpenWrtCheck() {
		if err := exec.Command(constant.TailscaleInitdScript, "stop").Run(); err != nil {
			return fmt.Errorf("stop service failed: %w", err)
		}
	} else {
		if err := exec.Command("systemctl", "stop", "tailscaled.service").Run(); err != nil {
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

// getInstalledVersionOf 运行指定二进制文件的 version 命令，返回版本号。
func (t *Tailscale) getInstalledVersionOf(binPath string) (string, error) {
	out, err := exec.Command(binPath, "version").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run %s version: %w", binPath, err)
	}
	return ParseVersionOutput(string(out))
}

// getInstalledVersion 返回 tailscale 和 tailscaled 中较旧的版本号。
// 两者都必须达到最新版本，Update() 才能軭行。
func (t *Tailscale) getInstalledVersion() (string, error) {
	clientVer, clientErr := t.getInstalledVersionOf(filepath.Join(installDir, "tailscale"))
	daemonVer, daemonErr := t.getInstalledVersionOf(filepath.Join(installDir, "tailscaled"))

	// 两者都失败，返回客户端的错误
	if clientErr != nil && daemonErr != nil {
		return "", clientErr
	}
	// 仅客户端失败，以守护进程版本为准（会触发更新）
	if clientErr != nil {
		return daemonVer, nil
	}
	// 仅守护进程失败，以客户端版本为准（会触发更新）
	if daemonErr != nil {
		return clientVer, nil
	}
	if clientVer != daemonVer {
		// Log or handle version mismatch if necessary.
		// For now returning clientVer to trigger update
		return clientVer, nil
	}
	return clientVer, nil
}

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// fetchLatestTailscaleVersion 从 auto_fetch_tailscale 的 GitHub Releases 获取最新版本号
func (t *Tailscale) fetchLatestTailscaleVersion() (string, error) {
	url := "https://api.github.com/repos/sixban6/auto_fetch_tailscale/releases/latest"

	// 如果配置了 mirror 并且 Google 不可达，尝试通过镜像拉取 API
	if !netinfo.CheckGoogleConnectivity() && t.DownloadURL != "" {
		// 某些镜像服务可以代理 api.github.com
		mirror := strings.TrimRight(t.DownloadURL, "/")
		if strings.Contains(mirror, "ghproxy") || strings.Contains(mirror, "mirror") {
			// 如果是通用代理前缀，拼上 api 地址
			url = mirror + "/https://api.github.com/repos/sixban6/auto_fetch_tailscale/releases/latest"
		}
	}

	resp, err := t.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned status: %s", resp.Status)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("failed to decode releases response: %w", err)
	}

	// 去掉可能存在的 'v' 前缀
	return strings.TrimPrefix(rel.TagName, "v"), nil
}

// Update 将 Tailscale 更新到最新版 (通过 ghinstall)
func (t *Tailscale) Update() error {
	if t.OpenWrtCheck != nil && !t.OpenWrtCheck() {
		logger.Success("Tailscale update is skipped because system is not OpenWrt")
		return nil
	}

	logger.Info("Checking for Tailscale updates...")

	latestVersion, err := t.fetchLatestTailscaleVersion()
	if err != nil {
		// API 拉取失败，为了保险起见，继续执行安装逻辑，让 ghinstall 尝试最新版
		logger.Warn("Failed to fetch latest version from GitHub API: %v", err)
		latestVersion = "unknown"
	} else {
		logger.Info("Latest Tailscale version: %s", latestVersion)
	}

	installedVer, installErr := t.getInstalledVersion()
	if installErr != nil {
		logger.Warn("Could not determine installed versions (%v), proceeding with update...", installErr)
	} else if latestVersion != "unknown" && installedVer == latestVersion {
		logger.Success("Tailscale is already up to date (%s)", latestVersion)
		return nil
	} else if latestVersion != "unknown" {
		logger.Info("Updating Tailscale from %s to %s via ghinstall...", installedVer, latestVersion)
	} else {
		logger.Info("Updating Tailscale via ghinstall...")
	}

	ctx := context.Background()

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "tailscale-update-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	mirror := ""
	if !netinfo.CheckGoogleConnectivity() {
		mirror = t.DownloadURL
		logger.Info("Google appears unreachable, applying mirror config: %s", mirror)
	} else {
		logger.Info("Google is reachable, skipping mirror config.")
	}

	cfg := &ghinstall.Config{
		Github: []ghinstall.Repo{
			{
				URL:       "https://github.com/sixban6/auto_fetch_tailscale",
				OutputDir: tempDir,
			},
		},
		MirrorURL: mirror,
	}

	filter := ghinstall.CustomFilter(func(assets []ghinstall.Asset) (*ghinstall.Asset, error) {
		for _, asset := range assets {
			if t.SelectTailscaleAsset(asset.Name) {
				return &asset, nil
			}
		}
		return nil, fmt.Errorf("no suitable asset found for OS: %s, Arch: %s", runtime.GOOS, runtime.GOARCH)
	})

	if err := ghinstall.InstallWithConfigAndFilter(ctx, cfg, filter); err != nil {
		return fmt.Errorf("download tailscale update failed: %w", err)
	}

	tsBin, err := file.FindExecutable(tempDir, "tailscale")
	if err != nil {
		return fmt.Errorf("tailscale binary not found: %w", err)
	}

	tsdBin, err := file.FindExecutable(tempDir, "tailscaled")
	if err != nil {
		return fmt.Errorf("tailscaled binary not found: %w", err)
	}

	// 6. 停止服务，替换二进制文件，重启服务
	logger.Info("Stopping tailscale service before replacing binaries...")
	if err := stopTailscaledProcess(t.OpenWrtCheck()); err != nil {
		logger.Warn("Stop may be incomplete: %v", err)
	}

	if err := file.InstallOrReplace(tsBin, filepath.Join(installDir, "tailscale")); err != nil {
		return fmt.Errorf("replace tailscale binary failed: %w", err)
	}
	if err := file.InstallOrReplace(tsdBin, filepath.Join(installDir, "tailscaled")); err != nil {
		return fmt.Errorf("replace tailscaled binary failed: %w", err)
	}

	logger.Info("Restarting tailscale service...")
	if t.OpenWrtCheck() {
		if err := exec.Command(constant.TailscaleInitdScript, "start").Run(); err != nil {
			return fmt.Errorf("restart service failed: %w", err)
		}
	} else {
		if err := exec.Command("systemctl", "start", "tailscaled.service").Run(); err != nil {
			return fmt.Errorf("restart systemd service failed: %w", err)
		}
	}

	logger.Success("Tailscale updated successfully")
	return nil
}

// stopTailscaledProcess 先通过 init.d 或 systemctl 优雅停止服务，再用 killall -9 确保进程退出，
// 最后轮询等待 tailscaled 进程消失，防止替换二进制时出现 "text file busy" 错误。
func stopTailscaledProcess(isOpenWrt bool) error {
	// 1. 优雅停止
	if isOpenWrt {
		exec.Command(constant.TailscaleInitdScript, "stop").Run()
	} else {
		exec.Command("systemctl", "stop", "tailscaled.service").Run()
	}

	// 2. 强制杀掉仍在运行的 tailscaled（忽略 "no process" 错误）
	exec.Command("killall", "-9", "tailscaled").Run()

	// 3. 轮询等待进程彻底消失（最多 5 秒）
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		// "pgrep -x tailscaled" 退出码非 0 表示进程已不存在
		if err := exec.Command("pgrep", "-x", "tailscaled").Run(); err != nil {
			return nil // 进程已退出
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("tailscaled process did not exit within timeout")
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

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source failed: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create dest failed: %w", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("copy failed: %w", err)
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
