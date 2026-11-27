// 文件职责：提供 Tailscale 软件包安装、合体软链接部署、在线热切换启动与停止编排。
package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/common/netx"
	releasepkg "singctl/internal/common/release"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
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
		OpenWrtCheck: sysinfo.IsOpenWrt,
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
	return SelectTailscaleAssetForArch(assetName, arch)
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

	tempDir, err := os.MkdirTemp("", "tailscale-install-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// 直连获取发布元数据（信任锚，不走镜像）；压缩包按连通性选择直连/镜像
	mirror := ""
	if !netx.CheckGoogleConnectivity() {
		mirror = t.DownloadURL
		logger.Info("Google appears unreachable, applying mirror config: %s", mirror)
	}
	client := releasepkg.NewClient(mirror)
	client.DirectFirst = netx.CheckGoogleConnectivity()
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

	tsBin, err := fsx.FindExecutable(extractDir, "tailscale")
	if err != nil {
		return fmt.Errorf("tailscale binary not found: %w", err)
	}

	tsdBin, err := fsx.FindExecutable(extractDir, "tailscaled")
	if err != nil {
		return fmt.Errorf("tailscaled binary not found: %w", err)
	}

	if err := InstallTailscaleBinaries(tsBin, tsdBin, installDir); err != nil {
		return err
	}

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
	logger.Info("Waiting for tailscaled socket to initialize...")
	socketPath := DefaultTailscaledSocket
	for range 20 {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if _, err := os.Stat(socketPath); err != nil {
		out, _ := exec.Command("logread", "-e", "tailscale").Output()
		logSnippet := string(out)
		if len(logSnippet) > 1000 {
			logSnippet = logSnippet[len(logSnippet)-1000:]
		}
		logger.Warn("tailscaled logs before crash:\n%s", logSnippet)
		return fmt.Errorf("tailscaled socket didn't become available at %s within timeout", socketPath)
	}

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

	if shouldRunUp {
		args := []string{"up", "--reset", "--accept-dns=false"}
		if acceptRoutesOverride != nil {
			args = append(args, fmt.Sprintf("--accept-routes=%t", *acceptRoutesOverride))
		} else if IsMainRouter || advertiseExitNode {
			args = append(args, "--accept-routes=false")
		} else {
			args = append(args, "--accept-routes=true")
		}

		var lanSubnet string
		if t.config != nil {
			lanSubnet = strings.TrimSpace(t.config.Subnets)
		}
		var err error
		if IsMainRouter && lanSubnet == "" {
			logger.Warn("subnets not config will auto detect")
			lanSubnet, err = netx.GetLANSubnet()
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
		args = append(args, "--netfilter-mode=off")
		if advertiseExitNode {
			args = append(args, "--advertise-exit-node")
			logger.Info("Exit node advertisement enabled")
		}

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

	logger.Info("Optimizing UDP GRO settings for better performance...")
	if err := OptimizeUDPGRO(); err != nil {
		logger.Warn("Failed to optimize UDP GRO (non-critical): %v", err)
	}

	if isOpenWrt {
		configureOpenWrtTailscaleFirewall()
	}

	if runtime.GOOS == "linux" {
		t.syncLANShieldBestEffort(isOpenWrt, IsMainRouter)
	}

	logger.Success("Tailscale configured and started")
	return nil
}

func (t *Tailscale) syncLANShieldBestEffort(isOpenWrt, advertiseLAN bool) {
	sCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var localCIDRs []string
	if t.config != nil && strings.TrimSpace(t.config.Subnets) != "" {
		localCIDRs = append(localCIDRs, t.config.Subnets)
	}
	if sub, err := netx.GetLANSubnet(); err == nil && sub != "" {
		localCIDRs = append(localCIDRs, sub)
	}
	lanIP := ""
	if ni, err := netx.GetWithTimeout(2 * time.Second); err == nil && ni != nil {
		lanIP = ni.LANIPv4
	}
	if err := SyncLANCoexistenceShield(sCtx, LANShieldOptions{
		BinPath:            filepath.Join(installDir, "tailscale"),
		LocalCIDRs:         localCIDRs,
		LocalLANIP:         lanIP,
		AdvertiseLocalLAN:  advertiseLAN,
		IsOpenWrt:          isOpenWrt,
		EnsureNetfilterOff: isOpenWrt,
	}); err != nil {
		logger.Warn("同步 Tailscale 内网防劫持护盾失败（非致命）: %v", err)
	}
}

func (t *Tailscale) Stop() error {
	logger.Info("Stopping Tailscale...")

	if err := exec.Command(filepath.Join(installDir, "tailscale"), "down").Run(); err != nil {
		logger.Warn("tailscale down failed: %v", err)
	}

	if runtime.GOOS == "linux" {
		rCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = RemoveLANCoexistenceShield(rCtx, nil)
		cancel()
	}

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

// InstallTailscaleBinaries 安装或替换 tailscaled 与 tailscale；若包内 tailscale 为指向 tailscaled 的合体软链接，
// 则保留相对软链接（避免把单二进制重复复制两份导致双倍 Flash 占用）。
func InstallTailscaleBinaries(tsBin, tsdBin, targetDir string) error {
	targetTSD := filepath.Join(targetDir, "tailscaled")
	targetTS := filepath.Join(targetDir, "tailscale")

	if err := fsx.InstallOrReplace(tsdBin, targetTSD); err != nil {
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

	if err := fsx.InstallOrReplace(tsBin, targetTS); err != nil {
		return fmt.Errorf("install tailscale binary failed: %w", err)
	}
	return nil
}
