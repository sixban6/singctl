// 文件职责：定义 Tailscale 两阶段零失联升级状态机、发布版本预检（Preflight）与 SafeUpdate 主编排入口。
package tailscale

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"singctl/internal/common/fsx"
	"singctl/internal/common/netx"
	"singctl/internal/common/proc"
	releasepkg "singctl/internal/common/release"
	"singctl/internal/common/sysinfo"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"strconv"
	"strings"
	"time"
)

const (
	// TailscaleSwapHandoffMarker is emitted to stdout right before handing off to the
	// detached POSIX swapper so WebUI / runner can detect the zero-lockout handoff cleanly.
	TailscaleSwapHandoffMarker = "SINGCTL_TS_SWAP_HANDOFF"

	// tailscaleReleaseRepo 与 tailscaleReleaseTag 为本仓库统一托管的 Tailscale 精简合体包发布通道。
	// 使用独立 prerelease tag（tailscale-latest）避免干扰 singctl 自身的 /releases/latest 自更新接口。
	tailscaleReleaseRepo = constant.GitHubRepo
	tailscaleReleaseTag  = "tailscale-latest"
	// legacyAutoFetchRepo 为历史独立编译仓库，仅当主通道首次构建尚未就绪（HTTP 404）时平滑兜底。
	legacyAutoFetchRepo = "sixban6/auto_fetch_tailscale"

	defaultUpgradeStateFile = "/tmp/singctl-ts-upgrade.state"
	defaultUpgradeLogFile   = "/tmp/singctl-ts-upgrade.log"
	defaultUpgradeLockFile  = "/tmp/singctl-ts-upgrade.lock"
	defaultUpgradeSystemd   = "tailscaled.service"

	StagedTailscaledName = ".tailscaled.new"
	StagedTailscaleName  = ".tailscale.new"
	stagedTailscaledName = StagedTailscaledName
	stagedTailscaleName  = StagedTailscaleName

	upgradeFlashSafetyMarginBytes int64 = 4 << 20   // 4 MiB safety margin alongside staged files
	maxBinaryExtractBytes         int64 = 256 << 20 // 256 MiB defensive cap per entry
	maxLogTailBytes               int64 = 8192
)

const (
	UpgradePhaseIdle       = "idle"
	UpgradePhaseStaging    = "staging"
	UpgradePhaseSwapping   = "swapping"
	UpgradePhaseVerifying  = "verifying"
	UpgradePhaseSucceeded  = "succeeded"
	UpgradePhaseRolledBack = "rolled_back"
	UpgradePhaseFailed     = "failed"
)

var releaseVersionRe = regexp.MustCompile(`tailscale_([\d\.]+)_`)

// UpgradePaths allows tests and E2E harnesses to isolate filesystem targets cleanly.
type UpgradePaths struct {
	InstallDir  string
	StateFile   string
	LogFile     string
	LockFile    string
	SocketPath  string
	InitScript  string
	SystemdUnit string
}

func (p UpgradePaths) withDefaults() UpgradePaths {
	p.InstallDir = cmp.Or(strings.TrimSpace(p.InstallDir), installDir)
	p.StateFile = cmp.Or(strings.TrimSpace(p.StateFile), defaultUpgradeStateFile)
	p.LogFile = cmp.Or(strings.TrimSpace(p.LogFile), defaultUpgradeLogFile)
	p.LockFile = cmp.Or(strings.TrimSpace(p.LockFile), defaultUpgradeLockFile)
	p.SocketPath = cmp.Or(strings.TrimSpace(p.SocketPath), DefaultTailscaledSocket)
	p.InitScript = cmp.Or(strings.TrimSpace(p.InitScript), constant.TailscaleInitdScript)
	p.SystemdUnit = cmp.Or(strings.TrimSpace(p.SystemdUnit), defaultUpgradeSystemd)
	return p
}

// UpgradeOptions controls transactional Tailscale upgrade preflight and execution.
type UpgradeOptions struct {
	Force            bool
	DryRun           bool
	Wait             bool
	HealthTimeoutSec int // Default 25, clamped 5..60
	GraceDelaySec    int // Default 2 when 0; negative -> 0; clamped 0..5

	Paths              UpgradePaths
	ReleaseClient      *releasepkg.Client
	ArchOverride       string
	LinuxCheck         func() bool
	StatfsFn           func(string) (uint64, error)
	MemInfoFn          func() (uint64, uint64)
	InitSystemOverride string
}

func (o UpgradeOptions) normalizedHealthTimeout() int {
	if o.HealthTimeoutSec <= 0 {
		return 25
	}
	return min(max(o.HealthTimeoutSec, 5), 60)
}

func (o UpgradeOptions) normalizedGraceDelay() int {
	if o.GraceDelaySec == 0 {
		return 2
	}
	if o.GraceDelaySec < 0 {
		return 0
	}
	return min(o.GraceDelaySec, 5)
}

// UpgradeState represents persisted transactional upgrade progress written atomically with 0600.
type UpgradeState struct {
	Phase                string `json:"phase"`
	FromVersion          string `json:"fromVersion,omitempty"`
	ToVersion            string `json:"toVersion,omitempty"`
	Arch                 string `json:"arch,omitempty"`
	Combined             bool   `json:"combined"`
	Force                bool   `json:"force"`
	StartedAt            string `json:"startedAt,omitempty"`
	UpdatedAt            string `json:"updatedAt,omitempty"`
	FinishedAt           string `json:"finishedAt,omitempty"`
	FlashFreeBeforeBytes uint64 `json:"flashFreeBeforeBytes,omitempty"`
	FlashFreeAfterBytes  uint64 `json:"flashFreeAfterBytes,omitempty"`
	Message              string `json:"message,omitempty"`
	Error                string `json:"error,omitempty"`
	RolledBack           bool   `json:"rolledBack"`
	LogTail              string `json:"logTail,omitempty"`
	SwapperPID           int    `json:"swapperPid,omitempty"`
}

// UpgradePreflight describes pre-upgrade checks surfaced to CLI --dry-run and WebUI drawer.
type UpgradePreflight struct {
	Supported             bool          `json:"supported"`
	UnsupportedReason     string        `json:"unsupportedReason,omitempty"`
	Arch                  string        `json:"arch,omitempty"`
	IsOpenWrt             bool          `json:"isOpenWrt"`
	InitSystem            string        `json:"initSystem,omitempty"`
	CurrentVersion        string        `json:"currentVersion,omitempty"`
	LatestVersion         string        `json:"latestVersion,omitempty"`
	UpToDate              bool          `json:"upToDate"`
	AssetName             string        `json:"assetName,omitempty"`
	AssetSizeBytes        int64         `json:"assetSizeBytes,omitempty"`
	EstimatedInstallBytes int64         `json:"estimatedInstallBytes,omitempty"`
	RequiredFreeBytes     int64         `json:"requiredFreeBytes,omitempty"`
	CombinedMinimal       bool          `json:"combinedMinimal"`
	HasOfficialDigest     bool          `json:"hasOfficialDigest"`
	FlashFreeBytes        uint64        `json:"flashFreeBytes"`
	MemAvailableBytes     uint64        `json:"memAvailableBytes"`
	SwapFreeBytes         uint64        `json:"swapFreeBytes"`
	TailscaleRunning      bool          `json:"tailscaleRunning"`
	BackendState          string        `json:"backendState,omitempty"`
	CanProceed            bool          `json:"canProceed"`
	CanForceProceed       bool          `json:"canForceProceed"`
	BlockedReasons        []string      `json:"blockedReasons,omitempty"`
	Warnings              []string      `json:"warnings,omitempty"`
	ViaTailscale          bool          `json:"viaTailscale"`
	ActiveSwap            *UpgradeState `json:"activeSwap,omitempty"`

	selectedAsset *releasepkg.Asset
	client        *releasepkg.Client
}

// SelectedAsset 返回预检阶段匹配到的目标发布资产元数据。
func (p *UpgradePreflight) SelectedAsset() *releasepkg.Asset {
	if p == nil {
		return nil
	}
	return p.selectedAsset
}

// ReadUpgradeState reads the persisted swapper state (if present) and attaches tail of LogFile.
func ReadUpgradeState(paths UpgradePaths) (*UpgradeState, error) {
	paths = paths.withDefaults()
	raw, err := os.ReadFile(paths.StateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &UpgradeState{Phase: UpgradePhaseIdle}, nil
		}
		return nil, fmt.Errorf("read upgrade state: %w", err)
	}
	var st UpgradeState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("decode upgrade state: %w", err)
	}
	if st.Phase == "" {
		st.Phase = UpgradePhaseIdle
	}
	if (st.Phase == UpgradePhaseSwapping || st.Phase == UpgradePhaseVerifying) && st.SwapperPID > 0 && !proc.IsAlive(st.SwapperPID) {
		st.Phase = UpgradePhaseFailed
		if st.Error == "" {
			st.Error = "后台切换进程已意外退出"
		}
	}
	st.LogTail = readLogTail(paths.LogFile, maxLogTailBytes)
	return &st, nil
}

// WriteUpgradeState writes UpgradeState atomically with strict 0600 file permissions.
func WriteUpgradeState(paths UpgradePaths, st *UpgradeState) error {
	if st == nil {
		return fmt.Errorf("upgrade state is nil")
	}
	paths = paths.withDefaults()
	if err := os.MkdirAll(filepath.Dir(paths.StateFile), 0755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	copyState := *st
	copyState.LogTail = ""
	if copyState.UpdatedAt == "" {
		copyState.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	data, err := json.Marshal(copyState)
	if err != nil {
		return fmt.Errorf("marshal upgrade state: %w", err)
	}
	if err := fsx.WriteAtomic0600(paths.StateFile, data); err != nil {
		return fmt.Errorf("write upgrade state: %w", err)
	}
	return nil
}

func readLogTail(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return ""
	}
	size := info.Size()
	if size > maxBytes {
		if _, err := f.Seek(size-maxBytes, io.SeekStart); err != nil {
			return ""
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SelectTailscaleAssetForArch 按严格边界匹配目标架构的 Tailscale 归档包名。
func SelectTailscaleAssetForArch(assetName, arch string) bool {
	return selectTailscaleAssetForArch(assetName, arch)
}

func selectTailscaleAssetForArch(assetName, arch string) bool {
	name := strings.ToLower(strings.TrimSpace(assetName))
	arch = strings.ToLower(strings.TrimSpace(arch))
	if arch == "" || !strings.Contains(name, "tailscale") {
		return false
	}
	if !strings.HasSuffix(name, ".tgz") && !strings.HasSuffix(name, ".tar.gz") {
		return false
	}
	// Require delimiter boundaries so "arm" never matches "arm64".
	return strings.Contains(name, "_"+arch+".") ||
		strings.Contains(name, "_"+arch+"_") ||
		strings.Contains(name, "-"+arch+".") ||
		strings.Contains(name, "-"+arch+"-")
}

func (t *Tailscale) resolveArch(override string) (string, error) {
	if s := strings.TrimSpace(override); s != "" {
		return s, nil
	}
	if arch, err := t.GetSystemArchitecture(); err == nil && arch != "" {
		return arch, nil
	}
	switch runtime.GOARCH {
	case "amd64", "arm64", "arm", "386":
		return runtime.GOARCH, nil
	default:
		return "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}
}

func (t *Tailscale) newReleaseClient(override *releasepkg.Client) *releasepkg.Client {
	if override != nil {
		return override
	}
	directOK := netx.CheckGoogleConnectivity()
	mirror := ""
	if !directOK {
		mirror = t.DownloadURL
	}
	c := releasepkg.NewClient(mirror)
	c.DirectFirst = directOK
	c.HTTP = &http.Client{Timeout: 120 * time.Second}
	return c
}

// PreflightUpgrade evaluates target compatibility, latest release metadata, disk/RAM margins, and active swap state.
func (t *Tailscale) PreflightUpgrade(ctx context.Context, opts UpgradeOptions) (*UpgradePreflight, error) {
	paths := opts.Paths.withDefaults()
	isLinux := runtime.GOOS == "linux"
	if opts.LinuxCheck != nil {
		isLinux = opts.LinuxCheck()
	}
	if !isLinux {
		return &UpgradePreflight{
			Supported:         false,
			UnsupportedReason: "仅支持 Linux / OpenWrt 系统，当前系统请使用 Tailscale 官方客户端",
			Arch:              cmp.Or(opts.ArchOverride, runtime.GOARCH),
		}, nil
	}

	isOpenWrt := false
	if t.OpenWrtCheck != nil {
		isOpenWrt = t.OpenWrtCheck()
	}
	initSys := detectInitSystem(paths, isOpenWrt, opts.InitSystemOverride)

	arch, archErr := t.resolveArch(opts.ArchOverride)
	clientVer, clientErr := t.getInstalledVersionOf(filepath.Join(paths.InstallDir, "tailscale"))
	daemonVer, daemonErr := t.getInstalledVersionOf(filepath.Join(paths.InstallDir, "tailscaled"))
	installedEqual := clientErr == nil && daemonErr == nil && clientVer != "" && clientVer == daemonVer
	currentVer := cmp.Or(clientVer, daemonVer)

	backendState, tsRunning := queryTailscaleLocalState(ctx, paths)

	statfsFn := opts.StatfsFn
	if statfsFn == nil {
		statfsFn = func(p string) (uint64, error) {
			ds, err := sysinfo.Statfs(p)
			return ds.AvailBytes, err
		}
	}
	flashFree, flashErr := statfsFn(paths.InstallDir)

	memInfoFn := opts.MemInfoFn
	if memInfoFn == nil {
		memInfoFn = func() (uint64, uint64) {
			mi, _ := sysinfo.ReadMemInfo()
			return mi.AvailableBytes, mi.SwapFreeBytes
		}
	}
	memAvail, swapFree := memInfoFn()

	activeSwap, _ := ReadUpgradeState(paths)

	pre := &UpgradePreflight{
		Supported:         true,
		Arch:              arch,
		IsOpenWrt:         isOpenWrt,
		InitSystem:        initSys,
		CurrentVersion:    currentVer,
		CombinedMinimal:   arch == "arm64",
		FlashFreeBytes:    flashFree,
		MemAvailableBytes: memAvail,
		SwapFreeBytes:     swapFree,
		TailscaleRunning:  tsRunning,
		BackendState:      backendState,
		ActiveSwap:        activeSwap,
	}

	if archErr != nil {
		pre.BlockedReasons = append(pre.BlockedReasons, fmt.Sprintf("不支持的系统架构: %v", archErr))
	}
	if initSys == "unknown" {
		pre.BlockedReasons = append(pre.BlockedReasons, "未检测到 OpenWrt procd (/etc/init.d/tailscale) 或 systemd 服务管理器")
	}
	if activePID := readActiveLockPID(paths.LockFile); activePID > 0 {
		pre.BlockedReasons = append(pre.BlockedReasons, fmt.Sprintf("已有 Tailscale 升级切换任务在后台运行中 (PID %d)", activePID))
	}
	if currentVer == "" {
		pre.Warnings = append(pre.Warnings, "当前未检测到已安装的 Tailscale 二进制，本次操作将尝试执行下载修复并启动")
	} else if !installedEqual {
		pre.Warnings = append(pre.Warnings, fmt.Sprintf("检测到 tailscale (%s) 与 tailscaled (%s) 版本不一致，建议执行更新对齐", cmp.Or(clientVer, "缺失"), cmp.Or(daemonVer, "缺失")))
	}

	client := t.newReleaseClient(opts.ReleaseClient)
	pre.client = client

	metaCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	info, sourceRepo, unifiedChannel, err := fetchTailscaleReleaseInfo(metaCtx, client)
	if err != nil {
		pre.BlockedReasons = append(pre.BlockedReasons, fmt.Sprintf("无法直连 GitHub API 获取发布元数据: %v", err))
		return pre, nil
	}

	var matched *releasepkg.Asset
	if arch != "" {
		for i := range info.Assets {
			if selectTailscaleAssetForArch(info.Assets[i].Name, arch) {
				matched = &info.Assets[i]
				break
			}
		}
	}
	if matched == nil {
		pre.BlockedReasons = append(pre.BlockedReasons, fmt.Sprintf("发布列表中未找到匹配架构 %q 的 Tailscale 压缩包", arch))
		return pre, nil
	}

	// Fallback to checksums.txt if GitHub Release API asset digest is empty.
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(matched.Digest)), "sha256:") {
		if sums, err := client.FetchChecksums(metaCtx, sourceRepo, info.TagName, nil, info); err == nil {
			if sum, ok := sums[matched.Name]; ok && sum != "" {
				matched.Digest = "sha256:" + sum
			}
		}
	}

	// 本仓库统一通道下 AMD64 与 ARM64 均采用精简合体构建（<24 MiB 且 tailscale -> tailscaled）；
	// 若走历史旧仓兜底，则按架构与包体积区分精简合体版与标准双二进制包。
	isMinimal := unifiedChannel || arch == "arm64" || (matched.Size > 0 && matched.Size < 24<<20)
	pre.CombinedMinimal = isMinimal
	pre.selectedAsset = matched
	pre.AssetName = matched.Name
	pre.AssetSizeBytes = matched.Size
	pre.HasOfficialDigest = strings.HasPrefix(strings.ToLower(strings.TrimSpace(matched.Digest)), "sha256:")

	if m := releaseVersionRe.FindStringSubmatch(matched.Name); len(m) > 1 {
		pre.LatestVersion = m[1]
	} else {
		pre.LatestVersion = strings.TrimPrefix(strings.TrimSpace(info.TagName), "v")
	}

	est := estimateUnpackedInstallBytes(matched.Size, isMinimal)
	pre.EstimatedInstallBytes = est
	pre.RequiredFreeBytes = est + upgradeFlashSafetyMarginBytes

	if flashErr != nil {
		pre.Warnings = append(pre.Warnings, fmt.Sprintf("无法读取 %s 所在分区剩余空间: %v", paths.InstallDir, flashErr))
	} else if int64(flashFree) < pre.RequiredFreeBytes {
		pre.BlockedReasons = append(pre.BlockedReasons, fmt.Sprintf(
			"可用存储空间不足：剩余 %s，安全零失联切换（含回滚备份）需至少 %s",
			formatIECBytes(flashFree), formatIECBytes(uint64(pre.RequiredFreeBytes)),
		))
	}

	if memAvail > 0 && memAvail < (24<<20) {
		pre.Warnings = append(pre.Warnings, fmt.Sprintf("当前可用内存偏低 (%s)，已启用 0 MB /tmp 流式直写模式", formatIECBytes(memAvail)))
	}
	if !pre.HasOfficialDigest {
		pre.Warnings = append(pre.Warnings, "上游发布元数据未提供 SHA256 digest，将仅校验文件大小与可执行性")
	}

	pre.UpToDate = pre.LatestVersion != "" && currentVer == pre.LatestVersion && installedEqual
	pre.CanForceProceed = pre.Supported && len(pre.BlockedReasons) == 0 && pre.selectedAsset != nil
	pre.CanProceed = pre.CanForceProceed && !pre.UpToDate
	return pre, nil
}

// fetchTailscaleReleaseInfo 优先从本仓库 tailscale-latest 独立通道直连拉取发布元数据；
// 仅当主通道首次构建尚未创建（HTTP 404）时平滑兜底旧仓库，其它网络/限流错误直接返回。
func fetchTailscaleReleaseInfo(ctx context.Context, client *releasepkg.Client) (info *releasepkg.Info, sourceRepo string, unifiedChannel bool, err error) {
	info, err = client.FetchTag(ctx, tailscaleReleaseRepo, tailscaleReleaseTag)
	if err == nil {
		return info, tailscaleReleaseRepo, true, nil
	}
	if releasepkg.IsNotFound(err) {
		legacyInfo, legacyErr := client.FetchLatest(ctx, legacyAutoFetchRepo)
		if legacyErr == nil {
			return legacyInfo, legacyAutoFetchRepo, false, nil
		}
		return nil, "", false, legacyErr
	}
	return nil, "", false, err
}

func estimateUnpackedInstallBytes(archiveSize int64, combinedMinimal bool) int64 {
	if combinedMinimal {
		if archiveSize <= 0 {
			return 16 << 20
		}
		return max(archiveSize*11/4, 16<<20)
	}
	if archiveSize <= 0 {
		return 48 << 20
	}
	return max(archiveSize*5/2, 48<<20)
}

func formatIECBytes(b uint64) string {
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
	)
	switch {
	case b >= gib:
		return fmt.Sprintf("%.2f GiB", float64(b)/float64(gib))
	case b >= mib:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(mib))
	case b >= kib:
		return fmt.Sprintf("%.0f KiB", float64(b)/float64(kib))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func detectInitSystem(paths UpgradePaths, isOpenWrt bool, override string) string {
	if s := strings.TrimSpace(override); s != "" {
		return s
	}
	if isOpenWrt {
		if _, err := os.Stat(paths.InitScript); err == nil {
			return "procd"
		}
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			return "systemd"
		}
		if _, err := os.Stat(constant.TailscaleSystemdService); err == nil {
			return "systemd"
		}
	}
	if _, err := os.Stat(paths.InitScript); err == nil {
		return "procd"
	}
	return "unknown"
}

func queryTailscaleLocalState(ctx context.Context, paths UpgradePaths) (backendState string, running bool) {
	qCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Primary: Unix socket LocalAPI directly.
	api := &UnixLocalAPIClient{SocketPath: paths.SocketPath}
	if st, err := api.Status(qCtx); err == nil && st != nil && st.BackendState != "" {
		return st.BackendState, st.BackendState == "Running"
	}

	// Fallback: CLI status --json with explicit socket flag.
	tsBin := filepath.Join(paths.InstallDir, "tailscale")
	if _, err := os.Stat(tsBin); err == nil {
		out, err := exec.CommandContext(qCtx, tsBin, "--socket="+paths.SocketPath, "status", "--json").Output()
		if err == nil {
			var parsed struct {
				BackendState string `json:"BackendState"`
			}
			if json.Unmarshal(out, &parsed) == nil && parsed.BackendState != "" {
				return parsed.BackendState, parsed.BackendState == "Running"
			}
		}
	}
	return "", false
}

func readActiveLockPID(lockPath string) int {
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return 0
	}
	if !proc.IsAlive(pid) {
		return 0
	}
	return pid
}

// SafeUpdate executes the two-phase zero-lockout Tailscale upgrade (Preflight -> Streaming Stage & ELF Check -> Detached Atomic Swap + Auto-Rollback).
func (t *Tailscale) SafeUpdate(ctx context.Context, opts UpgradeOptions) error {
	paths := opts.Paths.withDefaults()
	healthTimeout := opts.normalizedHealthTimeout()
	graceDelay := opts.normalizedGraceDelay()

	logger.Info("正在执行 Tailscale 升级前体检...")
	pre, err := t.PreflightUpgrade(ctx, opts)
	if err != nil {
		return err
	}

	if !pre.Supported {
		return fmt.Errorf("%s", pre.UnsupportedReason)
	}

	printPreflightSummary(pre)

	if opts.DryRun {
		if len(pre.BlockedReasons) > 0 {
			return fmt.Errorf("升级体检未通过: %s", strings.Join(pre.BlockedReasons, "；"))
		}
		logger.Success("✅ 升级前体检通过（--dry-run 模式未对系统做任何修改）")
		return nil
	}

	if len(pre.BlockedReasons) > 0 {
		return fmt.Errorf("升级安全门禁已拦截: %s", strings.Join(pre.BlockedReasons, "；"))
	}

	if pre.UpToDate && !opts.Force {
		logger.Success("✅ Tailscale 已是最新版本 (当前: %s)", pre.CurrentVersion)
		return nil
	}

	if pre.UpToDate && opts.Force {
		logger.Info("🔄 已启用 --force 强制重刷同版本 (%s, arch=%s)...", pre.LatestVersion, pre.Arch)
	} else {
		logger.Info("⬆️ Tailscale 升级: %s -> %s (arch=%s, init=%s)...", cmp.Or(pre.CurrentVersion, "未安装"), pre.LatestVersion, pre.Arch, pre.InitSystem)
	}

	_ = WriteUpgradeState(paths, &UpgradeState{
		Phase:                UpgradePhaseStaging,
		FromVersion:          cmp.Or(pre.CurrentVersion, "unknown"),
		ToVersion:            pre.LatestVersion,
		Arch:                 pre.Arch,
		Combined:             pre.CombinedMinimal,
		Force:                opts.Force,
		StartedAt:            time.Now().UTC().Format(time.RFC3339),
		FlashFreeBeforeBytes: pre.FlashFreeBytes,
		Message:              fmt.Sprintf("正在流式下载并直写 Flash (%s, 0 MB /tmp)...", pre.AssetName),
	})

	logger.Info("📥 正在流式下载并直写安装目录 %s（零 /tmp 内存占用）...", paths.InstallDir)
	combined, shaOK, viaMirror, err := streamStageTailscaleArchive(ctx, pre.client, *pre.selectedAsset, paths.InstallDir)
	if err != nil {
		_ = WriteUpgradeState(paths, &UpgradeState{
			Phase:                UpgradePhaseFailed,
			FromVersion:          cmp.Or(pre.CurrentVersion, "unknown"),
			ToVersion:            pre.LatestVersion,
			Arch:                 pre.Arch,
			Force:                opts.Force,
			FinishedAt:           time.Now().UTC().Format(time.RFC3339),
			FlashFreeBeforeBytes: pre.FlashFreeBytes,
			Error:                err.Error(),
			Message:              "在线流式下载或完整性校验失败，当前服务完全未受影响",
		})
		return err
	}
	if shaOK {
		logger.Success("✅ SHA256 流式强校验通过，与 GitHub 官方 digest 一致 (%s)", pre.AssetName)
	} else if viaMirror {
		logger.Warn("⚠️ 经镜像流式下载完成；官方元数据未提供 digest，已按文件大小校验 (%d 字节)", pre.AssetSizeBytes)
	}

	logger.Info("🔍 正在执行新版二进制离线可执行兼容预检...")
	stagedVer, err := verifyStagedBinaries(ctx, paths.InstallDir, combined)
	if err != nil {
		_ = WriteUpgradeState(paths, &UpgradeState{
			Phase:                UpgradePhaseFailed,
			FromVersion:          cmp.Or(pre.CurrentVersion, "unknown"),
			ToVersion:            pre.LatestVersion,
			Arch:                 pre.Arch,
			Combined:             combined,
			Force:                opts.Force,
			FinishedAt:           time.Now().UTC().Format(time.RFC3339),
			FlashFreeBeforeBytes: pre.FlashFreeBytes,
			Error:                err.Error(),
			Message:              "新版二进制兼容预检失败，已清理暂存文件，当前服务保持原状",
		})
		return err
	}
	logger.Success("✅ 新版二进制预检通过 (version=%s, combined=%v)", stagedVer, combined)

	logger.Info("🚀 移交脱离进程的原子切换与 %ds 自动回滚保护器 (%ds 后开始切流)...", healthTimeout, graceDelay)
	pid, err := launchDetachedSwapper(paths, pre, combined, opts.Force, graceDelay, healthTimeout, pre.LatestVersion)
	if err != nil {
		removeStagedFiles(paths.InstallDir)
		return err
	}
	logger.Info("%s pid=%d log=%s", TailscaleSwapHandoffMarker, pid, paths.LogFile)

	if !opts.Wait {
		logger.Success("已安全移交后台切换进程 (PID %d)，若经 Tailscale 连接将在 3~8 秒内无感重连", pid)
		return nil
	}

	logger.Info("⏳ 等待后台切换与健康门禁完成（最长 %ds）...", graceDelay+healthTimeout+20)
	return waitForSwapCompletion(ctx, paths, time.Duration(graceDelay+healthTimeout+25)*time.Second)
}

func printPreflightSummary(pre *UpgradePreflight) {
	logger.Info("  架构: %s | 服务管理: %s | 包模式: %s",
		pre.Arch, pre.InitSystem, func() string {
			if pre.CombinedMinimal {
				return "精简合体版 (symlink)"
			}
			return "标准双二进制"
		}())
	logger.Info("  版本: %s -> %s | 状态: %s",
		cmp.Or(pre.CurrentVersion, "未安装"), pre.LatestVersion, cmp.Or(pre.BackendState, "未运行"))
	logger.Info("  Flash 剩余: %s (安全切换需 %s) | 可用内存: %s | Swap 剩余: %s",
		formatIECBytes(pre.FlashFreeBytes),
		formatIECBytes(uint64(max(0, pre.RequiredFreeBytes))),
		formatIECBytes(pre.MemAvailableBytes),
		formatIECBytes(pre.SwapFreeBytes))
	for _, w := range pre.Warnings {
		logger.Warn("  ⚠️ %s", w)
	}
	for _, b := range pre.BlockedReasons {
		logger.Error("  ❌ %s", b)
	}
}

func waitForSwapCompletion(ctx context.Context, paths UpgradePaths, maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	lastPhase := ""
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		st, err := ReadUpgradeState(paths)
		if err == nil && st != nil {
			if st.Phase != lastPhase && st.Message != "" {
				logger.Info("  [%s] %s", st.Phase, st.Message)
				lastPhase = st.Phase
			}
			switch st.Phase {
			case UpgradePhaseSucceeded:
				logger.Success("✅ %s", cmp.Or(st.Message, "Tailscale 升级成功"))
				return nil
			case UpgradePhaseRolledBack:
				return fmt.Errorf("Tailscale 新版验证失败并已自动回滚 (%s): %s", cmp.Or(st.Error, "health check failed"), st.Message)
			case UpgradePhaseFailed:
				return fmt.Errorf("Tailscale 后台切换异常: %s", cmp.Or(st.Error, st.Message))
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return fmt.Errorf("等待 Tailscale 后台切换超时（请查看日志 %s）", paths.LogFile)
}
