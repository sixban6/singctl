// 文件职责：负责纯 Go WARP（windtf/wireproxy）完整部署编排、三阶段事务性身份轮换（RotateWarpIdentity）、Endpoint 自动切换与二进制下载安装。
//
// 架构设计原则：
//   - 高内聚职责拆 file：配置纯函数内核位于 warp_config.go；离网探测与路径解析位于 warp_probe.go；
//     旧版 fscarmen/warp-go 清理位于 warp_legacy.go；本文件聚焦顶层状态编排与事务回滚。
//   - 三阶段原子事务（Stage 1 预验证 → Stage 2 0600 备份与原子切换 → Stage 3 实测验证或回滚）：
//     确保任何注册、重启或握手异常均不破坏现网隧道与 0600 密钥文件权限。
package deploy

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/util/netinfo"
)

type warpRegRequest struct {
	Key          string `json:"key"`
	InstallID    string `json:"install_id"`
	FCMToken     string `json:"fcm_token"`
	TOS          string `json:"tos"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	Locale       string `json:"locale"`
}

type warpRegResponse struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Token  string `json:"token"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4   string `json:"v4"`
				V6   string `json:"v6"`
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

const (
	DefaultWireproxyBin     = "/usr/local/bin/wireproxy"
	DefaultWireproxyConf    = "/etc/wireproxy/wireproxy.conf"
	DefaultWireproxyService = "/etc/systemd/system/wireproxy.service"
	LegacyWireproxyConf     = "/etc/wireguard/proxy.conf"
)

// WarpCandidateEndpoints 定义 Cloudflare WARP 多端口/多 Anycast Endpoint 备选池（IPv4 直连防 DNS 解析死锁）
var WarpCandidateEndpoints = []string{
	"162.159.192.1:2408",
	"162.159.195.1:500",
	"188.114.96.1:4500",
	"162.159.193.10:1701",
}

// DeployWarp installs wireproxy using Cloudflare WARP API in pure Go
func DeployWarp() error {
	return DeployWarpWithConfig(nil)
}

// DeployWarpWithConfig installs and configures wireproxy with Cloudflare WARP in pure Go
func DeployWarpWithConfig(cfg *config.Config) error {
	logger.Info("Starting WARP (wireproxy) pure-Go deployment...")

	// 0. 优先清理遗留的 fscarmen / warp-go / /etc/wireguard/proxy.conf 产物
	if purged, err := PurgeLegacyFscarmenWarp(); err != nil {
		logger.Warn("清理旧版 fscarmen WARP 残留警告: %v", err)
	} else if purged {
		logger.Info("已自动清理旧版 fscarmen WARP 残留并切换至纯 Go 架构")
	}

	// 1. 若标准 windtf/wireproxy 已存在且隧道健康，就地规范化配置即可快速返回
	if IsWindtfWireproxyBinary(DefaultWireproxyBin) {
		if raw, err := os.ReadFile(DefaultWireproxyConf); err == nil {
			if normalized, changed := NormalizeWireproxyConfigContent(string(raw)); changed {
				_ = writeFileAtomic0600(DefaultWireproxyConf, []byte(normalized))
				_ = writeWireproxySystemdUnit(DefaultWireproxyService, DefaultWireproxyBin, DefaultWireproxyConf)
				_ = serviceMgr().DaemonReload(context.Background())
				_ = serviceMgr().Restart(context.Background(), "wireproxy")
				time.Sleep(1500 * time.Millisecond)
			}
			if isWarpSocksRunning() && IsWarpTunnelHealthy(3*time.Second) {
				logger.Success("WARP (wireproxy) is already running cleanly on 127.0.0.1:40000")
				return nil
			}
		}
	}

	// 2. 安装或校验纯 Go windtf/wireproxy 二进制
	wireproxyBin, err := ensureWireproxyBinary(cfg)
	if err != nil {
		return fmt.Errorf("failed to ensure wireproxy binary: %w", err)
	}

	// 3. 生成 WireGuard X25519 密钥对并向 Cloudflare 注册身份
	privKey, pubKey, err := GenerateWireguardKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate WireGuard keypair: %w", err)
	}
	logger.Info("Registering Cloudflare WARP account via API...")
	reg, err := registerCloudflareWarp(pubKey)
	if err != nil {
		return fmt.Errorf("failed to register Cloudflare WARP account: %w", err)
	}

	// 4. 渲染 /etc/wireproxy/wireproxy.conf (0600)
	if err := os.MkdirAll(filepath.Dir(DefaultWireproxyConf), 0700); err != nil {
		return fmt.Errorf("failed to create /etc/wireproxy: %w", err)
	}
	hasV6 := hasGlobalIPv6()
	candidates := slices.Clone(WarpCandidateEndpoints)
	if regEP := extractRegV4Endpoint(reg); regEP != "" && !slices.Contains(candidates, regEP) {
		candidates = append(candidates, regEP)
	}
	confContent := renderWireproxyConfigFromReg(privKey, reg, hasV6, WarpCandidateEndpoints[0])
	if IsWindtfWireproxyBinary(wireproxyBin) {
		stageCtx, stageCancel := context.WithTimeout(context.Background(), 6*time.Second)
		winEP, winConf, _, _, ok := stageSelectWorkingEndpoint(stageCtx, wireproxyBin, privKey, reg, hasV6, candidates, nil)
		stageCancel()
		if ok && winConf != "" {
			confContent = winConf
			logger.Info("WARP 预探测选定可用 Endpoint: %s", winEP)
		}
	}
	if err := writeFileAtomic0600(DefaultWireproxyConf, []byte(confContent)); err != nil {
		return fmt.Errorf("failed to write %s: %w", DefaultWireproxyConf, err)
	}

	// 5. 生成标准 systemd unit 并启动服务
	if err := writeWireproxySystemdUnit(DefaultWireproxyService, wireproxyBin, DefaultWireproxyConf); err != nil {
		return fmt.Errorf("failed to write %s: %w", DefaultWireproxyService, err)
	}
	ctx := context.Background()
	mgr := serviceMgr()
	_ = mgr.DaemonReload(ctx)
	if err := mgr.Enable(ctx, "wireproxy"); err != nil {
		return fmt.Errorf("failed to enable wireproxy service: %w", err)
	}
	if err := mgr.Restart(ctx, "wireproxy"); err != nil {
		return fmt.Errorf("failed to restart wireproxy service: %w", err)
	}

	// 6. 探测 SOCKS5 监听与隧道握手（失败时自动轮换备选 Endpoint）
	logger.Info("Verifying WARP SOCKS5 proxy on 127.0.0.1:40000...")
	var success bool
	for range 5 {
		time.Sleep(600 * time.Millisecond)
		if isWarpSocksRunning() && IsWarpTunnelHealthy(2*time.Second) {
			success = true
			break
		}
	}
	if !success && isWarpSocksRunning() {
		logger.Warn("当前 Endpoint 握手未就绪，尝试自动轮换备选 Endpoint...")
		if ep, _, _, swErr := SwitchWarpEndpoint(); swErr == nil {
			logger.Success("已自动切换至可用 Endpoint (%s)", ep)
			success = true
		}
	}
	if !success {
		logger.Warn("WARP service started, waiting for tunnel readiness. Verify with: systemctl status wireproxy")
	} else {
		logger.Success("WARP (wireproxy) deployed successfully on 127.0.0.1:40000")
	}
	return nil
}

// WarpRotateDeps 定义更换 WARP IP 时的可注入外部依赖（用于离线单元测试与模拟回滚）。
type WarpRotateDeps struct {
	PathEnv            WireproxyPathEnv
	PurgeLegacy        func() (bool, error)
	CandidateEndpoints []string
	PreviousIP         string
	GenerateKeypair    func() (privKey, pubKey string, err error)
	RegisterWarp       func(pubKey string) (*warpRegResponse, error)
	HasIPv6            func() bool
	RestartService     func() error
	FetchExitInfo      func(timeout time.Duration) (ip, loc, state string, ok bool)
	StageProbe         func(endpoint, confContent string) (ip, loc string, ok bool)
	DeployFallback     func() error
	PollAttempts       int
	PollInterval       time.Duration
}

type warpConfigBackup struct {
	activePath      string
	mirrorPaths     []string
	oldActive       []byte
	bakPath         string
	existingMirrors map[string][]byte
	createdMirrors  []string
}

// RotateWarpIdentity 重新注册 Cloudflare WARP 设备密钥并热切换本地 wireproxy 出口 IP（带离网预验证、多 Endpoint 自动回退、0600 备份与失败自动回滚）
func RotateWarpIdentity() (newIP, newLoc string, err error) {
	return RotateWarpIdentityFrom("")
}

// RotateWarpIdentityFrom 尝试换取与 previousIP 不同的全新 WARP 出口身份并热切换本地 wireproxy。
func RotateWarpIdentityFrom(previousIP string) (newIP, newLoc string, err error) {
	return RotateWarpIdentityWithDeps(&WarpRotateDeps{
		PurgeLegacy:        PurgeLegacyFscarmenWarp,
		CandidateEndpoints: WarpCandidateEndpoints,
		PreviousIP:         strings.TrimSpace(previousIP),
	})
}

func RotateWarpIdentityWithDeps(deps *WarpRotateDeps) (newIP, newLoc string, err error) {
	d := normalizeWarpRotateDeps(deps)

	activePath, mirrorPaths, exists := ResolveWireproxyConfigPathsWithEnv(d.PathEnv)
	if !exists {
		return bootstrapWarpIfMissing(d, activePath)
	}

	bak, err := prepareWarpConfigBackup(activePath, mirrorPaths)
	if err != nil {
		return "", "", err
	}

	useStaging := d.StageProbe != nil || ((deps == nil || (deps.RestartService == nil && deps.FetchExitInfo == nil)) && IsWindtfWireproxyBinary(DefaultWireproxyBin))
	if useStaging {
		return rotateWarpViaStaging(deps, d, bak)
	}
	return rotateWarpDirectFallback(d, bak)
}

func normalizeWarpRotateDeps(deps *WarpRotateDeps) WarpRotateDeps {
	var d WarpRotateDeps
	if deps != nil {
		d = *deps
	}
	if d.PurgeLegacy != nil {
		_, _ = d.PurgeLegacy()
	} else if d.PathEnv.PrimaryConf == "" && len(d.PathEnv.UnitFiles) == 0 {
		_, _ = PurgeLegacyFscarmenWarp()
	}
	if d.GenerateKeypair == nil {
		d.GenerateKeypair = GenerateWireguardKeypair
	}
	if d.RegisterWarp == nil {
		d.RegisterWarp = registerCloudflareWarp
	}
	if d.HasIPv6 == nil {
		d.HasIPv6 = hasGlobalIPv6
	}
	if d.RestartService == nil {
		d.RestartService = func() error {
			return serviceMgr().Restart(context.Background(), "wireproxy")
		}
	}
	if d.FetchExitInfo == nil {
		d.FetchExitInfo = func(timeout time.Duration) (string, string, string, bool) {
			if !isWarpSocksRunning() {
				return "", "", "", false
			}
			return FetchWarpExitInfo(timeout)
		}
	}
	if d.DeployFallback == nil {
		d.DeployFallback = func() error {
			return DeployWarpWithConfig(nil)
		}
	}
	if d.PollAttempts <= 0 {
		d.PollAttempts = 2
	}
	if d.PollInterval <= 0 {
		d.PollInterval = 350 * time.Millisecond
	}
	return d
}

func bootstrapWarpIfMissing(d WarpRotateDeps, activePath string) (string, string, error) {
	if err := d.DeployFallback(); err != nil {
		return "", "", fmt.Errorf("未检测到已部署的 WARP 配置 (%s)，且自动初始化失败: %w", activePath, err)
	}
	for range d.PollAttempts {
		if ip, loc, _, ok := d.FetchExitInfo(2 * time.Second); ok && ip != "" {
			return ip, loc, nil
		}
		time.Sleep(d.PollInterval)
	}
	return "", "", fmt.Errorf("WARP 已完成自动初始化，但暂未探测到出口 IP，请稍后刷新查看")
}

func prepareWarpConfigBackup(activePath string, mirrorPaths []string) (warpConfigBackup, error) {
	oldActive, err := os.ReadFile(activePath)
	if err != nil {
		return warpConfigBackup{}, fmt.Errorf("读取现网 WARP 配置 (%s) 失败: %w", activePath, err)
	}
	_ = os.Chmod(activePath, 0600)

	// 以 0600 备份现网生效配置，并保留最近 3 份历史备份防止磁盘膨胀
	bakPath := fmt.Sprintf("%s.%d.bak", activePath, time.Now().UnixNano())
	_ = os.WriteFile(bakPath, oldActive, 0600)
	_ = os.Chmod(bakPath, 0600)
	pruneWireproxyBackups(activePath, 3)

	existingMirrors := make(map[string][]byte, len(mirrorPaths))
	var createdMirrors []string
	for _, mp := range mirrorPaths {
		if b, mErr := os.ReadFile(mp); mErr == nil {
			existingMirrors[mp] = b
		} else {
			createdMirrors = append(createdMirrors, mp)
		}
	}
	return warpConfigBackup{
		activePath:      activePath,
		mirrorPaths:     mirrorPaths,
		oldActive:       oldActive,
		bakPath:         bakPath,
		existingMirrors: existingMirrors,
		createdMirrors:  createdMirrors,
	}, nil
}

func (b warpConfigBackup) writeActiveAndMirrors(content []byte) error {
	if err := writeFileAtomic0600(b.activePath, content); err != nil {
		return fmt.Errorf("写入新 wireproxy 配置 (%s) 失败: %w", b.activePath, err)
	}
	for _, mp := range b.mirrorPaths {
		_ = writeFileAtomic0600(mp, content)
	}
	return nil
}

func (b warpConfigBackup) rollback(restart func() error) {
	_ = writeFileAtomic0600(b.activePath, b.oldActive)
	for mp, oldBytes := range b.existingMirrors {
		_ = writeFileAtomic0600(mp, oldBytes)
	}
	for _, mp := range b.createdMirrors {
		_ = os.Remove(mp)
	}
	_ = restart()
}

func rotateWarpViaStaging(deps *WarpRotateDeps, d WarpRotateDeps, bak warpConfigBackup) (string, string, error) {
	// Stage 1: 离网注册与临时端口连通性预验证（零影响现网隧道）
	currentEP := ExtractWireproxyEndpoint(string(bak.oldActive))
	hasV6 := d.HasIPv6()
	prevIP := strings.TrimSpace(d.PreviousIP)
	maxReg := 1
	if prevIP != "" {
		maxReg = 2
	}

	var chosenConf, stageIP, stageLoc string
	for attempt := range maxReg {
		privKey, pubKey, kErr := d.GenerateKeypair()
		if kErr != nil {
			if attempt == 0 || chosenConf == "" {
				_ = os.Remove(bak.bakPath)
				return "", "", fmt.Errorf("生成 WireGuard 密钥对失败: %w", kErr)
			}
			break
		}
		reg, rErr := d.RegisterWarp(pubKey)
		if rErr != nil {
			if attempt == 0 || chosenConf == "" {
				_ = os.Remove(bak.bakPath)
				return "", "", fmt.Errorf("注册 Cloudflare WARP 新身份失败: %w", rErr)
			}
			break
		}

		endpoints := buildOrderedWarpCandidateEndpoints(d.CandidateEndpoints, currentEP, reg)
		stageCtx, stageCancel := context.WithTimeout(context.Background(), 5500*time.Millisecond)
		_, winConf, sIP, sLoc, ok := stageSelectWorkingEndpoint(stageCtx, DefaultWireproxyBin, privKey, reg, hasV6, endpoints, d.StageProbe)
		stageCancel()
		if !ok || winConf == "" {
			if attempt == 0 || chosenConf == "" {
				_ = os.Remove(bak.bakPath)
				return "", "", fmt.Errorf("新 WARP 身份在备选 Endpoint 握手超时，已保留原隧道不断流")
			}
			break
		}

		chosenConf = winConf
		stageIP = sIP
		stageLoc = sLoc
		if prevIP == "" || stageIP != prevIP || attempt == maxReg-1 {
			break
		}
	}

	// Stage 2: 0600 原子写入新配置并重启 wireproxy 服务
	if err := bak.writeActiveAndMirrors([]byte(chosenConf)); err != nil {
		return "", "", err
	}
	if err := d.RestartService(); err != nil {
		bak.rollback(d.RestartService)
		return "", "", fmt.Errorf("重启 wireproxy 失败，已回滚原配置: %w", err)
	}

	// 若单元测试仅注入 StageProbe 而未模拟本地 127.0.0.1:40000，则直接采信离网探测结果
	if deps != nil && deps.StageProbe != nil && deps.FetchExitInfo == nil {
		return stageIP, stageLoc, nil
	}

	// Stage 3: 实网隧道验证，连续失败则触发原配置原子回滚
	preferIPv6 := strings.Contains(chosenConf, "ResolveStrategy = ipv6")
	for attempt := range 4 {
		if attempt == 0 {
			time.Sleep(250 * time.Millisecond)
		} else {
			time.Sleep(300 * time.Millisecond)
		}
		if deps != nil && deps.FetchExitInfo != nil {
			if liveIP, liveLoc, _, ok := d.FetchExitInfo(1800 * time.Millisecond); ok && liveIP != "" {
				return liveIP, cmp.Or(liveLoc, stageLoc), nil
			}
			continue
		}
		if isWarpSocksRunning() {
			if liveIP, liveLoc, _, ok := fetchWarpTraceViaProxy(context.Background(), "127.0.0.1:40000", preferIPv6, 1800*time.Millisecond); ok && liveIP != "" {
				return liveIP, cmp.Or(liveLoc, stageLoc), nil
			}
			if liveIP, liveLoc, _, ok := d.FetchExitInfo(1800 * time.Millisecond); ok && liveIP != "" {
				return liveIP, cmp.Or(liveLoc, stageLoc), nil
			}
		}
	}

	bak.rollback(d.RestartService)
	return "", "", fmt.Errorf("新 WARP 身份加载后本地隧道未就绪，已自动回滚保留原有出口隧道")
}

func rotateWarpDirectFallback(d WarpRotateDeps, bak warpConfigBackup) (string, string, error) {
	privKey, pubKey, kErr := d.GenerateKeypair()
	if kErr != nil {
		return "", "", fmt.Errorf("生成 WireGuard 密钥对失败: %w", kErr)
	}
	reg, rErr := d.RegisterWarp(pubKey)
	if rErr != nil {
		return "", "", fmt.Errorf("注册 Cloudflare WARP 新身份失败: %w", rErr)
	}

	currentEP := ExtractWireproxyEndpoint(string(bak.oldActive))
	endpoints := buildOrderedWarpCandidateEndpoints(d.CandidateEndpoints, currentEP, reg)
	hasV6 := d.HasIPv6()

	var lastRestartErr error
	for _, ep := range endpoints {
		freshConf := renderWireproxyConfigFromReg(privKey, reg, hasV6, ep)
		if err := bak.writeActiveAndMirrors([]byte(freshConf)); err != nil {
			return "", "", err
		}
		if err := d.RestartService(); err != nil {
			lastRestartErr = err
			continue
		}
		for range d.PollAttempts {
			time.Sleep(d.PollInterval)
			if ip, loc, _, ok := d.FetchExitInfo(1800 * time.Millisecond); ok && ip != "" {
				return ip, loc, nil
			}
		}
	}

	bak.rollback(d.RestartService)
	if lastRestartErr != nil && len(endpoints) == 1 {
		return "", "", fmt.Errorf("重启 wireproxy 失败，已回滚原配置: %w", lastRestartErr)
	}
	return "", "", fmt.Errorf("新 WARP 身份握手超时，已自动回滚保留原有出口隧道")
}

func pruneWireproxyBackups(path string, keep int) {
	if keep < 1 {
		keep = 1
	}
	matches, err := filepath.Glob(path + ".*.bak")
	if err != nil || len(matches) <= keep {
		return
	}
	slices.Sort(matches)
	slices.Reverse(matches)
	for i := keep; i < len(matches); i++ {
		_ = os.Remove(matches[i])
	}
}

// WarpEndpointSwitchDeps 允许测试注入 Endpoint 切换流程的外部依赖。
type WarpEndpointSwitchDeps struct {
	ConfPath           string
	CandidateEndpoints []string
	RestartService     func() error
	ProbeTargets       func(timeout time.Duration) (ip, loc string, err error)
	PollAttempts       int
	PollInterval       time.Duration
}

// SwitchWarpEndpoint 轮换 wireproxy Endpoint 节点并重启隧道，直至真实外网探测连通（全部失败自动恢复原配置）。
func SwitchWarpEndpoint() (endpoint, ip, loc string, err error) {
	return SwitchWarpEndpointWithDeps(nil)
}

func SwitchWarpEndpointWithDeps(deps *WarpEndpointSwitchDeps) (endpoint, ip, loc string, err error) {
	var d WarpEndpointSwitchDeps
	if deps != nil {
		d = *deps
	}
	confPath := cmp.Or(strings.TrimSpace(d.ConfPath), DefaultWireproxyConf)
	if len(d.CandidateEndpoints) == 0 {
		d.CandidateEndpoints = WarpCandidateEndpoints
	}
	if d.RestartService == nil {
		d.RestartService = func() error {
			return serviceMgr().Restart(context.Background(), "wireproxy")
		}
	}
	if d.ProbeTargets == nil {
		d.ProbeTargets = ProbeWarpRealTargets
	}
	if d.PollAttempts <= 0 {
		d.PollAttempts = 2
	}
	if d.PollInterval <= 0 {
		d.PollInterval = 350 * time.Millisecond
	}

	origBytes, readErr := os.ReadFile(confPath)
	if readErr != nil {
		return "", "", "", fmt.Errorf("读取 wireproxy 配置失败: %w", readErr)
	}
	origContent := string(origBytes)
	currentEP := ExtractWireproxyEndpoint(origContent)
	ordered := orderCandidateEndpointsAfterCurrent(d.CandidateEndpoints, currentEP)

	var lastErr error
	for _, cand := range ordered {
		updated := ReplaceWireproxyEndpoint(origContent, cand)
		if normalized, changed := NormalizeWireproxyConfigContent(updated); changed {
			updated = normalized
		}
		if wErr := writeFileAtomic0600(confPath, []byte(updated)); wErr != nil {
			lastErr = wErr
			continue
		}
		if rErr := d.RestartService(); rErr != nil {
			lastErr = rErr
			continue
		}
		for range d.PollAttempts {
			time.Sleep(d.PollInterval)
			if probeIP, probeLoc, pErr := d.ProbeTargets(2500 * time.Millisecond); pErr == nil && probeIP != "" {
				return cand, probeIP, probeLoc, nil
			} else if pErr != nil {
				lastErr = pErr
			}
		}
	}

	_ = writeFileAtomic0600(confPath, origBytes)
	_ = d.RestartService()
	return "", "", "", fmt.Errorf("所有备选 WARP Endpoint (%d 个) 均不可达: %v", len(ordered), lastErr)
}

// SyncWarpConfigIfNeeded 检查并自愈本机 WARP (wireproxy) 配置与隧道握手状态（同时自动清理遗留的 fscarmen 脚本产物）
func SyncWarpConfigIfNeeded() (healed bool, msg string, err error) {
	purged, _ := PurgeLegacyFscarmenWarp()

	activePath, _, exists := ResolveWireproxyConfigPaths()
	if purged && (!exists || !IsWindtfWireproxyBinary(DefaultWireproxyBin)) {
		if dErr := DeployWarpWithConfig(nil); dErr != nil {
			return false, "", fmt.Errorf("已清理旧版 fscarmen WARP，但重建纯 Go wireproxy 失败: %w", dErr)
		}
		return true, "已清理旧版 fscarmen WARP 并迁移至内置纯 Go wireproxy (MTU=1280)", nil
	}

	if !exists {
		return false, "", nil
	}
	if !IsWindtfWireproxyBinary(DefaultWireproxyBin) {
		if dErr := DeployWarpWithConfig(nil); dErr != nil {
			return false, "", fmt.Errorf("升级为纯 Go wireproxy 失败: %w", dErr)
		}
		return true, "已替换升级为内置纯 Go windtf/wireproxy 引擎", nil
	}

	raw, rErr := os.ReadFile(activePath)
	if rErr != nil {
		return false, "", nil
	}
	anyChanged := purged
	if normalized, changed := NormalizeWireproxyConfigContent(string(raw)); changed {
		if wErr := writeFileAtomic0600(activePath, []byte(normalized)); wErr != nil {
			return false, "", fmt.Errorf("写入 %s 失败: %w", activePath, wErr)
		}
		anyChanged = true
	}

	if !anyChanged && isWarpSocksRunning() {
		if _, _, pErr := ProbeWarpRealTargets(3 * time.Second); pErr == nil {
			return false, "", nil
		}
	}

	_ = writeWireproxySystemdUnit(DefaultWireproxyService, DefaultWireproxyBin, activePath)
	ctx := context.Background()
	mgr := serviceMgr()
	_ = mgr.DaemonReload(ctx)
	_ = mgr.Restart(ctx, "wireproxy")
	for range 4 {
		time.Sleep(800 * time.Millisecond)
		if _, _, pErr := ProbeWarpRealTargets(3 * time.Second); pErr == nil {
			return true, "WARP (wireproxy) 已规范化 MTU=1280/IPv4 策略并恢复真实出口连通", nil
		}
	}

	if ep, _, _, swErr := SwitchWarpEndpoint(); swErr == nil {
		return true, fmt.Sprintf("WARP (wireproxy) 已自动切换至可用 Endpoint (%s)", ep), nil
	}

	if newIP, _, rErr := RotateWarpIdentity(); rErr == nil {
		return true, fmt.Sprintf("WARP (wireproxy) 已自动重新注册身份并切换出口 IP (%s)", newIP), nil
	} else {
		return false, "", rErr
	}
}

func GenerateWireguardKeypair() (string, string, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privKey := base64.StdEncoding.EncodeToString(priv.Bytes())
	pubKey := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	return privKey, pubKey, nil
}

func registerCloudflareWarp(publicKey string) (*warpRegResponse, error) {
	reqBody := warpRegRequest{
		Key:          publicKey,
		InstallID:    "",
		FCMToken:     "",
		TOS:          time.Now().UTC().Format(time.RFC3339Nano),
		Model:        "PC",
		SerialNumber: "",
		Locale:       "en_US",
	}
	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	regURL := "https://api.cloudflareclient.com/v0a3922/reg"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, regURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cloudflare API error (%s): %s", resp.Status, string(body))
	}

	var reg warpRegResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return nil, fmt.Errorf("failed to decode cloudflare registration response: %w", err)
	}

	return &reg, nil
}

func ensureWireproxyBinary(cfg *config.Config) (string, error) {
	if IsWindtfWireproxyBinary(DefaultWireproxyBin) {
		return DefaultWireproxyBin, nil
	}

	arch := runtime.GOARCH
	switch arch {
	case "amd64", "arm64", "386", "arm", "mipsle":
	default:
		return "", fmt.Errorf("unsupported architecture for wireproxy: %s", arch)
	}

	mirror := ""
	if cfg != nil {
		mirror = cfg.GitHub.MirrorURL
	}

	downloadURL := fmt.Sprintf("https://github.com/windtf/wireproxy/releases/latest/download/wireproxy_linux_%s.tar.gz", arch)
	reachableURL := netinfo.GetReachableURL(downloadURL, mirror)

	logger.Info("Downloading windtf/wireproxy binary from: %s", reachableURL)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(reachableURL)
	if err != nil {
		return "", fmt.Errorf("failed to download wireproxy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download wireproxy (status %s)", resp.Status)
	}

	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to gunzip wireproxy: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	targetPath := DefaultWireproxyBin
	found := false

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("reading tar entry: %w", err)
		}
		baseName := filepath.Base(hdr.Name)
		if baseName == "wireproxy" {
			_ = os.MkdirAll(filepath.Dir(targetPath), 0755)
			tmpBin := fmt.Sprintf("%s.%d.tmp", targetPath, time.Now().UnixNano())
			outFile, err := os.OpenFile(tmpBin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return "", fmt.Errorf("failed to create %s: %w", tmpBin, err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				_ = os.Remove(tmpBin)
				return "", fmt.Errorf("failed to write %s: %w", tmpBin, err)
			}
			outFile.Close()
			if !IsWindtfWireproxyBinary(tmpBin) {
				_ = os.Remove(tmpBin)
				return "", fmt.Errorf("downloaded wireproxy binary failed compatibility check (missing ResolveStrategy)")
			}
			if err := os.Rename(tmpBin, targetPath); err != nil {
				_ = os.Remove(tmpBin)
				return "", fmt.Errorf("failed to install %s: %w", targetPath, err)
			}
			_ = os.Chmod(targetPath, 0755)
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("wireproxy binary not found inside archive")
	}

	logger.Success("Installed windtf/wireproxy binary to %s", targetPath)
	return targetPath, nil
}
