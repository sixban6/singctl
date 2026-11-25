// 文件职责：负责 SmartDNS 官方静态二进制资产选择、零 /tmp 流式安装自检与文件指纹版本缓存。
package smartdns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/netx"
	releasepkg "singctl/internal/common/release"
	"singctl/internal/logger"
)

type versionCacheEntry struct {
	fingerprint string
	version     string
}

var (
	binVerCacheMu sync.RWMutex
	binVerCache   = make(map[string]versionCacheEntry)
)

// SelectAssetName 根据目标操作系统与 CPU 架构返回 pymumu/smartdns 官方静态单文件二进制资产名。
func SelectAssetName(goos, goarch string) (string, error) {
	if goos != "linux" {
		return "", fmt.Errorf("SmartDNS static binary is only supported on Linux/OpenWrt (current OS: %s)", goos)
	}
	switch goarch {
	case "arm64":
		return "smartdns-aarch64", nil
	case "amd64":
		return "smartdns-x86_64", nil
	case "arm":
		return "smartdns-arm", nil
	case "386":
		return "smartdns-x86", nil
	case "mips":
		return "smartdns-mips", nil
	case "mipsle":
		return "smartdns-mipsel", nil
	default:
		return "", fmt.Errorf("unsupported Linux architecture for SmartDNS: %s", goarch)
	}
}

// ParseVersionOutput 从 smartdns -v 输出中提取规整的首行版本标识。
func ParseVersionOutput(raw string) string {
	for line := range strings.SplitSeq(raw, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// CachedBinaryVersion 按二进制文件指纹 (path|mtime|size) 缓存 smartdns -v 输出，避免高频状态接口反复 fork 子进程。
func CachedBinaryVersion(binPath string) string {
	info, err := os.Stat(binPath)
	if err != nil || info.IsDir() {
		return ""
	}
	fp := fmt.Sprintf("%d|%d", info.ModTime().UnixNano(), info.Size())

	binVerCacheMu.RLock()
	if entry, ok := binVerCache[binPath]; ok && entry.fingerprint == fp && entry.version != "" {
		ver := entry.version
		binVerCacheMu.RUnlock()
		return ver
	}
	binVerCacheMu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	out, err := exec.CommandContext(ctx, binPath, "-v").CombinedOutput()
	cancel()
	if err != nil {
		return ""
	}
	ver := ParseVersionOutput(string(out))
	if ver != "" {
		binVerCacheMu.Lock()
		binVerCache[binPath] = versionCacheEntry{fingerprint: fp, version: ver}
		binVerCacheMu.Unlock()
	}
	return ver
}

func (m *Manager) detectInstalledVersion() string {
	if m.execVerifyFunc != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ver, err := m.execVerifyFunc(ctx, m.binPath)
		if err != nil {
			return ""
		}
		return ParseVersionOutput(ver)
	}
	return CachedBinaryVersion(m.binPath)
}

func (m *Manager) verifyBinary(ctx context.Context, candidatePath string) (string, error) {
	verifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if m.execVerifyFunc != nil {
		ver, err := m.execVerifyFunc(verifyCtx, candidatePath)
		if err != nil {
			return "", err
		}
		return ParseVersionOutput(ver), nil
	}

	out, err := exec.CommandContext(verifyCtx, candidatePath, "-v").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return "", fmt.Errorf("%w (%s)", err, msg)
		}
		return "", err
	}
	ver := ParseVersionOutput(string(out))
	if ver == "" {
		return "", errors.New("smartdns -v returned empty output")
	}
	return ver, nil
}

// downloadAndInstallBinary 流式直写 <binPath>.tmp（零 /tmp 占用），完成 -v 自检后原子替换目标二进制。
func (m *Manager) downloadAndInstallBinary(ctx context.Context) error {
	assetName, err := SelectAssetName(m.goos, m.goarch)
	if err != nil {
		return err
	}

	binDir := filepath.Dir(m.binPath)
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("create smartdns binary dir %s: %w", binDir, err)
	}

	tmpPath := m.binPath + ".tmp"
	_ = os.Remove(tmpPath)
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if m.downloadFunc != nil {
		if err := m.downloadFunc(ctx, assetName, tmpPath); err != nil {
			return fmt.Errorf("下载 SmartDNS 失败: %w", err)
		}
	} else {
		if err := m.downloadReleaseAsset(ctx, assetName, tmpPath); err != nil {
			return err
		}
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("设置 SmartDNS 可执行权限失败: %w", err)
	}

	ver, err := m.verifyBinary(ctx, tmpPath)
	if err != nil {
		return fmt.Errorf("SmartDNS 二进制自检 (%s -v) 失败，已自动清理临时文件: %w", assetName, err)
	}

	if err := os.Rename(tmpPath, m.binPath); err != nil {
		return fmt.Errorf("原子替换 SmartDNS 二进制到 %s 失败: %w", m.binPath, err)
	}
	cleanupTmp = false
	_ = os.Chmod(m.binPath, 0755)
	logger.Success("SmartDNS 核心 (%s) 已流式安装至 %s", ver, m.binPath)
	return nil
}

func (m *Manager) downloadReleaseAsset(ctx context.Context, assetName, tmpDestPath string) error {
	cfg := m.snapshotConfig()
	logger.Info("正在获取 SmartDNS 最新稳定版发布信息 (%s)...", assetName)

	client := releasepkg.NewClient(cfg.MirrorURL)
	if m.httpClient != nil {
		client.HTTP = m.httpClient
	}
	if m.releaseAPIBase != "" {
		client.APIBase = m.releaseAPIBase
		client.DirectFirst = true
	} else {
		client.DirectFirst = netx.CheckGoogleConnectivity()
	}

	info, err := client.FetchLatest(ctx, SmartDNSRepo)
	if err != nil {
		return fmt.Errorf("获取 SmartDNS 最新 Release 元数据失败: %w", err)
	}

	var targetAsset *releasepkg.Asset
	for i := range info.Assets {
		if info.Assets[i].Name == assetName {
			targetAsset = &info.Assets[i]
			break
		}
	}
	if targetAsset == nil {
		return fmt.Errorf("SmartDNS %s 未提供当前架构静态二进制: %s", info.TagName, assetName)
	}

	// 复用 releasepkg 流式下载与 SHA256/Size 校验，将目标名定向为 <binPath>.tmp 直写目标目录（零 /tmp 占用）。
	stagedAsset := *targetAsset
	if stagedAsset.BrowserDownloadURL == "" {
		stagedAsset.BrowserDownloadURL = fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", SmartDNSRepo, info.TagName, targetAsset.Name)
	}
	stagedAsset.Name = filepath.Base(tmpDestPath)

	logger.Info("正在流式下载 SmartDNS %s (%s -> %s)...", info.TagName, targetAsset.Name, tmpDestPath)
	res, err := client.Download(ctx, stagedAsset, filepath.Dir(tmpDestPath))
	if err != nil {
		return fmt.Errorf("流式下载 SmartDNS 失败: %w", err)
	}
	if res.SHA256Verified {
		logger.Success("SmartDNS sha256 官方摘要校验通过 (%s)", targetAsset.Name)
	}
	return nil
}
