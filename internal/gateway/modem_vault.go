// 文件职责：提供本地 0600 双槽位光猫凭据保险箱（超级管理员与普通用户）的脱敏摘要读取、原子更新与校验提取。
package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/fsx"
)

const (
	ModemCredentialSlotSuper = "super"
	ModemCredentialSlotUser  = "user"
	defaultModemVaultPath    = "/etc/singctl/modem-auth.json"
	maxModemCredentialBytes  = 128
)

var modemVaultMu sync.Mutex

// ModemCredentialSlotSummary 描述单个光猫凭据槽位的脱敏元数据（绝不向摘要接口回传密码明文）。
type ModemCredentialSlotSummary struct {
	Saved     bool   `json:"saved"`
	Username  string `json:"username,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

// ModemCredentialsSummary 描述双槽位光猫凭据保存概览。
type ModemCredentialsSummary struct {
	Super ModemCredentialSlotSummary `json:"super"`
	User  ModemCredentialSlotSummary `json:"user"`
}

type modemVaultSlotRecord struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	UpdatedAt string `json:"updatedAt"`
}

type modemVaultDisk struct {
	Super *modemVaultSlotRecord `json:"super,omitempty"`
	User  *modemVaultSlotRecord `json:"user,omitempty"`
}

// ModemVaultPath 返回与主配置文件同目录的独立 0600 光猫凭据保险箱路径。
func ModemVaultPath(configPath string) string {
	trimmed := strings.TrimSpace(configPath)
	if trimmed == "" {
		return defaultModemVaultPath
	}
	dir := filepath.Dir(trimmed)
	if dir == "" || dir == "." {
		return "modem-auth.json"
	}
	return filepath.Join(dir, "modem-auth.json")
}

func normalizeModemCredentialSlot(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case ModemCredentialSlotSuper:
		return ModemCredentialSlotSuper, nil
	case ModemCredentialSlotUser:
		return ModemCredentialSlotUser, nil
	default:
		return "", fmt.Errorf("不支持的光猫凭据槽位 %q（仅允许 super 或 user）", raw)
	}
}

func validateModemCredentialField(fieldLabel, val string, required bool) error {
	if required && val == "" {
		return fmt.Errorf("请填写%s", fieldLabel)
	}
	if len(val) > maxModemCredentialBytes {
		return fmt.Errorf("%s长度不能超过 %d 字符", fieldLabel, maxModemCredentialBytes)
	}
	for i := range len(val) {
		c := val[i]
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("%s包含非法控制字符", fieldLabel)
		}
	}
	return nil
}

func readModemVaultDiskLocked(vaultPath string) modemVaultDisk {
	raw, err := os.ReadFile(vaultPath)
	if err != nil || len(raw) == 0 {
		return modemVaultDisk{}
	}
	var disk modemVaultDisk
	if jErr := json.Unmarshal(raw, &disk); jErr != nil {
		return modemVaultDisk{}
	}
	return disk
}

func summarizeModemVaultDisk(disk modemVaultDisk) ModemCredentialsSummary {
	var out ModemCredentialsSummary
	if disk.Super != nil && disk.Super.Username != "" && disk.Super.Password != "" {
		out.Super = ModemCredentialSlotSummary{
			Saved:     true,
			Username:  disk.Super.Username,
			UpdatedAt: disk.Super.UpdatedAt,
		}
	}
	if disk.User != nil && disk.User.Username != "" && disk.User.Password != "" {
		out.User = ModemCredentialSlotSummary{
			Saved:     true,
			Username:  disk.User.Username,
			UpdatedAt: disk.User.UpdatedAt,
		}
	}
	return out
}

// LoadModemCredentialsSummary 读取双槽位光猫凭据的脱敏状态（仅返回是否已保存、用户名与更新时间）。
func LoadModemCredentialsSummary(vaultPath string) ModemCredentialsSummary {
	modemVaultMu.Lock()
	defer modemVaultMu.Unlock()
	return summarizeModemVaultDisk(readModemVaultDiskLocked(ModemVaultPathOrDefault(vaultPath)))
}

// ModemVaultPathOrDefault 将空路径回退到默认 0600 保险箱路径。
func ModemVaultPathOrDefault(vaultPath string) string {
	if trimmed := strings.TrimSpace(vaultPath); trimmed != "" {
		return trimmed
	}
	return defaultModemVaultPath
}

// SaveModemCredentialSlot 验证并原子保存（或清空）指定槽位的光猫登录凭据，强制 0600 落盘。
func SaveModemCredentialSlot(vaultPath, slot, username, password string, clearSlot bool, now time.Time) (ModemCredentialsSummary, error) {
	normSlot, err := normalizeModemCredentialSlot(slot)
	if err != nil {
		return ModemCredentialsSummary{}, err
	}
	targetPath := ModemVaultPathOrDefault(vaultPath)
	if now.IsZero() {
		now = time.Now()
	}

	modemVaultMu.Lock()
	defer modemVaultMu.Unlock()

	disk := readModemVaultDiskLocked(targetPath)
	if clearSlot {
		if normSlot == ModemCredentialSlotSuper {
			disk.Super = nil
		} else {
			disk.User = nil
		}
		if err := writeModemVaultDiskLocked(targetPath, disk); err != nil {
			return ModemCredentialsSummary{}, err
		}
		return summarizeModemVaultDisk(disk), nil
	}

	cleanUser := strings.TrimSpace(username)
	if err := validateModemCredentialField("光猫账号", cleanUser, true); err != nil {
		return ModemCredentialsSummary{}, err
	}
	if err := validateModemCredentialField("光猫密码", password, false); err != nil {
		return ModemCredentialsSummary{}, err
	}

	var prevPass string
	if normSlot == ModemCredentialSlotSuper && disk.Super != nil {
		prevPass = disk.Super.Password
	} else if normSlot == ModemCredentialSlotUser && disk.User != nil {
		prevPass = disk.User.Password
	}

	finalPass := password
	if finalPass == "" {
		finalPass = prevPass
	}
	if err := validateModemCredentialField("光猫密码", finalPass, true); err != nil {
		return ModemCredentialsSummary{}, err
	}

	rec := &modemVaultSlotRecord{
		Username:  cleanUser,
		Password:  finalPass,
		UpdatedAt: now.UTC().Format(time.RFC3339),
	}
	if normSlot == ModemCredentialSlotSuper {
		disk.Super = rec
	} else {
		disk.User = rec
	}

	if err := writeModemVaultDiskLocked(targetPath, disk); err != nil {
		return ModemCredentialsSummary{}, err
	}
	return summarizeModemVaultDisk(disk), nil
}

func writeModemVaultDiskLocked(targetPath string, disk modemVaultDisk) error {
	raw, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	return fsx.WriteAtomic0600(targetPath, append(raw, '\n'))
}

// ReadModemCredentialSecret 按槽位读取用于一键填充登录的光猫用户名与密码。
func ReadModemCredentialSecret(vaultPath, slot string) (string, string, error) {
	normSlot, err := normalizeModemCredentialSlot(slot)
	if err != nil {
		return "", "", err
	}
	targetPath := ModemVaultPathOrDefault(vaultPath)

	modemVaultMu.Lock()
	defer modemVaultMu.Unlock()

	disk := readModemVaultDiskLocked(targetPath)
	var rec *modemVaultSlotRecord
	if normSlot == ModemCredentialSlotSuper {
		rec = disk.Super
	} else {
		rec = disk.User
	}
	if rec == nil || rec.Username == "" || rec.Password == "" {
		return "", "", errors.New("该槽位尚未保存光猫登录凭据")
	}
	return rec.Username, rec.Password, nil
}
