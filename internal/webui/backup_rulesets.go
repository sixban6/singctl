// 文件职责：提供 V2 网关加密备份离线规则集 tar.gz 安全打包/校验解包、跨机路径对齐与全事务原子回滚原语。
package webui

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"singctl/internal/common/fsx"
	"singctl/internal/singbox"
)

const (
	maxRuleSetArchiveUncompressedBytes = 32 * 1024 * 1024 // 32 MiB 解压硬上限（防压缩炸弹）
	maxRuleSetArchiveFiles             = 200              // 归档文件数硬上限
	lowMemorySkippedRuleSetFile        = "geosite-ad2.srs"
	lowMemorySkippedRuleSetHashFile    = "geosite-ad2.srs.sha256"
)

type ruleSetArchiveEntry struct {
	Name string
	Data []byte
}

func (s *Server) ruleSetCacheDir() string {
	if customSB := strings.TrimSpace(s.opts.SingBoxConfigPath); customSB != "" {
		return filepath.Join(filepath.Dir(customSB), "rule_sets")
	}
	return singbox.RuleSetCacheDir()
}

// isValidRuleSetArchiveFileName 严格校验离线规则集归档条目名：
// 仅允许扁平白名单文件名（*.srs / *.sha256 / manifest.json），严禁路径穿越、绝对路径、子目录与隐藏文件。
func isValidRuleSetArchiveFileName(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	if strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	if filepath.IsAbs(name) || filepath.Base(name) != name || filepath.Clean(name) != name {
		return false
	}
	if name == "manifest.json" {
		return true
	}
	if strings.HasSuffix(name, ".srs") && len(name) > len(".srs") {
		return true
	}
	if strings.HasSuffix(name, ".sha256") && len(name) > len(".sha256") {
		return true
	}
	return false
}

// packRuleSetsTarGz 将规则集缓存目录下的白名单普通文件打包为确定性 tar.gz，并返回 .srs 规则集数量。
func packRuleSetsTarGz(dir string) ([]byte, int, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, 0, nil
	}
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, err
	}

	var names []string
	for _, de := range dirEntries {
		name := de.Name()
		if !isValidRuleSetArchiveFileName(name) {
			continue
		}
		info, statErr := os.Lstat(filepath.Join(dir, name))
		if statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, 0, nil
	}
	slices.Sort(names)

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	var totalBytes int64
	fileCount := 0
	srsCount := 0

	for _, name := range names {
		if fileCount >= maxRuleSetArchiveFiles {
			break
		}
		fullPath := filepath.Join(dir, name)
		info, statErr := os.Lstat(fullPath)
		if statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		data, readErr := os.ReadFile(fullPath)
		if readErr != nil {
			continue
		}
		if totalBytes+int64(len(data)) > maxRuleSetArchiveUncompressedBytes {
			return nil, 0, fmt.Errorf("离线规则集总体积超过 32MB 上限")
		}
		hdr := &tar.Header{
			Name:     name,
			Mode:     0600,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
			ModTime:  info.ModTime().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, 0, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, 0, err
		}
		totalBytes += int64(len(data))
		fileCount++
		if strings.HasSuffix(name, ".srs") {
			srsCount++
		}
	}

	if err := tw.Close(); err != nil {
		return nil, 0, err
	}
	if err := gzw.Close(); err != nil {
		return nil, 0, err
	}
	if fileCount == 0 {
		return nil, 0, nil
	}
	return buf.Bytes(), srsCount, nil
}

// parseAndValidateRuleSetsTarGz 在落盘前完整解压并安全校验离线规则集 tar.gz 归档。
func parseAndValidateRuleSetsTarGz(archive []byte) ([]ruleSetArchiveEntry, error) {
	if len(archive) == 0 {
		return nil, nil
	}
	gzr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("规则集归档 gzip 格式非法: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var (
		entries    []ruleSetArchiveEntry
		seen       = make(map[string]bool)
		totalBytes int64
	)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("规则集归档 tar 结构损坏: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("规则集归档包含非普通文件条目 (%s, type=%d)，已拒绝", hdr.Name, hdr.Typeflag)
		}
		if !isValidRuleSetArchiveFileName(hdr.Name) {
			return nil, fmt.Errorf("规则集归档包含非法路径或未授权扩展名: %s", hdr.Name)
		}
		if seen[hdr.Name] {
			return nil, fmt.Errorf("规则集归档包含重复文件条目: %s", hdr.Name)
		}
		seen[hdr.Name] = true

		if len(entries)+1 > maxRuleSetArchiveFiles {
			return nil, fmt.Errorf("规则集归档文件数量超过上限 (%d)", maxRuleSetArchiveFiles)
		}
		remaining := maxRuleSetArchiveUncompressedBytes - totalBytes
		if hdr.Size < 0 || hdr.Size > remaining {
			return nil, fmt.Errorf("规则集归档解压总大小超过 32MB 上限")
		}
		data, readErr := io.ReadAll(io.LimitReader(tr, remaining+1))
		if readErr != nil {
			return nil, fmt.Errorf("读取规则集归档条目 %s 失败: %w", hdr.Name, readErr)
		}
		if int64(len(data)) > remaining {
			return nil, fmt.Errorf("规则集归档解压总大小超过 32MB 上限")
		}
		if hdr.Name == "manifest.json" {
			var checkManifest map[string]any
			if err := json.Unmarshal(data, &checkManifest); err != nil {
				return nil, fmt.Errorf("规则集归档中的 manifest.json 格式非法: %w", err)
			}
		}
		totalBytes += int64(len(data))
		entries = append(entries, ruleSetArchiveEntry{
			Name: hdr.Name,
			Data: data,
		})
	}
	return entries, nil
}

// alignLocalRuleSetPathsJSON 将配置中 type=local 且文件名命中本次恢复目录的规则集 path 对齐至目标机 rule_sets 目录。
func alignLocalRuleSetPathsJSON(rawJSON, ruleSetDir string, writtenFiles map[string]bool) string {
	if strings.TrimSpace(rawJSON) == "" || strings.TrimSpace(ruleSetDir) == "" || len(writtenFiles) == 0 {
		return rawJSON
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil || root == nil {
		return rawJSON
	}
	route, _ := root["route"].(map[string]any)
	if route == nil {
		return rawJSON
	}
	arr, _ := route["rule_set"].([]any)
	changed := false
	for _, raw := range arr {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := entry["type"].(string)
		if typ != "local" {
			continue
		}
		p, _ := entry["path"].(string)
		base := filepath.Base(strings.TrimSpace(p))
		if base == "" || !writtenFiles[base] {
			continue
		}
		desired := filepath.Join(ruleSetDir, base)
		if p != desired {
			entry["path"] = desired
			changed = true
		}
	}
	if !changed {
		return rawJSON
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return rawJSON
	}
	return string(out) + "\n"
}

// restoreTransaction 记录迁移恢复前的文件与目录快照，任意步骤失败时自动逆序回滚并刷新 cfgStore。
type fileRollbackEntry struct {
	path    string
	existed bool
	data    []byte
	perm    os.FileMode
}

type restoreTransaction struct {
	srv         *Server
	committed   bool
	seenPaths   map[string]bool
	files       []fileRollbackEntry
	createdDirs []string
}

func newRestoreTransaction(s *Server) *restoreTransaction {
	return &restoreTransaction{
		srv:       s,
		seenPaths: make(map[string]bool),
	}
}

func (tx *restoreTransaction) snapshotFile(path string) error {
	clean := strings.TrimSpace(path)
	if clean == "" || tx.seenPaths[clean] {
		return nil
	}
	tx.seenPaths[clean] = true

	info, err := os.Stat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			tx.files = append(tx.files, fileRollbackEntry{path: clean, existed: false})
			return nil
		}
		return err
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		return err
	}
	perm := info.Mode().Perm()
	if perm == 0 {
		perm = 0600
	}
	tx.files = append(tx.files, fileRollbackEntry{
		path:    clean,
		existed: true,
		data:    data,
		perm:    perm,
	})
	return nil
}

func (tx *restoreTransaction) ensureDir(dir string) error {
	clean := strings.TrimSpace(dir)
	if clean == "" {
		return nil
	}
	if _, err := os.Stat(clean); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(clean, 0755); err != nil {
		return err
	}
	tx.createdDirs = append(tx.createdDirs, clean)
	return nil
}

func (tx *restoreTransaction) commit() {
	tx.committed = true
}

func (tx *restoreTransaction) rollbackIfNeeded() {
	if tx.committed {
		return
	}
	for i := len(tx.files) - 1; i >= 0; i-- {
		f := tx.files[i]
		if f.existed {
			_ = os.MkdirAll(filepath.Dir(f.path), 0755)
			if err := fsx.WriteAtomic(f.path, f.data, f.perm); err != nil {
				_ = os.WriteFile(f.path, f.data, f.perm)
				_ = os.Chmod(f.path, f.perm)
			}
		} else {
			_ = os.Remove(f.path)
		}
	}
	for i := len(tx.createdDirs) - 1; i >= 0; i-- {
		_ = os.Remove(tx.createdDirs[i])
	}
	if tx.srv != nil {
		tx.srv.invalidateConfigStore()
		tx.srv.invalidateIOSCache()
	}
}

func applyRuleSetEntriesToDir(
	tx *restoreTransaction,
	dir string,
	entries []ruleSetArchiveEntry,
	lowMemory bool,
) (restoredSRS int, skippedHeavy bool, writtenFiles map[string]bool, err error) {
	if len(entries) == 0 || strings.TrimSpace(dir) == "" {
		return 0, false, nil, nil
	}
	if err = tx.ensureDir(dir); err != nil {
		return 0, false, nil, fmt.Errorf("创建规则集缓存目录失败: %w", err)
	}
	writtenFiles = make(map[string]bool, len(entries))
	for _, entry := range entries {
		if lowMemory && (entry.Name == lowMemorySkippedRuleSetFile || entry.Name == lowMemorySkippedRuleSetHashFile) {
			if entry.Name == lowMemorySkippedRuleSetFile {
				skippedHeavy = true
			}
			continue
		}
		dstPath := filepath.Join(dir, entry.Name)
		if err = tx.snapshotFile(dstPath); err != nil {
			return 0, skippedHeavy, writtenFiles, fmt.Errorf("快照现有规则集 %s 失败: %w", entry.Name, err)
		}
		if err = fsx.WriteAtomic0600(dstPath, entry.Data); err != nil {
			return 0, skippedHeavy, writtenFiles, fmt.Errorf("写入离线规则集 %s 失败: %w", entry.Name, err)
		}
		writtenFiles[entry.Name] = true
		if strings.HasSuffix(entry.Name, ".srs") {
			restoredSRS++
		}
	}
	return restoredSRS, skippedHeavy, writtenFiles, nil
}

func isDNSLocalPointingToLocalAdGuard(rawJSON string) bool {
	var doc struct {
		DNS *struct {
			Servers []struct {
				Tag    string `json:"tag"`
				Server string `json:"server"`
			} `json:"servers"`
		} `json:"dns"`
	}
	if err := json.Unmarshal([]byte(rawJSON), &doc); err != nil || doc.DNS == nil {
		return false
	}
	for _, srv := range doc.DNS.Servers {
		if srv.Tag == "dns_local" && strings.TrimSpace(srv.Server) == "127.0.0.1" {
			return true
		}
	}
	return false
}

func preserveLiveClashSecret(existingJSON, targetJSON string) string {
	var curRoot, dstRoot map[string]any
	if err := json.Unmarshal([]byte(existingJSON), &curRoot); err != nil || curRoot == nil {
		return targetJSON
	}
	cExp, _ := curRoot["experimental"].(map[string]any)
	cClash, _ := cExp["clash_api"].(map[string]any)
	curSecret, _ := cClash["secret"].(string)
	curSecret = strings.TrimSpace(curSecret)
	if curSecret == "" {
		return targetJSON
	}
	if err := json.Unmarshal([]byte(targetJSON), &dstRoot); err != nil || dstRoot == nil {
		return targetJSON
	}
	dExp, _ := dstRoot["experimental"].(map[string]any)
	if dExp == nil {
		dExp = map[string]any{}
		dstRoot["experimental"] = dExp
	}
	dClash, _ := dExp["clash_api"].(map[string]any)
	if dClash == nil {
		dClash = make(map[string]any, len(cClash))
		for k, v := range cClash {
			dClash[k] = v
		}
		dExp["clash_api"] = dClash
	} else {
		dClash["secret"] = curSecret
	}
	if dSvcs, ok := dstRoot["services"].([]any); ok {
		for _, item := range dSvcs {
			svc, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if typ, _ := svc["type"].(string); strings.EqualFold(strings.TrimSpace(typ), "api") {
				if _, has := svc["secret"]; has {
					svc["secret"] = curSecret
				}
			}
		}
	}
	b, err := json.MarshalIndent(dstRoot, "", "  ")
	if err != nil {
		return targetJSON
	}
	return string(b) + "\n"
}

func adaptSingBoxJSONForTarget(
	rawJSON string,
	ruleSetDir string,
	writtenRS map[string]bool,
	noAdGuard bool,
	lowMemory bool,
) (adapted string, didFallbackDoH bool, didPruneAd2 bool, err error) {
	adapted = alignLocalRuleSetPathsJSON(rawJSON, ruleSetDir, writtenRS)
	if noAdGuard {
		wasLocalExternal := isDNSLocalPointingToLocalAdGuard(adapted)
		patched, changed, pErr := singbox.PatchDNSLocalJSON(adapted, false, 0)
		if pErr != nil {
			return "", false, false, fmt.Errorf("跨机自适配回退内置 DoH 失败: %w", pErr)
		}
		if changed {
			adapted = patched
			if wasLocalExternal {
				didFallbackDoH = true
			}
		}
	}
	if lowMemory {
		pruned, changed, pErr := singbox.PruneLowMemoryRuleSetsJSON(adapted)
		if pErr != nil {
			return "", didFallbackDoH, false, fmt.Errorf("低内存自适配裁剪 geosite-ad2 失败: %w", pErr)
		}
		if changed {
			adapted = pruned
			didPruneAd2 = true
		}
	}
	return adapted, didFallbackDoH, didPruneAd2, nil
}
