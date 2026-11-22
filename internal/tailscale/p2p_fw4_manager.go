// 文件职责：负责 OpenWrt fw4 drop-in 落盘重载、原子 nftables 直写兜底及动态 JIT 打洞白名单集合管理。
package tailscale

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FW4Manager 负责将 SingCtl P2P 防线规则通过 OpenWrt fw4 drop-in + 原子直写 nftables 兜底生效，
// 并提供 JIT 白名单元素的毫秒级开关与计数查询。
type FW4Manager struct {
	BaseDir string
	Runner  CmdRunner

	mu            sync.Mutex
	lastDigest    string
	lastApplyMode string
}

func (m *FW4Manager) baseDir() string {
	return cmp.Or(strings.TrimSpace(m.BaseDir), DefaultNFTablesDDir)
}

func (m *FW4Manager) run(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	if m.Runner != nil {
		return m.Runner(ctx, stdin, name, args...)
	}
	return defaultCmdRunner(ctx, stdin, name, args...)
}

func (m *FW4Manager) dropInPaths() map[string]string {
	base := m.baseDir()
	return map[string]string{
		"table-pre":         filepath.Join(base, "table-pre", "singctl-ts-jit.nft"),
		"input-wan":         filepath.Join(base, "chain-pre", "input_wan", "singctl-ts-jit.nft"),
		"input-tailscale":   filepath.Join(base, "chain-pre", "input_tailscale", "singctl-ts-acl.nft"),
		"forward-tailscale": filepath.Join(base, "chain-pre", "forward_tailscale", "singctl-ts-acl.nft"),
	}
}

type fileSnapshot struct {
	existed bool
	data    []byte
}

func snapshotFiles(paths map[string]string) map[string]fileSnapshot {
	snaps := make(map[string]fileSnapshot, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			snaps[p] = fileSnapshot{existed: true, data: data}
		} else {
			snaps[p] = fileSnapshot{existed: false}
		}
	}
	return snaps
}

func restoreFiles(snaps map[string]fileSnapshot) {
	for p, s := range snaps {
		if s.existed {
			_ = os.MkdirAll(filepath.Dir(p), 0755)
			_ = os.WriteFile(p, s.data, 0644)
		} else {
			_ = os.Remove(p)
		}
	}
}

// Apply 将渲染后的防线规则安全落盘并通过 fw4 reload（健康时）或原子 nftables 直写生效。
func (m *FW4Manager) Apply(ctx context.Context, d FW4DropIns) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if out, err := m.run(ctx, d.RenderDryRunCheckScript(), "nft", "-c", "-f", "-"); err != nil {
		return "", fmt.Errorf("nft syntax self-check failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	paths := m.dropInPaths()
	wantContents := map[string]string{
		paths["table-pre"]:         d.TablePre,
		paths["input-wan"]:         d.InputWANPre,
		paths["input-tailscale"]:   d.InputTailscalePre,
		paths["forward-tailscale"]: d.ForwardTailscalePre,
	}

	snaps := snapshotFiles(paths)
	filesMatch := true
	for p, want := range wantContents {
		snap, ok := snaps[p]
		if !ok || !snap.existed || string(snap.data) != want {
			filesMatch = false
			break
		}
	}

	digest := d.Digest()
	if filesMatch && m.lastDigest == digest && m.liveChainExists(ctx) {
		return cmp.Or(m.lastApplyMode, ApplyModeFW4Reload), nil
	}

	for p, content := range wantContents {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			restoreFiles(snaps)
			return "", fmt.Errorf("create nftables drop-in dir: %w", err)
		}
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
			_ = os.Remove(tmp)
			restoreFiles(snaps)
			return "", fmt.Errorf("write %s: %w", p, err)
		}
		if err := os.Rename(tmp, p); err != nil {
			_ = os.Remove(tmp)
			restoreFiles(snaps)
			return "", fmt.Errorf("rename %s: %w", p, err)
		}
	}

	if _, err := m.run(ctx, "", "fw4", "check"); err == nil {
		if out, reloadErr := m.run(ctx, "", "fw4", "reload"); reloadErr != nil {
			restoreFiles(snaps)
			_, _ = m.run(ctx, "", "fw4", "reload")
			return "", fmt.Errorf("fw4 reload failed: %w (%s)", reloadErr, strings.TrimSpace(string(out)))
		}
		m.lastDigest = digest
		m.lastApplyMode = ApplyModeFW4Reload
		return ApplyModeFW4Reload, nil
	}

	if err := m.applyNFTDirect(ctx, d); err != nil {
		restoreFiles(snaps)
		return "", err
	}
	m.lastDigest = digest
	m.lastApplyMode = ApplyModeNFTDirect
	return ApplyModeNFTDirect, nil
}

func (m *FW4Manager) liveChainExists(ctx context.Context) bool {
	_, err := m.run(ctx, "", "nft", "list", "chain", "inet", "fw4", chainJITGuard)
	return err == nil
}

type fw4TableInspection struct {
	setsPresent   map[string]bool
	chainsPresent map[string]bool
	taggedHandles map[string][]int
}

func parseFW4Inspection(raw string) fw4TableInspection {
	res := fw4TableInspection{
		setsPresent:   make(map[string]bool),
		chainsPresent: make(map[string]bool),
		taggedHandles: make(map[string][]int),
	}
	var currentKind, currentName string
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if m := openBraceSelRe.FindStringSubmatch(trimmed); len(m) == 3 {
			currentKind = m[1]
			currentName = m[2]
			switch currentKind {
			case "set":
				res.setsPresent[currentName] = true
			case "chain":
				res.chainsPresent[currentName] = true
			}
			continue
		}
		if trimmed == "}" {
			currentKind = ""
			currentName = ""
			continue
		}
		if currentKind == "chain" && (currentName == "input_wan" || currentName == "input_tailscale" || currentName == "forward_tailscale") {
			if strings.Contains(trimmed, jitCommentTag) || strings.Contains(trimmed, aclCommentTag) {
				if hm := nftHandleRe.FindStringSubmatch(trimmed); len(hm) == 2 {
					if handle, err := strconv.Atoi(hm[1]); err == nil && handle > 0 {
						res.taggedHandles[currentName] = append(res.taggedHandles[currentName], handle)
					}
				}
			}
		}
	}
	return res
}

func (m *FW4Manager) applyNFTDirect(ctx context.Context, d FW4DropIns) error {
	raw, err := m.run(ctx, "", "nft", "-a", "list", "table", "inet", "fw4")
	if err != nil {
		return fmt.Errorf("fw4 check failed and table inet fw4 unavailable for atomic nft reconcile: %w (%s)", err, strings.TrimSpace(string(raw)))
	}
	insp := parseFW4Inspection(string(raw))

	var b strings.Builder
	if !insp.setsPresent[setTSJITAllow4] {
		fmt.Fprintf(&b, "add set inet fw4 %s { type ipv4_addr; flags timeout; timeout %ds; }\n", setTSJITAllow4, d.JITWindowSec)
	}
	if !insp.setsPresent[setTSJITAllow6] {
		fmt.Fprintf(&b, "add set inet fw4 %s { type ipv6_addr; flags timeout; timeout %ds; }\n", setTSJITAllow6, d.JITWindowSec)
	}

	writeChainPatch := func(chain string, rules []string) {
		fmt.Fprintf(&b, "add chain inet fw4 %s\n", chain)
		fmt.Fprintf(&b, "flush chain inet fw4 %s\n", chain)
		for _, r := range rules {
			fmt.Fprintf(&b, "add rule inet fw4 %s %s\n", chain, r)
		}
	}
	writeChainPatch(chainJITGuard, d.JITGuardRules)
	writeChainPatch(chainInputACL, d.InputACLRules)
	writeChainPatch(chainForwardACL, d.ForwardACLRules)

	patchJump := func(parent string, ruleExpr string) {
		for _, h := range insp.taggedHandles[parent] {
			fmt.Fprintf(&b, "delete rule inet fw4 %s handle %d\n", parent, h)
		}
		if insp.chainsPresent[parent] {
			fmt.Fprintf(&b, "insert rule inet fw4 %s %s\n", parent, ruleExpr)
		}
	}
	patchJump("input_wan", d.inputWANRule())
	patchJump("input_tailscale", d.inputTailscaleRule())
	patchJump("forward_tailscale", d.forwardTailscaleRule())

	script := b.String()
	if out, err := m.run(ctx, script, "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("atomic nft patch check failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := m.run(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("atomic nft patch apply failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Remove 彻底清理全部 drop-in 文件并撤销运行时防火墙规则（幂等安全）。
func (m *FW4Manager) Remove(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	paths := m.dropInPaths()
	snaps := snapshotFiles(paths)
	anyRemoved := false
	for _, s := range snaps {
		if s.existed {
			anyRemoved = true
			break
		}
	}
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove drop-in %s: %w", p, err)
		}
	}

	if _, err := m.run(ctx, "", "fw4", "check"); err == nil {
		if anyRemoved || m.liveChainExists(ctx) {
			if out, reloadErr := m.run(ctx, "", "fw4", "reload"); reloadErr != nil {
				restoreFiles(snaps)
				return fmt.Errorf("fw4 reload after remove failed: %w (%s)", reloadErr, strings.TrimSpace(string(out)))
			}
		}
		m.lastDigest = ""
		m.lastApplyMode = ""
		return nil
	}

	raw, err := m.run(ctx, "", "nft", "-a", "list", "table", "inet", "fw4")
	if err != nil {
		m.lastDigest = ""
		m.lastApplyMode = ""
		return nil
	}
	insp := parseFW4Inspection(string(raw))

	var b strings.Builder
	for _, parent := range []string{"input_wan", "input_tailscale", "forward_tailscale"} {
		for _, h := range insp.taggedHandles[parent] {
			fmt.Fprintf(&b, "delete rule inet fw4 %s handle %d\n", parent, h)
		}
	}
	for _, ch := range []string{chainJITGuard, chainInputACL, chainForwardACL} {
		if insp.chainsPresent[ch] {
			fmt.Fprintf(&b, "flush chain inet fw4 %s\n", ch)
			fmt.Fprintf(&b, "delete chain inet fw4 %s\n", ch)
		}
	}
	for _, setName := range []string{setTSJITAllow4, setTSJITAllow6} {
		if insp.setsPresent[setName] {
			fmt.Fprintf(&b, "delete set inet fw4 %s\n", setName)
		}
	}

	if b.Len() > 0 {
		if out, err := m.run(ctx, b.String(), "nft", "-f", "-"); err != nil {
			return fmt.Errorf("atomic nft remove failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	m.lastDigest = ""
	m.lastApplyMode = ""
	return nil
}

// OpenPinhole 仅在打洞窗口秒数内向内核动态集合插入候选公网 IPv4/IPv6，超时由内核自动驱逐。
func (m *FW4Manager) OpenPinhole(ctx context.Context, v4 []netip.Addr, v6 []netip.Addr, windowSec int) error {
	win := min(max(3, windowSec), 10)
	for _, ip := range v4 {
		elem := fmt.Sprintf("{ %s timeout %ds }", ip.String(), win)
		if out, err := m.run(ctx, "", "nft", "add", "element", "inet", "fw4", setTSJITAllow4, elem); err != nil {
			return fmt.Errorf("nft add element v4: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	for _, ip := range v6 {
		elem := fmt.Sprintf("{ %s timeout %ds }", ip.String(), win)
		if out, err := m.run(ctx, "", "nft", "add", "element", "inet", "fw4", setTSJITAllow6, elem); err != nil {
			return fmt.Errorf("nft add element v6: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// ClosePinhole 在直连切换完成或打洞结束时立即吊销瞬时集合元素，若已被内核超时回收则静默忽略。
func (m *FW4Manager) ClosePinhole(ctx context.Context, v4 []netip.Addr, v6 []netip.Addr) error {
	deleteOne := func(setName string, ip netip.Addr) error {
		elem := fmt.Sprintf("{ %s }", ip.String())
		out, err := m.run(ctx, "", "nft", "delete", "element", "inet", "fw4", setName, elem)
		if err == nil {
			return nil
		}
		msg := strings.ToLower(string(out) + " " + err.Error())
		if strings.Contains(msg, "no such file or directory") || strings.Contains(msg, "enoent") {
			return nil
		}
		return fmt.Errorf("nft delete element %s: %w (%s)", setName, err, strings.TrimSpace(string(out)))
	}
	for _, ip := range v4 {
		if err := deleteOne(setTSJITAllow4, ip); err != nil {
			return err
		}
	}
	for _, ip := range v6 {
		if err := deleteOne(setTSJITAllow6, ip); err != nil {
			return err
		}
	}
	return nil
}

// CountOpenPinholes 实时读取内核 TS_JIT_ALLOW4 / TS_JIT_ALLOW6 集合中的活跃条目数量。
func (m *FW4Manager) CountOpenPinholes(ctx context.Context) (int, []string) {
	var ips []string
	for _, setName := range []string{setTSJITAllow4, setTSJITAllow6} {
		out, err := m.run(ctx, "", "nft", "-j", "list", "set", "inet", "fw4", setName)
		if err != nil || len(bytes.TrimSpace(out)) == 0 {
			continue
		}
		ips = append(ips, parseNFTSetJSONElems(out)...)
	}
	slices.Sort(ips)
	return len(ips), ips
}

func parseNFTSetJSONElems(raw []byte) []string {
	var doc struct {
		NFTables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []string
	for _, entry := range doc.NFTables {
		if entry.Set == nil {
			continue
		}
		for _, elemRaw := range entry.Set.Elem {
			var strVal string
			if json.Unmarshal(elemRaw, &strVal) == nil && strVal != "" {
				out = append(out, strVal)
				continue
			}
			var obj struct {
				Elem *struct {
					Val string `json:"val"`
				} `json:"elem"`
			}
			if json.Unmarshal(elemRaw, &obj) == nil && obj.Elem != nil && obj.Elem.Val != "" {
				out = append(out, obj.Elem.Val)
			}
		}
	}
	return out
}

// IsFW4Available 检测当前宿主机是否处于存在 inet fw4 防火墙表的 OpenWrt 环境。
func IsFW4Available() bool {
	if _, err := exec.LookPath("fw4"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "nft", "list", "table", "inet", "fw4").Run() == nil
}
