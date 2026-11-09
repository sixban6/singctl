package fleet

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/config"
	"singctl/internal/subhub"

	"golang.org/x/crypto/ssh"
)

var (
	ansiEscapeRe  = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	doctorScoreRe = regexp.MustCompile(`综合健康指数:\s*(\d+)\s*/\s*100`)
	versionLineRe = regexp.MustCompile(`SingCtl\s+(v[0-9]+\.[0-9]+\.[0-9]+[^\s]*)`)
)

// RunnerFunc executes a shell script on a remote fleet node and returns stdout and SSH RTT in ms.
type RunnerFunc func(ctx context.Context, node Node, script string) (stdout string, latencyMs int, err error)

// NodeActionResult captures the outcome of a fleet operation on a single node.
type NodeActionResult struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Success        bool     `json:"success"`
	LatencyMs      int      `json:"latencyMs"`
	SingctlVersion string   `json:"singctlVersion,omitempty"`
	DoctorScore    int      `json:"doctorScore,omitempty"`
	SyncedNodes    int      `json:"syncedNodes,omitempty"`
	Message        string   `json:"message"`
	Output         string   `json:"output,omitempty"`
	Protocols      []string `json:"protocols,omitempty"`
}

// Manager coordinates concurrent operations across fleet nodes and syncs endpoints into SubHub.
type Manager struct {
	Store         *Store
	SubStore      *subhub.Store
	ConfigPath    string
	CFClient      *CloudflareDNSClient
	GeoProber     GeoProberFunc
	HTTPProber    HTTPSProberFunc
	Runner        RunnerFunc
	patrolStarted atomic.Bool
	probeMu       sync.Mutex
}

// NewManager creates a Fleet Manager backed by fleetStore and subStore.
func NewManager(fleetStore *Store, subStore *subhub.Store) *Manager {
	cfgPath := ""
	if fleetStore != nil && fleetStore.FilePath != "" {
		cand := filepath.Join(filepath.Dir(fleetStore.FilePath), "singctl.yaml")
		if _, err := os.Stat(cand); err == nil {
			cfgPath = cand
		}
	}
	return &Manager{
		Store:      fleetStore,
		SubStore:   subStore,
		ConfigPath: cfgPath,
		CFClient:   NewCloudflareDNSClient(),
		GeoProber:  DefaultGeoProber,
		HTTPProber: DefaultHTTPSProber,
		Runner:     DefaultSSHRunner,
	}
}

func (m *Manager) loadMasterConfig() *config.Config {
	p := strings.TrimSpace(m.ConfigPath)
	if p == "" && m.Store != nil && m.Store.FilePath != "" {
		p = filepath.Join(filepath.Dir(m.Store.FilePath), "singctl.yaml")
	}
	if p == "" {
		p = "/etc/singctl/singctl.yaml"
	}
	cfg, err := config.Load(p)
	if err != nil || cfg == nil {
		return &config.Config{}
	}
	return cfg
}

// GetBootstrapDefaults returns sanitized Master configuration metadata for zero-config UI/CLI bootstrap.
func (m *Manager) GetBootstrapDefaults(ctx context.Context) BootstrapDefaults {
	cfg := m.loadMasterConfig()
	masterDom := strings.TrimSpace(cfg.Server.GetNodeDomain())
	hasCF := strings.TrimSpace(cfg.Server.CFDNSKey) != ""
	rootZone := guessRootDomain(masterDom)
	if hasCF && m.CFClient != nil {
		zCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		if z, err := m.CFClient.FindZone(zCtx, cfg.Server.CFDNSKey, masterDom, false); err == nil && z != nil {
			rootZone = z.Name
		}
		cancel()
	}
	return BootstrapDefaults{
		HasMasterCFToken:     hasCF,
		MasterNodeDomain:     masterDom,
		SuggestedRootZone:    rootZone,
		DefaultSNI:           cmp.Or(strings.TrimSpace(cfg.Server.Sni), "swdist.apple.com"),
		DefaultTargetSSHPort: DefaultTargetSSHPort,
		Hy2Up:                cmp.Or(cfg.Hy2.Up, 50),
		Hy2Down:              cmp.Or(cfg.Hy2.Down, 300),
	}
}

func guessRootDomain(d string) string {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if d == "" || d == "node.yourdomain.com" {
		return ""
	}
	parts := strings.Split(d, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return d
}

// DefaultSSHRunner connects via either OpenSSH config alias or native Go crypto/ssh.
func DefaultSSHRunner(ctx context.Context, node Node, script string) (string, int, error) {
	start := time.Now()
	if node.AuthType == AuthSSHAlias {
		alias := cmp.Or(strings.TrimSpace(node.SSHAlias), strings.TrimSpace(node.Host))
		if err := ValidateHostTarget(alias); err != nil {
			return "", 0, err
		}
		target := alias
		effUser := strings.TrimSpace(node.User)
		if before, _, hasAt := strings.Cut(alias, "@"); hasAt {
			effUser = before
		} else if effUser != "" {
			target = effUser + "@" + alias
		}
		remoteSh := "sh -s"
		if effUser != "" && effUser != "root" {
			remoteSh = "sudo -n sh -s"
		}
		cmd := exec.CommandContext(ctx, "ssh",
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=10",
			"--", target,
			remoteSh,
		)
		cmd.Stdin = strings.NewReader(script)
		var outBuf, errBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		err := cmd.Run()
		rtt := int(time.Since(start).Milliseconds())
		if err != nil {
			errMsg := strings.TrimSpace(errBuf.String())
			if errMsg != "" {
				return outBuf.String(), rtt, fmt.Errorf("SSH 执行失败: %s", truncateLine(errMsg, 200))
			}
			return outBuf.String(), rtt, fmt.Errorf("SSH 连接失败: %w", err)
		}
		return outBuf.String(), rtt, nil
	}

	if err := ValidateHostTarget(node.Host); err != nil {
		return "", 0, err
	}
	port := node.Port
	if port <= 0 {
		port = 22
	}

	var authMethods []ssh.AuthMethod
	switch node.AuthType {
	case AuthKeyFile, AuthInlineKey:
		keyBytes, err := os.ReadFile(expandHomePath(node.KeyPath))
		if err != nil {
			return "", 0, fmt.Errorf("读取 SSH 私钥失败: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return "", 0, fmt.Errorf("解析 SSH 私钥失败: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	case AuthPassword:
		if node.Password == "" {
			return "", 0, errors.New("未配置 SSH 密码")
		}
		pw := node.Password
		authMethods = append(authMethods,
			ssh.Password(pw),
			ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				ans := make([]string, len(questions))
				for i := range questions {
					ans[i] = pw
				}
				return ans, nil
			}),
		)
	default:
		return "", 0, fmt.Errorf("未知认证类型: %s", node.AuthType)
	}

	addr := net.JoinHostPort(strings.TrimSpace(node.Host), strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", 0, fmt.Errorf("TCP 连接 %s 失败: %w", addr, err)
	}
	rtt := int(time.Since(start).Milliseconds())

	if deadline, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	} else {
		_ = rawConn.SetDeadline(time.Now().Add(90 * time.Second))
	}

	sshCfg := &ssh.ClientConfig{
		User:            cmp.Or(node.User, "root"),
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, sshCfg)
	if err != nil {
		_ = rawConn.Close()
		return "", rtt, fmt.Errorf("SSH 握手失败: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", rtt, fmt.Errorf("创建 SSH 会话失败: %w", err)
	}
	defer sess.Close()

	var outBuf, errBuf bytes.Buffer
	sess.Stdout = &outBuf
	sess.Stderr = &errBuf
	sess.Stdin = strings.NewReader(script)

	execCmd := "sh -s"
	if sshCfg.User != "root" {
		execCmd = "sudo -n sh -s"
	}
	if err := sess.Run(execCmd); err != nil {
		errMsg := strings.TrimSpace(errBuf.String())
		if errMsg != "" {
			return outBuf.String(), rtt, fmt.Errorf("远程命令执行失败: %s", truncateLine(errMsg, 200))
		}
		return outBuf.String(), rtt, fmt.Errorf("远程命令执行失败: %w", err)
	}
	return outBuf.String(), rtt, nil
}

const remoteProbeScript = `
set -e
MASTER_IP=$(printf '%s' "${SSH_CLIENT:-}" | awk '{print $1}')
LOCAL_SSH_PORT=$(printf '%s' "${SSH_CONNECTION:-}" | awk '{print $4}')
if [ -n "$MASTER_IP" ]; then
  if command -v nft >/dev/null 2>&1 && nft list table inet security >/dev/null 2>&1; then
    nft delete element inet security protected_ports { 1080 } >/dev/null 2>&1 || true
    [ -n "$LOCAL_SSH_PORT" ] && nft delete element inet security protected_ports { "$LOCAL_SSH_PORT" } >/dev/null 2>&1 || true
    nft add element inet security whitelist_ip { "$MASTER_IP" } >/dev/null 2>&1 || true
    nft delete element inet security blocklist_ip4 { "$MASTER_IP" } >/dev/null 2>&1 || true
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qw active; then
    ufw delete deny from "$MASTER_IP" to any port 2222 >/dev/null 2>&1 || true
    [ -n "$LOCAL_SSH_PORT" ] && ufw delete deny from "$MASTER_IP" to any port "$LOCAL_SSH_PORT" >/dev/null 2>&1 || true
    ufw delete deny from "$MASTER_IP" >/dev/null 2>&1 || true
  fi
fi
VER=$(singctl version 2>&1 | tr '\n' ' ' || true)
LOAD=$(awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null || echo "-")
MEM=$(awk '/MemTotal:/ {t=$2} /MemAvailable:/ {a=$2} END {if (t>0) printf "%.1f", (t-a)*100/t; else print "0"}' /proc/meminfo 2>/dev/null || echo "0")
CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
if [ ! -s /etc/sub-store/sub-store.json ] && command -v singctl >/dev/null 2>&1; then
  singctl sr sync --restart=false >/dev/null 2>&1 || true
fi
SUB_B64=""
if [ -f /etc/sub-store/sub-store.json ]; then
  SUB_B64=$(base64 /etc/sub-store/sub-store.json | tr -d '\r\n')
fi
printf "SINGCTL_VER=%s\n" "$VER"
printf "SINGCTL_LOAD=%s\n" "$LOAD"
printf "SINGCTL_MEM=%s\n" "$MEM"
printf "SINGCTL_CC=%s\n" "$CC"
printf "SINGCTL_SUB_B64=%s\n" "$SUB_B64"
`

// SyncNode probes a single worker node, updates its runtime telemetry, and syncs its proxy URIs into SubHub.
func (m *Manager) SyncNode(ctx context.Context, id string) NodeActionResult {
	node, ok, err := m.Store.Get(id)
	if err != nil || !ok {
		return NodeActionResult{ID: id, Success: false, Message: fmt.Sprintf("未找到子节点 %s", id)}
	}
	return m.syncNodeObj(ctx, node)
}

func (m *Manager) syncNodeObj(ctx context.Context, node Node) NodeActionResult {
	runner := m.Runner
	if runner == nil {
		runner = DefaultSSHRunner
	}

	callCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	out, rtt, err := runner(callCtx, node, remoteProbeScript)
	nowStr := time.Now().Format(time.RFC3339)
	if err != nil {
		_, _ = m.Store.UpdateRuntimeState(node.ID, func(n *Node) {
			n.Online = false
			n.LastError = err.Error()
			n.LastSyncAt = nowStr
		})
		return NodeActionResult{
			ID:        node.ID,
			Name:      node.Name,
			Success:   false,
			LatencyMs: rtt,
			Message:   err.Error(),
		}
	}

	var verStr, loadStr, memStr, ccStr, subB64 string
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "SINGCTL_VER="):
			rawVer := ansiEscapeRe.ReplaceAllString(strings.TrimPrefix(line, "SINGCTL_VER="), "")
			if m := versionLineRe.FindStringSubmatch(rawVer); len(m) > 1 {
				verStr = m[1]
			}
		case strings.HasPrefix(line, "SINGCTL_LOAD="):
			loadStr = strings.TrimSpace(strings.TrimPrefix(line, "SINGCTL_LOAD="))
		case strings.HasPrefix(line, "SINGCTL_MEM="):
			memStr = strings.TrimSpace(strings.TrimPrefix(line, "SINGCTL_MEM="))
		case strings.HasPrefix(line, "SINGCTL_CC="):
			ccStr = strings.TrimSpace(strings.TrimPrefix(line, "SINGCTL_CC="))
		case strings.HasPrefix(line, "SINGCTL_SUB_B64="):
			subB64 = strings.TrimSpace(strings.TrimPrefix(line, "SINGCTL_SUB_B64="))
		}
	}

	memPct, _ := strconv.ParseFloat(memStr, 64)
	bbr := strings.EqualFold(ccStr, "bbr")

	uris, protos := extractAutoURIsFromSubStoreB64(subB64)
	syncedCount := len(uris)

	if m.SubStore != nil {
		srcName := SubHubSourceName(node.ID)
		if node.Enabled && len(uris) > 0 {
			enabled := true
			_, upsertErr := m.SubStore.UpsertSource(ctx, subhub.SourceUpsertInput{
				Name:        srcName,
				DisplayName: fmt.Sprintf("🌐 [舰队] %s", node.Name),
				Source:      "local",
				Content:     strings.Join(uris, "\n"),
				Remark:      fmt.Sprintf("自动同步自子节点 %s (%s)", node.Name, node.ID),
				Enabled:     &enabled,
			})
			if upsertErr != nil {
				err = fmt.Errorf("写入主控 SubHub 失败: %w", upsertErr)
			}
		} else if !node.Enabled {
			_ = m.SubStore.DeleteSource(srcName)
		}
	}

	if err != nil {
		return NodeActionResult{
			ID:        node.ID,
			Name:      node.Name,
			Success:   false,
			LatencyMs: rtt,
			Message:   err.Error(),
		}
	}

	inferredDomain := extractFirstURIHost(uris)
	inferredHy2Port := extractProtocolURIPort(uris, "hysteria2://", "hy2://")
	inferredVlessPort := extractProtocolURIPort(uris, "vless://")

	_, _ = m.Store.UpdateRuntimeState(node.ID, func(n *Node) {
		n.Online = true
		n.LastError = ""
		n.LastSyncAt = nowStr
		n.LatencyMs = rtt
		if verStr != "" {
			n.SingctlVersion = verStr
		}
		if n.Domain == "" && inferredDomain != "" {
			n.Domain = inferredDomain
		}
		if n.Hy2Port == 0 && inferredHy2Port > 0 && inferredHy2Port != 443 {
			n.Hy2Port = inferredHy2Port
		}
		if n.VlessPort == 0 && inferredVlessPort > 0 && inferredVlessPort != 443 {
			n.VlessPort = inferredVlessPort
		}
		n.CPULoad = loadStr
		n.MemPercent = memPct
		n.BBREnabled = bbr
		n.SyncedNodes = syncedCount
		n.Protocols = protos
	})

	msg := fmt.Sprintf("在线 (%d ms)，已同步 %d 个协议节点至主订阅", rtt, syncedCount)
	if syncedCount == 0 {
		msg = fmt.Sprintf("在线 (%d ms)，远端暂未读取到自动生成节点", rtt)
	}
	return NodeActionResult{
		ID:             node.ID,
		Name:           node.Name,
		Success:        true,
		LatencyMs:      rtt,
		SingctlVersion: verStr,
		SyncedNodes:    syncedCount,
		Protocols:      protos,
		Message:        msg,
	}
}

func extractAutoURIsFromSubStoreB64(b64 string) ([]string, []string) {
	if b64 == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil
	}
	var doc struct {
		Subs []struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"subs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil
	}
	var uris []string
	protoSet := make(map[string]bool)
	for _, sub := range doc.Subs {
		if sub.Name != "auto_generated_hy2" && sub.Name != "auto_generated_vless" {
			continue
		}
		for line := range strings.SplitSeq(sub.Content, "\n") {
			u := strings.TrimSpace(line)
			if u == "" {
				continue
			}
			uris = append(uris, u)
			switch {
			case strings.HasPrefix(strings.ToLower(u), "hysteria2://"), strings.HasPrefix(strings.ToLower(u), "hy2://"):
				protoSet["Hysteria2"] = true
			case strings.HasPrefix(strings.ToLower(u), "vless://"):
				protoSet["VLESS-Reality"] = true
			}
		}
	}
	var protos []string
	if protoSet["Hysteria2"] {
		protos = append(protos, "Hysteria2")
	}
	if protoSet["VLESS-Reality"] {
		protos = append(protos, "VLESS-Reality")
	}
	return uris, protos
}

// RunAcross executes an action concurrently across targetIDs (or all nodes when targetIDs is empty).
func (m *Manager) RunAcross(ctx context.Context, action string, targetIDs []string) ([]NodeActionResult, error) {
	nodes, err := m.Store.List()
	if err != nil {
		return nil, err
	}
	var selected []Node
	if len(targetIDs) == 0 {
		selected = nodes
	} else {
		want := make(map[string]bool, len(targetIDs))
		for _, id := range targetIDs {
			want[strings.TrimSpace(id)] = true
		}
		for _, n := range nodes {
			if want[n.ID] {
				selected = append(selected, n)
			}
		}
	}
	if len(selected) == 0 {
		return []NodeActionResult{}, nil
	}

	results := make([]NodeActionResult, len(selected))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6) // bounded concurrency

	for i, n := range selected {
		wg.Add(1)
		go func(idx int, node Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			switch action {
			case "sync":
				results[idx] = m.syncNodeObj(ctx, node)
			case "probe":
				results[idx] = m.probeNodeActionObj(ctx, node)
			case "doctor":
				results[idx] = m.doctorNodeObj(ctx, node)
			case "reset":
				results[idx] = m.resetNodeObj(ctx, node)
			case "update":
				results[idx] = m.updateNodeObj(ctx, node)
			default:
				results[idx] = NodeActionResult{
					ID:      node.ID,
					Name:    node.Name,
					Success: false,
					Message: "未知舰队指令: " + action,
				}
			}
		}(i, n)
	}
	wg.Wait()
	return results, nil
}

func (m *Manager) runner() RunnerFunc {
	if m.Runner != nil {
		return m.Runner
	}
	return DefaultSSHRunner
}

func (m *Manager) doctorNodeObj(ctx context.Context, node Node) NodeActionResult {
	runner := m.runner()
	callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	out, rtt, err := runner(callCtx, node, "printf 'SINGCTL_VER=%s\\n' \"$(singctl version 2>&1 | tr '\\n' ' ' || true)\"; singctl sr doctor 2>&1")
	var verStr string
	var filteredLines []string
	for line := range strings.SplitSeq(out, "\n") {
		if after, ok := strings.CutPrefix(strings.TrimSpace(line), "SINGCTL_VER="); ok {
			rawVer := ansiEscapeRe.ReplaceAllString(after, "")
			if m := versionLineRe.FindStringSubmatch(rawVer); len(m) > 1 {
				verStr = m[1]
			}
			continue
		}
		filteredLines = append(filteredLines, line)
	}
	clean := strings.TrimSpace(ansiEscapeRe.ReplaceAllString(strings.Join(filteredLines, "\n"), ""))
	if err != nil {
		_, _ = m.Store.UpdateRuntimeState(node.ID, func(n *Node) {
			n.Online = false
			n.LastError = err.Error()
		})
		return NodeActionResult{
			ID:        node.ID,
			Name:      node.Name,
			Success:   false,
			LatencyMs: rtt,
			Message:   err.Error(),
			Output:    clean,
		}
	}

	score := 0
	if match := doctorScoreRe.FindStringSubmatch(clean); len(match) > 1 {
		score, _ = strconv.Atoi(match[1])
	}
	summary := fmt.Sprintf("健康指数 %d / 100", score)
	_, _ = m.Store.UpdateRuntimeState(node.ID, func(n *Node) {
		n.Online = true
		n.LastError = ""
		n.LatencyMs = rtt
		if verStr != "" {
			n.SingctlVersion = verStr
		}
		if score > 0 {
			n.DoctorScore = score
			n.DoctorSummary = summary
		}
	})
	return NodeActionResult{
		ID:          node.ID,
		Name:        node.Name,
		Success:     true,
		LatencyMs:   rtt,
		DoctorScore: score,
		Message:     fmt.Sprintf("%s (RTT %d ms)", summary, rtt),
		Output:      clean,
	}
}

func (m *Manager) resetNodeObj(ctx context.Context, node Node) NodeActionResult {
	runner := m.runner()
	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	_, rtt, err := runner(callCtx, node, "set -e\nsingctl sr reset sb >/dev/null 2>&1\nsingctl sr sync >/dev/null 2>&1\n")
	if err != nil {
		return NodeActionResult{
			ID:        node.ID,
			Name:      node.Name,
			Success:   false,
			LatencyMs: rtt,
			Message:   "远端重置节点凭证失败: " + err.Error(),
		}
	}
	syncRes := m.syncNodeObj(ctx, node)
	if syncRes.Success {
		syncRes.Message = fmt.Sprintf("凭证已轮换并自动回传 %d 个新节点至主订阅", syncRes.SyncedNodes)
	}
	return syncRes
}

func (m *Manager) updateNodeObj(ctx context.Context, node Node) NodeActionResult {
	runner := m.runner()
	callCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	script := `
set -e
singctl update self >/dev/null 2>&1
if systemctl list-unit-files singctl-sub.service >/dev/null 2>&1; then
  systemctl restart singctl-sub >/dev/null 2>&1 || true
fi
singctl sr ui restart >/dev/null 2>&1 || true
`
	_, rtt, err := runner(callCtx, node, script)
	if err != nil {
		return NodeActionResult{
			ID:        node.ID,
			Name:      node.Name,
			Success:   false,
			LatencyMs: rtt,
			Message:   "远端升级失败: " + err.Error(),
		}
	}
	syncRes := m.syncNodeObj(ctx, node)
	if syncRes.Success {
		syncRes.Message = fmt.Sprintf("已升级至 %s 并同步状态", cmp.Or(syncRes.SingctlVersion, "最新版"))
	}
	return syncRes
}

// BootstrapPlan describes the resolved configuration for a fleet node bootstrap (inheriting Master defaults when omitted).
type BootstrapPlan struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Host             string `json:"host"`
	Domain           string `json:"domain"`
	DomainAutoDerive bool   `json:"domainAutoDerive"`
	CFDNSKey         string `json:"-"`
	InheritCFToken   bool   `json:"inheritCfToken"`
	MasterDomain     string `json:"masterDomain,omitempty"`
	SNI              string `json:"sni"`
	SubstoreDomain   string `json:"substoreDomain,omitempty"`
	MirrorURL        string `json:"mirrorUrl"`
	Hy2Up            int    `json:"hy2Up"`
	Hy2Down          int    `json:"hy2Down"`
	NodeTag          string `json:"nodeTag"`
	Hy2Port          int    `json:"hy2Port"`
	VlessPort        int    `json:"vlessPort"`
	TargetSSHPort    int    `json:"targetSshPort"`
}

// PreviewBootstrapNode resolves omitted ID, Name, Domain, CF Token, SNI, and HY2 bandwidth from GeoIP + Master config.
func (m *Manager) PreviewBootstrapNode(ctx context.Context, in BootstrapInput) (BootstrapPlan, error) {
	hostTarget := cmp.Or(strings.TrimSpace(in.Host), strings.TrimSpace(in.SSHAlias))
	if err := ValidateHostTarget(hostTarget); err != nil {
		return BootstrapPlan{}, err
	}

	masterCfg := m.loadMasterConfig()
	masterDom := strings.TrimSpace(masterCfg.Server.GetNodeDomain())
	if masterDom == "node.yourdomain.com" {
		masterDom = ""
	}

	takenIDs := make(map[string]bool)
	if mTag := strings.ToLower(strings.TrimSpace(masterCfg.Server.NodeTag)); mTag != "" {
		takenIDs[mTag] = true
	}
	if m.Store != nil {
		if existing, err := m.Store.List(); err == nil {
			for _, n := range existing {
				takenIDs[strings.ToLower(strings.TrimSpace(n.ID))] = true
			}
		}
	}

	var geo GeoInfo
	if strings.TrimSpace(in.ID) == "" || strings.TrimSpace(in.Name) == "" {
		prober := m.GeoProber
		if prober == nil {
			prober = DefaultGeoProber
		}
		if strings.TrimSpace(in.Host) != "" {
			geo = prober(ctx, in.Host)
		} else {
			geo = GeoInfo{Tag: "node", DisplayName: "边缘节点"}
		}
	}

	allocID, allocName := AllocateUniqueIDAndName(in.ID, in.Name, geo.Tag, geo.DisplayName, takenIDs)
	if !validNodeIDRe.MatchString(allocID) {
		return BootstrapPlan{}, fmt.Errorf("无效的子节点代号 %q (仅允许字母、数字、连字符和下划线，最长 32 位)", allocID)
	}

	explicitCF := cmp.Or(strings.TrimSpace(in.CFDNSKey), strings.TrimSpace(os.Getenv("CF_DNS_API_TOKEN")))
	masterCF := strings.TrimSpace(masterCfg.Server.CFDNSKey)
	cfKey := cmp.Or(explicitCF, masterCF)
	if cfKey == "" {
		return BootstrapPlan{}, errors.New("未检测到 Cloudflare DNS API Token：主控 /etc/singctl/singctl.yaml 未配置 cf_dns_key，请通过 --cf-token 传入")
	}

	explicitDom := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.NodeDomain)), ".")
	domainAuto := false
	resolvedDom := explicitDom
	if explicitDom != "" {
		if unsafeHostChars.MatchString(explicitDom) {
			return BootstrapPlan{}, errors.New("节点域名包含非法字符")
		}
	} else {
		domainAuto = true
		rootZone := guessRootDomain(masterDom)
		if m.CFClient != nil {
			zCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if z, zErr := m.CFClient.FindZone(zCtx, cfKey, masterDom, false); zErr == nil && z != nil {
				rootZone = z.Name
			}
			cancel()
		}
		if rootZone != "" {
			resolvedDom = FormatAutoCDNSubdomain(allocID, rootZone)
		}
	}

	sni := cmp.Or(strings.TrimSpace(in.SNI), strings.TrimSpace(masterCfg.Server.Sni), "swdist.apple.com")
	mirrorURL := cmp.Or(strings.TrimSpace(masterCfg.GitHub.MirrorURL), "https://gh-proxy.com")
	hy2Up := cmp.Or(masterCfg.Hy2.Up, 50)
	hy2Down := cmp.Or(masterCfg.Hy2.Down, 300)
	tag := cmp.Or(strings.TrimSpace(in.NodeTag), allocID)
	hy2Port := in.Hy2Port
	if hy2Port <= 0 || hy2Port > 65535 {
		hy2Port = 443
	}
	vlessPort := in.VlessPort
	if vlessPort <= 0 || vlessPort > 65535 {
		vlessPort = 443
	}
	targetPort := in.TargetSSHPort
	if targetPort <= 0 {
		targetPort = DefaultTargetSSHPort
	}

	return BootstrapPlan{
		ID:               allocID,
		Name:             allocName,
		Host:             hostTarget,
		Domain:           resolvedDom,
		DomainAutoDerive: domainAuto,
		CFDNSKey:         cfKey,
		InheritCFToken:   explicitCF == "" && masterCF != "",
		MasterDomain:     masterDom,
		SNI:              sni,
		SubstoreDomain:   cmp.Or(strings.TrimSpace(in.SubstoreDomain), resolvedDom),
		MirrorURL:        mirrorURL,
		Hy2Up:            hy2Up,
		Hy2Down:          hy2Down,
		NodeTag:          tag,
		Hy2Port:          hy2Port,
		VlessPort:        vlessPort,
		TargetSSHPort:    targetPort,
	}, nil
}

// BootstrapNode provisions a fresh Linux VPS with intelligent Master inheritance:
//  1. Auto-resolves omitted ID/Name via GeoIP and inherits Master's CF Token, SNI, HY2 bandwidth, and GitHub mirror
//  2. (Default ON) Hardens SSH: injects Master + operator public keys, transitions port 22 -> 2222 with anti-lockout verification, disables password auth, and wipes plaintext password
//  3. Auto-allocates and provisions a grey-cloud Cloudflare A/AAAA DNS record (collision-free) before certificate issuance
//  4. Installs SingCtl (with SHA-256 verification), deploys the 4-core server stack, and syncs endpoints into Master SubHub
func (m *Manager) BootstrapNode(ctx context.Context, in BootstrapInput) (NodeActionResult, error) {
	plan, err := m.PreviewBootstrapNode(ctx, in)
	if err != nil {
		return NodeActionResult{}, err
	}
	in.ID = plan.ID
	in.Name = plan.Name

	initialNode, err := NormalizeUpsertInput(in.UpsertInput)
	if err != nil {
		return NodeActionResult{}, err
	}
	if initialNode.AuthType == AuthKeyFile && initialNode.KeyPath == "" {
		initialNode.KeyPath = defaultLocalSSHKeyPath()
	}
	if initialNode.AuthType == AuthInlineKey {
		saved, uErr := m.Store.Upsert(in.UpsertInput)
		if uErr != nil {
			return NodeActionResult{}, uErr
		}
		initialNode = saved
	}

	upsertIn := in.UpsertInput
	sshHardenedMsg := ""
	if shouldHardenBootstrapSSH(in, initialNode.AuthType) {
		hardenedNode, hErr := m.hardenBootstrapSSH(ctx, initialNode, plan.TargetSSHPort, in.ExtraAuthorizedKeys)
		if hErr != nil {
			return NodeActionResult{
				ID:      initialNode.ID,
				Name:    initialNode.Name,
				Success: false,
				Message: "SSH 安全基线加固未完成: " + hErr.Error(),
			}, nil
		}
		if initialNode.AuthType == AuthInlineKey {
			_ = os.Remove(filepath.Join(m.Store.KeysDir, initialNode.ID+".pem"))
		}
		upsertIn.Port = hardenedNode.Port
		upsertIn.AuthType = AuthKeyFile
		upsertIn.KeyPath = hardenedNode.KeyPath
		upsertIn.Password = ""
		upsertIn.PrivateKey = ""
		sshHardenedMsg = fmt.Sprintf("（SSH 已收敛至 %d 免密并禁用密码）", hardenedNode.Port)
	}

	// Provision Cloudflare grey-cloud DNS record AFTER SSH succeeds (zero orphan DNS if password/IP was wrong) and BEFORE Caddy ACME challenge.
	finalDomain := plan.Domain
	dnsAutoManaged := false
	dnsMsg := ""
	if !in.SkipDNS && m.CFClient != nil && strings.TrimSpace(in.Host) != "" {
		dnsCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		provDom, autoManaged, dnsErr := m.CFClient.ProvisionNodeDNS(
			dnsCtx,
			plan.CFDNSKey,
			plan.MasterDomain,
			plan.ID,
			in.NodeDomain,
			in.Host,
		)
		cancel()
		if dnsErr != nil {
			if plan.DomainAutoDerive {
				return NodeActionResult{}, fmt.Errorf("自动创建 Cloudflare DNS 解析失败: %w", dnsErr)
			}
		} else if provDom != "" {
			finalDomain = provDom
			dnsAutoManaged = autoManaged
			if autoManaged {
				dnsMsg = fmt.Sprintf("（DNS %s 已自动绑定灰云解析）", finalDomain)
			}
		}
	}
	if finalDomain == "" {
		return NodeActionResult{}, errors.New("无法自动推导节点域名，请通过 --domain 显式指定")
	}

	upsertIn.Domain = finalDomain
	upsertIn.Hy2Port = plan.Hy2Port
	upsertIn.VlessPort = plan.VlessPort
	upsertIn.DNSAutoManaged = &dnsAutoManaged

	node, err := m.Store.Upsert(upsertIn)
	if err != nil {
		return NodeActionResult{}, err
	}

	subDom := cmp.Or(strings.TrimSpace(in.SubstoreDomain), finalDomain)
	portYAML := ""
	if plan.Hy2Port > 0 && plan.Hy2Port != 443 {
		portYAML += fmt.Sprintf("  hy2_port: %d\n", plan.Hy2Port)
	}
	if plan.VlessPort > 0 && plan.VlessPort != 443 {
		portYAML += fmt.Sprintf("  vless_port: %d\n", plan.VlessPort)
	}

	yamlContent := fmt.Sprintf(`github:
  mirror_url: %q
hy2:
  up: %d
  down: %d
server:
  node_tag: %q
  node_domain: %q
%s  substore_domain: %q
  cf_dns_key: %q
  sni: %q
  web_terminal:
    ssh_port: %d
`, plan.MirrorURL, plan.Hy2Up, plan.Hy2Down, plan.NodeTag, finalDomain, portYAML, subDom, plan.CFDNSKey, plan.SNI, node.Port)

	cfgB64 := base64.StdEncoding.EncodeToString([]byte(yamlContent))

	installEnv := fmt.Sprintf("SSH_PORT=%d", node.Port)
	if plan.Hy2Port > 0 && plan.Hy2Port != 443 {
		installEnv += fmt.Sprintf(" HY2_PORT=%d", plan.Hy2Port)
	}
	if plan.VlessPort > 0 && plan.VlessPort != 443 {
		installEnv += fmt.Sprintf(" VLESS_PORT=%d", plan.VlessPort)
	}

	bootstrapScript := fmt.Sprintf(`
set -e
if ! command -v singctl >/dev/null 2>&1; then
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) PKG="singctl-linux-amd64.tar.gz" ;;
    aarch64|arm64) PKG="singctl-linux-arm64.tar.gz" ;;
    *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
  esac
  TMPD=$(mktemp -d)
  curl -fsSL "https://github.com/sixban6/singctl/releases/latest/download/checksums.txt" -o "${TMPD}/checksums.txt" || true
  curl -fsSL "https://github.com/sixban6/singctl/releases/latest/download/${PKG}" -o "${TMPD}/${PKG}"
  if [ -s "${TMPD}/checksums.txt" ] && command -v sha256sum >/dev/null 2>&1; then
    EXPECTED=$(grep "  ${PKG}$" "${TMPD}/checksums.txt" | awk '{print $1}')
    ACTUAL=$(sha256sum "${TMPD}/${PKG}" | awk '{print $1}')
    if [ -n "$EXPECTED" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
      rm -rf "${TMPD}"
      echo "SHA256 verification failed for ${PKG}" >&2
      exit 1
    fi
  fi
  tar -xzf "${TMPD}/${PKG}" -C "${TMPD}"
  BIN=$(find "${TMPD}" -type f -name singctl | head -n1)
  install -m 0755 "$BIN" /usr/local/bin/singctl
  rm -rf "${TMPD}"
else
  singctl update self >/dev/null 2>&1 || true
fi
mkdir -p /etc/singctl
printf '%%s' %q | base64 -d > /etc/singctl/singctl.yaml
chmod 600 /etc/singctl/singctl.yaml
%s singctl sr install >/dev/null 2>&1
if command -v systemctl >/dev/null 2>&1; then
  for _i in $(seq 1 30); do
    if systemctl is-active --quiet caddy && systemctl is-active --quiet sing-box; then
      break
    fi
    if systemctl is-active --quiet caddy && ! systemctl is-active --quiet sing-box; then
      if find /var/lib/caddy/.local/share/caddy/certificates -name "*.crt" 2>/dev/null | grep -q .; then
        systemctl restart sing-box >/dev/null 2>&1 || true
      fi
    fi
    sleep 2
  done
  if ! systemctl is-active --quiet caddy; then
    echo "Caddy gateway failed to start after install" >&2
    exit 1
  fi
fi
`, cfgB64, installEnv)

	runner := m.runner()
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	_, rtt, runErr := runner(callCtx, node, bootstrapScript)
	if runErr != nil {
		_, _ = m.Store.UpdateRuntimeState(node.ID, func(n *Node) {
			n.Online = false
			n.LastError = runErr.Error()
		})
		return NodeActionResult{
			ID:        node.ID,
			Name:      node.Name,
			Success:   false,
			LatencyMs: rtt,
			Message:   "远端自动化部署失败: " + runErr.Error(),
		}, nil
	}

	syncRes := m.syncNodeObj(ctx, node)
	if syncRes.Success {
		syncRes.Message = fmt.Sprintf("新机 [%s] 自动化部署成功%s%s，已纳管 %d 个节点至总订阅",
			node.ID, sshHardenedMsg, dnsMsg, syncRes.SyncedNodes)
	}
	return syncRes, nil
}

// RemoveNode removes a node from fleet.yaml, cleans up its SubHub source entry, and deletes any auto-managed Cloudflare DNS record matching the node IP.
func (m *Manager) RemoveNode(id string) error {
	_, err := m.RemoveNodeWithOptions(context.Background(), id, false)
	return err
}

// RemoveNodeWithOptions removes a node and optionally preserves its Cloudflare DNS record when keepDNS is true.
func (m *Manager) RemoveNodeWithOptions(ctx context.Context, id string, keepDNS bool) (dnsDeleted bool, err error) {
	existing, hasNode, _ := m.Store.Get(id)
	if err := m.Store.Delete(id); err != nil {
		return false, err
	}
	if m.SubStore != nil {
		_ = m.SubStore.DeleteSource(SubHubSourceName(id))
	}
	if !keepDNS && hasNode && existing.DNSAutoManaged && existing.Domain != "" && existing.Host != "" && m.CFClient != nil {
		masterCfg := m.loadMasterConfig()
		cfKey := cmp.Or(strings.TrimSpace(masterCfg.Server.CFDNSKey), strings.TrimSpace(os.Getenv("CF_DNS_API_TOKEN")))
		if cfKey != "" {
			dCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			deleted, _ := m.CFClient.DeleteNodeDNSIfMatching(dCtx, cfKey, existing.Domain, existing.Host)
			cancel()
			dnsDeleted = deleted
		}
	}
	return dnsDeleted, nil
}

func extractFirstURIHost(uris []string) string {
	for _, raw := range uris {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			continue
		}
		h := u.Hostname()
		if h != "" && net.ParseIP(h) == nil {
			return strings.ToLower(h)
		}
	}
	return ""
}

func extractProtocolURIPort(uris []string, schemePrefixes ...string) int {
	for _, raw := range uris {
		trimmed := strings.TrimSpace(raw)
		lower := strings.ToLower(trimmed)
		matched := len(schemePrefixes) == 0
		for _, prefix := range schemePrefixes {
			if strings.HasPrefix(lower, strings.ToLower(prefix)) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		u, err := url.Parse(trimmed)
		if err != nil || u.Host == "" {
			continue
		}
		if pStr := u.Port(); pStr != "" {
			if p, err := strconv.Atoi(pStr); err == nil && p > 0 && p <= 65535 {
				return p
			}
		}
	}
	return 0
}

func truncateLine(s string, maxLen int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " | ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
