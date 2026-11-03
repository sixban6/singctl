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
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

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
	Store    *Store
	SubStore *subhub.Store
	Runner   RunnerFunc
}

// NewManager creates a Fleet Manager backed by fleetStore and subStore.
func NewManager(fleetStore *Store, subStore *subhub.Store) *Manager {
	return &Manager{
		Store:    fleetStore,
		SubStore: subStore,
		Runner:   DefaultSSHRunner,
	}
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
			rawVer := strings.TrimPrefix(line, "SINGCTL_VER=")
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

	_, _ = m.Store.UpdateRuntimeState(node.ID, func(n *Node) {
		n.Online = true
		n.LastError = ""
		n.LastSyncAt = nowStr
		n.LatencyMs = rtt
		if verStr != "" {
			n.SingctlVersion = verStr
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

	out, rtt, err := runner(callCtx, node, "singctl sr doctor 2>&1")
	clean := strings.TrimSpace(ansiEscapeRe.ReplaceAllString(out, ""))
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
singctl sr web restart >/dev/null 2>&1 || true
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

// BootstrapNode provisions a fresh Linux VPS with SingCtl, deploys all server components, and enrolls it into the fleet.
func (m *Manager) BootstrapNode(ctx context.Context, in BootstrapInput) (NodeActionResult, error) {
	domain := strings.TrimSpace(in.NodeDomain)
	cfKey := strings.TrimSpace(in.CFDNSKey)
	if domain == "" || unsafeHostChars.MatchString(domain) {
		return NodeActionResult{}, errors.New("节点域名不能为空且不能包含非法字符")
	}
	if cfKey == "" {
		return NodeActionResult{}, errors.New("Cloudflare DNS API Token 不能为空")
	}

	node, err := m.Store.Upsert(in.UpsertInput)
	if err != nil {
		return NodeActionResult{}, err
	}

	sni := cmp.Or(strings.TrimSpace(in.SNI), "swdist.apple.com")
	subDom := strings.TrimSpace(in.SubstoreDomain)
	tag := strings.TrimSpace(in.NodeTag)

	yamlContent := fmt.Sprintf(`github:
  mirror_url: "https://gh-proxy.com"
hy2:
  up: 50
  down: 300
server:
  node_tag: %q
  node_domain: %q
  substore_domain: %q
  cf_dns_key: %q
  sni: %q
`, tag, domain, subDom, cfKey, sni)

	cfgB64 := base64.StdEncoding.EncodeToString([]byte(yamlContent))

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
  curl -fsSL "https://github.com/sixban6/singctl/releases/latest/download/${PKG}" -o "${TMPD}/pkg.tgz"
  tar -xzf "${TMPD}/pkg.tgz" -C "${TMPD}"
  BIN=$(find "${TMPD}" -type f -name singctl | head -n1)
  install -m 0755 "$BIN" /usr/local/bin/singctl
  rm -rf "${TMPD}"
fi
mkdir -p /etc/singctl
printf '%%s' %q | base64 -d > /etc/singctl/singctl.yaml
chmod 600 /etc/singctl/singctl.yaml
singctl sr install >/dev/null 2>&1
`, cfgB64)

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
		syncRes.Message = fmt.Sprintf("新机自动化部署成功，已纳管 %d 个节点至总订阅", syncRes.SyncedNodes)
	}
	return syncRes, nil
}

// RemoveNode removes a node from fleet.json and cleans up its SubHub source entry.
func (m *Manager) RemoveNode(id string) error {
	if err := m.Store.Delete(id); err != nil {
		return err
	}
	if m.SubStore != nil {
		_ = m.SubStore.DeleteSource(SubHubSourceName(id))
	}
	return nil
}

func truncateLine(s string, maxLen int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " | ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
