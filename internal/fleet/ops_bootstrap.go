// 文件职责：负责 Fleet 新节点纳管预检方案推导（BootstrapPlan）与一键无人值守初始化安装流程。
package fleet

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"singctl/internal/constant"
	"strings"
	"time"
)

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
	if d == "" || d == "node.yourdomain.com" || d == "node.example.com" {
		return ""
	}
	parts := strings.Split(d, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return d
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
	reqID := strings.ToLower(strings.TrimSpace(in.ID))
	rawHostInput := cmp.Or(strings.TrimSpace(in.Host), strings.TrimSpace(in.SSHAlias))
	reqHost := normalizeFleetTargetHost(in.Host)

	var existingNodes []Node
	if m.Store != nil {
		if existing, err := m.Store.List(); err == nil {
			existingNodes = existing
		}
	}

	var matchedByID, matchedByHost *Node
	for i := range existingNodes {
		n := &existingNodes[i]
		if reqID != "" && strings.EqualFold(strings.TrimSpace(n.ID), reqID) {
			matchedByID = n
		}
		nHost := normalizeFleetTargetHost(n.Host)
		if reqHost != "" && nHost != "" && nHost == reqHost {
			matchedByHost = n
		} else if in.Host == "" && strings.TrimSpace(in.SSHAlias) != "" && strings.EqualFold(strings.TrimSpace(n.SSHAlias), strings.TrimSpace(in.SSHAlias)) {
			matchedByHost = n
		}
	}

	if matchedByID != nil && matchedByHost != nil && !strings.EqualFold(matchedByID.ID, matchedByHost.ID) {
		return BootstrapPlan{}, fmt.Errorf("指定代号 %q 与目标主机 %s 分别属于不同已纳管节点 (%s vs %s)",
			in.ID, cmp.Or(reqHost, rawHostInput), matchedByID.ID, matchedByHost.ID)
	}

	matchedNode := matchedByID
	if matchedNode == nil {
		matchedNode = matchedByHost
	}

	if matchedNode != nil && !in.Reprovision {
		return BootstrapPlan{}, fmt.Errorf(
			"节点 %s (%s) 已在舰队清单中纳管：若服务器未重装系统、仅需修复网关或终端服务，请直接登录节点执行修复（如 'singctl sr term install' / 'singctl sr doctor'）；若该 VPS 已重装空白系统需原地重开并轮换凭据，请显式加上 --reprovision 参数",
			matchedNode.ID, cmp.Or(strings.TrimSpace(matchedNode.Host), matchedNode.Name),
		)
	}

	if matchedNode != nil && in.Reprovision {
		if strings.TrimSpace(in.ID) == "" {
			in.ID = matchedNode.ID
		}
		if strings.TrimSpace(in.Name) == "" {
			in.Name = matchedNode.Name
		}
		if rawHostInput == "" {
			in.Host = matchedNode.Host
			in.SSHAlias = matchedNode.SSHAlias
			rawHostInput = cmp.Or(strings.TrimSpace(in.Host), strings.TrimSpace(in.SSHAlias))
		}
		if strings.TrimSpace(in.NodeDomain) == "" && strings.TrimSpace(matchedNode.Domain) != "" {
			in.NodeDomain = matchedNode.Domain
		}
	}

	hostTarget := rawHostInput
	if err := ValidateHostTarget(hostTarget); err != nil {
		return BootstrapPlan{}, err
	}

	masterCfg := m.loadMasterConfig()
	masterDom := strings.TrimSpace(masterCfg.Server.GetNodeDomain())
	if masterDom == "node.yourdomain.com" || masterDom == "node.example.com" {
		masterDom = ""
	}

	takenIDs := make(map[string]bool)
	if mTag := strings.ToLower(strings.TrimSpace(masterCfg.Server.NodeTag)); mTag != "" {
		takenIDs[mTag] = true
	}
	for _, n := range existingNodes {
		if in.Reprovision && matchedNode != nil && strings.EqualFold(n.ID, matchedNode.ID) {
			continue
		}
		takenIDs[strings.ToLower(strings.TrimSpace(n.ID))] = true
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
	var prevReprovisionNode *Node
	reprovisionAutoDNS := false
	reprovisionOrigDomain := strings.TrimSpace(in.NodeDomain) == ""

	plan, err := m.PreviewBootstrapNode(ctx, in)
	if err != nil {
		return NodeActionResult{}, err
	}
	in.ID = plan.ID
	in.Name = plan.Name
	if strings.TrimSpace(in.Host) == "" && strings.TrimSpace(in.SSHAlias) == "" {
		in.Host = plan.Host
	}
	if in.Reprovision && m.Store != nil {
		if prev, ok, _ := m.Store.Get(plan.ID); ok {
			prevCopy := prev
			prevReprovisionNode = &prevCopy
			reprovisionAutoDNS = prev.DNSAutoManaged && reprovisionOrigDomain && strings.TrimSpace(prev.Domain) != ""
		}
	}

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
	explicitDNSArg := in.NodeDomain
	if explicitDNSArg == "" && in.Reprovision && prevReprovisionNode != nil && strings.TrimSpace(prevReprovisionNode.Domain) != "" {
		explicitDNSArg = prevReprovisionNode.Domain
	}
	if !in.SkipDNS && m.CFClient != nil && strings.TrimSpace(in.Host) != "" {
		dnsCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		provDom, autoManaged, dnsErr := m.CFClient.ProvisionNodeDNS(
			dnsCtx,
			plan.CFDNSKey,
			plan.MasterDomain,
			plan.ID,
			explicitDNSArg,
			in.Host,
		)
		cancel()
		if dnsErr != nil {
			if plan.DomainAutoDerive {
				return NodeActionResult{}, fmt.Errorf("自动创建 Cloudflare DNS 解析失败: %w", dnsErr)
			}
		} else if provDom != "" {
			finalDomain = provDom
			dnsAutoManaged = autoManaged || reprovisionAutoDNS
			if dnsAutoManaged {
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

	yamlContent := fmt.Sprintf(`server:
  node_tag: %q
  node_domain: %q
%s  substore_domain: %q
  cf_dns_key: %q
  sni: %q
  web_terminal:
    ssh_port: %d
`, plan.NodeTag, finalDomain, portYAML, subDom, plan.CFDNSKey, plan.SNI, node.Port)

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
  curl -fsSL "`+constant.GitHubRepoURL+`/releases/latest/download/checksums.txt" -o "${TMPD}/checksums.txt" || true
  curl -fsSL "`+constant.GitHubRepoURL+`/releases/latest/download/${PKG}" -o "${TMPD}/${PKG}"
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
