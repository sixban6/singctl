package fleet

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	validNodeIDRe   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)
	unsafeHostChars = regexp.MustCompile(`[\s;|&$` + "`" + `\\'"]`)
)

// AuthType constants supported for connecting to worker nodes.
const (
	AuthKeyFile   = "key_file"
	AuthInlineKey = "inline_key"
	AuthSSHAlias  = "ssh_alias"
	AuthPassword  = "password"
)

const fleetYAMLHeader = "# SingCtl 全球节点舰队清单 (由 singctl fleet 自动维护，支持人工查阅编辑，请保持 0600 权限)\n"

// Node represents a managed remote SingCtl server in the fleet.
type Node struct {
	ID             string   `json:"id" yaml:"id"`
	Name           string   `json:"name" yaml:"name"`
	Host           string   `json:"host" yaml:"host"`
	Domain         string   `json:"domain,omitempty" yaml:"domain,omitempty"`
	Hy2Port        int      `json:"hy2Port,omitempty" yaml:"hy2_port,omitempty"`
	VlessPort      int      `json:"vlessPort,omitempty" yaml:"vless_port,omitempty"`
	DNSAutoManaged bool     `json:"dnsAutoManaged,omitempty" yaml:"dns_auto_managed,omitempty"`
	Port           int      `json:"port" yaml:"port"`
	User           string   `json:"user" yaml:"user"`
	AuthType       string   `json:"authType" yaml:"auth_type"`
	SSHAlias       string   `json:"sshAlias,omitempty" yaml:"ssh_alias,omitempty"`
	KeyPath        string   `json:"keyPath,omitempty" yaml:"key_path,omitempty"`
	Password       string   `json:"password,omitempty" yaml:"password,omitempty"`
	HasCredential  bool     `json:"hasCredential" yaml:"-"`
	Enabled        bool     `json:"enabled" yaml:"enabled"`
	AddedAt        string   `json:"addedAt,omitempty" yaml:"added_at,omitempty"`
	LastSyncAt     string   `json:"lastSyncAt,omitempty" yaml:"last_sync_at,omitempty"`
	LastProbeAt    string   `json:"lastProbeAt,omitempty" yaml:"last_probe_at,omitempty"`
	ProbeStatus    string   `json:"probeStatus,omitempty" yaml:"probe_status,omitempty"`
	CertDaysLeft   int      `json:"certDaysLeft,omitempty" yaml:"cert_days_left,omitempty"`
	Online         bool     `json:"online" yaml:"online"`
	LastError      string   `json:"lastError,omitempty" yaml:"last_error,omitempty"`
	LatencyMs      int      `json:"latencyMs" yaml:"latency_ms,omitempty"`
	SingctlVersion string   `json:"singctlVersion,omitempty" yaml:"singctl_version,omitempty"`
	DoctorScore    int      `json:"doctorScore" yaml:"doctor_score,omitempty"`
	DoctorSummary  string   `json:"doctorSummary,omitempty" yaml:"doctor_summary,omitempty"`
	CPULoad        string   `json:"cpuLoad,omitempty" yaml:"cpu_load,omitempty"`
	MemPercent     float64  `json:"memPercent" yaml:"mem_percent,omitempty"`
	BBREnabled     bool     `json:"bbrEnabled" yaml:"bbr_enabled,omitempty"`
	SyncedNodes    int      `json:"syncedNodes" yaml:"synced_nodes,omitempty"`
	Protocols      []string `json:"protocols,omitempty" yaml:"protocols,omitempty"`
}

// PublicView returns a sanitized copy safe for API responses (stripping secrets).
func (n Node) PublicView() Node {
	cp := n
	cp.HasCredential = cp.Password != "" || cp.KeyPath != "" || cp.SSHAlias != ""
	cp.Password = ""
	if cp.AuthType == AuthInlineKey {
		cp.KeyPath = ""
	}
	if cp.Protocols == nil {
		cp.Protocols = []string{}
	}
	return cp
}

// UpsertInput defines parameters to create or update a fleet node.
type UpsertInput struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Host           string `json:"host"`
	Domain         string `json:"domain,omitempty"`
	Hy2Port        int    `json:"hy2Port,omitzero"`
	VlessPort      int    `json:"vlessPort,omitzero"`
	DNSAutoManaged *bool  `json:"dnsAutoManaged,omitzero"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	AuthType       string `json:"authType"`
	SSHAlias       string `json:"sshAlias"`
	KeyPath        string `json:"keyPath"`
	PrivateKey     string `json:"privateKey"` // inline PEM key content
	Password       string `json:"password"`
	Enabled        *bool  `json:"enabled,omitzero"`
}

// BootstrapInput extends UpsertInput with initial SingCtl server deployment & SSH hardening parameters.
type BootstrapInput struct {
	UpsertInput
	NodeDomain          string `json:"nodeDomain"`
	SubstoreDomain      string `json:"substoreDomain"`
	CFDNSKey            string `json:"cfDnsKey"`
	NodeTag             string `json:"nodeTag"`
	SNI                 string `json:"sni"`
	SkipDNS             bool   `json:"skipDns,omitzero"`
	HardenSSH           *bool  `json:"hardenSsh,omitzero"`
	TargetSSHPort       int    `json:"targetSshPort,omitzero"`
	ExtraAuthorizedKeys string `json:"extraAuthorizedKeys,omitzero"`
}

// BootstrapDefaults exposes sanitized Master configuration defaults so CLI and WebUI can guide zero-config bootstrap.
type BootstrapDefaults struct {
	HasMasterCFToken     bool   `json:"hasMasterCfToken"`
	MasterNodeDomain     string `json:"masterNodeDomain,omitempty"`
	SuggestedRootZone    string `json:"suggestedRootZone,omitempty"`
	DefaultSNI           string `json:"defaultSni"`
	DefaultTargetSSHPort int    `json:"defaultTargetSshPort"`
	Hy2Up                int    `json:"hy2Up"`
	Hy2Down              int    `json:"hy2Down"`
}

type fleetFileDoc struct {
	Version string `json:"version" yaml:"version"`
	Nodes   []Node `json:"nodes" yaml:"nodes"`
}

// Store persists fleet node metadata (fleet.yaml) and SSH key files with 0600 permissions.
type Store struct {
	FilePath string
	KeysDir  string
	mu       sync.RWMutex
}

// ResolveFleetFilePath resolves fleet.yaml alongside singctl.yaml.
func ResolveFleetFilePath(configPath string) string {
	if strings.TrimSpace(configPath) != "" {
		return filepath.Join(filepath.Dir(configPath), "fleet.yaml")
	}
	if st, err := os.Stat("/etc/singctl"); err == nil && st.IsDir() {
		return "/etc/singctl/fleet.yaml"
	}
	return filepath.Join(os.TempDir(), "singctl-fleet", "fleet.yaml")
}

// NewStore creates a Fleet Store rooted at filePath and automatically migrates legacy fleet.json if present.
func NewStore(filePath string) *Store {
	if strings.TrimSpace(filePath) == "" {
		filePath = ResolveFleetFilePath("")
	}
	s := &Store{
		FilePath: filePath,
		KeysDir:  filepath.Join(filepath.Dir(filePath), "fleet_keys"),
	}
	s.migrateLegacyJSONIfNeeded()
	return s
}

func (s *Store) legacyJSONPath() string {
	ext := strings.ToLower(filepath.Ext(s.FilePath))
	if ext != ".yaml" && ext != ".yml" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.FilePath), "fleet.json")
}

func (s *Store) migrateLegacyJSONIfNeeded() {
	s.mu.Lock()
	defer s.mu.Unlock()

	legacyPath := s.legacyJSONPath()
	if legacyPath == "" {
		return
	}
	if _, err := os.Stat(s.FilePath); err == nil {
		return
	}
	raw, err := os.ReadFile(legacyPath)
	if err != nil {
		return
	}
	nodes, err := parseFleetBytes(raw, legacyPath)
	if err != nil {
		return
	}
	if err := s.writeLocked(nodes); err == nil {
		_ = os.Remove(legacyPath)
	}
}

func parseFleetBytes(raw []byte, sourcePath string) ([]Node, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return []Node{}, nil
	}

	var doc fleetFileDoc
	// Legacy JSON files use camelCase tags (authType, keyPath, syncedNodes), so decode JSON first when starting with '{'.
	if trimmed[0] == '{' || strings.EqualFold(filepath.Ext(sourcePath), ".json") {
		if err := json.Unmarshal(trimmed, &doc); err == nil {
			for i := range doc.Nodes {
				doc.Nodes[i].HasCredential = doc.Nodes[i].Password != "" || doc.Nodes[i].KeyPath != "" || doc.Nodes[i].SSHAlias != ""
			}
			if doc.Nodes == nil {
				return []Node{}, nil
			}
			return doc.Nodes, nil
		}
	}

	if err := yaml.Unmarshal(trimmed, &doc); err != nil {
		return nil, fmt.Errorf("解析舰队配置 %s 失败: %w", filepath.Base(sourcePath), err)
	}
	for i := range doc.Nodes {
		doc.Nodes[i].HasCredential = doc.Nodes[i].Password != "" || doc.Nodes[i].KeyPath != "" || doc.Nodes[i].SSHAlias != ""
	}
	if doc.Nodes == nil {
		return []Node{}, nil
	}
	return doc.Nodes, nil
}

// ValidateHostTarget guards against leading '-' or shell metacharacters in host/alias.
func ValidateHostTarget(val string) error {
	val = strings.TrimSpace(val)
	if val == "" {
		return errors.New("主机地址或别名不能为空")
	}
	if strings.HasPrefix(val, "-") {
		return errors.New("主机地址或别名不能以 '-' 开头")
	}
	if unsafeHostChars.MatchString(val) {
		return errors.New("主机地址或别名包含非法字符")
	}
	return nil
}

// SubHubSourceName returns the deterministic SubHub source name for a fleet worker node.
func SubHubSourceName(nodeID string) string {
	return "fleet_" + strings.TrimSpace(nodeID)
}

func (s *Store) readLocked() ([]Node, error) {
	raw, err := os.ReadFile(s.FilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if legacy := s.legacyJSONPath(); legacy != "" {
				if legacyRaw, lErr := os.ReadFile(legacy); lErr == nil {
					return parseFleetBytes(legacyRaw, legacy)
				}
			}
			return []Node{}, nil
		}
		return nil, err
	}
	return parseFleetBytes(raw, s.FilePath)
}

func (s *Store) writeLocked(nodes []Node) error {
	dir := filepath.Dir(s.FilePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	doc := fleetFileDoc{
		Version: "1",
		Nodes:   nodes,
	}

	var out []byte
	if strings.EqualFold(filepath.Ext(s.FilePath), ".json") {
		var err error
		out, err = json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return err
		}
	} else {
		var buf bytes.Buffer
		buf.WriteString(fleetYAMLHeader)
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(doc); err != nil {
			_ = enc.Close()
			return err
		}
		_ = enc.Close()
		out = buf.Bytes()
	}

	tmp := s.FilePath + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.FilePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Chmod(s.FilePath, 0600)
}

// List returns all fleet nodes (raw internal representation; call PublicView for HTTP responses).
func (s *Store) List() ([]Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nodes, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	return slices.Clone(nodes), nil
}

// ListPublic returns sanitized fleet nodes safe for UI/API serialization.
func (s *Store) ListPublic() ([]Node, error) {
	nodes, err := s.List()
	if err != nil {
		return nil, err
	}
	pub := make([]Node, len(nodes))
	for i, n := range nodes {
		pub[i] = n.PublicView()
	}
	return pub, nil
}

// Get returns a single fleet node by ID.
func (s *Store) Get(id string) (Node, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nodes, err := s.readLocked()
	if err != nil {
		return Node{}, false, err
	}
	for _, n := range nodes {
		if n.ID == id {
			return n, true, nil
		}
	}
	return Node{}, false, nil
}

// NormalizeUpsertInput validates and resolves an UpsertInput into a clean Node without writing to disk.
func NormalizeUpsertInput(in UpsertInput) (Node, error) {
	id := strings.ToLower(strings.TrimSpace(in.ID))
	if id == "" && strings.TrimSpace(in.Name) != "" {
		slug := regexp.MustCompile(`[^a-z0-9_-]+`).ReplaceAllString(strings.ToLower(strings.TrimSpace(in.Name)), "-")
		id = strings.Trim(slug, "-")
	}
	if !validNodeIDRe.MatchString(id) {
		return Node{}, errors.New("节点代号格式不合法（仅允许字母、数字、下划线或连字符，1-32 位）")
	}

	authType := strings.ToLower(strings.TrimSpace(in.AuthType))
	if authType == "" {
		switch {
		case strings.TrimSpace(in.SSHAlias) != "":
			authType = AuthSSHAlias
		case strings.TrimSpace(in.PrivateKey) != "":
			authType = AuthInlineKey
		case strings.TrimSpace(in.KeyPath) != "":
			authType = AuthKeyFile
		case strings.TrimSpace(in.Password) != "":
			authType = AuthPassword
		default:
			authType = AuthKeyFile
		}
	}

	if authType == AuthSSHAlias {
		if err := ValidateHostTarget(cmp.Or(in.SSHAlias, in.Host)); err != nil {
			return Node{}, err
		}
	} else {
		if err := ValidateHostTarget(in.Host); err != nil {
			return Node{}, err
		}
	}

	port := in.Port
	if port <= 0 || port > 65535 {
		port = 22
	}
	user := cmp.Or(strings.TrimSpace(in.User), "root")
	if err := ValidateHostTarget(user); err != nil {
		return Node{}, errors.New("SSH 用户名包含非法字符")
	}

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	hy2Port := in.Hy2Port
	if hy2Port < 0 || hy2Port > 65535 || hy2Port == 443 {
		hy2Port = 0
	}
	vlessPort := in.VlessPort
	if vlessPort < 0 || vlessPort > 65535 || vlessPort == 443 {
		vlessPort = 0
	}

	return Node{
		ID:        id,
		Name:      cmp.Or(strings.TrimSpace(in.Name), id),
		Host:      strings.TrimSpace(in.Host),
		Hy2Port:   hy2Port,
		VlessPort: vlessPort,
		Port:      port,
		User:      user,
		AuthType:  authType,
		SSHAlias:  strings.TrimSpace(in.SSHAlias),
		KeyPath:   expandHomePath(strings.TrimSpace(in.KeyPath)),
		Password:  in.Password,
		Enabled:   enabled,
	}, nil
}

// Upsert creates or updates a fleet node and securely persists any inline SSH key.
func (s *Store) Upsert(in UpsertInput) (Node, error) {
	parsed, err := NormalizeUpsertInput(in)
	if err != nil {
		return Node{}, err
	}
	id := parsed.ID
	authType := parsed.AuthType

	s.mu.Lock()
	defer s.mu.Unlock()

	nodes, err := s.readLocked()
	if err != nil {
		return Node{}, err
	}

	idx := slices.IndexFunc(nodes, func(n Node) bool { return n.ID == id })
	var target Node
	if idx >= 0 {
		target = nodes[idx]
	} else {
		target = Node{
			ID:      id,
			AddedAt: time.Now().Format(time.RFC3339),
			Enabled: true,
		}
	}

	target.Name = cmp.Or(strings.TrimSpace(in.Name), target.Name, id)
	if strings.TrimSpace(in.Domain) != "" {
		target.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	}
	if in.Hy2Port > 0 && in.Hy2Port <= 65535 {
		if in.Hy2Port == 443 {
			target.Hy2Port = 0
		} else {
			target.Hy2Port = in.Hy2Port
		}
	}
	if in.VlessPort > 0 && in.VlessPort <= 65535 {
		if in.VlessPort == 443 {
			target.VlessPort = 0
		} else {
			target.VlessPort = in.VlessPort
		}
	}
	if in.DNSAutoManaged != nil {
		target.DNSAutoManaged = *in.DNSAutoManaged
	}
	target.AuthType = authType
	target.Port = parsed.Port
	target.User = parsed.User
	if in.Enabled != nil {
		target.Enabled = *in.Enabled
	}

	switch authType {
	case AuthSSHAlias:
		alias := cmp.Or(parsed.SSHAlias, parsed.Host)
		target.SSHAlias = alias
		target.Host = cmp.Or(parsed.Host, alias)
		target.Password = ""
	case AuthInlineKey:
		target.Host = parsed.Host
		target.SSHAlias = ""
		if strings.TrimSpace(in.PrivateKey) != "" {
			if err := os.MkdirAll(s.KeysDir, 0700); err != nil {
				return Node{}, fmt.Errorf("创建密钥目录失败: %w", err)
			}
			keyFile := filepath.Join(s.KeysDir, id+".pem")
			pem := strings.TrimSpace(in.PrivateKey) + "\n"
			if err := os.WriteFile(keyFile, []byte(pem), 0600); err != nil {
				return Node{}, fmt.Errorf("保存 SSH 私钥失败: %w", err)
			}
			_ = os.Chmod(keyFile, 0600)
			target.KeyPath = keyFile
			target.Password = ""
		} else if target.KeyPath == "" {
			return Node{}, errors.New("请提供 SSH 私钥内容")
		}
	case AuthKeyFile:
		target.Host = parsed.Host
		target.SSHAlias = ""
		if parsed.KeyPath != "" {
			target.KeyPath = parsed.KeyPath
		} else if target.KeyPath == "" {
			target.KeyPath = defaultLocalSSHKeyPath()
		}
		target.Password = ""
	case AuthPassword:
		target.Host = parsed.Host
		target.SSHAlias = ""
		if in.Password != "" {
			target.Password = in.Password
		} else if target.Password == "" {
			return Node{}, errors.New("请提供 SSH 登录密码")
		}
	default:
		return Node{}, fmt.Errorf("不支持的认证方式: %s", authType)
	}

	target.HasCredential = target.Password != "" || target.KeyPath != "" || target.SSHAlias != ""

	if idx >= 0 {
		nodes[idx] = target
	} else {
		nodes = append(nodes, target)
	}

	if err := s.writeLocked(nodes); err != nil {
		return Node{}, err
	}
	if legacy := s.legacyJSONPath(); legacy != "" {
		_ = os.Remove(legacy)
	}
	return target, nil
}

// UpdateRuntimeState updates telemetry/health fields on an existing node without touching credentials.
func (s *Store) UpdateRuntimeState(id string, mutator func(*Node)) (Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nodes, err := s.readLocked()
	if err != nil {
		return Node{}, err
	}
	idx := slices.IndexFunc(nodes, func(n Node) bool { return n.ID == id })
	if idx < 0 {
		return Node{}, fmt.Errorf("未找到子节点 %q", id)
	}
	mutator(&nodes[idx])
	if err := s.writeLocked(nodes); err != nil {
		return Node{}, err
	}
	return nodes[idx], nil
}

// Delete removes a fleet node and shreds any managed inline SSH key file.
func (s *Store) Delete(id string) error {
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()

	nodes, err := s.readLocked()
	if err != nil {
		return err
	}
	idx := slices.IndexFunc(nodes, func(n Node) bool { return n.ID == id })
	if idx < 0 {
		return fmt.Errorf("未找到子节点 %q", id)
	}
	removed := nodes[idx]
	nodes = slices.Delete(nodes, idx, idx+1)
	if err := s.writeLocked(nodes); err != nil {
		return err
	}
	if removed.AuthType == AuthInlineKey {
		_ = os.Remove(filepath.Join(s.KeysDir, id+".pem"))
	}
	return nil
}

func expandHomePath(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func defaultLocalSSHKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for _, name := range []string{"id_ed25519", "id_rsa"} {
		candidate := filepath.Join(home, ".ssh", name)
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate
		}
	}
	return filepath.Join(home, ".ssh", "id_ed25519")
}
