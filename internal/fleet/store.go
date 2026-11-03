package fleet

import (
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

// Node represents a managed remote SingCtl server in the fleet.
type Node struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	User           string   `json:"user"`
	AuthType       string   `json:"authType"`
	SSHAlias       string   `json:"sshAlias,omitempty"`
	KeyPath        string   `json:"keyPath,omitempty"`
	Password       string   `json:"password,omitempty"`
	HasCredential  bool     `json:"hasCredential"`
	Enabled        bool     `json:"enabled"`
	AddedAt        string   `json:"addedAt,omitempty"`
	LastSyncAt     string   `json:"lastSyncAt,omitempty"`
	Online         bool     `json:"online"`
	LastError      string   `json:"lastError,omitempty"`
	LatencyMs      int      `json:"latencyMs"`
	SingctlVersion string   `json:"singctlVersion,omitempty"`
	DoctorScore    int      `json:"doctorScore"`
	DoctorSummary  string   `json:"doctorSummary,omitempty"`
	CPULoad        string   `json:"cpuLoad,omitempty"`
	MemPercent     float64  `json:"memPercent"`
	BBREnabled     bool     `json:"bbrEnabled"`
	SyncedNodes    int      `json:"syncedNodes"`
	Protocols      []string `json:"protocols,omitempty"`
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
	ID         string `json:"id"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	AuthType   string `json:"authType"`
	SSHAlias   string `json:"sshAlias"`
	KeyPath    string `json:"keyPath"`
	PrivateKey string `json:"privateKey"` // inline PEM key content
	Password   string `json:"password"`
	Enabled    *bool  `json:"enabled,omitzero"`
}

// BootstrapInput extends UpsertInput with initial SingCtl server deployment parameters.
type BootstrapInput struct {
	UpsertInput
	NodeDomain     string `json:"nodeDomain"`
	SubstoreDomain string `json:"substoreDomain"`
	CFDNSKey       string `json:"cfDnsKey"`
	NodeTag        string `json:"nodeTag"`
	SNI            string `json:"sni"`
}

type fleetFileDoc struct {
	Version string `json:"version"`
	Nodes   []Node `json:"nodes"`
}

// Store persists fleet node metadata and SSH key files with 0600 permissions.
type Store struct {
	FilePath string
	KeysDir  string
	mu       sync.RWMutex
}

// ResolveFleetFilePath resolves fleet.json alongside singctl.yaml.
func ResolveFleetFilePath(configPath string) string {
	if strings.TrimSpace(configPath) != "" {
		return filepath.Join(filepath.Dir(configPath), "fleet.json")
	}
	if st, err := os.Stat("/etc/singctl"); err == nil && st.IsDir() {
		return "/etc/singctl/fleet.json"
	}
	return filepath.Join(os.TempDir(), "singctl-fleet", "fleet.json")
}

// NewStore creates a Fleet Store rooted at filePath.
func NewStore(filePath string) *Store {
	if strings.TrimSpace(filePath) == "" {
		filePath = ResolveFleetFilePath("")
	}
	return &Store{
		FilePath: filePath,
		KeysDir:  filepath.Join(filepath.Dir(filePath), "fleet_keys"),
	}
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
			return []Node{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return []Node{}, nil
	}
	var doc fleetFileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析 fleet.json 失败: %w", err)
	}
	if doc.Nodes == nil {
		return []Node{}, nil
	}
	return doc.Nodes, nil
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
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
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

// Upsert creates or updates a fleet node and securely persists any inline SSH key.
func (s *Store) Upsert(in UpsertInput) (Node, error) {
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
	target.AuthType = authType
	target.Port = port
	target.User = user
	if in.Enabled != nil {
		target.Enabled = *in.Enabled
	}

	switch authType {
	case AuthSSHAlias:
		alias := cmp.Or(strings.TrimSpace(in.SSHAlias), strings.TrimSpace(in.Host))
		target.SSHAlias = alias
		target.Host = cmp.Or(strings.TrimSpace(in.Host), alias)
	case AuthInlineKey:
		target.Host = strings.TrimSpace(in.Host)
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
		target.Host = strings.TrimSpace(in.Host)
		target.SSHAlias = ""
		if strings.TrimSpace(in.KeyPath) != "" {
			target.KeyPath = expandHomePath(strings.TrimSpace(in.KeyPath))
		} else if target.KeyPath == "" {
			target.KeyPath = defaultLocalSSHKeyPath()
		}
		target.Password = ""
	case AuthPassword:
		target.Host = strings.TrimSpace(in.Host)
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
