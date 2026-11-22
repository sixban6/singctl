// 文件职责：集中定义 VPS 服务端配置模型（ServerConfig、WebAdminConfig、WebTerminalConfig）及其域名/端口/标签读取与管理面板凭据初始化方法。
//
// 架构设计原则：
//   - 服务端/客户端关注点分离：VPS 部署与 Web 管理后台配置独立成文件，避免客户端路由改动干扰服务端模型，同时保留向后兼容方法签名。
package config

import (
	"strings"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	NodeTag            string            `yaml:"node_tag"`             // (可选) 节点地区/名称标识 (例如: los, sg, hk)，留空自动根据公网 IP 智能识别
	SBDomain           string            `yaml:"sb_domain,omitempty"`  // 兼容旧配置：默认主域名
	NodeDomain         string            `yaml:"node_domain"`          // 节点主域名 (Hysteria 2 / VLESS 分享链接主机)
	Hy2Port            int               `yaml:"hy2_port,omitempty"`   // (可选) Hysteria 2 (UDP QUIC) 对外监听与订阅端口，默认 443
	VlessPort          int               `yaml:"vless_port,omitempty"` // (可选) VLESS Reality (TCP) 与 HTTPS 伪装站对外监听与订阅端口，默认 443
	SubstoreDomain     string            `yaml:"substore_domain"`      // Sub-Store 专属域名
	ServerIP           string            `yaml:"server_ip"`            // 公网 IP 地址（选填，未填写时自动探测用于申请 Let's Encrypt 原生 IP 证书）
	CFDNSKey           string            `yaml:"cf_dns_key"`
	Sni                string            `yaml:"sni"`
	CorsAllowedOrigins string            `yaml:"cors_allowed_origins,omitempty"`
	WebTerminal        WebTerminalConfig `yaml:"web_terminal,omitempty"`
	WebAdmin           WebAdminConfig    `yaml:"web_admin,omitempty"`
	WarpRouting        WarpRoutingConfig `yaml:"warp_routing,omitempty"`
}

type WebAdminConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Port               int    `yaml:"port,omitempty"`       // 默认 8092
	Path               string `yaml:"path,omitempty"`       // 随机隐藏路径，如 /sr/<24位>
	Username           string `yaml:"username,omitempty"`   // 管理员账号，默认 singctl
	Password           string `yaml:"password,omitempty"`   // 随机生成的强管理密码
	PasswordPendingAck bool   `yaml:"password_pending_ack"` // 安装生成的密码尚未在面板确认保存
}

func (s *ServerConfig) GetWebAdminPort() int {
	if s.WebAdmin.Port > 0 {
		return s.WebAdmin.Port
	}
	return 8092
}

func (s *ServerConfig) GetWebAdminPath() string {
	p := strings.TrimSpace(s.WebAdmin.Path)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimSuffix(p, "/")
}

func (s *ServerConfig) GetWebAdminUsername() string {
	if strings.TrimSpace(s.WebAdmin.Username) != "" {
		return strings.TrimSpace(s.WebAdmin.Username)
	}
	return "singctl"
}

func (s *ServerConfig) GetWebAdminPassword() string {
	return strings.TrimSpace(s.WebAdmin.Password)
}

// EnsureWebAdminCredentials 确保 Web 管理面板拥有随机安全路径、用户名与强随机密码
func (s *ServerConfig) EnsureWebAdminCredentials() bool {
	changed := false
	if s.WebAdmin.Port <= 0 {
		s.WebAdmin.Port = 8092
		changed = true
	}
	// 如果为空、包含过时的 admin 标识、缺少 /sr/ 前缀或随机长度不足 16 位，则升级生成全新 /sr/<16位> 路径
	trimmedPath := strings.TrimSpace(s.WebAdmin.Path)
	cleanPath := strings.Trim(trimmedPath, "/")
	parts := strings.Split(cleanPath, "/")
	if trimmedPath == "" || strings.Contains(trimmedPath, "admin") || len(parts) != 2 || parts[0] != "sr" || len(parts[1]) < 16 {
		s.WebAdmin.Path = GenerateRandomAdminPath()
		changed = true
	}
	// 如果为空或者为旧默认 admin，则换为非 admin 用户名
	if strings.TrimSpace(s.WebAdmin.Username) == "" || strings.TrimSpace(s.WebAdmin.Username) == "admin" {
		s.WebAdmin.Username = "singctl"
		changed = true
	}
	// 如果密码为空，生成 16 位混合大小写和数字的随机密码，并要求首次登录后确认已保存
	if strings.TrimSpace(s.WebAdmin.Password) == "" {
		s.WebAdmin.Password = GenerateSecurePassword(16)
		s.WebAdmin.PasswordPendingAck = true
		changed = true
	}
	if !s.WebAdmin.Enabled {
		s.WebAdmin.Enabled = true
		changed = true
	}
	return changed
}

type WebTerminalConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Port          int    `yaml:"port,omitempty"`            // 默认 18080 (GoTTY)
	Path          string `yaml:"path,omitempty"`            // 隐蔽访问路径，如 /ops-shell-8f9a
	MtlsCA        string `yaml:"mtls_ca,omitempty"`         // CA 证书路径，默认 /etc/singctl/mtls/ca.crt
	Password      string `yaml:"password,omitempty"`        // client.p12 证书导出密码
	SSHTunnelPort int    `yaml:"ssh_tunnel_port,omitempty"` // wstunnel 本地监听端口，默认 18081
	SSHTunnelPath string `yaml:"ssh_tunnel_path,omitempty"` // wstunnel 访问路径，默认 /ssh-ws
	SSHPort       int    `yaml:"ssh_port,omitempty"`        // 目标 SSH 端口 (e.g. 2222)
}

func (w *WebTerminalConfig) UnmarshalYAML(node *yaml.Node) error {
	var a struct {
		Enabled       bool   `yaml:"enabled"`
		Port          any    `yaml:"port"`
		Path          string `yaml:"path"`
		MtlsCA        string `yaml:"mtls_ca"`
		Password      string `yaml:"password"`
		SSHTunnelPort any    `yaml:"ssh_tunnel_port"`
		SSHTunnelPath string `yaml:"ssh_tunnel_path"`
		SSHPort       any    `yaml:"ssh_port"`
	}
	if err := node.Decode(&a); err != nil {
		return err
	}
	w.Enabled = a.Enabled
	w.Path = a.Path
	w.MtlsCA = a.MtlsCA
	w.Password = a.Password
	w.SSHTunnelPath = a.SSHTunnelPath
	if a.Port != nil {
		if p, err := parseIntAny(a.Port); err == nil {
			w.Port = p
		}
	}
	if a.SSHTunnelPort != nil {
		if p, err := parseIntAny(a.SSHTunnelPort); err == nil {
			w.SSHTunnelPort = p
		}
	}
	if a.SSHPort != nil {
		if p, err := parseIntAny(a.SSHPort); err == nil {
			w.SSHPort = p
		}
	}
	return nil
}

// GetServerIP returns the server's public IP address.
// If ServerIP is explicitly set in config, it returns that value.
// Otherwise, it attempts to discover the public IP automatically.
func (s *ServerConfig) GetServerIP() string {
	if s.ServerIP != "" {
		return strings.TrimSpace(s.ServerIP)
	}
	return DiscoverPublicIP()
}

// GetNodeDomain returns the domain for proxy nodes (Hy2 / VLESS).
// Falls back to SBDomain if NodeDomain is not set.
func (s *ServerConfig) GetNodeDomain() string {
	if s.NodeDomain != "" {
		return strings.TrimSpace(s.NodeDomain)
	}
	return strings.TrimSpace(s.SBDomain)
}

// GetHy2Port returns the external UDP port for Hysteria 2 (defaults to 443 when unset or out of range).
func (s *ServerConfig) GetHy2Port() int {
	if s != nil && s.Hy2Port > 0 && s.Hy2Port <= 65535 {
		return s.Hy2Port
	}
	return 443
}

// GetVlessPort returns the external TCP port for VLESS Reality & Caddy L4 TCP (defaults to 443 when unset or out of range).
func (s *ServerConfig) GetVlessPort() int {
	if s != nil && s.VlessPort > 0 && s.VlessPort <= 65535 {
		return s.VlessPort
	}
	return 443
}

// GetSubstoreDomain returns the domain for Sub-Store.
// Falls back to SBDomain if SubstoreDomain is not set.
func (s *ServerConfig) GetSubstoreDomain() string {
	if s.SubstoreDomain != "" {
		return strings.TrimSpace(s.SubstoreDomain)
	}
	return strings.TrimSpace(s.SBDomain)
}

// GetNodeTag returns the location/name tag for server nodes (e.g. "los", "sg").
// If node_tag is explicitly configured, it returns that value.
// Otherwise, it discovers the location from the server's public IP GeoIP.
// If discovery fails, it falls back to the first segment of node_domain or "node".
func (s *ServerConfig) GetNodeTag() string {
	if s != nil && strings.TrimSpace(s.NodeTag) != "" {
		tag := sanitizeTag(s.NodeTag)
		if tag != "" {
			return tag
		}
	}

	if tag := cachedLocationTag(); tag != "" {
		return tag
	}

	var ip string
	if s != nil {
		ip = s.GetServerIP()
	} else {
		ip = DiscoverPublicIP()
	}
	if ip != "" {
		if tag := DiscoverLocationTag(ip); tag != "" {
			return tag
		}
	}

	if s != nil {
		nodeDomain := s.GetNodeDomain()
		if nodeDomain != "" {
			first, _, _ := strings.Cut(nodeDomain, ".")
			first = sanitizeTag(first)
			if first != "" {
				return first
			}
		}
	}
	return "node"
}

// FastNodeTag 零网络阻塞返回节点标签（优先读取配置显式 node_tag 或已缓存地区代号，未命中时回退域名前缀或 "node"，绝不发起外网 IP 探测）。
func (s *ServerConfig) FastNodeTag() string {
	if s != nil && strings.TrimSpace(s.NodeTag) != "" {
		if tag := sanitizeTag(s.NodeTag); tag != "" {
			return tag
		}
	}
	if tag := cachedLocationTag(); tag != "" {
		return tag
	}
	if s != nil {
		if nodeDomain := s.GetNodeDomain(); nodeDomain != "" {
			first, _, _ := strings.Cut(nodeDomain, ".")
			if first = sanitizeTag(first); first != "" {
				return first
			}
		}
	}
	return "node"
}
