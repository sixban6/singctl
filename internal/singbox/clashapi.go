package singbox

import (
	"encoding/json"
	"net"
	"os"
	"strings"

	"singctl/internal/constant"
	"singctl/internal/util/netinfo"
)

// clashAPIConfig 用于从生成的 sing-box 配置中提取 clash_api 信息
type clashAPIConfig struct {
	Experimental *struct {
		ClashAPI *struct {
			ExternalController string `json:"external_controller"`
			Secret             string `json:"secret"`
		} `json:"clash_api"`
	} `json:"experimental"`
}

// ClashAPIEndpoints 返回 clash API 的候选地址列表(含 http:// 前缀)。
//
// 解析顺序为:
//  1. 读取生成的配置文件中的 external_controller(最准确)
//  2. 127.0.0.1:9090(本机默认回环)
//  3. 本机 LAN IP:9090(兼容旧版监听内网 IP 的配置)
//
// 调用方应依次尝试,以第一个可达的为准。
func ClashAPIEndpoints() []string {
	return ClashAPIEndpointsForConfig(constant.SingBoxConfigFile)
}

// ClashAPIEndpointsForConfig 根据指定 sing-box 配置文件路径返回 Clash API 候选地址。
func ClashAPIEndpointsForConfig(sbConfigPath string) []string {
	if strings.TrimSpace(sbConfigPath) == "" {
		sbConfigPath = constant.SingBoxConfigFile
	}
	var out []string
	add := func(addr string) {
		if u := normalizeClashAddr(addr); u != "" {
			for _, existing := range out {
				if existing == u {
					return
				}
			}
			out = append(out, u)
		}
	}

	// 1. 解析生成的配置
	if data, err := os.ReadFile(sbConfigPath); err == nil {
		var cfg clashAPIConfig
		if err := json.Unmarshal(data, &cfg); err == nil &&
			cfg.Experimental != nil && cfg.Experimental.ClashAPI != nil {
			add(cfg.Experimental.ClashAPI.ExternalController)
		}
	}

	// 2. loopback 兜底
	add("127.0.0.1:9090")

	// 3. LAN IP(兼容旧版绑定 LAN IP 的配置)
	if ni, err := netinfo.Get(); err == nil && ni.LANIPv4 != "" {
		add(ni.LANIPv4 + ":9090")
	}

	return out
}

// ClashAPISecret 返回生成配置中 clash_api 的 secret(未配置时为空)。
func ClashAPISecret() string {
	return ClashAPISecretForConfig(constant.SingBoxConfigFile)
}

// ClashAPISecretForConfig 从指定 sing-box 配置文件中提取 clash_api.secret。
func ClashAPISecretForConfig(sbConfigPath string) string {
	if strings.TrimSpace(sbConfigPath) == "" {
		sbConfigPath = constant.SingBoxConfigFile
	}
	data, err := os.ReadFile(sbConfigPath)
	if err != nil {
		return ""
	}
	var cfg clashAPIConfig
	if err := json.Unmarshal(data, &cfg); err != nil ||
		cfg.Experimental == nil || cfg.Experimental.ClashAPI == nil {
		return ""
	}
	return cfg.Experimental.ClashAPI.Secret
}

// normalizeClashAddr 将 external_controller 的值规范化为 http URL。
// 处理 ":9090"、"0.0.0.0:9090"、"[::]:9090" 等通配写法。
func normalizeClashAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// 没有端口,补默认
		host, port = addr, "9090"
	}

	switch {
	case host == "" || host == "0.0.0.0" || host == "[::]" || host == "::":
		host = "127.0.0.1"
	}

	return "http://" + net.JoinHostPort(host, port)
}
