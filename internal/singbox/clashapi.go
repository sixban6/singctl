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
// 生成配置在 Linux 上把 external_controller 绑定到 LAN IP(如 192.168.1.1:9090),
// 而不是 0.0.0.0 或 127.0.0.1 —— 绑定特定 IP 时 loopback 连接会被直接拒绝。
// 因此解析顺序为:
//  1. 读取生成的配置文件中的 external_controller(最准确)
//  2. 127.0.0.1:9090(手动配置的兜底)
//  3. 本机 LAN IP:9090(生成器的默认行为)
//
// 调用方应依次尝试,以第一个可达的为准。
func ClashAPIEndpoints() []string {
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
	if data, err := os.ReadFile(constant.SingBoxConfigFile); err == nil {
		var cfg clashAPIConfig
		if err := json.Unmarshal(data, &cfg); err == nil &&
			cfg.Experimental != nil && cfg.Experimental.ClashAPI != nil {
			add(cfg.Experimental.ClashAPI.ExternalController)
		}
	}

	// 2. loopback 兜底
	add("127.0.0.1:9090")

	// 3. LAN IP(生成器在 Linux 上的默认绑定)
	if ni, err := netinfo.Get(); err == nil && ni.LANIPv4 != "" {
		add(ni.LANIPv4 + ":9090")
	}

	return out
}

// ClashAPISecret 返回生成配置中 clash_api 的 secret(未配置时为空)。
func ClashAPISecret() string {
	data, err := os.ReadFile(constant.SingBoxConfigFile)
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
