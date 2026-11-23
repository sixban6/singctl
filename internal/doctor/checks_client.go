//go:build !lite

// 文件职责：实现客户端网关/透明代理模式下的声明式体检算子集合（系统环境、Linux BBR、订阅源、sing-box 客户端核心、本地控制面与外网 HTTPS 连通性）。
package doctor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
)

func defaultClientChecks() []Check {
	return []Check{
		{ID: "client.system", Scope: ScopeClient, Run: checkSystemItems},
		{ID: "client.bbr", Scope: ScopeClient, Run: checkClientBBRItems},
		{ID: "client.subs", Scope: ScopeClient, Run: checkClientSubsItems},
		{ID: "client.singbox", Scope: ScopeClient, Run: checkClientSingBoxItems},
		{ID: "client.local_ports", Scope: ScopeClient, Run: checkClientLocalPortsItems},
		{ID: "client.wan_https", Scope: ScopeClient, Run: checkClientWANHTTPSItems},
	}
}

func checkClientBBRItems(ctx context.Context, cfg *config.Config, deps Deps) []DoctorItem {
	if deps.GOOS != "linux" {
		return nil
	}
	return checkBBRItems(ctx, cfg, deps)
}

func checkClientSubsItems(_ context.Context, cfg *config.Config, _ Deps) []DoctorItem {
	hasValidSub := false
	if cfg != nil {
		for _, sub := range cfg.Subs {
			if strings.TrimSpace(sub.URL) != "" {
				hasValidSub = true
				break
			}
		}
	}
	if hasValidSub {
		return []DoctorItem{{
			Name:     "客户端订阅配置",
			Category: "system",
			Status:   "ok",
			Summary:  fmt.Sprintf("已配置 %d 个订阅源", len(cfg.Subs)),
		}}
	}
	return []DoctorItem{{
		Name:     "客户端订阅配置",
		Category: "system",
		Status:   "warn",
		Summary:  "尚未配置有效订阅链接 (subs.url)",
		Detail:   "若作为客户端使用，请编辑 singctl.yaml 填入订阅地址；若为服务端请运行 'singctl sr doctor'",
	}}
}

func checkClientSingBoxItems(_ context.Context, _ *config.Config, deps Deps) []DoctorItem {
	if !deps.FileExists(constant.SingBoxConfigFile) {
		return []DoctorItem{{
			Name:     "sing-box 客户端核心",
			Category: "services",
			Status:   "warn",
			Summary:  "未检测到客户端配置 (" + constant.SingBoxConfigFile + ")",
			Detail:   "可执行 'singctl sb install && singctl sb start' 初始化客户端",
		}}
	}
	if deps.IsServiceActive("sing-box") {
		return []DoctorItem{{
			Name:     "sing-box 客户端核心",
			Category: "services",
			Status:   "ok",
			Summary:  "配置文件就绪且 sing-box 正在运行",
		}}
	}
	return []DoctorItem{{
		Name:     "sing-box 客户端核心",
		Category: "services",
		Status:   "warn",
		Summary:  "配置文件已生成，但 sing-box 当前未运行",
		Detail:   "可执行 'singctl sb start' 启动客户端代理",
	}}
}

func checkClientLocalPortsItems(_ context.Context, _ *config.Config, deps Deps) []DoctorItem {
	var activeLocalPorts []int
	for _, p := range []int{9090, 8090} {
		if deps.DialTCP(fmt.Sprintf("127.0.0.1:%d", p), 300*time.Millisecond) == nil {
			activeLocalPorts = append(activeLocalPorts, p)
		}
	}
	if len(activeLocalPorts) == 0 {
		return nil
	}
	return []DoctorItem{{
		Name:     "本地控制面板监听",
		Category: "network",
		Status:   "ok",
		Summary:  fmt.Sprintf("已检测到本地控制端口 (%s) 在线", joinInts(activeLocalPorts)),
	}}
}

func checkClientWANHTTPSItems(_ context.Context, _ *config.Config, deps Deps) []DoctorItem {
	_, latency, err := deps.HTTPGetStatus("https://cp.cloudflare.com/generate_204", 3*time.Second)
	if err == nil {
		return []DoctorItem{{
			Name:     "外网 HTTPS 连通性",
			Category: "network",
			Status:   "ok",
			Summary:  fmt.Sprintf("Cloudflare 连通探测正常 (延迟: %d ms)", latency.Milliseconds()),
		}}
	}
	return []DoctorItem{{
		Name:     "外网 HTTPS 连通性",
		Category: "network",
		Status:   "warn",
		Summary:  "无法直连 cp.cloudflare.com",
		Detail:   err.Error(),
	}}
}
