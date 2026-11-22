// 文件职责：定义客户端 WebUI 策略组拓扑与实时流量 DTO，并桥接实例级 clashapi.Client 端点解析与缓存。
package webui

import (
	"context"

	"singctl/internal/singbox/clashapi"
)

// SbProxyNodeMeta 描述单个出站节点的实时元信息与最新测速结果。
type SbProxyNodeMeta struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Delay  int    `json:"delay"`
	Tested bool   `json:"tested,omitempty"`
	UDP    bool   `json:"udp,omitempty"`
}

// SbProxyGroup 描述一个策略组（Selector / URLTest / Fallback）的完整视图与关联业务分流信息。
type SbProxyGroup struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	CanSelect     bool     `json:"canSelect"`
	Now           string   `json:"now,omitempty"`
	ResolvedChain []string `json:"resolvedChain,omitempty"`
	ResolvedNode  string   `json:"resolvedNode,omitempty"`
	ResolvedDelay int      `json:"resolvedDelay,omitempty"`
	All           []string `json:"all"`
	UsedBy        []string `json:"usedBy,omitempty"`
	UsedByCount   int      `json:"usedByCount,omitempty"`
	FailedOver    bool     `json:"failedOver,omitempty"`
	FailoverFrom  string   `json:"failoverFrom,omitempty"`
	FailoverSince string   `json:"failoverSince,omitempty"`
}

// SbProxiesSnapshot 供原生 sing-box 节点控制页面使用的策略组全景快照。
type SbProxiesSnapshot struct {
	Running      bool                       `json:"running"`
	Mode         string                     `json:"mode"`
	PrimaryGroup string                     `json:"primaryGroup,omitempty"`
	PrimaryNode  string                     `json:"primaryNode,omitempty"`
	PrimaryDelay int                        `json:"primaryDelay,omitempty"`
	Groups       []SbProxyGroup             `json:"groups"`
	Nodes        map[string]SbProxyNodeMeta `json:"nodes"`
	Error        string                     `json:"error,omitempty"`
}

type sbProxySwitchRequest struct {
	Group  string `json:"group"`
	Target string `json:"target"`
}

type sbProxyDelayRequest struct {
	Group     string `json:"group,omitempty"`
	Node      string `json:"node,omitempty"`
	URL       string `json:"url,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`
}

type sbModeRequest struct {
	Mode string `json:"mode"`
}

// SbTrafficResponse 描述 /api/sb/traffic 实时上下行速率、累计流量、活跃连接数与内存占用响应。
type SbTrafficResponse struct {
	Running       bool   `json:"running"`
	Up            int64  `json:"up"`
	Down          int64  `json:"down"`
	UploadTotal   int64  `json:"uploadTotal"`
	DownloadTotal int64  `json:"downloadTotal"`
	Connections   int    `json:"connections"`
	Memory        int64  `json:"memory"`
	Error         string `json:"error,omitempty"`
}

func (s *Server) clashClient() *clashapi.Client {
	if s != nil && s.clash != nil {
		return s.clash
	}
	return clashapi.NewClient(clashapi.Options{ConfigPath: s.sbConfigPath()})
}

func (s *Server) invalidateClashCache() {
	s.clashClient().InvalidateCache()
}

func (s *Server) clashEndpointAndSecret(ctx context.Context) (string, string, error) {
	return s.clashClient().ResolveEndpoint(ctx)
}
