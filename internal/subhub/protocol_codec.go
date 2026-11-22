// 文件职责：定义 SubHub 多协议双向编解码契约（ProtocolCodec）与声明式协议注册表。
package subhub

import (
	"slices"
	"strings"

	"github.com/sixban6/singgen/pkg/model"
)

// ProtocolCodec 描述单个代理协议在多格式入站解码与多客户端出站渲染上的正交能力钩子。
// 某目标客户端不支持该协议时对应编码字段留 nil，避免强迫空实现。
type ProtocolCodec struct {
	Type            string
	Aliases         []string
	URISchemes      []string
	DecodeSingBox   func(ob map[string]any, n *model.Node) bool
	DecodeClash     func(p map[string]any, n *model.Node) bool
	EncodeURI       func(n model.Node, hostPort, escapedFrag string) string
	EncodeClash     func(n model.Node, base map[string]any, opts RenderOptions) (map[string]any, bool)
	EncodeSurgeLine func(n model.Node, tag string, opts RenderOptions) (string, bool)
	EncodeLoonLine  func(n model.Node, tag string, opts RenderOptions) (string, bool)
}

type protocolCodec = ProtocolCodec

// ProtocolRegistry 维护协议及别名的快速查找表与受支持 URI Scheme 集合。
type ProtocolRegistry struct {
	byType     map[string]*ProtocolCodec
	uriSchemes []string
}

var defaultProtocols = NewProtocolRegistry(builtinProtocolCodecs()...)

// DefaultProtocols 返回内置 7 协议注册表只读实例。
func DefaultProtocols() *ProtocolRegistry {
	return defaultProtocols
}

// NewProtocolRegistry 从一组 ProtocolCodec 构建新的协议注册表。
func NewProtocolRegistry(codecs ...ProtocolCodec) *ProtocolRegistry {
	reg := &ProtocolRegistry{
		byType: make(map[string]*ProtocolCodec, len(codecs)*2),
	}
	for i := range codecs {
		c := codecs[i]
		key := strings.ToLower(strings.TrimSpace(c.Type))
		if key == "" {
			continue
		}
		cp := &c
		reg.byType[key] = cp
		for _, alias := range c.Aliases {
			ak := strings.ToLower(strings.TrimSpace(alias))
			if ak != "" {
				reg.byType[ak] = cp
			}
		}
		for _, scheme := range c.URISchemes {
			sk := strings.ToLower(strings.TrimSpace(scheme))
			if sk != "" && !slices.Contains(reg.uriSchemes, sk) {
				reg.uriSchemes = append(reg.uriSchemes, sk)
			}
		}
	}
	return reg
}

func (r *ProtocolRegistry) Resolve(typ string) (*ProtocolCodec, bool) {
	if r == nil {
		return nil, false
	}
	c, ok := r.byType[strings.ToLower(strings.TrimSpace(typ))]
	return c, ok
}

func (r *ProtocolRegistry) HasSupportedScheme(line string) bool {
	if r == nil {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(line))
	for _, p := range r.uriSchemes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func (r *ProtocolRegistry) DecodeSingBox(typ string, ob map[string]any, n *model.Node) bool {
	c, ok := r.Resolve(typ)
	if !ok || c.DecodeSingBox == nil || n == nil {
		return false
	}
	if !c.DecodeSingBox(ob, n) {
		return false
	}
	n.Type = c.Type
	return true
}

func (r *ProtocolRegistry) DecodeClash(typ string, p map[string]any, n *model.Node) bool {
	c, ok := r.Resolve(typ)
	if !ok || c.DecodeClash == nil || n == nil {
		return false
	}
	if !c.DecodeClash(p, n) {
		return false
	}
	n.Type = c.Type
	return true
}

func (r *ProtocolRegistry) EncodeURI(n model.Node, hostPort, escapedFrag string) string {
	c, ok := r.Resolve(n.Type)
	if !ok || c.EncodeURI == nil {
		return ""
	}
	return c.EncodeURI(n, hostPort, escapedFrag)
}

func (r *ProtocolRegistry) EncodeClash(n model.Node, base map[string]any, opts RenderOptions) (map[string]any, bool) {
	c, ok := r.Resolve(n.Type)
	if !ok || c.EncodeClash == nil {
		return nil, false
	}
	return c.EncodeClash(n, base, opts)
}

func (r *ProtocolRegistry) EncodeSurgeLine(n model.Node, tag string, opts RenderOptions) (string, bool) {
	c, ok := r.Resolve(n.Type)
	if !ok || c.EncodeSurgeLine == nil {
		return "", false
	}
	return c.EncodeSurgeLine(n, tag, opts)
}

func (r *ProtocolRegistry) EncodeLoonLine(n model.Node, tag string, opts RenderOptions) (string, bool) {
	c, ok := r.Resolve(n.Type)
	if !ok || c.EncodeLoonLine == nil {
		return "", false
	}
	return c.EncodeLoonLine(n, tag, opts)
}

func (r *ProtocolRegistry) hasSupportedScheme(line string) bool { return r.HasSupportedScheme(line) }
func (r *ProtocolRegistry) decodeSingBox(typ string, ob map[string]any, n *model.Node) bool {
	return r.DecodeSingBox(typ, ob, n)
}
func (r *ProtocolRegistry) decodeClash(typ string, p map[string]any, n *model.Node) bool {
	return r.DecodeClash(typ, p, n)
}
func (r *ProtocolRegistry) encodeURI(n model.Node, hostPort, escapedFrag string) string {
	return r.EncodeURI(n, hostPort, escapedFrag)
}
func (r *ProtocolRegistry) encodeClash(n model.Node, base map[string]any, opts RenderOptions) (map[string]any, bool) {
	return r.EncodeClash(n, base, opts)
}
func (r *ProtocolRegistry) encodeSurgeLine(n model.Node, tag string, opts RenderOptions) (string, bool) {
	return r.EncodeSurgeLine(n, tag, opts)
}
func (r *ProtocolRegistry) encodeLoonLine(n model.Node, tag string, opts RenderOptions) (string, bool) {
	return r.EncodeLoonLine(n, tag, opts)
}
