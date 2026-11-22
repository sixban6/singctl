// 文件职责：定义 SubHub 多协议双向编解码契约（protocolCodec）与声明式协议注册表。
package subhub

import (
	"slices"
	"strings"

	"github.com/sixban6/singgen/pkg/model"
)

// protocolCodec 描述单个代理协议在多格式入站解码与多客户端出站渲染上的正交能力钩子。
// 某目标客户端不支持该协议时对应编码字段留 nil，避免强迫空实现。
type protocolCodec struct {
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

type protocolRegistry struct {
	byType     map[string]*protocolCodec
	uriSchemes []string
}

var defaultProtocols = newProtocolRegistry(builtinProtocolCodecs()...)

func newProtocolRegistry(codecs ...protocolCodec) *protocolRegistry {
	reg := &protocolRegistry{
		byType: make(map[string]*protocolCodec, len(codecs)*2),
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

func (r *protocolRegistry) resolve(typ string) (*protocolCodec, bool) {
	if r == nil {
		return nil, false
	}
	c, ok := r.byType[strings.ToLower(strings.TrimSpace(typ))]
	return c, ok
}

func (r *protocolRegistry) hasSupportedScheme(line string) bool {
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

func (r *protocolRegistry) decodeSingBox(typ string, ob map[string]any, n *model.Node) bool {
	c, ok := r.resolve(typ)
	if !ok || c.DecodeSingBox == nil || n == nil {
		return false
	}
	if !c.DecodeSingBox(ob, n) {
		return false
	}
	n.Type = c.Type
	return true
}

func (r *protocolRegistry) decodeClash(typ string, p map[string]any, n *model.Node) bool {
	c, ok := r.resolve(typ)
	if !ok || c.DecodeClash == nil || n == nil {
		return false
	}
	if !c.DecodeClash(p, n) {
		return false
	}
	n.Type = c.Type
	return true
}

func (r *protocolRegistry) encodeURI(n model.Node, hostPort, escapedFrag string) string {
	c, ok := r.resolve(n.Type)
	if !ok || c.EncodeURI == nil {
		return ""
	}
	return c.EncodeURI(n, hostPort, escapedFrag)
}

func (r *protocolRegistry) encodeClash(n model.Node, base map[string]any, opts RenderOptions) (map[string]any, bool) {
	c, ok := r.resolve(n.Type)
	if !ok || c.EncodeClash == nil {
		return nil, false
	}
	return c.EncodeClash(n, base, opts)
}

func (r *protocolRegistry) encodeSurgeLine(n model.Node, tag string, opts RenderOptions) (string, bool) {
	c, ok := r.resolve(n.Type)
	if !ok || c.EncodeSurgeLine == nil {
		return "", false
	}
	return c.EncodeSurgeLine(n, tag, opts)
}

func (r *protocolRegistry) encodeLoonLine(n model.Node, tag string, opts RenderOptions) (string, bool) {
	c, ok := r.resolve(n.Type)
	if !ok || c.EncodeLoonLine == nil {
		return "", false
	}
	return c.EncodeLoonLine(n, tag, opts)
}
