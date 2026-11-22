// 文件职责：负责托管服务环境变量白名单防注入校验，以及向 systemd Unit 与 OpenWrt procd 脚本无损渲染环境变量。
package servicemgr

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateEnvMap 校验服务环境变量键值合法性，拦截空键、换行符、控制字符与 Shell/Unit 指令注入载荷。
func ValidateEnvMap(env map[string]string) error {
	for k, v := range env {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("invalid service environment key %q", k)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("invalid control character in service environment %q", k)
			}
			switch r {
			case '`', '$', ';', '&', '|', '<', '>', '\'', '"', '\\':
				return fmt.Errorf("unsafe metacharacter %q in service environment %q", r, k)
			}
		}
	}
	return nil
}

// RenderSystemdBody 将 UnitSpec.Env 按键名字母序安全注入 systemd [Service] 段（Environment="KEY=VAL"）。
func RenderSystemdBody(spec UnitSpec) (string, error) {
	if err := ValidateEnvMap(spec.Env); err != nil {
		return "", err
	}
	if len(spec.Env) == 0 {
		return spec.SystemdBody, nil
	}

	keys := slices.Sorted(maps.Keys(spec.Env))
	var envLines []string
	for _, k := range keys {
		line := fmt.Sprintf(`Environment="%s=%s"`, k, spec.Env[k])
		if !strings.Contains(spec.SystemdBody, line) {
			envLines = append(envLines, line)
		}
	}
	if len(envLines) == 0 {
		return spec.SystemdBody, nil
	}

	lines := strings.Split(spec.SystemdBody, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "[Service]" {
			out := make([]string, 0, len(lines)+len(envLines))
			out = append(out, lines[:i+1]...)
			out = append(out, envLines...)
			out = append(out, lines[i+1:]...)
			return strings.Join(out, "\n"), nil
		}
	}

	var b strings.Builder
	b.WriteString(spec.SystemdBody)
	if !strings.HasSuffix(spec.SystemdBody, "\n") && spec.SystemdBody != "" {
		b.WriteByte('\n')
	}
	b.WriteString("[Service]\n")
	for _, el := range envLines {
		b.WriteString(el)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// RenderProcdBody 将 UnitSpec.Env 按键名字母序安全注入 OpenWrt procd start_service 实例（procd_set_param env ...）。
func RenderProcdBody(spec UnitSpec) (string, error) {
	if err := ValidateEnvMap(spec.Env); err != nil {
		return "", err
	}
	if len(spec.Env) == 0 {
		return spec.ProcdBody, nil
	}

	keys := slices.Sorted(maps.Keys(spec.Env))
	tokens := make([]string, 0, len(keys))
	for _, k := range keys {
		v := spec.Env[k]
		if strings.ContainsAny(v, " \t") {
			tokens = append(tokens, fmt.Sprintf(`"%s=%s"`, k, v))
		} else {
			tokens = append(tokens, k+"="+v)
		}
	}
	directive := "procd_set_param env " + strings.Join(tokens, " ")
	if strings.Contains(spec.ProcdBody, directive) {
		return spec.ProcdBody, nil
	}

	lines := strings.Split(spec.ProcdBody, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "procd_close_instance") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			if indent == "" {
				indent = "    "
			}
			out := make([]string, 0, len(lines)+1)
			out = append(out, lines[:i]...)
			out = append(out, indent+directive)
			out = append(out, lines[i:]...)
			return strings.Join(out, "\n"), nil
		}
	}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "procd_set_param command") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			if indent == "" {
				indent = "    "
			}
			out := make([]string, 0, len(lines)+1)
			out = append(out, lines[:i+1]...)
			out = append(out, indent+directive)
			out = append(out, lines[i+1:]...)
			return strings.Join(out, "\n"), nil
		}
	}

	var b strings.Builder
	b.WriteString(spec.ProcdBody)
	if !strings.HasSuffix(spec.ProcdBody, "\n") && spec.ProcdBody != "" {
		b.WriteByte('\n')
	}
	b.WriteString("    " + directive + "\n")
	return b.String(), nil
}
