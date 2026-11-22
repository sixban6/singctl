// 文件职责：通过 go:embed 与 text/template 内嵌并渲染 Fleet 远端 SSH 双端口防锁死加固、回滚及新机无人值守安装 POSIX Shell 脚本。
package fleet

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"
)

var (
	//go:embed scripts/ssh_stage1.sh
	sshStage1Script string

	//go:embed scripts/ssh_rollback.sh
	sshRollbackScript string

	//go:embed scripts/ssh_finalize.sh
	sshFinalizeScript string

	//go:embed scripts/bootstrap_install.sh
	bootstrapInstallScript string

	sshStage1Tmpl        = template.Must(template.New("ssh_stage1").Parse(sshStage1Script))
	sshRollbackTmpl      = template.Must(template.New("ssh_rollback").Parse(sshRollbackScript))
	sshFinalizeTmpl      = template.Must(template.New("ssh_finalize").Parse(sshFinalizeScript))
	bootstrapInstallTmpl = template.Must(template.New("bootstrap_install").Parse(bootstrapInstallScript))
)

func execScriptTemplate(tmpl *template.Template, data any) string {
	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, data)
	return buf.String()
}

// RenderSSHStage1Script 渲染阶段 1 公钥注入与双端口并行监听准备脚本。
func RenderSSHStage1Script(keysB64 string, targetPort int, portDirectives string) string {
	return execScriptTemplate(sshStage1Tmpl, struct {
		KeysB64        string
		TargetPort     int
		PortDirectives string
	}{
		KeysB64:        keysB64,
		TargetPort:     targetPort,
		PortDirectives: portDirectives,
	})
}

// RenderSSHRollbackScript 渲染新端口验证未通过时的自动回滚脚本。
func RenderSSHRollbackScript(rbPortDirectives string) string {
	return execScriptTemplate(sshRollbackTmpl, struct {
		RBPortDirectives string
	}{
		RBPortDirectives: rbPortDirectives,
	})
}

// RenderSSHFinalizeScript 渲染外部免密验证通过后的 SSH 最终收口加固脚本。
func RenderSSHFinalizeScript(finalPortDirectives string, oldPort, targetPort int) string {
	return execScriptTemplate(sshFinalizeTmpl, struct {
		FinalPortDirectives string
		OldPort             int
		TargetPort          int
	}{
		FinalPortDirectives: finalPortDirectives,
		OldPort:             oldPort,
		TargetPort:          targetPort,
	})
}

// RenderBootstrapInstallScript 渲染远端新机安装校验与四核启动脚本。
func RenderBootstrapInstallScript(repoURL, cfgB64 string, sshPort, hy2Port, vlessPort int) string {
	envPrefix := fmt.Sprintf("SSH_PORT=%d ", sshPort)
	if hy2Port > 0 && hy2Port != 443 {
		envPrefix += fmt.Sprintf("HY2_PORT=%d ", hy2Port)
	}
	if vlessPort > 0 && vlessPort != 443 {
		envPrefix += fmt.Sprintf("VLESS_PORT=%d ", vlessPort)
	}
	return execScriptTemplate(bootstrapInstallTmpl, struct {
		RepoURL          string
		CfgB64           string
		InstallEnvPrefix string
	}{
		RepoURL:          repoURL,
		CfgB64:           cfgB64,
		InstallEnvPrefix: envPrefix,
	})
}
