// 文件职责：封装服务端管理面板有界命令执行与服务配置路径解析，底层命令执行委托 common/execx。
package serverweb

import (
	"os/exec"
	"strings"

	"singctl/internal/common/execx"
	"singctl/internal/platform/servicemgr"
)

type serviceCmdRunner = execx.Runner

type defaultServiceCmdRunner = execx.DefaultRunner

func (s *Server) activeCmdRunner() serviceCmdRunner {
	if s != nil {
		return execx.Active(s.snapshotDeps().CmdRunner)
	}
	return defaultServiceCmdRunner{}
}

func (s *Server) serviceMgr() servicemgr.Manager {
	return servicemgr.NewSystemd(s.activeCmdRunner())
}

func (s *Server) resolveServiceConfigPath(service, fallback string) string {
	if s != nil {
		if paths := s.snapshotDeps().ServiceConfigPaths; paths != nil {
			if override := strings.TrimSpace(paths[service]); override != "" {
				return override
			}
		}
	}
	return fallback
}

func (s *Server) canRunSystemctl() bool {
	if s != nil && s.snapshotDeps().CmdRunner != nil {
		return true
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
}
