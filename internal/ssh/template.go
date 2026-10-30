package ssh

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultTemplateYAML provides a thoroughly annotated ssh-init.yaml sample
const DefaultTemplateYAML = `# ==============================================================================
# singctl ssh 初始化与安全加固配置清单
# ==============================================================================
# 约定说明:
# 1. 默认在执行 singctl ssh init / test / harden 时自动读取当前目录的 ./ssh-init.yaml
# 2. 支持环境变量展开, 例如 "${ROOT_PASS}" 或 "$MY_PASS"
# 3. 采用“双端口过渡防失联机制”, 2222 端口探活成功后才关闭 22 端口与密码登录
# ==============================================================================

version: "1.0"

# 全局默认参数 (若主机项未显式声明，则继承此处的设定)
defaults:
  user: root                              # 默认登录用户
  current_port: 22                        # 目标机当前 SSH 端口
  target_port: 2222                       # 加固切换后的目标 SSH 端口
  identity_file: ~/.ssh/id_ed25519.pub    # 本地待分发的公钥路径
  private_key: ~/.ssh/id_ed25519          # 本地用于探活与写入 ~/.ssh/config 的私钥路径
  disable_password_auth: true             # 是否彻底关闭密码登录 (PasswordAuthentication no)
  manage_firewall: true                   # 是否自动配置远端防火墙 (ufw/firewalld) 与 SELinux
  strict_host_key_checking: false         # 首次连接是否自动忽略 known_hosts 提示
  timeout_seconds: 15                     # SSH 连接与命令超时时间 (秒)

# 目标主机清单
hosts:
  # 场景 1: 全新服务器 (仅有初始密码, 自动推公钥、改到 2222 端口、关密码、写 ~/.ssh/config)
  - name: hk-prod-01                      # 唯一别名 (写入 ~/.ssh/config 的 Host 项)
    ip: 43.154.10.1
    auth:
      password: "${HK_ROOT_PASS:-InitialPassword123}" # 支持环境变量, 也可直接写密码

  # 场景 2: 非 root 用户、自定义目标端口、自定义临时密码
  - name: us-gpu-02
    ip: 104.21.33.8
    user: ubuntu
    target_port: 22222                    # 单机覆盖目标端口
    auth:
      password: "InitTempPassword123"

  # 场景 3: 已拥有临时 Key 的服务器 (无需密码)，仅做安全加固与端口收敛
  - name: jp-edge-03
    ip: 129.226.50.12
    auth:
      key: ~/.ssh/old_temp_rsa            # 初始连接时所使用的已有私钥
`

// GenerateTemplate writes the default template to the specified output path.
func GenerateTemplate(outputPath string, force bool) error {
	if outputPath == "" {
		outputPath = "ssh-init.yaml"
	}

	cleanPath := filepath.Clean(outputPath)
	if !force {
		if _, err := os.Stat(cleanPath); err == nil {
			return fmt.Errorf("file %s already exists. Use --force to overwrite", cleanPath)
		}
	}

	dir := filepath.Dir(cleanPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(cleanPath, []byte(DefaultTemplateYAML), 0644); err != nil {
		return fmt.Errorf("failed to write template to %s: %w", cleanPath, err)
	}

	return nil
}
