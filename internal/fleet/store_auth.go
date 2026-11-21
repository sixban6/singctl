// 文件职责：负责 Fleet 节点多认证凭据策略分发（key_file / inline_key / ssh_alias / password）与敏感私钥文件 0600 持久化。
//
// 架构设计原则：
//   - 开闭原则（OCP）：通过 authCredentialApplier 策略映射表解耦不同认证模式的校验与持久化，
//     新增认证方式只需向注册表注册新策略函数，无需在 Store.Upsert 中堆砌 switch 分支。
//   - 最小权限落盘：内联私钥统一写入 0700 权限 KeysDir 下的独立文件，并强制设为 0600。
package fleet

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// authCredentialApplier 定义单个认证模式对目标 Node 的凭据写入策略。
type authCredentialApplier func(s *Store, id string, in UpsertInput, parsed Node, target *Node) error

var defaultAuthAppliers = map[string]authCredentialApplier{
	AuthSSHAlias:  applySSHAliasAuth,
	AuthInlineKey: applyInlineKeyAuth,
	AuthKeyFile:   applyKeyFileAuth,
	AuthPassword:  applyPasswordAuth,
}

func applySSHAliasAuth(_ *Store, _ string, _ UpsertInput, parsed Node, target *Node) error {
	alias := cmp.Or(parsed.SSHAlias, parsed.Host)
	target.SSHAlias = alias
	target.Host = cmp.Or(parsed.Host, alias)
	target.Password = ""
	return nil
}

func applyInlineKeyAuth(s *Store, id string, in UpsertInput, parsed Node, target *Node) error {
	target.Host = parsed.Host
	target.SSHAlias = ""
	if strings.TrimSpace(in.PrivateKey) != "" {
		if err := os.MkdirAll(s.KeysDir, 0700); err != nil {
			return fmt.Errorf("创建密钥目录失败: %w", err)
		}
		_ = os.Chmod(s.KeysDir, 0700)
		keyFile := filepath.Join(s.KeysDir, id+".pem")
		pem := strings.TrimSpace(in.PrivateKey) + "\n"
		if err := os.WriteFile(keyFile, []byte(pem), 0600); err != nil {
			return fmt.Errorf("保存 SSH 私钥失败: %w", err)
		}
		_ = os.Chmod(keyFile, 0600)
		target.KeyPath = keyFile
		target.Password = ""
		return nil
	}
	if target.KeyPath == "" {
		return errors.New("请提供 SSH 私钥内容")
	}
	return nil
}

func applyKeyFileAuth(_ *Store, _ string, _ UpsertInput, parsed Node, target *Node) error {
	target.Host = parsed.Host
	target.SSHAlias = ""
	if parsed.KeyPath != "" {
		target.KeyPath = parsed.KeyPath
	} else if target.KeyPath == "" {
		target.KeyPath = defaultLocalSSHKeyPath()
	}
	target.Password = ""
	return nil
}

func applyPasswordAuth(_ *Store, _ string, in UpsertInput, parsed Node, target *Node) error {
	target.Host = parsed.Host
	target.SSHAlias = ""
	if in.Password != "" {
		target.Password = in.Password
		return nil
	}
	if target.Password == "" {
		return errors.New("请提供 SSH 登录密码")
	}
	return nil
}

// applyAuthCredentialWithRegistry 根据 parsed.AuthType 查找并执行认证凭据持久化策略，支持测试注入 overrides 覆盖或扩展。
func applyAuthCredentialWithRegistry(
	s *Store,
	id string,
	in UpsertInput,
	parsed Node,
	target *Node,
	overrides map[string]authCredentialApplier,
) error {
	if applier, ok := overrides[parsed.AuthType]; ok && applier != nil {
		return applier(s, id, in, parsed, target)
	}
	applier, ok := defaultAuthAppliers[parsed.AuthType]
	if !ok {
		return fmt.Errorf("不支持的认证方式: %s", parsed.AuthType)
	}
	return applier(s, id, in, parsed, target)
}
