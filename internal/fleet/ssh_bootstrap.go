// 文件职责：负责 Fleet 新机主控 Ed25519 密钥对管理、防锁死双端口 SSH 基线加固与失败自动回滚。
package fleet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultTargetSSHPort is the standard hardened SSH port applied during bare-metal fleet bootstrap.
const DefaultTargetSSHPort = 2222

// EnsureMasterKeypair loads or generates the dedicated Fleet Master Ed25519 SSH keypair (0600)
// at <KeysDir>/master_ed25519 and returns its private key path and authorized_keys public line.
func (s *Store) EnsureMasterKeypair() (privKeyPath string, pubKeyLine string, err error) {
	if err := os.MkdirAll(s.KeysDir, 0700); err != nil {
		return "", "", fmt.Errorf("创建舰队密钥目录失败: %w", err)
	}
	privKeyPath = filepath.Join(s.KeysDir, "master_ed25519")
	pubKeyPath := privKeyPath + ".pub"

	if rawPriv, readErr := os.ReadFile(privKeyPath); readErr == nil && len(bytes.TrimSpace(rawPriv)) > 0 {
		signer, parseErr := ssh.ParsePrivateKey(rawPriv)
		if parseErr != nil {
			return "", "", fmt.Errorf("解析现有主控密钥 %s 失败: %w", privKeyPath, parseErr)
		}
		_ = os.Chmod(privKeyPath, 0600)
		pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " singctl-fleet-master"
		_ = os.WriteFile(pubKeyPath, []byte(pubLine+"\n"), 0644)
		return privKeyPath, pubLine, nil
	}

	_, priv, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		return "", "", fmt.Errorf("生成主控 Ed25519 密钥失败: %w", genErr)
	}
	pemBlock, marshalErr := ssh.MarshalPrivateKey(priv, "singctl-fleet-master")
	if marshalErr != nil {
		return "", "", fmt.Errorf("序列化主控私钥失败: %w", marshalErr)
	}
	privPEM := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(privKeyPath, privPEM, 0600); err != nil {
		return "", "", fmt.Errorf("写入主控私钥失败: %w", err)
	}
	_ = os.Chmod(privKeyPath, 0600)

	sshPub, pubErr := ssh.NewPublicKey(priv.Public())
	if pubErr != nil {
		return "", "", fmt.Errorf("派生主控公钥失败: %w", pubErr)
	}
	pubKeyLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " singctl-fleet-master"
	_ = os.WriteFile(pubKeyPath, []byte(pubLineOr(pubKeyLine)+"\n"), 0644)

	return privKeyPath, pubKeyLine, nil
}

func pubLineOr(v string) string { return v }

// CollectMasterAuthorizedKeys combines the Fleet Master public key, any existing admin keys in
// Master's ~/.ssh/authorized_keys (so the operator's personal workstation is not locked out),
// and optional extra public keys, deduplicated by cryptographic key material.
func CollectMasterAuthorizedKeys(masterPubKey, extraKeys string) []string {
	var result []string
	seen := make(map[string]struct{})

	addLine := func(rawLine string) {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return
		}
		wire := string(pub.Marshal())
		if _, exists := seen[wire]; exists {
			return
		}
		seen[wire] = struct{}{}
		formatted := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
		if strings.TrimSpace(comment) != "" {
			formatted += " " + strings.TrimSpace(comment)
		}
		result = append(result, formatted)
	}

	addLine(masterPubKey)

	candidateFiles := []string{"/root/.ssh/authorized_keys"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		p := filepath.Join(home, ".ssh", "authorized_keys")
		if p != candidateFiles[0] {
			candidateFiles = append(candidateFiles, p)
		}
	}
	for _, p := range candidateFiles {
		if raw, err := os.ReadFile(p); err == nil {
			for line := range strings.SplitSeq(string(raw), "\n") {
				addLine(line)
			}
		}
	}

	for line := range strings.SplitSeq(extraKeys, "\n") {
		addLine(line)
	}

	return result
}

func shouldHardenBootstrapSSH(in BootstrapInput, authType string) bool {
	if authType == AuthSSHAlias {
		return false
	}
	if in.HardenSSH != nil {
		return *in.HardenSSH
	}
	return true
}

func (m *Manager) hardenBootstrapSSH(ctx context.Context, initialNode Node, targetPort int, extraKeys string) (Node, error) {
	if targetPort <= 0 || targetPort > 65535 {
		targetPort = DefaultTargetSSHPort
	}
	currentPort := initialNode.Port
	if currentPort <= 0 || currentPort > 65535 {
		currentPort = 22
	}

	masterKeyPath, masterPubLine, err := m.Store.EnsureMasterKeypair()
	if err != nil {
		return Node{}, err
	}
	pubKeys := CollectMasterAuthorizedKeys(masterPubLine, extraKeys)
	if len(pubKeys) == 0 {
		return Node{}, fmt.Errorf("未能生成有效的 SSH 授权公钥")
	}
	keysB64 := base64.StdEncoding.EncodeToString([]byte(strings.Join(pubKeys, "\n") + "\n"))

	var portDirectives string
	if currentPort == targetPort {
		portDirectives = fmt.Sprintf("Port %d", targetPort)
	} else {
		portDirectives = fmt.Sprintf("Port %d\nPort %d", currentPort, targetPort)
	}

	stage1Script := RenderSSHStage1Script(keysB64, targetPort, portDirectives)

	runner := m.runner()
	stage1Ctx, cancel1 := context.WithTimeout(ctx, 45*time.Second)
	stage1Out, _, err := runner(stage1Ctx, initialNode, stage1Script)
	cancel1()
	if err != nil {
		return Node{}, fmt.Errorf("SSH 免密注入与双端口预备阶段失败: %w", err)
	}
	localSSHPort := parseDetectedLocalSSHPort(stage1Out, currentPort)

	hardenedNode := initialNode
	hardenedNode.Port = targetPort
	hardenedNode.AuthType = AuthKeyFile
	hardenedNode.KeyPath = masterKeyPath
	hardenedNode.Password = ""
	hardenedNode.HasCredential = true

	var verifyOut string
	var verifyErr error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-ctx.Done():
				return Node{}, ctx.Err()
			}
		}
		vCtx, vCancel := context.WithTimeout(ctx, 12*time.Second)
		verifyOut, _, verifyErr = runner(vCtx, hardenedNode, "echo SINGCTL_FLEET_SSH_VERIFIED")
		vCancel()
		if verifyErr == nil && strings.Contains(verifyOut, "SINGCTL_FLEET_SSH_VERIFIED") {
			break
		}
	}

	if (verifyErr != nil || !strings.Contains(verifyOut, "SINGCTL_FLEET_SSH_VERIFIED")) && currentPort != 22 && targetPort != currentPort {
		fallbackNode := hardenedNode
		fallbackNode.Port = currentPort
		fCtx, fCancel := context.WithTimeout(ctx, 12*time.Second)
		fOut, _, fErr := runner(fCtx, fallbackNode, "echo SINGCTL_FLEET_SSH_VERIFIED")
		fCancel()
		if fErr == nil && strings.Contains(fOut, "SINGCTL_FLEET_SSH_VERIFIED") {
			hardenedNode = fallbackNode
			targetPort = currentPort
			verifyOut = fOut
			verifyErr = nil
		}
	}

	if verifyErr != nil || !strings.Contains(verifyOut, "SINGCTL_FLEET_SSH_VERIFIED") {
		rbPortDirectives := fmt.Sprintf("Port %d", currentPort)
		if localSSHPort > 0 && localSSHPort != currentPort {
			rbPortDirectives = fmt.Sprintf("Port %d\nPort %d", localSSHPort, currentPort)
		}
		rbScript := RenderSSHRollbackScript(rbPortDirectives)
		rbCtx, rbCancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, _, _ = runner(rbCtx, initialNode, rbScript)
		rbCancel()
		return Node{}, fmt.Errorf(
			"新 SSH 端口 %d 外部免密验证未通过（请检查云厂商安全组/防火墙是否已放行 TCP %d），已自动回滚保留原端口 %d，未锁死服务器: %v",
			targetPort, targetPort, currentPort, verifyErr,
		)
	}

	finalPortDirectives := fmt.Sprintf("Port %d", targetPort)
	effectiveOldPort := currentPort
	if targetPort == currentPort && localSSHPort > 0 && localSSHPort != targetPort {
		finalPortDirectives = fmt.Sprintf("Port %d\nPort %d", localSSHPort, targetPort)
		effectiveOldPort = targetPort
	}

	finalizeScript := RenderSSHFinalizeScript(finalPortDirectives, effectiveOldPort, targetPort)

	finCtx, finCancel := context.WithTimeout(ctx, 25*time.Second)
	_, _, finErr := runner(finCtx, hardenedNode, finalizeScript)
	finCancel()
	if finErr != nil {
		return Node{}, fmt.Errorf("SSH 最终收口加固失败: %w", finErr)
	}

	return hardenedNode, nil
}

func parseDetectedLocalSSHPort(stage1Out string, fallbackPort int) int {
	for line := range strings.SplitSeq(stage1Out, "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "SINGCTL_LOCAL_SSH_PORT="); ok {
			if p, err := strconv.Atoi(strings.TrimSpace(after)); err == nil && p > 0 && p <= 65535 {
				return p
			}
		}
	}
	return fallbackPort
}
