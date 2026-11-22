// 文件职责：负责 Web 终端 mTLS 根证书与客户端 PKCS#12 证书链生成、多版本 OpenSSL 兼容导出与保险库持久化。
package terminal

import (
	"fmt"
	"os"
	"path/filepath"

	"singctl/internal/deploy"
	"singctl/internal/logger"
)

func resolveMtlsArtifact(name, legacyPath string) (string, bool) {
	vaultPath := deploy.VaultMtlsFilePath(name)
	if info, err := os.Stat(vaultPath); err == nil && !info.IsDir() && info.Size() > 0 {
		return vaultPath, true
	}
	if legacyPath != "" {
		if info, err := os.Stat(legacyPath); err == nil && !info.IsDir() && info.Size() > 0 {
			return legacyPath, true
		}
	}
	return vaultPath, false
}

func generateMTLSCertificates(password string, force bool) error {
	if err := deploy.MigrateLegacyCaddyMtlsToVault(); err != nil {
		return err
	}

	vaultP12 := deploy.VaultMtlsFilePath("client.p12")
	vaultCA := deploy.VaultMtlsFilePath("ca.crt")
	if !force {
		p12Info, pErr := os.Stat(vaultP12)
		caInfo, cErr := os.Stat(vaultCA)
		if pErr == nil && p12Info.Size() > 0 && cErr == nil && caInfo.Size() > 0 {
			if _, _, err := deploy.EnsureCaddyMtlsTrustPool(""); err != nil {
				return err
			}
			logger.Success("检测到已有 mTLS 证书，复用现有证书 (如需重建可加 --force)")
			return nil
		}
	}

	logger.Info("正在生成 10 年期 mTLS 双向认证证书 (兼容 macOS 与现代浏览器)...")

	tmpDir, err := os.MkdirTemp("", "singctl-mtls-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	caKey := filepath.Join(tmpDir, "ca.key")
	caCrt := filepath.Join(tmpDir, "ca.crt")
	clientKey := filepath.Join(tmpDir, "client.key")
	clientCsr := filepath.Join(tmpDir, "client.csr")
	clientExt := filepath.Join(tmpDir, "client.ext")
	clientCrt := filepath.Join(tmpDir, "client.crt")
	clientP12 := filepath.Join(tmpDir, "client.p12")

	// 1. 生成自签名根证书 CA
	if err := runCmd("openssl", "genrsa", "-out", caKey, "4096"); err != nil {
		return fmt.Errorf("生成 CA 私钥失败: %w", err)
	}
	if err := runCmd("openssl", "req", "-x509", "-new", "-nodes", "-key", caKey,
		"-sha256", "-days", "3650", "-subj", "/O=PersonalOps/CN=OpsRootCA", "-out", caCrt); err != nil {
		return fmt.Errorf("生成 CA 证书失败: %w", err)
	}

	// 2. 生成客户端私钥与 CSR
	if err := runCmd("openssl", "genrsa", "-out", clientKey, "2048"); err != nil {
		return fmt.Errorf("生成客户端私钥失败: %w", err)
	}
	if err := runCmd("openssl", "req", "-new", "-key", clientKey,
		"-subj", "/O=PersonalOps/CN=AdminClient", "-out", clientCsr); err != nil {
		return fmt.Errorf("生成客户端 CSR 失败: %w", err)
	}

	// 3. 写入 client.ext 扩展属性 (clientAuth)
	extContent := `basicConstraints = CA:FALSE
nsCertType = client
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
`
	if err := os.WriteFile(clientExt, []byte(extContent), 0644); err != nil {
		return fmt.Errorf("写入 client.ext 失败: %w", err)
	}

	// 4. 用 CA 签发客户端证书
	if err := runCmd("openssl", "x509", "-req", "-in", clientCsr, "-CA", caCrt,
		"-CAkey", caKey, "-CAcreateserial", "-out", clientCrt, "-days", "3650",
		"-sha256", "-extfile", clientExt); err != nil {
		return fmt.Errorf("签发客户端证书失败: %w", err)
	}

	// 5. 打包为客户端用的 .p12 文件 (多重兼容策略：确保 macOS Keychain、Windows 与现代浏览器无缝导入)
	p12AlgoArgs := []string{
		"pkcs12", "-export",
		"-keypbe", "PBE-SHA1-3DES",
		"-certpbe", "PBE-SHA1-3DES",
		"-macalg", "sha1",
		"-out", clientP12,
		"-inkey", clientKey,
		"-in", clientCrt,
		"-certfile", caCrt,
		"-passout", fmt.Sprintf("pass:%s", password),
	}
	exportErr := runCmd("openssl", p12AlgoArgs...)

	if exportErr != nil {
		p12Args := []string{
			"pkcs12", "-export", "-legacy",
			"-out", clientP12,
			"-inkey", clientKey,
			"-in", clientCrt,
			"-certfile", caCrt,
			"-passout", fmt.Sprintf("pass:%s", password),
		}
		exportErr = runCmd("openssl", p12Args...)
	}

	if exportErr != nil {
		p12ProviderArgs := []string{
			"pkcs12", "-export",
			"-provider", "default", "-provider", "legacy",
			"-out", clientP12,
			"-inkey", clientKey,
			"-in", clientCrt,
			"-certfile", caCrt,
			"-passout", fmt.Sprintf("pass:%s", password),
		}
		exportErr = runCmd("openssl", p12ProviderArgs...)
	}

	if exportErr != nil {
		p12FallbackArgs := []string{
			"pkcs12", "-export",
			"-out", clientP12,
			"-inkey", clientKey,
			"-in", clientCrt,
			"-certfile", caCrt,
			"-passout", fmt.Sprintf("pass:%s", password),
		}
		if err2 := runCmd("openssl", p12FallbackArgs...); err2 != nil {
			return fmt.Errorf("打包 PKCS#12 客户端证书失败: %w", exportErr)
		}
	}

	// 6. 将全套凭据存入持久化 0700/0600 主库，并只读投射公钥 ca.crt 给 Caddy
	bundle := make(map[string][]byte, 4)
	for _, spec := range []struct {
		name string
		src  string
		req  bool
	}{
		{"ca.crt", caCrt, true},
		{"client.p12", clientP12, true},
		{"client.crt", clientCrt, false},
		{"client.key", clientKey, false},
	} {
		data, rErr := os.ReadFile(spec.src)
		if rErr != nil {
			if spec.req {
				return fmt.Errorf("读取生成的 %s 失败: %w", spec.name, rErr)
			}
			continue
		}
		bundle[spec.name] = data
	}

	if err := deploy.SaveMtlsBundleToVault(bundle); err != nil {
		return fmt.Errorf("保存 mTLS 证书至主库失败: %w", err)
	}
	if _, _, err := deploy.EnsureCaddyMtlsTrustPool(""); err != nil {
		return fmt.Errorf("投射 Caddy ca.crt 失败: %w", err)
	}

	logger.Success("mTLS 证书生成成功：主库 %s 与 Caddy 只读 ca.crt 已就绪。", deploy.MtlsVaultDir())
	return nil
}
