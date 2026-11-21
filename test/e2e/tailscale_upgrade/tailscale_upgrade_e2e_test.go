package tailscale_upgrade_e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"singctl/internal/tailscale"
)

const e2eImageTag = "singctl-openwrt24-e2e:local"

// TestTailscaleUpgradeOpenWrtE2E 使用真实 OpenWrt 24.10 容器 (BusyBox ash + df -Pk + pidof + Unix socket)
// 端到端验证未修改的生产 singctl 二进制零失联升级：
//  1. 正常合体版升级 (1.94.2 -> 1.104.7, --no-wait)：零 TMPDIR 占用、软链保留、.bak 清理、0600 状态文件、Running 恢复；
//  2. 故障注入自动回滚 (1.94.2 -> 1.104.8 假崩溃守护进程, --timeout 6)：通过预检但在启动门禁崩溃，自动回滚并恢复 1.94.2 Running。
func TestTailscaleUpgradeOpenWrtE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OpenWrt Tailscale Upgrade Docker E2E in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed, skipping E2E test")
	}
	if out, err := exec.CommandContext(t.Context(), "docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	ctx := t.Context()
	workDir := t.TempDir()
	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	ensureOpenWrtE2EImage(t, ctx, repoRoot)
	targetArch := detectImageGoArch(t, ctx, e2eImageTag)

	// 1. Cross-compile unmodified production singctl binary for container arch.
	singctlBin := filepath.Join(workDir, "singctl")
	buildGoBinary(t, ctx, repoRoot, targetArch, "", singctlBin, "./cmd/singctl")

	// 2. Cross-compile fake tailscaled binaries (1.94.2, 1.104.7 healthy, 1.104.8 crash-on-start) and mock GitHub HTTPS server.
	toolsDir := writeMockSources(t, workDir)
	good194Bin := filepath.Join(workDir, "tailscaled-1.94.2")
	good1104Bin := filepath.Join(workDir, "tailscaled-1.104.7")
	crash11048Bin := filepath.Join(workDir, "tailscaled-1.104.8")
	mockSrvBin := filepath.Join(workDir, "mock-gh")

	buildGoBinary(t, ctx, toolsDir, targetArch,
		"-s -w -X main.FakeVersion=1.94.2 -X main.CrashDaemon=false",
		good194Bin, "./fakets")
	buildGoBinary(t, ctx, toolsDir, targetArch,
		"-s -w -X main.FakeVersion=1.104.7 -X main.CrashDaemon=false",
		good1104Bin, "./fakets")
	buildGoBinary(t, ctx, toolsDir, targetArch,
		"-s -w -X main.FakeVersion=1.104.8 -X main.CrashDaemon=true",
		crash11048Bin, "./fakets")
	buildGoBinary(t, ctx, toolsDir, targetArch, "-s -w", mockSrvBin, "./mockgh")

	// 3. Boot isolated OpenWrt 24.10 container.
	cName := fmt.Sprintf("sc-ts-upg-%d", time.Now().UnixNano()%1000000)
	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanCtx, "docker", "rm", "-f", cName).Run()
	})

	mustRun(t, ctx, "docker", "run", "-d", "--name", cName,
		"-v", singctlBin+":/usr/bin/singctl:ro",
		"-v", good194Bin+":/opt/bins/tailscaled-1.94.2:ro",
		"-v", good1104Bin+":/opt/bins/tailscaled-1.104.7:ro",
		"-v", crash11048Bin+":/opt/bins/tailscaled-1.104.8:ro",
		"-v", mockSrvBin+":/usr/bin/mock-gh:ro",
		e2eImageTag, "/bin/sh", "-c", "mkdir -p /var/run /var/lock /etc/singctl /var/run/tailscale && exec sleep 3600",
	)

	// Setup /etc/init.d/tailscale (BusyBox sh procd-like wrapper), /etc/hosts, config, initial 1.94.2 daemon, and local TLS mock GitHub server.
	initScript := `cat > /etc/init.d/tailscale <<'INITEOF'
#!/bin/sh
PIDFILE=/var/run/tailscale/fake.pid
case "$1" in
  start)
    mkdir -p /var/run/tailscale
    /usr/sbin/tailscaled --socket=/var/run/tailscale/tailscaled.sock --port=41641 </dev/null >/tmp/fake-tsd.log 2>&1 &
    echo "$!" > "$PIDFILE"
    ;;
  stop)
    if [ -f "$PIDFILE" ]; then
      PID=$(cat "$PIDFILE" 2>/dev/null || true)
      [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
      rm -f "$PIDFILE"
    fi
    killall -9 tailscaled 2>/dev/null || true
    ;;
  *)
    exit 1
    ;;
esac
INITEOF
chmod 755 /etc/init.d/tailscale
printf "subs: []\n" > /etc/singctl/singctl.yaml
chmod 600 /etc/singctl/singctl.yaml

cp /opt/bins/tailscaled-1.94.2 /usr/sbin/tailscaled
chmod 755 /usr/sbin/tailscaled
ln -sf tailscaled /usr/sbin/tailscale
/etc/init.d/tailscale start

mock-gh -arch ` + targetArch + ` -ca /tmp/e2e-ca.pem -good /opt/bins/tailscaled-1.104.7 -bad /opt/bins/tailscaled-1.104.8 -mode good </dev/null >/tmp/mock-gh.log 2>&1 &
i=0
while [ "$i" -lt 20 ]; do
  if [ -f /tmp/e2e-ca.pem ] && [ -S /var/run/tailscale/tailscaled.sock ]; then
    break
  fi
  sleep 1
  i=$((i + 1))
done
if ! grep -q "api.github.com" /etc/hosts; then
  printf "\n127.0.0.1 api.github.com\n" >> /etc/hosts
fi
[ -f /tmp/e2e-ca.pem ] && [ -S /var/run/tailscale/tailscaled.sock ]
`
	mustExec(t, ctx, cName, initScript)

	// Verify baseline 1.94.2 Running
	baseVer := strings.TrimSpace(mustExec(t, ctx, cName, "/usr/sbin/tailscale version"))
	if baseVer != "1.94.2" {
		t.Fatalf("expected baseline 1.94.2, got %q", baseVer)
	}

	// ─────────────────── Scenario 1: Happy Path (--no-wait, 1.94.2 -> 1.104.7, zero TMPDIR) ───────────────────
	handoffOut := mustExec(t, ctx, cName, `
set -e
mkdir -p /tmp/e2e-tmpdir
out=$(SSL_CERT_FILE=/tmp/e2e-ca.pem TMPDIR=/tmp/e2e-tmpdir singctl --config /etc/singctl/singctl.yaml ts update --no-wait)
printf '%s\n' "$out"
left=$(ls -A /tmp/e2e-tmpdir | wc -l)
if [ "$left" != "0" ]; then
  echo "TMPDIR_NOT_EMPTY: $(ls -A /tmp/e2e-tmpdir)" >&2
  exit 1
fi
`)
	if !strings.Contains(handoffOut, tailscale.TailscaleSwapHandoffMarker) {
		t.Fatalf("expected %s marker in --no-wait output, got:\n%s", tailscale.TailscaleSwapHandoffMarker, handoffOut)
	}

	stHappy := waitContainerStateTerminal(t, ctx, cName, 25*time.Second)
	if stHappy.Phase != tailscale.UpgradePhaseSucceeded || stHappy.RolledBack {
		t.Fatalf("Scenario 1 expected succeeded without rollback, got %+v\nSwap log:\n%s", stHappy, stHappy.LogTail)
	}

	verAfterHappy := strings.TrimSpace(mustExec(t, ctx, cName, "/usr/sbin/tailscale version"))
	if verAfterHappy != "1.104.7" {
		t.Fatalf("Scenario 1 expected 1.104.7 after upgrade, got %q", verAfterHappy)
	}
	linkTarget := strings.TrimSpace(mustExec(t, ctx, cName, "readlink /usr/sbin/tailscale"))
	if linkTarget != "tailscaled" {
		t.Fatalf("Scenario 1 expected tailscale symlink -> tailscaled, got %q", linkTarget)
	}
	stJSONHappy := mustExec(t, ctx, cName, "/usr/sbin/tailscale --socket=/var/run/tailscale/tailscaled.sock status --json")
	if !strings.Contains(stJSONHappy, `"Running"`) {
		t.Fatalf("Scenario 1 expected Running backend after upgrade, got %s", stJSONHappy)
	}
	permHappy := strings.TrimSpace(mustExec(t, ctx, cName, "ls -l /tmp/singctl-ts-upgrade.state | awk '{print $1}'"))
	if !strings.HasPrefix(permHappy, "-rw-------") {
		t.Fatalf("Scenario 1 expected 0600 (-rw-------) permissions on state file, got %q", permHappy)
	}
	leftoversHappy := strings.TrimSpace(mustExec(t, ctx, cName, "ls -a /usr/sbin | grep '^\\.tailscale' || true"))
	if leftoversHappy != "" {
		t.Fatalf("Scenario 1 left backup/staged files in /usr/sbin: %q", leftoversHappy)
	}

	// ─────────────────── Scenario 2: Fault Injection Auto-Rollback (1.94.2 -> 1.104.8 crashing daemon, --timeout 6) ───────────────────
	// Reset router to 1.94.2 Running and switch mock GitHub server to serve crashing 1.104.8 build.
	mustExec(t, ctx, cName, `
set -e
/etc/init.d/tailscale stop
rm -f /tmp/singctl-ts-upgrade.state /tmp/singctl-ts-upgrade.log /tmp/singctl-ts-upgrade.lock
cp /opt/bins/tailscaled-1.94.2 /usr/sbin/tailscaled
chmod 755 /usr/sbin/tailscaled
ln -sf tailscaled /usr/sbin/tailscale
/etc/init.d/tailscale start
i=0
while [ "$i" -lt 10 ]; do
  [ -S /var/run/tailscale/tailscaled.sock ] && break
  sleep 1
  i=$((i + 1))
done
touch /tmp/mock-mode-bad
`)

	rbOut, rbErr := execIn(ctx, cName, "SSL_CERT_FILE=/tmp/e2e-ca.pem singctl --config /etc/singctl/singctl.yaml ts update --timeout 6")
	if rbErr == nil {
		t.Fatalf("Scenario 2 expected non-zero exit on health-gate rollback, but succeeded! Output:\n%s", rbOut)
	}

	stRaw := mustExec(t, ctx, cName, "cat /tmp/singctl-ts-upgrade.state")
	var stRB tailscale.UpgradeState
	if err := json.Unmarshal([]byte(stRaw), &stRB); err != nil {
		t.Fatalf("Scenario 2 decode state failed: %v\nRaw:\n%s", err, stRaw)
	}
	if stRB.Phase != tailscale.UpgradePhaseRolledBack || !stRB.RolledBack {
		t.Fatalf("Scenario 2 expected rolled_back state, got %+v\nCLI out:\n%s", stRB, rbOut)
	}

	verAfterRB := strings.TrimSpace(mustExec(t, ctx, cName, "/usr/sbin/tailscale version"))
	if verAfterRB != "1.94.2" {
		t.Fatalf("Scenario 2 expected rollback to 1.94.2, got %q", verAfterRB)
	}
	stJSONRB := mustExec(t, ctx, cName, "/usr/sbin/tailscale --socket=/var/run/tailscale/tailscaled.sock status --json")
	if !strings.Contains(stJSONRB, `"Running"`) {
		t.Fatalf("Scenario 2 expected restored 1.94.2 Running backend, got %s", stJSONRB)
	}
	leftoversRB := strings.TrimSpace(mustExec(t, ctx, cName, "ls -a /usr/sbin | grep '^\\.tailscale' || true"))
	if leftoversRB != "" {
		t.Fatalf("Scenario 2 left backup/staged files in /usr/sbin: %q", leftoversRB)
	}
}

func waitContainerStateTerminal(t *testing.T, ctx context.Context, cName string, timeout time.Duration) tailscale.UpgradeState {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		raw, err := execIn(ctx, cName, "cat /tmp/singctl-ts-upgrade.state 2>/dev/null || true")
		if err == nil && strings.TrimSpace(raw) != "" {
			var st tailscale.UpgradeState
			if json.Unmarshal([]byte(raw), &st) == nil {
				if st.Phase == tailscale.UpgradePhaseSucceeded || st.Phase == tailscale.UpgradePhaseRolledBack || st.Phase == tailscale.UpgradePhaseFailed {
					st.LogTail, _ = execIn(ctx, cName, "cat /tmp/singctl-ts-upgrade.log 2>/dev/null || true")
					return st
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	logOut, _ := execIn(ctx, cName, "cat /tmp/singctl-ts-upgrade.log 2>/dev/null || true")
	t.Fatalf("timed out waiting for container upgrade state terminal phase; log:\n%s", logOut)
	return tailscale.UpgradeState{}
}

func buildGoBinary(t *testing.T, ctx context.Context, srcDir, targetArch, ldflags, outPath, pkg string) {
	t.Helper()
	args := []string{"build"}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "-o", outPath, pkg)
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+targetArch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s (arch=%s) failed: %v\n%s", pkg, targetArch, err, string(out))
	}
}

func writeMockSources(t *testing.T, workDir string) string {
	t.Helper()
	toolsDir := filepath.Join(workDir, "mocktools")
	if err := os.MkdirAll(filepath.Join(toolsDir, "fakets"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(toolsDir, "mockgh"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsDir, "go.mod"), []byte("module e2emock\n\ngo 1.24\n"), 0644); err != nil {
		t.Fatal(err)
	}

	fakeTSSrc := `package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	FakeVersion = "1.94.2"
	CrashDaemon = "false"
)

func main() {
	base := filepath.Base(os.Args[0])
	args := os.Args[1:]

	if len(args) == 1 && args[0] == "--version" && strings.Contains(base, "tailscaled") {
		fmt.Println(FakeVersion)
		return
	}
	if len(args) == 1 && args[0] == "version" && !strings.Contains(base, "tailscaled") {
		fmt.Println(FakeVersion)
		return
	}

	sockPath := "/var/run/tailscale/tailscaled.sock"
	isStatus := false
	for i := 0; i < len(args); i++ {
		if after, ok := strings.CutPrefix(args[i], "--socket="); ok {
			sockPath = after
		} else if args[i] == "status" {
			isStatus = true
		}
	}

	if isStatus {
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
				},
			},
		}
		resp, err := client.Get("http://local-tailscaled.sock/localapi/v0/status")
		if err != nil {
			os.Exit(1)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(os.Stdout, resp.Body)
		return
	}

	// Daemon mode
	if CrashDaemon == "true" {
		fmt.Fprintln(os.Stderr, "simulated fatal startup failure for", FakeVersion)
		os.Exit(1)
	}

	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/localapi/v0/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "{\"Version\":%q,\"BackendState\":\"Running\",\"Self\":{\"ID\":\"nSelf\",\"HostName\":\"OpenWrt\"},\"Peer\":{}}\n", FakeVersion)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	_ = srv.Close()
	_ = os.Remove(sockPath)
}
`

	mockGHSrc := `package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

func makePkg(binPath, ver, arch string) ([]byte, string) {
	binData, err := os.ReadFile(binPath)
	if err != nil {
		panic(err)
	}
	prefix := fmt.Sprintf("tailscale_%s_%s", ver, arch)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	_ = tw.WriteHeader(&tar.Header{Name: prefix + "/tailscaled", Typeflag: tar.TypeReg, Mode: 0755, Size: int64(len(binData))})
	_, _ = tw.Write(binData)
	_ = tw.WriteHeader(&tar.Header{Name: prefix + "/tailscale", Typeflag: tar.TypeSymlink, Mode: 0777, Linkname: "tailscaled"})
	_ = tw.Close()
	_ = gw.Close()
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

func makeSelfSignedTLS(caPath string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "api.github.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"api.github.com", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = os.WriteFile(caPath, certPEM, 0644)
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return cert
}

func main() {
	arch := flag.String("arch", "arm64", "")
	caPath := flag.String("ca", "/tmp/e2e-ca.pem", "")
	goodPath := flag.String("good", "", "")
	badPath := flag.String("bad", "", "")
	flag.String("mode", "good", "")
	flag.Parse()

	goodBytes, goodSHA := makePkg(*goodPath, "1.104.7", *arch)
	badBytes, badSHA := makePkg(*badPath, "1.104.8", *arch)
	cert := makeSelfSignedTLS(*caPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/sixban6/singctl/releases/tags/tailscale-latest", func(w http.ResponseWriter, r *http.Request) {
		isBad := false
		if _, err := os.Stat("/tmp/mock-mode-bad"); err == nil {
			isBad = true
		}
		ver, size, sum := "1.104.7", len(goodBytes), goodSHA
		if isBad {
			ver, size, sum = "1.104.8", len(badBytes), badSHA
		}
		name := fmt.Sprintf("tailscale_%s_%s.tgz", ver, *arch)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "tailscale-latest",
			"assets": []map[string]any{{
				"name":                 name,
				"browser_download_url": "https://api.github.com/assets/" + name,
				"size":                 size,
				"digest":               "sha256:" + sum,
			}},
		})
	})
	mux.HandleFunc("/assets/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat("/tmp/mock-mode-bad"); err == nil {
			_, _ = w.Write(badBytes)
			return
		}
		_, _ = w.Write(goodBytes)
	})

	srv := &http.Server{
		Addr:      "127.0.0.1:443",
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
}
`

	if err := os.WriteFile(filepath.Join(toolsDir, "fakets", "main.go"), []byte(fakeTSSrc), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsDir, "mockgh", "main.go"), []byte(mockGHSrc), 0644); err != nil {
		t.Fatal(err)
	}
	return toolsDir
}

func ensureOpenWrtE2EImage(t *testing.T, ctx context.Context, repoRoot string) {
	t.Helper()
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", e2eImageTag).Run(); err == nil {
		return
	}
	dfDir := filepath.Join(repoRoot, "test", "docker_env")
	mustRun(t, ctx, "docker", "build", "-t", e2eImageTag, dfDir)
}

func detectImageGoArch(t *testing.T, ctx context.Context, image string) string {
	t.Helper()
	out := strings.ToLower(strings.TrimSpace(mustRun(t, ctx, "docker", "image", "inspect", "--format", "{{.Architecture}}", image)))
	switch {
	case strings.Contains(out, "arm64"), strings.Contains(out, "aarch64"):
		return "arm64"
	case strings.Contains(out, "amd64"), strings.Contains(out, "x86_64"):
		return "amd64"
	default:
		return runtime.GOARCH
	}
}

func mustRun(t *testing.T, ctx context.Context, name string, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("command %s %v failed: %v\nOutput:\n%s", name, args, err, string(out))
	}
	return string(out)
}

func execIn(ctx context.Context, container, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", container, "/bin/sh", "-s")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustExec(t *testing.T, ctx context.Context, container, script string) string {
	t.Helper()
	out, err := execIn(ctx, container, script)
	if err != nil {
		t.Fatalf("exec in %s failed: %v\nScript:\n%s\nOutput:\n%s", container, err, script, out)
	}
	return out
}
