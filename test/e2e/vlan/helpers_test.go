// 文件职责：提供 OpenWrt VLAN Docker 多容器集群 E2E 测试的镜像探测、交叉编译、独立 netns 探针程序与容器命令辅助函数。
package vlan_e2e

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
)

const (
	openWrt24Image = "openwrt/rootfs:aarch64_generic"
	openWrtIptImg  = "singctl-openwrt24-e2e:local"
)

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

func imageExists(ctx context.Context, image string) bool {
	return exec.CommandContext(ctx, "docker", "image", "inspect", image).Run() == nil
}

func crossCompileSingCtl(t *testing.T, ctx context.Context, repoRoot, workDir, targetArch string) string {
	t.Helper()
	outBin := filepath.Join(workDir, "singctl-"+targetArch)
	cmd := exec.CommandContext(ctx, "go", "build", "-tags", "lite", "-o", outBin, "./cmd/singctl")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+targetArch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-compile singctl linux/%s failed: %v\n%s", targetArch, err, string(out))
	}
	return outBin
}

// buildProbeHelper 构建极简静态 Linux 探针，支持：
//   - serve <addr> <tag>：HTTP 探测服务端
//   - http <method> <url> [localIP|-] [jsonBody]：HTTP 客户端
//   - netns-spawn <pidFile> <sockPath>：启动独立 CLONE_NEWNET 网络命名空间进程，通过 Unix Socket 执行网内配置/HTTP/服务（零依赖 ip netns / unshare）
//   - netns-ctl <sockPath> <op> [args...]：向指定独立网络命名空间发送 sh / http / serve 指令
func buildProbeHelper(t *testing.T, ctx context.Context, workDir, targetArch string) string {
	t.Helper()
	dir := filepath.Join(workDir, "probe-"+targetArch)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir probe dir: %v", err)
	}
	src := `package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type nsReq struct {
	Op       string ` + "`json:\"op\"`" + `
	Cmd      string ` + "`json:\"cmd,omitempty\"`" + `
	Method   string ` + "`json:\"method,omitempty\"`" + `
	URL      string ` + "`json:\"url,omitempty\"`" + `
	LocalIP  string ` + "`json:\"localIp,omitempty\"`" + `
	Body     string ` + "`json:\"body,omitempty\"`" + `
	Addr     string ` + "`json:\"addr,omitempty\"`" + `
	Tag      string ` + "`json:\"tag,omitempty\"`" + `
}

type nsResp struct {
	OK     bool   ` + "`json:\"ok\"`" + `
	Status int    ` + "`json:\"status,omitempty\"`" + `
	Output string ` + "`json:\"output,omitempty\"`" + `
	Error  string ` + "`json:\"error,omitempty\"`" + `
}

func doHTTP(method, url, localIP, jsonBody string) (int, string, error) {
	var body io.Reader
	if jsonBody != "" {
		body = bytes.NewBufferString(jsonBody)
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	if localIP != "" && localIP != "-" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
	}
	cli := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return 0, "", err
	}
	if body != nil || (method != "GET" && method != "HEAD") {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cli.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(raw)), nil
}

func runServe(listenAddr, tag string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "OK:%s:from=%s\n", tag, r.RemoteAddr)
	})
	return http.ListenAndServe(listenAddr, mux)
}

func runNetNSAgent(pidFile, sockPath string) {
	_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen unix %s: %v\n", sockPath, err)
		os.Exit(1)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			var req nsReq
			if err := json.NewDecoder(c).Decode(&req); err != nil {
				_ = json.NewEncoder(c).Encode(nsResp{OK: false, Error: err.Error()})
				return
			}
			switch req.Op {
			case "sh":
				cmd := exec.Command("/bin/sh", "-c", "export PATH=/usr/sbin:/usr/bin:/sbin:/bin; "+req.Cmd)
				out, err := cmd.CombinedOutput()
				resp := nsResp{OK: err == nil, Output: strings.TrimSpace(string(out))}
				if err != nil {
					resp.Error = err.Error()
				}
				_ = json.NewEncoder(c).Encode(resp)
			case "http":
				code, body, err := doHTTP(req.Method, req.URL, req.LocalIP, req.Body)
				resp := nsResp{OK: err == nil, Status: code, Output: body}
				if err != nil {
					resp.Error = err.Error()
				}
				_ = json.NewEncoder(c).Encode(resp)
			case "serve":
				go func(addr, tag string) { _ = runServe(addr, tag) }(req.Addr, req.Tag)
				time.Sleep(100 * time.Millisecond)
				_ = json.NewEncoder(c).Encode(nsResp{OK: true})
			default:
				_ = json.NewEncoder(c).Encode(nsResp{OK: false, Error: "unknown op"})
			}
		}(conn)
	}
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := runServe(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "serve: %v\n", err)
			os.Exit(1)
		}
	case "http":
		localIP := "-"
		body := ""
		if len(os.Args) >= 5 {
			localIP = os.Args[4]
		}
		if len(os.Args) >= 6 {
			body = os.Args[5]
		}
		code, out, err := doHTTP(os.Args[2], os.Args[3], localIP, body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERR:%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("STATUS=%d\n%s", code, out)
	case "netns-spawn":
		// Re-exec self in a brand new isolated Linux network namespace (CLONE_NEWNET) with detached stdio.
		cmd := exec.Command(os.Args[0], "netns-agent", os.Args[2], os.Args[3])
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWNET,
			Setsid:     true,
		}
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "spawn netns: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(cmd.Process.Pid)
	case "netns-agent":
		runNetNSAgent(os.Args[2], os.Args[3])
	case "netns-ctl":
		sock := os.Args[2]
		op := os.Args[3]
		req := nsReq{Op: op}
		switch op {
		case "sh":
			req.Cmd = os.Args[4]
		case "http":
			req.Method = os.Args[4]
			req.URL = os.Args[5]
			if len(os.Args) >= 7 {
				req.LocalIP = os.Args[6]
			}
			if len(os.Args) >= 8 {
				req.Body = os.Args[7]
			}
		case "serve":
			req.Addr = os.Args[4]
			req.Tag = os.Args[5]
		}
		conn, err := net.DialTimeout("unix", sock, 5*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dial %s: %v\n", sock, err)
			os.Exit(1)
		}
		defer conn.Close()
		_ = json.NewEncoder(conn).Encode(req)
		var resp nsResp
		if err := json.NewDecoder(conn).Decode(&resp); err != nil {
			fmt.Fprintf(os.Stderr, "decode: %v\n", err)
			os.Exit(1)
		}
		if !resp.OK {
			fmt.Fprintf(os.Stderr, "ERR:%s\n%s\n", resp.Error, resp.Output)
			os.Exit(1)
		}
		if op == "http" {
			fmt.Printf("STATUS=%d\n%s", resp.Status, resp.Output)
		} else if resp.Output != "" {
			fmt.Print(resp.Output)
		}
	default:
		os.Exit(2)
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatalf("write probe main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module vlanprobe\n\ngo 1.24\n"), 0644); err != nil {
		t.Fatalf("write probe go.mod: %v", err)
	}
	outBin := filepath.Join(workDir, "vlan-probe-"+targetArch)
	cmd := exec.CommandContext(ctx, "go", "build", "-o", outBin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+targetArch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build probe helper linux/%s failed: %v\n%s", targetArch, err, string(out))
	}
	return outBin
}

func mustRun(t *testing.T, ctx context.Context, name string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %s\nerr: %v\noutput:\n%s", name, strings.Join(args, " "), err, string(out))
	}
	return string(out)
}

func dockerExec(ctx context.Context, container, shCmd string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", container, "/bin/sh", "-c",
		`export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; `+shCmd)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustDockerExec(t *testing.T, ctx context.Context, container, shCmd string) string {
	t.Helper()
	out, err := dockerExec(ctx, container, shCmd)
	if err != nil {
		t.Fatalf("docker exec %s failed: %v\ncmd:\n%s\noutput:\n%s", container, err, shCmd, out)
	}
	return out
}

func probeHTTP(ctx context.Context, container, method, url, localIP, jsonBody string) (int, string, error) {
	if localIP == "" {
		localIP = "-"
	}
	args := []string{"exec", container, "/usr/bin/vlan-probe", "http", method, url, localIP}
	if jsonBody != "" {
		args = append(args, jsonBody)
	}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return parseProbeHTTPOut(string(out), err)
}

func probeNetNSHTTP(ctx context.Context, container, sockPath, method, url, localIP, jsonBody string) (int, string, error) {
	if localIP == "" {
		localIP = "-"
	}
	args := []string{"exec", container, "/usr/bin/vlan-probe", "netns-ctl", sockPath, "http", method, url, localIP}
	if jsonBody != "" {
		args = append(args, jsonBody)
	}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return parseProbeHTTPOut(string(out), err)
}

func mustNetNSSh(t *testing.T, ctx context.Context, container, sockPath, shCmd string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", "exec", container, "/usr/bin/vlan-probe", "netns-ctl", sockPath, "sh", shCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("netns sh (%s) failed: %v\ncmd:\n%s\nout:\n%s", sockPath, err, shCmd, string(out))
	}
	return string(out)
}

func mustNetNSJSON(t *testing.T, ctx context.Context, container, sockPath, method, url string, payload any) (int, string) {
	t.Helper()
	bodyStr := ""
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		bodyStr = string(raw)
	}
	code, body, err := probeNetNSHTTP(ctx, container, sockPath, method, url, "-", bodyStr)
	if err != nil {
		t.Fatalf("netns HTTP %s %s (%s) failed: %v (output=%s)", method, url, sockPath, err, body)
	}
	return code, body
}

func parseProbeHTTPOut(text string, err error) (int, string, error) {
	if err != nil {
		return 0, text, err
	}
	firstLine, body, _ := strings.Cut(text, "\n")
	var code int
	if _, scanErr := fmt.Sscanf(strings.TrimSpace(firstLine), "STATUS=%d", &code); scanErr != nil {
		return 0, text, fmt.Errorf("parse status from %q: %w", firstLine, scanErr)
	}
	return code, strings.TrimSpace(body), nil
}

func waitUntil(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", desc)
}
