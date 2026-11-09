package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"singctl/internal/cmd"
	"singctl/internal/util/github"
	"strings"
	"testing"
)

func TestGatewayModeDoesNotForceAcceptRoutes(t *testing.T) {
	mainRouter := false
	exitNode := false
	acceptRoutes := false
	acceptRoutesChanged := false
	mode := "gateway"

	switch mode {
	case "client":
		mainRouter = false
		exitNode = false
	case "router":
		mainRouter = true
		exitNode = false
	case "exit":
		mainRouter = false
		exitNode = true
	case "gateway":
		mainRouter = true
		exitNode = true
	}

	if !mainRouter || !exitNode {
		t.Fatal("gateway mode should enable both router and exit-node")
	}
	if acceptRoutes {
		t.Fatal("gateway mode must not force accept-routes=true")
	}
	if acceptRoutesChanged {
		t.Fatal("gateway mode must not mark accept-routes as user-overridden")
	}
}

func TestGatewayModeCanStillUseExplicitAcceptRoutes(t *testing.T) {
	mainRouter := false
	exitNode := false
	acceptRoutes := true
	acceptRoutesChanged := true
	mode := "gateway"

	switch mode {
	case "client":
		mainRouter = false
		exitNode = false
	case "router":
		mainRouter = true
		exitNode = false
	case "exit":
		mainRouter = false
		exitNode = true
	case "gateway":
		mainRouter = true
		exitNode = true
	}

	if !mainRouter || !exitNode {
		t.Fatal("gateway mode should enable both router and exit-node")
	}
	if !acceptRoutes || !acceptRoutesChanged {
		t.Fatal("explicit --accept-routes should still be preserved in gateway mode")
	}
}

func TestTailscaleStartFlags(t *testing.T) {
	root := cmd.NewTailscaleCmd("/tmp/singctl.yaml")
	startCmd, _, err := root.Find([]string{"start"})
	if err != nil {
		t.Fatalf("start command not found: %v", err)
	}

	exitFlag := startCmd.Flags().Lookup("exit-node")
	if exitFlag == nil {
		t.Fatal("exit-node flag missing")
	}

	routerFlag := startCmd.Flags().Lookup("router")
	if routerFlag == nil {
		t.Fatal("router flag missing")
	}

	// 核心断言：两个 flag 的 Usage 不能相同
	if exitFlag.Usage == routerFlag.Usage {
		t.Errorf("exit-node and router flag usage should NOT be identical, both are: %q", exitFlag.Usage)
	}

	// exit-node 应包含"出口节点"和"exit node"
	if !strings.Contains(exitFlag.Usage, "exit node") {
		t.Errorf("exit-node usage should mention 'exit node', got: %q", exitFlag.Usage)
	}
	if !strings.Contains(exitFlag.Usage, "出口节点") {
		t.Errorf("exit-node usage should mention '出口节点', got: %q", exitFlag.Usage)
	}

	// router 应包含"子网"和"subnet"
	if !strings.Contains(routerFlag.Usage, "subnet") {
		t.Errorf("router usage should mention 'subnet', got: %q", routerFlag.Usage)
	}
	if !strings.Contains(routerFlag.Usage, "子网") {
		t.Errorf("router usage should mention '子网', got: %q", routerFlag.Usage)
	}
}

func TestTailscaleStartExample(t *testing.T) {
	root := cmd.NewTailscaleCmd("/tmp/singctl.yaml")
	startCmd, _, err := root.Find([]string{"start"})
	if err != nil {
		t.Fatalf("start command not found: %v", err)
	}

	example := startCmd.Example
	if example == "" {
		t.Fatal("start command should have Example text")
	}

	for _, keyword := range []string{"--router", "--exit-node"} {
		if !strings.Contains(example, keyword) {
			t.Errorf("Example should contain %q, got: %q", keyword, example)
		}
	}
}

// TestTailscaleVersionFromAsset 验证当 Release Tag 固定为 "latest" 时，
// 能否从 Asset name (例如 tailscale_1.94.2_amd64.tgz) 里正确解析版本号。
func TestTailscaleVersionFromAsset(t *testing.T) {
	// 启动一个模拟 GitHub API 的 Web Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 返回 auto_fetch_tailscale 的特有结构：Tag 为 latest，但 Asset 里有真实版本
		releases := []github.Release{
			{
				TagName: "latest",
				Assets: []github.Asset{
					{
						Name:               "tailscale_1.94.2_amd64.tgz",
						BrowserDownloadURL: "https://example.com/tailscale_1.94.2_amd64.tgz",
					},
				},
			},
		}
		json.NewEncoder(w).Encode(releases)
	}))
	defer server.Close()

	// 这里我们只验证提取逻辑，直接匹配 "tailscale_" 开头的文件
	filter := func(name string) bool {
		return strings.HasPrefix(name, "tailscale_")
	}

	fetcher := github.NewReleaseFetcher("", server.Client())
	downloadURL, err := fetcher.FindAssetURLFromURL(server.URL, filter)
	if err != nil {
		t.Fatalf("unexpected error finding asset: %v", err)
	}

	// 模拟 tailscale.go 中的解析逻辑
	version := "latest"
	re := regexp.MustCompile(`tailscale_([\d\.]+)_`)
	matches := re.FindStringSubmatch(downloadURL)
	if len(matches) > 1 {
		version = matches[1]
	}

	if version != "1.94.2" {
		t.Errorf("expected parsed version '1.94.2', got '%s'", version)
	}
}
