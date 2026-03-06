package test

import (
	"strings"
	"testing"

	"singctl/internal/cmd"
)

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
