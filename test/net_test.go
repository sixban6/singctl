package test

import (
	"bytes"
	"strings"
	"testing"

	"singctl/internal/cmd"
)

func TestNetCommand_Subcommands(t *testing.T) {
	netCmd := cmd.NewNetCmd("/tmp/singctl.yaml")
	if netCmd.Use != "net" {
		t.Errorf("expected use 'net', got %s", netCmd.Use)
	}

	expectedSubcmds := map[string]bool{
		"diag":   false,
		"ping":   false,
		"trace":  false,
		"return": false,
		"advice": false,
	}

	for _, sub := range netCmd.Commands() {
		useName := strings.Fields(sub.Use)[0]
		if _, ok := expectedSubcmds[useName]; ok {
			expectedSubcmds[useName] = true
		}
	}

	for name, found := range expectedSubcmds {
		if !found {
			t.Errorf("missing subcommand %s in singctl net", name)
		}
	}
}

func TestNetAdviceCommand_Execution(t *testing.T) {
	netCmd := cmd.NewNetCmd("/tmp/singctl.yaml")
	buf := new(bytes.Buffer)
	netCmd.SetOut(buf)
	netCmd.SetErr(buf)
	netCmd.SetArgs([]string{"advice", "--carrier", "cu"})

	if err := netCmd.Execute(); err != nil {
		t.Fatalf("singctl net advice execution failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "中国联通") {
		t.Errorf("expected output to contain '中国联通', got:\n%s", out)
	}

	// Test --all
	buf.Reset()
	netCmd.SetArgs([]string{"advice", "--all"})
	if err := netCmd.Execute(); err != nil {
		t.Fatalf("singctl net advice --all execution failed: %v", err)
	}
	if !strings.Contains(buf.String(), "全量百科") {
		t.Errorf("expected output to contain '全量百科', got:\n%s", buf.String())
	}
}
