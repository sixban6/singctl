package cmd

import (
	"testing"
)

func TestServerWebCmd_Subcommands(t *testing.T) {
	root := newServerWebCmd("/tmp/nonexistent.yaml")
	commands := make(map[string]bool)
	for _, sub := range root.Commands() {
		commands[sub.Name()] = true
		for _, alias := range sub.Aliases {
			commands[alias] = true
		}
	}

	expected := []string{"start", "stop", "restart", "r", "status", "unban"}
	for _, exp := range expected {
		if !commands[exp] {
			t.Errorf("expected subcommand or alias %q to exist under 'server web'", exp)
		}
	}
}
