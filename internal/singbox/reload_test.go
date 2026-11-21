package singbox

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReloadSingBoxProcess_HostZeroPollutionInTests(t *testing.T) {
	binDir := t.TempDir()
	marker := filepath.Join(binDir, "signal_sent")
	script := fmt.Sprintf("#!/bin/sh\necho \"$0 $*\" >> %q\nexit 0\n", marker)

	for _, name := range []string{"pkill", "killall"} {
		p := filepath.Join(binDir, name)
		if err := os.WriteFile(p, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	ReloadSingBoxProcess()

	if data, err := os.ReadFile(marker); err == nil {
		t.Fatalf("expected ReloadSingBoxProcess not to invoke pkill/killall under go test, got calls:\n%s", string(data))
	}
}
