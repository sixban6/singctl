//go:build !unix

package tailscale

import (
	"fmt"
	"os/exec"
)

func statfsFreeBytes(string) (uint64, error) {
	return 0, fmt.Errorf("statfs not supported on this platform")
}

func readSystemMemInfo() (uint64, uint64) {
	return 0, 0
}

func detachCmdAttrs(*exec.Cmd) {}

func isPIDAlive(int) bool {
	return false
}
