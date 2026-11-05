//go:build windows

package adguard

import "os/exec"

func setDetachedSysProcAttr(_ *exec.Cmd) {}
