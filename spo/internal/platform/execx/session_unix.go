//go:build unix

package execx

import (
	"os/exec"
	"syscall"
)

// detach puts the child in a new session: no controlling terminal.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
