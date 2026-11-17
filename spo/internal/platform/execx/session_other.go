//go:build !unix

package execx

import "os/exec"

// detach has no effect where there is no session notion; the tools driven this
// way are Unix tools.
func detach(cmd *exec.Cmd) {}
