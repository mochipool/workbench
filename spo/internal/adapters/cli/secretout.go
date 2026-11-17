package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/mochipool/workbench/spo/internal/platform/secretfd"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// checkSecretOutFlags refuses, before the command does anything, a flag that
// names a descriptor to receive a secret when that descriptor is not a pipe
// or a socket. The flags are the ones secretFDFlags classifies as
// uihint.SecretOut, so the classification the TUI reads and this check cannot
// disagree: a new secret-output flag is checked the moment it is classified.
// secretfd.Write checks again at the point of writing.
//
// spec: SPO-Xcustody-OUT-005
func checkSecretOutFlags(cmd *cobra.Command) error {
	var err error
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if err != nil || secretFDFlags[f.Name] != uihint.SecretOut {
			return
		}
		fd, gerr := cmd.Flags().GetInt(f.Name)
		if gerr != nil {
			return
		}
		err = secretfd.Check(f.Name, fd)
	})
	return err
}
