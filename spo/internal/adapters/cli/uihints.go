package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// secretFDFlags classifies every flag that names a file descriptor carrying a
// secret. A flag ending in -fd that is missing here is caught by a test in
// cmd/spo, so a new secret descriptor cannot reach an interactive driver
// unclassified.
var secretFDFlags = map[string]string{
	"passphrase-fd":          uihint.SecretIn,
	"new-passphrase-fd":      uihint.SecretIn,
	"old-passphrase-fd":      uihint.SecretIn,
	"cold-passphrase-fd":     uihint.SecretIn,
	"new-cold-passphrase-fd": uihint.SecretIn,
	"password-fd":            uihint.SecretIn,
	"recovery-key-in-fd":     uihint.SecretIn,
	"mnemonic-in-fd":         uihint.SecretIn,
	"pin-fd":                 uihint.SecretIn,
	"fido2-pin-fd":           uihint.SecretIn,
	"recovery-pin-fd":        uihint.SecretIn,
	"old-recovery-pin-fd":    uihint.SecretIn,
	"new-fido2-pin-fd":       uihint.SecretIn,
	"checkpoint-pin-fd":      uihint.SecretIn,
	"old-checkpoint-pin-fd":  uihint.SecretIn,
	"token-fd":               uihint.SecretIn,
	"message-passphrase-fd":  uihint.SecretIn,
	"protection-key-fd":      uihint.SecretIn,
	"recovery-key-fd":        uihint.SecretOut,
	"password-out-fd":        uihint.SecretOut,
}

// MarkForUI annotates a command tree for an interactive driver: secret
// descriptor flags, the root's session-wide flags, and the commands whose
// output can hold a secret (those with a secret descriptor to write to: the
// output is where the secret goes when none is given). It only adds
// annotations; the command line and every command's behaviour are unchanged.
func MarkForUI(root *cobra.Command) {
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) { setAnnotation(f, uihint.Global, "true") })
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		mark := func(f *pflag.Flag) {
			if dir, ok := secretFDFlags[f.Name]; ok {
				setAnnotation(f, uihint.SecretFD, dir)
				if dir == uihint.SecretOut {
					if c.Annotations == nil {
						c.Annotations = map[string]string{}
					}
					c.Annotations[uihint.SensitiveOutput] = "true"
				}
			}
		}
		c.Flags().VisitAll(mark)
		c.PersistentFlags().VisitAll(mark)
		applyHints(root, c)
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

func setAnnotation(f *pflag.Flag, key, value string) {
	if f.Annotations == nil {
		f.Annotations = map[string][]string{}
	}
	f.Annotations[key] = []string{value}
}
