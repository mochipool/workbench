package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/governance"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// govKeyOptions are the flags of the three key generation commands.
type govKeyOptions struct {
	mnemonic   bool
	mnemonicFD int
	account    uint32
	index      uint32
	replace    bool
}

func (o *govKeyOptions) add(cmd *cobra.Command, replace bool) {
	f := cmd.Flags()
	f.BoolVar(&o.mnemonic, "mnemonic", false, "derive the key (CIP-1852) from a freshly generated 24-word mnemonic, stored sealed in the workspace and not shown")
	f.IntVar(&o.mnemonicFD, "mnemonic-in-fd", -1, "derive the key from a mnemonic read from this file descriptor (never from the command line or the environment)")
	f.Uint32Var(&o.account, "account", 0, "account number of the derivation path (derived keys)")
	f.Uint32Var(&o.index, "index", 0, "address index of the derivation path (derived keys)")
	if replace {
		f.BoolVar(&o.replace, "replace", false, "replace an existing hot key and its files (the answer to upstream's prompt, which defaults to No)")
	}
}

// validate rejects the combinations the use case rejects, before anything
// is opened.
func (o *govKeyOptions) validate(fdSet bool, passFD int) error {
	if o.mnemonic && fdSet {
		return errors.New("--mnemonic and --mnemonic-in-fd are exclusive: generate a phrase or give one")
	}
	if fdSet && o.mnemonicFD < 0 {
		return errors.New("--mnemonic-in-fd needs a file descriptor number")
	}
	if fdSet && passFD >= 0 && o.mnemonicFD == passFD {
		return errors.New("--mnemonic-in-fd and --passphrase-fd name the same descriptor")
	}
	if !o.mnemonic && !fdSet && (o.account != 0 || o.index != 0) {
		return fmt.Errorf("%w: --account and --index select the derivation path of a derived key; add --mnemonic or --mnemonic-in-fd", governance.ErrOptionNotUsed)
	}
	if o.account > governance.MaxDerivationIndex || o.index > governance.MaxDerivationIndex {
		return governance.ErrDerivationRange
	}
	return nil
}

// govKeyRun is what one key command does with the validated options.
type govKeyRun func(ctx context.Context, s *session, env *Env, req governance.GenerateKeysRequest, fresh bool) error

func (a *app) govKeyCommand(use, short, long string, replace bool, needs func(derived, withWords bool) []Need, run govKeyRun) *cobra.Command {
	var o govKeyOptions
	var hw hardwareFlags
	var cf chainFlags
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fdSet := cmd.Flags().Changed("mnemonic-in-fd")
			if err := hw.validate(cmd); err != nil {
				return err
			}
			if hw.on {
				if o.mnemonic || fdSet {
					return errors.New("--hardware cannot be combined with --mnemonic or --mnemonic-in-fd: a hardware key has no mnemonic")
				}
				if o.account > governance.MaxDerivationIndex || o.index > governance.MaxDerivationIndex {
					return governance.ErrDerivationRange
				}
			} else if err := o.validate(fdSet, a.passFD); err != nil {
				return err
			}
			derived := o.mnemonic || fdSet
			need := needs(derived, o.mnemonic)
			if hw.on {
				need = []Need{CapHardware}
			}
			return a.withEnv(cmd, envSpec{flags: &cf, needs: need}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				req := governance.GenerateKeysRequest{Name: args[0], Source: governance.KeysRandom, Replace: o.replace, Holder: hw.holder()}
				if hw.on {
					req.Account, req.Index = o.account, o.index
					a.noteDevice()
				}
				if derived {
					req.Source, req.Account, req.Index = governance.KeysMnemonic, o.account, o.index
				}
				var phrase *secret.Buffer
				if fdSet {
					var err error
					if phrase, err = readFDSecret(o.mnemonicFD, "the mnemonic"); err != nil {
						return err
					}
					defer phrase.Destroy()
					req.Mnemonic = phrase
				}
				return run(ctx, s, env, req, o.mnemonic)
			})
		},
	}
	o.add(cmd, replace)
	hw.add(cmd, 0)
	addChainFlags(cmd, &cf, true)
	// Declared, so the usage and the TUI form know it; RunE keeps its own checks.
	cmd.MarkFlagsMutuallyExclusive("mnemonic", "mnemonic-in-fd", "hardware")
	return cmd
}

func keyNeeds(gen Cap) func(derived, withWords bool) []Need {
	return func(derived, withWords bool) []Need {
		switch {
		case withWords:
			return []Need{CapGovDeriver, CapMnemonics}
		case derived:
			return []Need{CapGovDeriver}
		}
		return []Need{gen}
	}
}

func (a *app) mnemonicNotice(stored bool) {
	if stored {
		fmt.Fprintf(a.d.Out, "\nThe recovery phrase was generated and is stored sealed in the workspace. It is not shown.\n"+
			"The command that displays it does not exist yet (the audited export is not built), so\n"+
			"until then this key can be recovered only from a backup of the workspace.\n")
	}
}
