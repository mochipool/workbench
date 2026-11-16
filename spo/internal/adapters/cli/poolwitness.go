package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// mainnetMagic is the network magic of mainnet.
const mainnetMagic = 764824073

// networkMagic is the magic of the workspace's network (preset: "mainnet" or
// the decimal testnet magic).
func networkMagic(o WireOptions) (uint32, error) {
	if o.Preset.Magic == "mainnet" {
		return mainnetMagic, nil
	}
	m, err := strconv.ParseUint(o.Preset.Magic, 10, 32)
	if err != nil || m == 0 {
		return 0, fmt.Errorf("the workspace has no known network magic (%q): create it with spo init --network <name>", o.Preset.Magic)
	}
	return uint32(m), nil
}

// terminalApprover shows a signer the decoded body and asks, default No. No
// flag answers it: a witness is never made for a body that was not shown.
type terminalApprover struct{ a *app }

func (t terminalApprover) ApproveSigning(ctx context.Context, slot string, v party.TxView) (bool, error) {
	printTxView(t.a.d.Out, v)
	fmt.Fprintf(t.a.d.Out, "You are asked to sign this as %q.\n", slot)
	ans, err := t.a.term.ReadLine(ctx, "Sign this transaction? [y/N] ")
	if errors.Is(err, ErrNoTerminal) {
		return false, errors.New("no terminal to ask on: a transaction is never signed unseen, and no flag answers this question")
	}
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

func (a *app) witnessSignCommand() *cobra.Command {
	var (
		key string
		cf  chainFlags
	)
	cmd := &cobra.Command{
		Use:   "sign <file> --key NAME",
		Short: "Sign a witness transfer file with a stored staking key (on the signer's machine)",
		Long: `Decode the transaction in the witness transfer file <file>, show it in full and
sign it with the stored staking key NAME (".staking" is added) when you answer
yes (default No). The file is rewritten in place with the witness and the date;
send it back to the pool operator, who imports it with: spo pool witness import.

The file is not trusted: the window (ttl) must be open, the key must be the one
the witness was requested for, the network must be this workspace's, and a body
with parts that cannot be shown in full (proposals, a mint, scripts, datums,
collateral, reference inputs) is refused. Nothing but the file and your own keys
is used, and no flag answers the question: a transaction is never signed unseen.
A key on a hardware wallet signs through the device.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if key == "" {
				return errors.New("--key NAME is required: the stored staking key that signs")
			}
			spec := envSpec{flags: &cf, config: true, needs: []Need{CapSigners, CapGenesis, CapTip, CapClock, CapTxView, CapTxID}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, o WireOptions) error {
				path := args[0]
				if _, err := os.Stat(path); err != nil {
					if alt := poolops.WitnessFileName(path); alt != path {
						if _, err2 := os.Stat(alt); err2 == nil {
							path = alt
						}
					}
				}
				st, err := os.Stat(path)
				if err != nil {
					return err
				}
				if !st.Mode().IsRegular() || st.Size() > maxWitnessFile {
					return fmt.Errorf("%s is not a regular file of at most %d bytes", path, maxWitnessFile)
				}
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				magic, err := networkMagic(o)
				if err != nil {
					return err
				}
				uc := poolops.SignWitnessFile{Store: s.Store, Tip: env.Tip, Clock: env.Clock, Viewer: env.TxViewer, TxIDs: env.TxIDs,
					Signers: env.Signers, Approver: terminalApprover{a}, NetworkMagic: magic}
				if env.Canonicalizer != nil {
					a.noteDevice()
				}
				res, err := uc.Run(ctx, poolops.SignRequest{File: b, Key: key})
				if err != nil {
					if errors.Is(err, poolops.ErrSigningNotApproved) {
						return fmt.Errorf("%w: nothing was signed and %s is unchanged", err, path)
					}
					return err
				}
				if res.NameMismatch {
					fmt.Fprintf(a.d.Err, "Warning: the file was requested for a key with another name than %s; the verification key matched, so it was signed.\n", key)
				}
				if err := writeInPlace(path, res.File); err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Signed. %s now holds your witness (checked against the window at slot %d). Send it back to the pool operator.\n", path, res.Tip)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "the stored staking key that signs (NAME or NAME.staking)")
	addChainFlags(cmd, &cf, false)
	return cmd
}

// writeInPlace replaces a file with data: written beside it and renamed, so a
// failure leaves the original.
func writeInPlace(path string, data []byte) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".witness-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(st.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (a *app) witnessInfoCommand() *cobra.Command {
	var cf chainFlags
	cmd := &cobra.Command{
		Use:   "info <pool>",
		Short: "Report the witness collection of a pool: state, window and which slots are signed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &cf, config: true, needs: []Need{CapGenesis, CapTip, CapTxID}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				res, err := poolops.WitnessInfo{Store: s.Store, Tip: env.Tip, TxIDs: env.TxIDs}.Run(ctx, args[0])
				w := a.d.Out
				if res.Present {
					fmt.Fprintf(w, "Witness collection %d (%s) for %s\n  paid by      %s\n  valid until  slot %d (now slot %d)\n  state        %s\n",
						res.ID, res.Type, res.Ticker, res.PayName, res.TTL, res.Tip, res.State)
					if res.MetadataFiles != "" {
						fmt.Fprintf(w, "  metadata     %s\n", res.MetadataFiles)
					}
					for _, sl := range res.Slots {
						if sl.Ready {
							fmt.Fprintf(w, "    signed     %s\n", sl.Name)
						} else {
							fmt.Fprintf(w, "    open       %s  (witness file %s)\n", sl.Name, sl.FileName)
						}
					}
				}
				if err != nil {
					return err
				}
				if !res.Present {
					fmt.Fprintln(w, "No witness collection is open.")
				}
				return nil
			})
		},
	}
	addChainFlags(cmd, &cf, false)
	return cmd
}

func (a *app) witnessClearCommand() *cobra.Command {
	var (
		yes bool
		cf  chainFlags
	)
	cmd := &cobra.Command{
		Use:   "clear <pool> [--yes]",
		Short: "Discard the open witness collection of a pool",
		Long: `Remove the witness collection from the pool's descriptor, after asking (default
No). The collected witnesses are lost; witness transfer files on disk are not
touched. Do this when the window is over or the registration should start again.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &cf, config: true, needs: []Need{CapTxID}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				ok, err := a.confirm(ctx, "Delete the witness collection of "+args[0]+"? The witnesses collected so far are lost.", yes)
				if err != nil {
					return err
				}
				res, err := poolops.ClearWitnesses{Store: s.Store, TxIDs: env.TxIDs}.Run(ctx, poolops.ClearRequest{Pool: args[0], Confirmed: ok})
				if err != nil {
					return err
				}
				switch {
				case !res.Present:
					fmt.Fprintln(a.d.Out, "No witness collection is open: nothing to clear.")
				case res.Cleared:
					fmt.Fprintln(a.d.Out, "Cleared the witness collection.")
				default:
					fmt.Fprintln(a.d.Out, "Not cleared: the collection is unchanged.")
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "answer yes to the question")
	addChainFlags(cmd, &cf, false)
	return cmd
}

// ---- BLS ---------------------------------------------------------------------

// blsMainnetWhy is the reason a BLS key is refused on mainnet: upstream ships
// 04f only in its testnet tree, and the key is needed by 05a only from
// protocol version 12 (SPO-04f, SPO-Pfiles-OUT-016).
const blsMainnetWhy = "upstream's 04f_genBLSKeys exists only in its testnet tree and the BLS key is needed in a pool registration certificate only from protocol version 12, which mainnet has not reached; refusing to make one for mainnet"

func (a *app) poolBLSCommand() *cobra.Command {
	var cf chainFlags
	bls := &cobra.Command{Use: "bls", Short: "Pool BLS keys (testnet only)"}
	bls.AddCommand(&cobra.Command{
		Use:   "generate <pool>",
		Short: "Generate the BLS key pair a pool registration needs from protocol version 12 (testnet only)",
		Long: `Generate the pool's BLS12-381 key pair into the workspace; the signing key is
sealed and never shown. It is refused on mainnet: ` + blsMainnetWhy + `.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o, _, err := a.wireOptions(cmd, &cf, true)
			if err != nil {
				return err
			}
			if o.Config.Network == "mainnet" {
				return errors.New(blsMainnetWhy)
			}
			spec := envSpec{flags: &cf, config: true, needs: []Need{CapBLSKeys}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				name, err := poolArg(args[0])
				if err != nil {
					return err
				}
				res, err := poolops.GenerateBLSKeys{Store: s.Store, KeyGen: env.BLSKeys}.Run(ctx, poolops.GenerateBLSKeysRequest{Pool: name})
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Generated the BLS keys of pool %s.\n%s\n", res.Pool, res.VKey)
				return nil
			})
		},
	})
	return bls
}
