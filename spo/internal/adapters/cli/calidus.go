package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/catalyst"
	"github.com/mochipool/workbench/spo/internal/app/poolkey"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The Calidus pool key (CIP-151, upstream 15_calidusPoolKey) and Catalyst
// (CIP-36, upstream 09a_catalystVote). Neither command submits anything: the
// registration is stored in the workspace and attached to an ordinary payment
// with `spo wallet send ... --metadata-record NAME`. No command prints a
// signing key or a mnemonic. The QR code of the Catalyst mobile app is not
// built.

// derivedKeyOptions are the flags of the two key commands.
type derivedKeyOptions struct {
	mnemonicFD     int
	account, index uint32
}

func (o *derivedKeyOptions) add(cmd *cobra.Command) {
	f := cmd.Flags()
	f.IntVar(&o.mnemonicFD, "mnemonic-in-fd", -1, "derive the key from a mnemonic read from this file descriptor (never from the command line or the environment); without it a fresh 24-word phrase is generated, stored sealed and not shown")
	f.Uint32Var(&o.account, "account", 0, "account number of the derivation path")
	f.Uint32Var(&o.index, "index", 0, "address index of the derivation path")
}

func (o *derivedKeyOptions) validate(fdSet bool, passFD int) error {
	if fdSet && o.mnemonicFD < 0 {
		return errors.New("--mnemonic-in-fd needs a file descriptor number")
	}
	if fdSet && passFD >= 0 && o.mnemonicFD == passFD {
		return errors.New("--mnemonic-in-fd and --passphrase-fd name the same descriptor")
	}
	if o.account > poolkey.MaxDerivationIndex || o.index > poolkey.MaxDerivationIndex {
		return poolkey.ErrDerivationRange
	}
	return nil
}

// phrase reads the mnemonic of --mnemonic-in-fd; nil when the flag is not set.
func (o *derivedKeyOptions) phrase(fdSet bool) (*secret.Buffer, error) {
	if !fdSet {
		return nil, nil
	}
	return readFDSecret(o.mnemonicFD, "the mnemonic")
}

func derivedNeeds(fdSet bool, keys Cap) []Need {
	if fdSet {
		return []Need{keys}
	}
	return []Need{keys, CapMnemonics}
}

// nonceFlag turns --nonce into the use cases' value, 0 meaning the default.
func checkNonce(cmd *cobra.Command, n uint64) error {
	if cmd.Flags().Changed("nonce") && n == 0 {
		return errors.New("--nonce must be greater than zero (zero would choose the default)")
	}
	return nil
}

// ---- pool calidus ------------------------------------------------------------------------

func (a *app) poolCalidusCommand() *cobra.Command {
	c := &cobra.Command{Use: "calidus", Short: "The Calidus pool key (CIP-151): generate it, register it, look it up"}
	c.AddCommand(a.calidusNewCommand(), a.calidusRegisterCommand(), a.calidusStatusCommand())
	return c
}

func (a *app) calidusNewCommand() *cobra.Command {
	var o derivedKeyOptions
	var cf chainFlags
	cmd := &cobra.Command{
		Use:   "new <name> [--mnemonic-in-fd N] [--account N] [--index N]",
		Short: "Generate a Calidus key from a mnemonic and print its id",
		Long: `Derive the Calidus key (CIP-151) along 1852H/1815H/<account>H/0/<index> from a
24-word phrase and store <name>.calidus.vkey, .skey, .mnemonics and .id sealed in
the workspace. --mnemonic-in-fd N reads the phrase from file descriptor N;
without it a fresh phrase is generated and stored, never shown. The signing
key and the phrase are never printed; the Calidus id and the public key are.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fdSet := cmd.Flags().Changed("mnemonic-in-fd")
			if err := o.validate(fdSet, a.passFD); err != nil {
				return err
			}
			return a.withEnv(cmd, envSpec{flags: &cf, needs: derivedNeeds(fdSet, CapCalidusKeys)}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				phrase, err := o.phrase(fdSet)
				if err != nil {
					return err
				}
				defer phrase.Destroy()
				req := poolkey.GenerateCalidusKeyRequest{Name: args[0], Account: o.account, Index: o.index}
				if phrase != nil {
					req.Mnemonic = phrase
				}
				res, err := poolkey.GenerateCalidusKey{Store: s.Store, Deriver: env.CalidusKeys, Mnemonics: env.Mnemonics}.Run(ctx, req)
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Generated the Calidus key %s.\n  Calidus id   %s\n  public key   %s\n", res.Name, res.ID, hex.EncodeToString(res.PublicKey[:]))
				a.mnemonicNotice(res.MnemonicStored && !fdSet)
				fmt.Fprintf(a.d.Out, "Register it with: spo pool calidus register-metadata %s <pool>\n", res.Name)
				return nil
			})
		},
	}
	o.add(cmd)
	addChainFlags(cmd, &cf, false)
	return cmd
}

func (a *app) calidusRegisterCommand() *cobra.Command {
	var (
		nonce uint64
		cf    chainFlags
	)
	cmd := &cobra.Command{
		Use:   "register-metadata <calidus-name> <pool> [--nonce N]",
		Short: "Sign the Calidus registration with the pool cold key and store the metadata",
		Long: `Build the CIP-88 (version 2) registration of the Calidus key <calidus-name> for
<pool> and sign it with the pool's cold key. The metadata is stored in the
workspace as <pool>_<time>.calidus-registration.json; nothing is submitted. The
cold key must be in the workspace: a cold key on a hardware wallet cannot sign
this and is refused before anything is built.

--nonce N sets the registration nonce; by default it is the current slot of the
work mode (the Shelley genesis is needed offline). Attach the stored metadata
to a payment of yours to put it on the chain:

  spo wallet send <payer> <payer> MIN --metadata-record <name printed here>`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkNonce(cmd, nonce); err != nil {
				return err
			}
			needs := []Need{CapSigners, CapSignatures, CapClock}
			return a.withEnv(cmd, envSpec{flags: &cf, needs: needs}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				if nonce == 0 && env.Tip == nil && env.NetworkID != ports.NetworkMainnet {
					return errors.New("this mode has no current slot to take the nonce from, and the default nonce is the mainnet slot: give --nonce N")
				}
				uc := poolkey.GenerateCalidusRegistration{Store: s.Store, Signers: env.Signers, Clock: env.Clock}
				if env.Tip != nil {
					uc.Tip = env.Tip
				}
				res, err := uc.Run(ctx, poolkey.CalidusRegistrationRequest{Calidus: args[0], Pool: args[1], Nonce: nonce})
				if err != nil {
					return err
				}
				w := a.d.Out
				name := recordFileName(res.Ref)
				fmt.Fprintf(w, "Signed the Calidus registration.\n  Calidus id   %s\n  pool id      %s\n  nonce        %d\n  stored as    %s\n", res.CalidusID, res.PoolBech, res.Nonce, name)
				fmt.Fprintf(w, "Put it on the chain with a payment of yours:\n  spo wallet send <payer> <payer> MIN --metadata-record %s\n", name)
				return nil
			})
		},
	}
	cmd.Flags().Uint64Var(&nonce, "nonce", 0, "registration nonce (default: the current slot)")
	addChainFlags(cmd, &cf, true)
	return cmd
}

func recordFileName(r ports.Ref) string { return r.Name + "." + string(r.Kind) }

func (a *app) calidusStatusCommand() *cobra.Command {
	var cf chainFlags
	cmd := &cobra.Command{
		Use:   "status <calidus-id|public-key|pool|name|all>",
		Short: "List the Calidus keys registered on chain for a pool or a key",
		Long: `Ask the chain provider which Calidus keys are registered. <subject> is a Calidus
id, a public key in hex, a pool id, the name of a stored Calidus key or pool, or
all. This needs a provider that reads CIP-88 registrations; see spo capabilities
(calidus-registrations).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.withEnv(cmd, envSpec{flags: &cf, config: true, needs: []Need{CapCalidusRead}}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				res, err := poolkey.QueryCalidus{Store: s.Store, Reader: env.CalidusReader}.Run(ctx, args[0])
				if err != nil {
					return err
				}
				w := a.d.Out
				if len(res.Entries) == 0 {
					fmt.Fprintf(w, "No Calidus key is registered for %s [%s].\n", args[0], env.CalidusReader.Source())
					return nil
				}
				fmt.Fprintf(w, "%d registration(s), %d Calidus key(s) [%s]\n", len(res.Entries), res.UniqueIDs, env.CalidusReader.Source())
				for _, e := range res.Entries {
					when := "-"
					if !e.BlockTime.IsZero() {
						when = e.BlockTime.UTC().Format(time.RFC3339)
					}
					fmt.Fprintf(w, "  pool %s\n    calidus id  %s\n    public key  %s\n    registered  %s\n", e.PoolBech, e.IDBech, e.PubKeyHex, when)
					if e.HasNonce {
						fmt.Fprintf(w, "    nonce       %d\n", e.Nonce)
					}
					if e.HasEpoch {
						fmt.Fprintf(w, "    epoch       %d\n", e.Epoch)
					}
					if e.TxHash != "" {
						fmt.Fprintf(w, "    transaction %s\n", e.TxHash)
					}
				}
				return nil
			})
		},
	}
	addChainFlags(cmd, &cf, false)
	return cmd
}

// ---- catalyst ----------------------------------------------------------------------------

func (a *app) catalystCommand() *cobra.Command {
	c := &cobra.Command{Use: "catalyst", Short: "Project Catalyst voting keys and CIP-36 registration"}
	key := &cobra.Command{Use: "key", Short: "Catalyst voting keys"}
	key.AddCommand(a.catalystKeyNewCommand())
	c.AddCommand(key, a.catalystRegisterCommand())
	return c
}

func (a *app) catalystKeyNewCommand() *cobra.Command {
	var o derivedKeyOptions
	var cf chainFlags
	cmd := &cobra.Command{
		Use:   "new <name> [--mnemonic-in-fd N] [--account N] [--index N]",
		Short: "Generate a Catalyst voting key from a mnemonic and print its public key",
		Long: `Derive the voting key (CIP-36) along 1694H/1815H/<account>H/0/<index> and store
<name>.voting.vkey, .skey, .pkey and .mnemonics sealed in the workspace.
--mnemonic-in-fd N reads the phrase from file descriptor N; without it a fresh
phrase is generated and stored, never shown. The signing key and the phrase are
never printed; the public key (cvote_vk) is.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fdSet := cmd.Flags().Changed("mnemonic-in-fd")
			if err := o.validate(fdSet, a.passFD); err != nil {
				return err
			}
			return a.withEnv(cmd, envSpec{flags: &cf, needs: derivedNeeds(fdSet, CapVotingKeys)}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				phrase, err := o.phrase(fdSet)
				if err != nil {
					return err
				}
				defer phrase.Destroy()
				req := catalyst.GenerateVotingKeyRequest{Name: args[0], Account: o.account, Index: o.index}
				if phrase != nil {
					req.Mnemonic = phrase
				}
				res, err := catalyst.GenerateVotingKey{Store: s.Store, Deriver: env.VotingKeys, Mnemonics: env.Mnemonics}.Run(ctx, req)
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Generated the voting key %s.\n  public key   %s\n", res.Name, res.PKey)
				a.mnemonicNotice(!fdSet)
				fmt.Fprintf(a.d.Out, "Delegate to it with: spo catalyst register <stake> <rewards> --vote-key %s\n", res.Name)
				return nil
			})
		},
	}
	o.add(cmd)
	addChainFlags(cmd, &cf, false)
	return cmd
}

// delegationWords turns `NAME[:WEIGHT]` flags into the delegation text of
// catalyst.ParseDelegation (`NAME WEIGHT|NAME WEIGHT`).
func delegationWords(voteKeys []string) (string, error) {
	if len(voteKeys) == 0 {
		return "", errors.New("--vote-key is required: NAME[:WEIGHT], repeatable")
	}
	parts := make([]string, 0, len(voteKeys))
	for _, v := range voteKeys {
		if strings.TrimSpace(v) == "" || strings.ContainsAny(v, "| \t") {
			return "", fmt.Errorf("--vote-key %q: write NAME or NAME:WEIGHT, one per flag", v)
		}
		ref, w, has := strings.Cut(v, ":")
		if ref == "" || (has && w == "") {
			return "", fmt.Errorf("--vote-key %q: write NAME or NAME:WEIGHT", v)
		}
		if has {
			parts = append(parts, ref+" "+w)
		} else {
			parts = append(parts, ref)
		}
	}
	return strings.Join(parts, "|"), nil
}

func (a *app) catalystRegisterCommand() *cobra.Command {
	var (
		voteKeys []string
		nonce    uint64
		purpose  uint64
		cf       chainFlags
	)
	cmd := &cobra.Command{
		Use:   "register <stake-name> <rewards-address|name> --vote-key NAME[:WEIGHT]... [--nonce N] [--purpose N]",
		Short: "Sign a Catalyst (CIP-36) registration with the stake key and store the metadata",
		Long: `Delegate the voting power of the stake account <stake-name> to the voting keys
given with --vote-key, and sign the registration with the stake key. A voting key
is the name of a stored key (spo catalyst key new), a public key in hex or a
cvote_vk text; WEIGHT defaults to 1. <rewards> is the payment address (or the
name of a stored address) that receives the Catalyst rewards.

The registration is stored in the workspace as <stake>_<time>.vote-registration.cbor
and nothing is submitted. A stake key on a hardware wallet is refused before
anything is built. --nonce defaults to the current slot of the work mode;
--purpose defaults to 0 (Catalyst). Put the registration on the chain with a
payment of yours:

  spo wallet send <payer> <payer> MIN --metadata-record <name printed here>

The QR code of the Catalyst mobile app is not built.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkNonce(cmd, nonce); err != nil {
				return err
			}
			delegation, err := delegationWords(voteKeys)
			if err != nil {
				return err
			}
			words, err := catalyst.ParseDelegation(delegation)
			if err != nil {
				return err
			}
			needs := []Need{CapSigners, CapSignatures, CapClock}
			return a.withEnv(cmd, envSpec{flags: &cf, needs: needs}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				uc := catalyst.GenerateRegistration{Store: s.Store, Signers: env.Signers, Clock: env.Clock, NetworkID: env.NetworkID}
				if env.Tip != nil {
					uc.Tip = env.Tip
				}
				res, err := uc.Run(ctx, catalyst.RegistrationRequest{Delegation: words, Stake: args[0], Rewards: args[1], Nonce: nonce, Purpose: purpose})
				if err != nil {
					if errors.Is(err, catalyst.ErrNoNonce) {
						return fmt.Errorf("%w (this mode has no current slot: pass --nonce N)", err)
					}
					return err
				}
				w := a.d.Out
				name := recordFileName(res.Ref)
				fmt.Fprintf(w, "Signed the Catalyst registration.\n  nonce        %d\n  rewards to   %s\n", res.Nonce, res.Rewards)
				for _, k := range res.Keys {
					fmt.Fprintf(w, "  vote key     %s  weight %d  (%s)\n", hex.EncodeToString(k.PublicKey[:]), k.Weight, k.Source)
				}
				fmt.Fprintf(w, "  stored as    %s\nPut it on the chain with a payment of yours:\n  spo wallet send <payer> <payer> MIN --metadata-record %s\n", name, name)
				return nil
			})
		},
	}
	cmd.Flags().StringArrayVar(&voteKeys, "vote-key", nil, "a voting key to delegate to, NAME[:WEIGHT] (repeatable; weight defaults to 1)")
	cmd.Flags().Uint64Var(&nonce, "nonce", 0, "registration nonce (default: the current slot)")
	cmd.Flags().Uint64Var(&purpose, "purpose", 0, "voting purpose (0 is Catalyst)")
	addChainFlags(cmd, &cf, true)
	return cmd
}
