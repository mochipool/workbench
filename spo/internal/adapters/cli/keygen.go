package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// poolKeysCommand is `pool keys`: the cold key pair and its issue counter.
func (a *app) poolKeysCommand() *cobra.Command {
	keys := &cobra.Command{Use: "keys", Short: "Pool cold keys"}
	var hw hardwareFlags
	gen := &cobra.Command{
		Use:   "generate <pool> [--hardware [--index N]]",
		Short: "Generate the cold key pair and the operational certificate issue counter",
		Long: `Generate the pool's cold key pair and its issue counter at 0. The signing key
goes into the workspace and is never shown; the pool id is printed.

--hardware makes the cold key on a Ledger or Keystone hardware wallet instead
(Trezor cannot hold a pool cold key and is refused before the device is asked
anything); --index N selects its derivation path 1853H/1815H/0H/<N>H. Only the
hardware signing file (a public key and its path) is stored. ` + hardwareUntested,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := hw.validate(cmd, "index"); err != nil {
				return err
			}
			needs := []Need{CapColdKeys}
			if hw.on {
				needs = []Need{CapHardware}
			}
			return a.withEnv(cmd, envSpec{needs: needs}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				req := poolops.GenerateColdKeysRequest{Pool: args[0], Holder: hw.holder(), Index: hw.index}
				if hw.on {
					a.noteDevice()
				}
				res, err := poolops.GenerateColdKeys{Store: s.Store, KeyGen: env.ColdKeys, Hardware: env.Hardware}.Run(ctx, req)
				if err != nil {
					return err
				}
				where := ""
				if hw.on {
					where = " on the hardware wallet"
				}
				fmt.Fprintf(a.d.Out, "Generated the cold keys%s and the issue counter of pool %s.\n", where, res.Pool)
				fmt.Fprintf(a.d.Out, "Pool id (hex)    %x\nPool id (bech32) %s\n", res.PoolID[:], res.PoolID.Bech32())
				return nil
			})
		},
	}
	hw.add(gen, hwIndex)
	keys.AddCommand(gen)
	return keys
}

// vrfCommand is `pool vrf`.
func (a *app) vrfCommand() *cobra.Command {
	vrf := &cobra.Command{Use: "vrf", Short: "Pool VRF keys"}
	vrf.AddCommand(&cobra.Command{
		Use:   "generate <pool>",
		Short: "Generate the VRF key pair",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.withEnv(cmd, envSpec{needs: []Need{CapVrfKeys}}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				res, err := poolops.GenerateVrfKeys{Store: s.Store, KeyGen: env.VrfKeys}.Run(ctx, poolops.GenerateVrfKeysRequest{Pool: args[0]})
				if err != nil {
					return err
				}
				// The verification key is public. The signing key is never shown.
				fmt.Fprintf(a.d.Out, "Generated the VRF keys of pool %s.\n%s\n", res.Pool, res.VKey)
				return nil
			})
		},
	})
	return vrf
}

// walletNewOptions are the flags of `wallet new`.
type walletNewOptions struct {
	stake, mnemonic bool
	mnemonicFD      int
	account, index  uint32
}

// validate rejects the combinations the use cases reject, before anything
// is opened. It also settles what the flags imply.
func (o *walletNewOptions) validate(fdSet bool, passFD int) error {
	if o.mnemonic && fdSet {
		return errors.New("--mnemonic and --mnemonic-in-fd are exclusive: generate a phrase or give one")
	}
	if fdSet && o.mnemonicFD < 0 {
		return errors.New("--mnemonic-in-fd needs a file descriptor number")
	}
	if fdSet && passFD >= 0 && o.mnemonicFD == passFD {
		return errors.New("--mnemonic-in-fd and --passphrase-fd name the same descriptor")
	}
	derived := o.mnemonic || fdSet
	if derived {
		o.stake = true // a mnemonic wallet always has a stake key
	}
	if !derived && (o.account != 0 || o.index != 0) {
		return fmt.Errorf("%w: --account and --index select the derivation path of a mnemonic wallet; add --mnemonic or --mnemonic-in-fd", wallet.ErrOptionNotUsed)
	}
	if o.account > wallet.MaxDerivationIndex || o.index > wallet.MaxDerivationIndex {
		return wallet.ErrDerivationRange
	}
	return nil
}

func (a *app) walletNewCommand() *cobra.Command {
	var o walletNewOptions
	var hw hardwareFlags
	cmd := &cobra.Command{
		Use:   "new <name> [--stake] [--mnemonic | --mnemonic-in-fd N] [--account N] [--index N] [--hardware [--multisig] [--hybrid]]",
		Short: "Create a wallet: a payment key and address, optionally with a stake key",
		Long: `Create a wallet in the workspace. Without --stake it is a payment key and its
enterprise address. With --stake it is a payment and a stake key, the base
address and the stake address, from random keys.

--mnemonic derives the keys (CIP-1852, --account and --index select the path)
from a fresh 24-word phrase; --mnemonic-in-fd N derives them from a phrase read
from file descriptor N. Both imply --stake. The phrase is never taken from the
command line or the environment, and a generated phrase is stored sealed in the
workspace and not shown. Signing keys are never shown.

--hardware makes the payment key (and with --stake the stake key) on a hardware
wallet, at the path --account and --index select; --multisig uses the
multi-signature purpose 1854H for the payment key; --hybrid, with --stake, keeps
the stake key in the workspace. Hardware keys have no mnemonic. ` + hardwareUntested,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fdSet := cmd.Flags().Changed("mnemonic-in-fd")
			if err := hw.validate(cmd); err != nil {
				return err
			}
			if hw.on && (o.mnemonic || fdSet) {
				return errors.New("--hardware cannot be combined with --mnemonic or --mnemonic-in-fd: a hardware key has no mnemonic")
			}
			if hw.hybrid && !o.stake {
				return errors.New("--hybrid is for a wallet with a stake key: add --stake")
			}
			if !hw.on {
				if err := o.validate(fdSet, a.passFD); err != nil {
					return err
				}
			}
			needs := []Need{CapAddressMake}
			switch {
			case hw.on:
				needs = append(needs, CapHardware)
				if hw.hybrid {
					needs = append(needs, CapStakeKeys)
				}
			case o.mnemonic:
				needs = append(needs, CapMnemonics, CapDeriver)
			case fdSet:
				needs = append(needs, CapDeriver)
			case o.stake:
				needs = append(needs, CapPaymentKeys, CapStakeKeys)
			default:
				needs = append(needs, CapPaymentKeys)
			}
			return a.withEnv(cmd, envSpec{needs: needs}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				if hw.on {
					a.noteDevice()
				}
				if !o.stake {
					res, err := wallet.GeneratePaymentAccount{
						Store: s.Store, KeyGen: env.PaymentKeys, Addresses: env.Addresses, NetworkID: env.NetworkID, Hardware: env.Hardware,
					}.Run(ctx, wallet.GeneratePaymentRequest{Name: args[0], Holder: hw.holder(), Account: o.account, Index: o.index, Multisig: hw.multisig})
					if err != nil {
						return err
					}
					fmt.Fprintf(a.d.Out, "Created wallet %s.\nAddress %s\n", res.Name, res.Address)
					return nil
				}
				req := wallet.GenerateWalletRequest{Name: args[0], Source: wallet.WalletKeysRandom}
				if hw.on {
					req.Holder, req.Multisig, req.Account, req.Index = hw.holder(), hw.multisig, o.account, o.index
					if hw.hybrid {
						req.StakeHolder = custody.HolderVault
					}
				}
				if o.mnemonic || fdSet {
					req.Source, req.Account, req.Index = wallet.WalletKeysMnemonic, o.account, o.index
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
				uc := wallet.GenerateWalletAccount{
					Store: s.Store, Payment: env.PaymentKeys, Stake: env.StakeKeys, Mnemonics: env.Mnemonics,
					Deriver: env.WalletDeriver, Addresses: env.Addresses, NetworkID: env.NetworkID, Hardware: env.Hardware,
				}
				res, err := uc.Run(ctx, req)
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Created wallet %s.\nPayment address %s\nStake address   %s\n", res.Name, res.PaymentAddress, res.StakeAddress)
				if res.MnemonicStored && !fdSet {
					fmt.Fprintf(a.d.Out, "\nThe recovery phrase was generated and is stored sealed in the workspace. It is not shown.\n"+
						"The command that displays it does not exist yet (the audited export is not built), so\n"+
						"until then this wallet can be recovered only from a backup of the workspace.\n")
				}
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.stake, "stake", false, "also create a stake key, the base address and the stake address")
	f.BoolVar(&o.mnemonic, "mnemonic", false, "derive the keys from a freshly generated 24-word mnemonic (implies --stake)")
	f.IntVar(&o.mnemonicFD, "mnemonic-in-fd", -1, "derive the keys from a mnemonic read from this file descriptor (implies --stake)")
	f.Uint32Var(&o.account, "account", 0, "account number of the derivation path (mnemonic and hardware wallets)")
	f.Uint32Var(&o.index, "index", 0, "address index of the derivation path (mnemonic and hardware wallets)")
	hw.add(cmd, hwMultisig|hwHybrid)
	return cmd
}
