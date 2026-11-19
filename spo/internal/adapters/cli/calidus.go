package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/app/catalyst"
	"github.com/mochipool/workbench/spo/internal/app/poolkey"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The Calidus pool key (CIP-151, upstream 15_calidusPoolKey) and Catalyst
// (CIP-36, upstream 09a_catalystVote). Neither command submits anything: the
// registration is stored in the workspace and attached to an ordinary payment
// with `spo wallet send ... --metadata-record NAME`. No command prints a
// signing key or a mnemonic. `catalyst key qrcode` draws the PIN-protected QR
// code of a voting key on a terminal (never to a file), the one command whose
// output is as secret as the key.

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
	c.AddCommand(a.calidusNewCommand(), a.calidusRegisterCommand(), a.calidusStatusCommand(), a.calidusSignCommand())
	return c
}

func (a *app) calidusNewCommand() *cobra.Command {
	var o derivedKeyOptions
	var hw hardwareFlags
	var cf chainFlags
	cmd := &cobra.Command{
		Use:   "new <name> [--mnemonic-in-fd N] [--account N] [--index N]",
		Short: "Generate a Calidus key from a mnemonic and print its id",
		Long: `Derive the Calidus key (CIP-151) along 1852H/1815H/<account>H/0/<index> from a
24-word phrase and store <name>.calidus.vkey, .skey, .mnemonics and .id sealed in
the workspace. --mnemonic-in-fd N reads the phrase from file descriptor N;
without it a fresh phrase is generated and stored, never shown. The signing
key and the phrase are never printed; the Calidus id and the public key are.

A Calidus key cannot be made on a hardware wallet: upstream suspends it until
CIP-151 has a dedicated derivation path (SPO-15-PRE-002), and --hardware says
so and does nothing. The pool cold key on a hardware wallet can still sign the
registration of a Calidus key kept in the workspace.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if hw.on {
				return poolkey.ErrHardwareCalidusSuspended
			}
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
	hw.add(cmd, 0)
	addChainFlags(cmd, &cf, false)
	return cmd
}

func (a *app) calidusRegisterCommand() *cobra.Command {
	var (
		nonce uint64
		yes   bool
		cf    chainFlags
	)
	cmd := &cobra.Command{
		Use:   "register-metadata <calidus-name> <pool> [--nonce N] [--yes]",
		Short: "Sign the Calidus registration with the pool cold key and store the metadata",
		Long: `Build the CIP-88 (version 2) registration of the Calidus key <calidus-name> for
<pool> and sign it with the pool's cold key. The metadata is stored in the
workspace as <pool>_<time>.calidus-registration.json; nothing is submitted.

A pool cold key on a hardware wallet (Ledger or Keystone; a Trezor is refused
before anything is built) signs it on the device with a CIP-8 message over the
hash of the payload. You are shown the hash the device will display and asked to
continue first; --yes answers that. The device's signature is checked against
the payload, the pool id and the cold key before anything is stored. When both a
cold signing key and a hardware signing file exist for the pool, the hardware
one is used (SPO-15-INV-002). ` + hardwareUntested + `

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
				uc.BeforeDevice = func(ctx context.Context, d poolkey.DeviceSigning) error {
					fmt.Fprintf(a.d.Out, "The pool cold key on the hardware wallet will sign this registration.\n  pool id        %s\n  Calidus id     %s\n  nonce          %d\n  hash on device %s\n", d.PoolBech, d.CalidusID, d.Nonce, d.DeviceHash)
					ok, err := a.confirm(ctx, "Sign the message with the pool cold key on the hardware wallet?", yes)
					if err != nil {
						return err
					}
					if !ok {
						return errors.New("declined: nothing was signed or stored")
					}
					a.noteDevice()
					return nil
				}
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
	cmd.Flags().BoolVar(&yes, "yes", false, "continue to the hardware wallet without asking (only when the cold key is on a device)")
	addChainFlags(cmd, &cf, true)
	return cmd
}

func recordFileName(r ports.NamedRef) string { return r.Name + "." + string(r.Kind) }

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
					fmt.Fprintf(w, "  pool %s\n    calidus id  %s\n    public key  %s\n    registered  %s\n", shown(e.PoolBech), shown(e.IDBech), shown(e.PubKeyHex), when)
					if e.HasNonce {
						fmt.Fprintf(w, "    nonce       %d\n", e.Nonce)
					}
					if e.HasEpoch {
						fmt.Fprintf(w, "    epoch       %d\n", e.Epoch)
					}
					if e.TxHash != "" {
						fmt.Fprintf(w, "    transaction %s\n", shown(e.TxHash))
					}
				}
				return nil
			})
		},
	}
	addChainFlags(cmd, &cf, false)
	return cmd
}

func (a *app) calidusSignCommand() *cobra.Command {
	var cf chainFlags
	cmd := &cobra.Command{
		Use:   "sign <calidus-name> <text>",
		Short: "Sign a text with the Calidus key",
		Long: `Sign <text> with the Calidus signing key <calidus-name> from the workspace and
print the Calidus id, the public key and the signature in hex. The signature is
a plain Ed25519 signature over the bytes of the text, not a CIP-8 message. A
Calidus key on a hardware wallet does not exist (see calidus new), so there is no
device variant. Nothing is written. Data that is not valid UTF-8 text, or that
is the signing input of a relay statement, is refused.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// refused before the workspace is unlocked (SPO-Xidentity-SEC-008)
			if err := ports.CheckSignableText([]byte(args[1])); err != nil {
				return err
			}
			return a.withEnv(cmd, envSpec{flags: &cf, needs: []Need{CapSigners, CapSignatures}}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				res, err := poolkey.SignWithCalidusKey{Store: s.Store, Signers: env.Signers}.Run(ctx, args[0], []byte(args[1]))
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Calidus id   %s\npublic key   %s\nsignature    %s\n", res.CalidusID, hex.EncodeToString(res.PublicKey[:]), res.SignatureHex)
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
	key.AddCommand(a.catalystKeyNewCommand(), a.catalystKeyQRCommand())
	c.AddCommand(key, a.catalystRegisterCommand())
	return c
}

func (a *app) catalystKeyNewCommand() *cobra.Command {
	var o derivedKeyOptions
	var hw hardwareFlags
	var cf chainFlags
	cmd := &cobra.Command{
		Use:   "new <name> [--mnemonic-in-fd N] [--account N] [--index N]",
		Short: "Generate a Catalyst voting key from a mnemonic and print its public key",
		Long: `Derive the voting key (CIP-36) along 1694H/1815H/<account>H/0/<index> and store
<name>.voting.vkey, .skey, .pkey and .mnemonics sealed in the workspace.
--mnemonic-in-fd N reads the phrase from file descriptor N; without it a fresh
phrase is generated and stored, never shown. The signing key and the phrase are
never printed; the public key (cvote_vk) is.

--hardware makes the key on a Ledger at the same path (the device's Cardano app
must be 6.0.3 or newer for it; Keystone and Trezor are refused before the device
is contacted) and stores only its public key and path: no signing key and no
phrase exist, so it has no QR code. ` + hardwareUntested,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fdSet := cmd.Flags().Changed("mnemonic-in-fd")
			if err := hw.validate(cmd); err != nil {
				return err
			}
			if hw.on {
				if fdSet {
					return errors.New("--hardware cannot be combined with --mnemonic-in-fd: a hardware key has no mnemonic")
				}
				if o.account > catalyst.MaxDerivationIndex || o.index > catalyst.MaxDerivationIndex {
					return catalyst.ErrDerivationRange
				}
			} else if err := o.validate(fdSet, a.passFD); err != nil {
				return err
			}
			needs := derivedNeeds(fdSet, CapVotingKeys)
			if hw.on {
				needs = []Need{CapHardware}
			}
			return a.withEnv(cmd, envSpec{flags: &cf, needs: needs}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				if hw.on {
					a.noteDevice()
					res, err := catalyst.GenerateVotingKey{Store: s.Store, Hardware: env.Hardware}.Run(ctx, catalyst.GenerateVotingKeyRequest{
						Name: args[0], Place: hw.place(), Account: o.account, Index: o.index})
					if err != nil {
						return err
					}
					fmt.Fprintf(a.d.Out, "Generated the voting key %s on the hardware wallet.\n  public key   %s\n", res.Name, res.PKey)
					fmt.Fprintf(a.d.Out, "Delegate to it with: spo catalyst register <stake> <rewards> --vote-key %s\n", res.Name)
					return nil
				}
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
	hw.add(cmd, 0)
	addChainFlags(cmd, &cf, false)
	return cmd
}

func (a *app) catalystKeyQRCommand() *cobra.Command {
	var (
		pinFD int
		yes   bool
		cf    chainFlags
	)
	cmd := &cobra.Command{
		Use:   "qrcode <name> [--pin-fd N] [--yes]",
		Short: "Show the PIN-protected QR code of a voting key on the terminal for the Catalyst mobile app",
		Long: `Encrypt the voting signing key <name> with a four-digit PIN and draw it as the
QR code the Catalyst mobile app scans to import the key. The code is drawn on
the terminal only: this program writes it to no file, because a four-digit PIN
protects the payload and four digits do not resist an offline guess (10,000
guesses). Standard output must be a terminal; a pipe or a redirect is refused
before anything is asked, and so is --yes there.

Before drawing, the command says that anyone who photographs or records the
screen can recover the key with at most 10,000 guesses, and asks for
confirmation (default no; --yes answers it, on a terminal only). The display is
recorded in the workspace's audit log first and is not made when the record
cannot be written. The drawing is on the terminal's alternate screen and the
screen is cleared when you press Enter, so it does not stay in the scrollback
(a terminal log, a recording or a shared screen can still hold it). The PIN is
read from a prompt, or from file descriptor N with --pin-fd; it is never an
argument.

The payload is the key encrypted with the PIN alone (PBKDF2-HMAC-SHA512,
ChaCha20-Poly1305, the format of the Catalyst toolbox, implemented from its
public source).

NOT VERIFIED against the mobile app: the format is built from the toolbox
source and checked against independently computed values and a round trip, but
no QR code made here has been scanned by the app. Scan one for a throw-away key
first. A voting key on a hardware wallet has no signing key and no QR code.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !stdoutIsTerminal(a.d.Out) {
				return errors.New("the QR code is drawn on a terminal only, and standard output is not one: this program writes it to no file, and --yes does not change that")
			}
			pinSet := cmd.Flags().Changed("pin-fd")
			if pinSet && pinFD < 0 {
				return errors.New("--pin-fd needs a file descriptor number")
			}
			if pinSet && a.passFD >= 0 && pinFD == a.passFD {
				return errors.New("--pin-fd and --passphrase-fd name the same descriptor")
			}
			if a.d.WorkspaceAuditor == nil {
				return errors.New("this build has no audit log, and the QR code is not shown without a record of it")
			}
			return a.withEnv(cmd, envSpec{flags: &cf, needs: []Need{CapVotingQR}}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				fmt.Fprintf(a.d.Out, "The QR code of the voting key %s is the key itself, protected by a four-digit PIN only.\nAnyone who photographs, records or shares this screen can recover the key with at most 10,000 guesses.\nThe display is recorded in the audit log.\n", textsafe.Text(args[0]))
				ok, err := a.confirm(ctx, "Draw the QR code on this terminal?", yes)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("not drawn: the QR code was not confirmed")
				}
				var pin *secret.Buffer
				if pinSet {
					pin, err = readFDSecret(pinFD, "the PIN")
				} else {
					pin, err = a.term.ReadSecret(ctx, "PIN for the QR code (four digits): ")
					if errors.Is(err, ErrNoTerminal) {
						return errors.New("no terminal to ask for the PIN on; give it on a file descriptor with --pin-fd N")
					}
				}
				if err != nil {
					return err
				}
				defer pin.Destroy()
				var res catalyst.QRExported
				err = pin.Use(func(b []byte) error {
					var rerr error
					res, rerr = catalyst.ExportVotingKeyQR{Store: s.Store, Source: env.VotingQR, Renderer: env.QRCodes,
						Auditor: a.d.WorkspaceAuditor(a.workspace, s.Store, "")}.Run(ctx, catalyst.QRRequest{Name: args[0], PIN: b})
					return rerr
				})
				if err != nil {
					return err
				}
				// The alternate screen keeps the drawing out of the scrollback; the
				// clear on the way out runs on every path.
				fmt.Fprint(a.d.Out, "\x1b[?1049h\x1b[2J\x1b[H")
				defer fmt.Fprint(a.d.Out, "\x1b[2J\x1b[?1049l")
				fmt.Fprintf(a.d.Out, "QR code of the voting key %s (the key, under a four-digit PIN)\n\n%s\nPress Enter to clear the screen.\n", textsafe.Text(res.Name), res.Terminal)
				if _, err := a.term.ReadLine(ctx, ""); err != nil {
					if errors.Is(err, ErrNoTerminal) {
						return errors.New("no terminal to wait on, so the screen was cleared at once; run the command on a terminal")
					}
					return err
				}
				return nil
			})
		},
	}
	cmd.Flags().IntVar(&pinFD, "pin-fd", -1, "read the four-digit PIN from this file descriptor (never from the command line)")
	cmd.Flags().BoolVar(&yes, "yes", false, "answer the confirmation (the code is drawn on a terminal only; this flag does not change that)")
	addChainFlags(cmd, &cf, false)
	return cmd
}

// stdoutIsTerminal reports whether w is a terminal. It is a variable so a test
// can stand in for one.
var stdoutIsTerminal = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
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
and nothing is submitted. A stake key on a Ledger (app 6.0.3 or newer; Keystone
and Trezor are refused before anything is built) signs on the device; when the
rewards address is the payment address of the same wallet, that key is handed to
the device too, so it does not warn of an unusual request. The device's
signature is checked against the registration before it is stored. --nonce
defaults to the current slot of the work mode; --purpose defaults to 0
(Catalyst). Put the registration on the chain with a payment of yours:

  spo wallet send <payer> <payer> MIN --metadata-record <name printed here>

The QR code of a voting key is made by spo catalyst key qrcode. ` + hardwareUntested + `
`,
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
					fmt.Fprintf(w, "  vote key     %s  weight %d  (%s)\n", hex.EncodeToString(k.PublicKey[:]), k.Weight, shown(fmt.Sprint(k.Source)))
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
