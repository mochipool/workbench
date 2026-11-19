package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/parties"
	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// RelayOps is the relay-identity stack the composition root builds (ADR 0014
// work package 8). This package names no signing port: the root gives it a
// relaybinding.Service already holding the vault's relay signer, and the device
// revoke as a function over the local identity.
type RelayOps struct {
	// Signing is the use case that signs relay statements, built over this
	// workspace's vault with the clock and the role-history source given. Nil
	// refuses every command that signs with a vault key.
	Signing func(clock ports.Clock, history func(context.Context, identity.Ref) (custody.RoleHistory, bool, error)) relaybinding.Service
	// SignDeviceRevoke signs the device-signed revoke of the local identity
	// through its typed method (relaybinding.Service.SignDeviceRevoke).
	SignDeviceRevoke func(ctx context.Context, svc relaybinding.Service, local ports.LocalIdentity, notBefore int64) (relaybinding.DeviceRevokeResult, error)
	// SendRevokes sends the pending revokes to every listed relay on revoke-only
	// connections (a mailbox.RevokeSender per relay, with no binding and no
	// signer) and returns each relay's own error by name; the book is told what
	// each relay recorded, with its name. Nil: revokes are stored and sent at the
	// next connection.
	SendRevokes func(ctx context.Context, c RelaySendConfig) (map[string]error, error)
	// Connect makes this device's client of every listed relay (one
	// mailbox.Client per relay over its tunnel, and mailbox.Multi over them).
	// Nil refuses --transport mailbox.
	Connect func(RelayConnectConfig) (RelayClient, error)
	// CheckAddress checks, without dialing, that a relay address leads to the
	// pinned node key. Nil refuses spo party relay add.
	CheckAddress func(e RelayEndpoint, nodeKey *secret.Buffer) error
}

// relayRemedy adds what to do to a refused identity (SPO-Xmailbox-OUT-099).
func relayRemedy(err error) error {
	if !errors.Is(err, ports.ErrIdentityRefused) {
		return err
	}
	return errors.Join(err, errors.New("the relay refuses this device's identity, and nothing is retried until you act: "+
		"if it refused the binding (invalid, expired or revoked), sign a new one with: spo party relay bind; "+
		"if it does not allow the wallet key, ask the relay's operator to allow it, or bind another key"))
}

// flushNote reports the error of one outbox run. A refused identity is told
// with its remedy once per command (told), not at every run of a loop: the
// client backs off by itself and asks no wallet for anything, and the operator
// acts once (SPO-Xmailbox-OUT-099). Any other error is told at every run.
func flushNote(w io.Writer, prefix string, err error, told *bool) {
	if errors.Is(err, ports.ErrIdentityRefused) {
		if !*told {
			fmt.Fprintf(w, "%s: %v\n", prefix, relayRemedy(err))
			*told = true
		}
		return
	}
	fmt.Fprintf(w, "%s: %v\n", prefix, err)
}

// history is the role-history source of this workspace's key index.
func (r *partyRun) history() func(context.Context, identity.Ref) (custody.RoleHistory, bool, error) {
	idx := labels.NewIndex(r.s.Anchored)
	return func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
		return ports.RoleHistoryOf(ctx, idx, id)
	}
}

// networkID is the workspace's network id: 1 on mainnet, 0 on the test networks.
func (r *partyRun) networkID() int {
	if r.o.Preset.Magic == "mainnet" {
		return 1
	}
	return 0
}

// relayCheck is the evidence check of a peer's binding (SPO-Xparty-PRE-008):
// the pools named in scopes are checked against the registry in the
// transaction, this workspace's own pool ids here.
func (r *partyRun) relayCheck() parties.RelayCheck {
	return parties.RelayCheck{History: r.history(), Network: r.networkID(), PoolIDs: r.ownPoolIDs}
}

// ownPoolIDs is the pool ids of this workspace's own pools: for each pool owner,
// its pool id record (56 hex), its bech32 pool id record and the hash of its
// cold verification key, whichever it has. A pool kept here only by its id has
// no role history of its cold key, so this is what stops that key hash from
// being taken as a payment or stake key (SPO-Xmailbox-SEC-075).
func (r *partyRun) ownPoolIDs(ctx context.Context) (map[[28]byte]bool, error) {
	names, err := labels.Named(r.s.Anchored).Names(ctx, identity.OwnerPool)
	if err != nil {
		return nil, err
	}
	out := map[[28]byte]bool{}
	err = r.s.Store.View(ctx, func(rd ports.NamedReader) error {
		get := func(name string, k ports.Kind) ([]byte, bool, error) {
			ref := ports.NamedRef{Name: name, Kind: k}
			if ref.Validate() != nil {
				return nil, false, nil
			}
			b, err := rd.Get(ref)
			if errors.Is(err, ports.ErrNotFound) {
				return nil, false, nil
			}
			return b, err == nil, err
		}
		for _, n := range names {
			if b, ok, err := get(n, ports.PoolIDFile); err != nil {
				return err
			} else if ok {
				if raw, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(raw) == 28 {
					out[[28]byte(raw)] = true
				}
			}
			if b, ok, err := get(n, ports.PoolIDBechFile); err != nil {
				return err
			} else if ok {
				if id, err := chain.ParsePoolBech32(strings.TrimSpace(string(b))); err == nil {
					out[[28]byte(id)] = true
				}
			}
			if b, ok, err := get(n, ports.NodeVKey); err != nil {
				return err
			} else if ok {
				if env, err := pool.ParseEnvelope(b); err == nil {
					if k32, err := env.Key32(); err == nil {
						out[[28]byte(txbuild.HashKey(k32))] = true
					}
				}
			}
		}
		return nil
	})
	return out, err
}

// knownPoolIDs is every pool id this workspace knows: its own and every pool
// named in the scope of an enrolled party.
func (r *partyRun) knownPoolIDs(ctx context.Context) (map[[28]byte]bool, error) {
	out, err := r.ownPoolIDs(ctx)
	if err != nil {
		return nil, err
	}
	err = r.s.Store.View(ctx, func(rd ports.NamedReader) error {
		ps, err := r.kit().Registry.List(rd)
		if err != nil {
			return err
		}
		for _, p := range ps {
			for _, s := range p.Scope.Pools {
				if id, err := chain.ParsePoolBech32(s); err == nil {
					out[[28]byte(id)] = true
				}
			}
		}
		return nil
	})
	return out, err
}

// signing is the relaybinding use case of this workspace.
func (r *partyRun) signing() (relaybinding.Service, error) {
	ops := r.kit().Relay
	if ops.Signing == nil {
		return relaybinding.Service{}, errors.New("this build cannot sign relay statements with a vault key")
	}
	return ops.Signing(r.env.Clock, r.history()), nil
}

// self is the relay-state use case of this device: it needs the local identity.
func (r *partyRun) self(ctx context.Context) (relayself.Service, error) {
	l, err := r.kit().Kit.Local(ctx)
	if err != nil {
		return relayself.Service{}, partyIdentityErr(err)
	}
	fp := l.Identity().Fingerprint()
	l.Destroy()
	sign, _ := r.signing() // a command that signs with the vault checks it itself
	if sign.Clock == nil {
		sign = relaybinding.Service{Clock: r.env.Clock, History: r.history()}
	}
	ops := r.kit().Relay
	svc := relayself.Service{Store: r.s.Store, Clock: r.env.Clock, Device: fp, Sign: sign, Send: r.relaySender(), PoolIDs: r.knownPoolIDs}
	if ops.SignDeviceRevoke != nil {
		svc.DeviceRevoke = func(ctx context.Context, nb int64) (relaybinding.DeviceRevokeResult, error) {
			l, err := r.kit().Kit.Local(ctx)
			if err != nil {
				return relaybinding.DeviceRevokeResult{}, err
			}
			defer l.Destroy()
			return ops.SignDeviceRevoke(ctx, sign, l, nb)
		}
	}
	return svc, nil
}

// readBindingFile reads a binding file of at most MaxBindingFileBytes, refusing
// a larger one before reading it all.
func readBindingFile(path string) (*parties.BindingEvidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, relayself.MaxBindingFileBytes+1))
	if err != nil {
		return nil, err
	}
	st, key, err := relayself.DecodeBindingFile(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &parties.BindingEvidence{Statement: st, Key: key}, nil
}

// printEvidence shows a binding as evidence next to the typed groups
// (SPO-Xparty-PR-007): the key hash, never the address bytes.
func printEvidence(w io.Writer, v parties.BindingView) {
	fmt.Fprintf(w, "  relay binding (evidence; it does not replace the groups you type)\n    wallet key  %s\n    signed for  %s\n    valid       %s to %s\n",
		v.WalletKeyHex(), v.Part, v.FromTime().Format(time.DateTime+" MST"), v.UntilTime().Format(time.DateTime+" MST"))
	if len(v.Shared) > 0 {
		fmt.Fprintf(w, "    the same wallet key is the relay identity of: %s\n", strings.Join(quoteAll(v.Shared), ", "))
	}
}

// decodeHexArg reads a hex argument of at most max bytes, the length checked
// before it is decoded.
func decodeHexArg(flag, s string, max int) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 2*max || len(s)%2 != 0 {
		return nil, fmt.Errorf("%s: want hex of 1 to %d bytes", flag, max)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: not hex", flag)
	}
	return b, nil
}

// parseDevice reads a device fingerprint: the grouped form of party show, or 40
// hexadecimal characters (the form a statement carries).
func parseDevice(s string) (party.Fingerprint, error) {
	if fp, err := party.ParseFingerprint(s); err == nil {
		return fp, nil
	}
	var fp party.Fingerprint
	b, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(s)))
	if err != nil || len(b) != len(fp) {
		return fp, fmt.Errorf("%q is not a device fingerprint: give the eight groups (spo party show) or 40 hexadecimal characters", s)
	}
	copy(fp[:], b)
	return fp, nil
}

// walletFlags say which wallet key signs: a payment or stake key of the vault
// by name, or an external wallet by --print then --import.
type walletFlags struct {
	key, role      string
	print, imp     bool
	wallet         string
	sign1, coseKey string
	lifetimeDays   int
}

func (f *walletFlags) add(cmd *cobra.Command, lifetime bool) {
	cmd.Flags().StringVar(&f.key, "key", "", "the name of a payment or stake key in this workspace's vault")
	cmd.Flags().StringVar(&f.role, "role", "payment", "the role of --key: payment or stake")
	cmd.Flags().BoolVar(&f.print, "print", false, "print the statement for an external wallet to sign (CIP-30 signData) and keep the request for ten minutes")
	cmd.Flags().StringVar(&f.wallet, "wallet", "", "with --print: the external wallet's key hash (56 hex) or address (hex) to sign for")
	cmd.Flags().BoolVar(&f.imp, "import", false, "import the external wallet's answer to the request printed last")
	cmd.Flags().StringVar(&f.sign1, "sign1", "", "with --import: the COSE_Sign1 the wallet returned, hex")
	cmd.Flags().StringVar(&f.coseKey, "cose-key", "", "with --import: the COSE_Key the wallet returned, hex")
	if lifetime {
		cmd.Flags().IntVar(&f.lifetimeDays, "lifetime-days", 0, "how long the binding is valid, 1 to 180 days (default 90)")
	}
}

// mode checks that exactly one way is chosen and its flags are complete.
func (f *walletFlags) mode() (string, error) {
	n := 0
	for _, b := range []bool{f.key != "", f.print, f.imp} {
		if b {
			n++
		}
	}
	switch {
	case n != 1:
		return "", errors.New("choose one of --key NAME (a vault key), --print --wallet HEX (an external wallet) or --import --sign1 HEX --cose-key HEX")
	case f.print && f.wallet == "":
		return "", errors.New("--print needs --wallet: the external wallet's key hash or address, hex")
	case !f.print && f.wallet != "":
		return "", errors.New("--wallet goes with --print")
	case f.imp && (f.sign1 == "" || f.coseKey == ""):
		return "", errors.New("--import needs --sign1 HEX and --cose-key HEX: the wallet's answer")
	case !f.imp && (f.sign1 != "" || f.coseKey != ""):
		return "", errors.New("--sign1 and --cose-key go with --import")
	case f.role != "payment" && f.role != "stake":
		return "", fmt.Errorf("--role %q: a relay wallet key is a payment or a stake key, never a cold key", f.role)
	case f.lifetimeDays < 0 || f.lifetimeDays > 180:
		return "", errors.New("--lifetime-days is 1 to 180 (0 is the default, 90)")
	case f.key != "":
		return "key", nil
	case f.print:
		return "print", nil
	}
	return "import", nil
}

func (f *walletFlags) lifetime() time.Duration { return time.Duration(f.lifetimeDays) * 24 * time.Hour }

// externalWallet reads --wallet: a 56-hex key hash, or an address in hex.
func (f *walletFlags) externalWallet() (relaybinding.ExternalWallet, error) {
	b, err := decodeHexArg("--wallet", f.wallet, relaybind.MaxAddressBytes)
	if err != nil {
		return relaybinding.ExternalWallet{}, err
	}
	if len(b) == relaybind.KeyHashSize {
		return relaybinding.ExternalWallet{KeyHash: relaybind.KeyHash(b)}, nil
	}
	return relaybinding.ExternalWallet{Address: b}, nil
}

func (f *walletFlags) answer() (sign1, key []byte, err error) {
	if sign1, err = decodeHexArg("--sign1", f.sign1, relaybind.MaxSign1Bytes); err != nil {
		return nil, nil, err
	}
	if key, err = decodeHexArg("--cose-key", f.coseKey, relaybind.MaxKeyBytes); err != nil {
		return nil, nil, err
	}
	return sign1, key, nil
}

// vaultKey resolves --key NAME --role R to the closed wallet key: the
// verification key of that name and role in the store, made into a key
// reference and through relaywallet.FromRef, which refuses every role but
// payment and stake (SPO-Xmailbox-SEC-074).
func (r *partyRun) vaultKey(ctx context.Context, name, role string) (relaywallet.WalletKey, error) {
	kind, crole := ports.AddrVKey, custody.RolePayment
	if role == "stake" {
		kind, crole = ports.StakingVKey, custody.RoleStake
	}
	var raw []byte
	err := r.s.Store.View(ctx, func(rd ports.NamedReader) error {
		var err error
		raw, err = rd.Get(ports.NamedRef{Name: name, Kind: kind})
		return err
	})
	if errors.Is(err, ports.ErrNotFound) {
		return relaywallet.WalletKey{}, fmt.Errorf("no %s key named %q in this workspace", role, name)
	}
	if err != nil {
		return relaywallet.WalletKey{}, err
	}
	env, err := pool.ParseEnvelope(raw)
	if err != nil {
		return relaywallet.WalletKey{}, err
	}
	k32, err := env.Key32()
	if err != nil {
		return relaywallet.WalletKey{}, err
	}
	h := txbuild.HashKey(k32)
	id, err := identity.NewRef(identity.KindKeyHash, h[:])
	if err != nil {
		return relaywallet.WalletKey{}, err
	}
	return relaywallet.FromRef(custody.KeyRef{Role: crole, Identity: id})
}

// confirmExternalKey checks an external wallet's key before anything is printed
// for it (no pool id this workspace knows, a history here of payment and stake
// only) and, for a key this workspace has no record of, asks the operator to
// type its role. Nothing here can show that such a key is not a pool cold key,
// so the operator states it. There is no flag for the answer, --yes does not
// give it, and with no terminal nothing is printed: the same rule as the typed
// fingerprint groups, because a wrong answer lets a cold key sign a relay
// statement (SPO-Xmailbox-SEC-075).
func (a *app) confirmExternalKey(ctx context.Context, svc relayself.Service, ext relaybinding.ExternalWallet) error {
	known, err := svc.CheckExternal(ctx, ext)
	if err != nil {
		return bindErr(err)
	}
	if known {
		return nil
	}
	k := ext.KeyHash
	if len(ext.Address) != 0 {
		k, _, _ = relaybind.KeyOfAddress(ext.Address)
	}
	fmt.Fprintf(a.d.Out, "This workspace has no record of the wallet key %x.\n"+
		"It MUST be a payment or a stake key. It must NEVER be a pool cold key (a pool id) or any other cold key:\n"+
		"a relay statement signed by a cold key shows the pool id to the relay and touches the cold device.\n", k[:])
	typed, err := a.term.ReadLine(ctx, "Type the role of this key, payment or stake, to go on: ")
	if errors.Is(err, ErrNoTerminal) {
		return errors.New("no terminal: the role of a key this workspace does not know is typed by the operator, and there is no flag for it. Nothing was printed")
	}
	if err != nil {
		return err
	}
	if t := strings.TrimSpace(typed); t != "payment" && t != "stake" {
		return errors.New("the key's role was not confirmed as payment or stake: nothing was printed")
	}
	return nil
}

// printPrepared shows what an external wallet must sign, with the device, the
// dates and the key spelled out for the operator to compare with the wallet's
// screen.
func printPrepared(w io.Writer, p relaybinding.Prepared, device party.Fingerprint) {
	fmt.Fprintf(w, "Sign this with the wallet whose key hash is %x.\n", p.WalletKey[:])
	fmt.Fprintf(w, "  payload (sign exactly this one line, not hashed):\n    %s\n  payload (hex)\n    %s\n  address to sign for (hex)\n    %s\n",
		p.PayloadText(), p.PayloadHex(), p.SignForHex())
	if p.Kind == relaybinding.PreparedBindingKind {
		fmt.Fprintf(w, "  device       %s (the payload names it as %x; it ends in ...%x)\n", device, device[:], device[len(device)-4:])
		fmt.Fprintf(w, "  valid        %s to %s\n", time.Unix(p.Binding.From, 0).UTC().Format(time.DateTime+" MST"), time.Unix(p.Binding.Until, 0).UTC().Format(time.DateTime+" MST"))
	} else {
		target := "every device of the key"
		if !p.Revoke.All {
			target = p.Revoke.Device.String()
		}
		fmt.Fprintf(w, "  revokes      %s\n  not before   %s\n", target, time.Unix(p.Revoke.NotBefore, 0).UTC().Format(time.DateTime+" MST"))
	}
	fmt.Fprintf(w, "If the wallet shows only hex, compare it with the payload hex above.\nThen, within %d minutes: the same command with --import --sign1 HEX --cose-key HEX\n", int(relaybinding.PreparedLifetime/time.Minute))
}

func (a *app) partyRelayCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "relay",
		Short: "This device's relay identity: the wallet key binding, revokes, and the relay identities of peers",
		Long: `A relay files mail by device and admits it by wallet key (ADR 0014). This device
is bound to a payment or stake key (never a cold key) by a binding the wallet
signs; peers record that wallet key when they enroll you with your binding.
The binding grants no authority: envelopes are still sealed to the device, and
a peer still enrolls you by the typed fingerprint groups.

The relays this device uses are listed with add, list and remove; spo party
relay login, spo party serve and spo party connect exchange over all of them
(the last two with --transport mailbox; logging out is the end of the command,
and in spo tui "Log out of relays" ends the login without closing the TUI). A revoke made here is stored, sent to
every listed relay at once when it can be, and sent again at every connection.`,
	}
	c.AddCommand(a.partyRelayBindCommand(), a.partyRelayStatusCommand(), a.partyRelayRevokeCommand(),
		a.partyRelayForgetCommand(), a.partyRelayPeerCommand(), a.partyRelayDropRevokeCommand(),
		a.partyRelayAddCommand(), a.partyRelayListCommand(), a.partyRelayRemoveCommand(), a.partyRelaySendRevokesCommand(),
		a.partyRelayLoginCommand())
	return c
}

// partyRelaySendRevokesCommand sends the pending revokes to every listed relay
// on revoke-only connections, which need no binding and sign nothing: how a
// revoke that a relay missed is completed after forget deleted the binding
// (SPO-Xmailbox-OUT-111).
func (a *app) partyRelaySendRevokesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "send-revokes",
		Short: "Send the pending revokes to every listed relay now (no binding needed)",
		Long: `Send every pending revoke to every listed relay now, on connections that carry
only revokes: they need no binding and sign nothing, so this works after forget
deleted the binding. It says, per relay, which revokes the relay has not
recorded yet, and fails while any is owed: a relay that has not recorded a
revoke keeps the revoked binding valid until it ends. Run it again until every
relay recorded them.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				svc, err := r.self(ctx)
				if err != nil {
					return err
				}
				st, err := svc.Status(ctx)
				if err != nil {
					return err
				}
				if len(st.Relays) == 0 {
					return errors.New("no relay is listed: add one with spo party relay add NAME --node-key HEX --address-file FILE")
				}
				if st.Pending == 0 {
					fmt.Fprintln(a.d.Out, "No revoke is waiting to be sent.")
					return nil
				}
				if svc.Send == nil {
					return errors.New("this build has no relay transport")
				}
				rep, err := svc.SendPending(ctx)
				if err != nil && rep.Relays == nil {
					return err
				}
				if err != nil {
					fmt.Fprintf(a.d.Err, "sending the revokes: %v\n", err)
				}
				fmt.Fprintln(a.d.Out, "Sent the pending revokes. At the relays:")
				if err := r.reportOwed(ctx, svc, "", rep.Relays); err != nil {
					return err
				}
				fmt.Fprintln(a.d.Out, "Every listed relay recorded every pending revoke. They are sent again on every connection until they end.")
				return nil
			})
		},
	}
}

// partyRelayDropRevokeCommand is the way out of a full revoke book: one named
// pending revoke is dropped after the operator confirms. A dropped revoke is
// not sent again, so there is no --yes and no default yes.
func (a *app) partyRelayDropRevokeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "drop-revoke ID",
		Short: "Stop sending one pending revoke (its ID is in spo party relay status)",
		Long: `Drop one revoke from the revokes waiting to be sent, to make room when the
book is full. A dropped revoke is not sent again: a relay that never got it keeps
the binding it revokes until that binding ends. It asks first, and there is no
flag that answers for you.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				svc, err := r.self(ctx)
				if err != nil {
					return err
				}
				s, err := svc.Status(ctx)
				if err != nil {
					return err
				}
				var v *relayself.RevokeView
				for i := range s.Revokes {
					if s.Revokes[i].ID == args[0] {
						v = &s.Revokes[i]
					}
				}
				if v == nil {
					return relayself.ErrNoRevoke
				}
				target := "every device of the wallet key " + hex.EncodeToString(v.WalletKey[:])
				if v.ByDevice || !v.All {
					target = "the device " + v.Device.String()
				}
				fmt.Fprintf(a.d.Out, "This revoke of %s is sent to every relay until %s. Dropped, it is not sent again.\n",
					target, time.Unix(v.Until, 0).UTC().Format(time.DateTime+" MST"))
				ok, err := a.askYes(ctx, "Drop it?") // no terminal: nothing is dropped
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("nothing was dropped")
				}
				if _, err := svc.DropRevoke(ctx, args[0]); err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Dropped the revoke %s.\n", args[0])
				return nil
			})
		},
	}
}

func (a *app) partyRelayBindCommand() *cobra.Command {
	var wf walletFlags
	cmd := &cobra.Command{
		Use:   "bind (--key NAME [--role payment|stake] | --print --wallet HEX | --import --sign1 HEX --cose-key HEX) [--lifetime-days N]",
		Short: "Bind this device to a wallet key: with a vault key, or print and import for an external wallet",
		Long: `Sign the binding "this device uses wallet key K at relays from T1 until T2" and
store it. With --key it is signed by a payment or stake key of this vault (its
role history must hold only payment and stake). With --print the exact one-line
payload is printed for an external wallet's CIP-30 signData (not hashed), with
the device and the dates spelled out to compare with the wallet's screen; the
request is kept ten minutes, and --import takes the wallet's COSE_Sign1 and
COSE_Key back and checks them strictly. A new binding replaces the old one;
renew before it ends (status warns 14 days ahead). Give it to peers with:
spo party export FILE --binding BFILE`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode, err := wf.mode()
			if err != nil {
				return err
			}
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				svc, err := r.self(ctx)
				if err != nil {
					return err
				}
				w := a.d.Out
				var res relaybinding.BindingResult
				switch mode {
				case "key":
					if _, err := r.signing(); err != nil {
						return err
					}
					k, err := r.vaultKey(ctx, wf.key, wf.role)
					if err != nil {
						return err
					}
					if res, err = svc.Bind(ctx, k, wf.lifetime()); err != nil {
						return bindErr(err)
					}
				case "print":
					ext, err := wf.externalWallet()
					if err != nil {
						return err
					}
					if err := a.confirmExternalKey(ctx, svc, ext); err != nil {
						return err
					}
					p, err := svc.PrintBinding(ctx, ext, wf.lifetime())
					if err != nil {
						return bindErr(err)
					}
					printPrepared(w, p, svc.Device)
					return nil
				case "import":
					s1, key, err := wf.answer()
					if err != nil {
						return err
					}
					got, err := svc.ImportBinding(ctx, s1, key)
					if err != nil {
						return bindErr(err)
					}
					res = got.BindingResult
					if !got.KnownToStore {
						fmt.Fprintln(w, "note: this workspace has no record of the wallet key; it lives in the external wallet.")
					}
				}
				fmt.Fprintf(w, "Bound this device to the wallet key %x.\n  valid  %s to %s\nGive it to the parties that enroll you: spo party export FILE --binding BFILE\n",
					res.WalletKey[:], time.Unix(res.Binding.From, 0).UTC().Format(time.DateTime+" MST"), time.Unix(res.Binding.Until, 0).UTC().Format(time.DateTime+" MST"))
				return nil
			})
		},
	}
	wf.add(cmd, true)
	return cmd
}

// bindErr says what to do about the refusals of a binding.
func bindErr(err error) error {
	var we *relaybinding.WaitError
	switch {
	case errors.As(err, &we):
		return fmt.Errorf("%w. Run the command again in %s; nothing was signed", err, we.Wait)
	case errors.Is(err, relayself.ErrNoPrepared):
		return err
	case errors.Is(err, relaybinding.ErrPreparedExpired):
		return fmt.Errorf("%w: run it with --print again and sign the new request", err)
	case errors.Is(err, relaywallet.ErrColdHistory), errors.Is(err, relaywallet.ErrOtherRoleHistory), errors.Is(err, relaywallet.ErrNoHistory),
		errors.Is(err, relayself.ErrPoolID):
		return fmt.Errorf("%w: bind a payment or stake key that was never anything else", err)
	}
	return err
}

func (a *app) partyRelayStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "This device's binding, its end, and the revokes waiting to be sent",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				svc, err := r.self(ctx)
				if err != nil {
					return err
				}
				s, err := svc.Status(ctx)
				if err != nil {
					return err
				}
				w := a.d.Out
				fmt.Fprintf(w, "device       %s\n", svc.Device)
				if b := s.Binding; b != nil {
					fmt.Fprintf(w, "wallet key   %x\nvalid        %s to %s\n", b.WalletKey[:],
						time.Unix(b.From, 0).UTC().Format(time.DateTime+" MST"), time.Unix(b.Until, 0).UTC().Format(time.DateTime+" MST"))
					switch {
					case s.Expired:
						fmt.Fprintln(w, "the binding has ENDED: no relay delivers to this device until you bind again (spo party relay bind)")
					case s.RenewDue:
						fmt.Fprintf(w, "renew now: %d day(s) left (spo party relay bind)\n", s.DaysLeft)
					default:
						fmt.Fprintf(w, "%d day(s) left\n", s.DaysLeft)
					}
				} else {
					fmt.Fprintln(w, "no binding: bind this device with spo party relay bind")
				}
				if f := s.Foreign; f != nil {
					fmt.Fprintf(a.d.Err, "NOTE: the stored binding was for the device %s (this workspace's identity before a rotation), wallet key %x, valid to %s.\n"+
						"  It is not this device's and is dropped at the next change. The old device is not revoked by this:\n"+
						"  revoke it with the wallet key: spo party relay revoke --device %x (--key NAME | --print --wallet HEX)\n",
						f.Device, f.WalletKey[:], time.Unix(f.Until, 0).UTC().Format(time.DateTime+" MST"), f.Device[:])
				}
				if s.ForeignPrepared {
					fmt.Fprintln(a.d.Err, "NOTE: a binding prepared for another device (before a rotation) was dropped; print a new one.")
				}
				fmt.Fprintf(w, "revokes waiting to be sent  %d (at most %d; %d of them only for forget, forget --lost and a rotation)\n",
					s.Pending, relayself.MaxPendingRevokes, relayself.ReservedRevokes)
				for _, v := range s.Revokes {
					target := "every device of wallet key " + hex.EncodeToString(v.WalletKey[:])
					switch {
					case v.ByDevice:
						target = "device " + v.Device.String() + " (signed by the device)"
					case !v.All:
						target = fmt.Sprintf("device %s of wallet key %x", v.Device, v.WalletKey[:])
					}
					fmt.Fprintf(w, "  %s  %s, not before %s, sent until %s\n", v.ID, target,
						time.Unix(v.NotBefore, 0).UTC().Format(time.DateTime+" MST"), time.Unix(v.Until, 0).UTC().Format(time.DateTime+" MST"))
					if len(s.Relays) > 0 {
						rec, owed := "none", "none"
						if len(v.RecordedAt) > 0 {
							rec = strings.Join(v.RecordedAt, ", ")
						}
						if len(v.OwedTo) > 0 {
							owed = strings.Join(v.OwedTo, ", ")
						}
						fmt.Fprintf(w, "      recorded at %s; NOT yet recorded at %s\n", rec, owed)
					}
				}
				if len(s.Owed) > 0 {
					fmt.Fprintln(w, "a relay that has not recorded a revoke keeps the revoked binding valid: send them with spo party relay send-revokes (no binding needed)")
				}
				if p := s.Prepared; p != nil {
					what := "binding"
					if p.Kind == relaybinding.PreparedRevokeKind {
						what = "revoke"
					}
					fmt.Fprintf(w, "a %s is prepared for an external wallet until %s\n", what, time.Unix(p.ExpiresAt, 0).UTC().Format(time.DateTime+" MST"))
				}
				return nil
			})
		},
	}
}

func (a *app) partyRelayRevokeCommand() *cobra.Command {
	var (
		wf     walletFlags
		device string
		all    bool
	)
	cmd := &cobra.Command{
		Use:   "revoke (--device FINGERPRINT | --all) (--key NAME [--role R] | --print --wallet HEX | --import --sign1 HEX --cose-key HEX)",
		Short: "Revoke a device of a wallet key, or all of them, with that wallet key",
		Long: `Make a wallet-signed revoke of one device (--device, the eight groups or 40 hex)
or of every device of the key (--all), dated now, and keep it to send to every
relay on every connection until the revoked binding ends. A relay deletes a
binding the revoke invalidates and the mail queued for that device.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode, err := wf.mode()
			if err != nil {
				return err
			}
			target, err := revokeTarget(device, all, mode != "import")
			if err != nil {
				return err
			}
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				return a.walletRevoke(ctx, r, &wf, mode, target, nil)
			})
		},
	}
	wf.add(cmd, false)
	cmd.Flags().StringVar(&device, "device", "", "the device fingerprint to revoke")
	cmd.Flags().BoolVar(&all, "all", false, "revoke every device of the wallet key")
	return cmd
}

func revokeTarget(device string, all, needed bool) (relaybinding.RevokeTarget, error) {
	switch {
	case !needed && (device != "" || all):
		return relaybinding.RevokeTarget{}, errors.New("--import takes the device from the request printed last: give neither --device nor --all")
	case !needed:
		return relaybinding.RevokeTarget{}, nil
	case (device == "") == !all:
		return relaybinding.RevokeTarget{}, errors.New("give exactly one of --device FINGERPRINT and --all")
	case all:
		return relaybinding.RevokeTarget{All: true}, nil
	}
	fp, err := parseDevice(device)
	return relaybinding.RevokeTarget{Device: fp}, err
}

// walletRevoke makes a wallet-signed revoke in one of the three ways and stores
// it. lost is the device of forget --lost (nil for revoke): its revoke is of
// exactly that device, may use the reserved places of the book, and is sent.
func (a *app) walletRevoke(ctx context.Context, r *partyRun, wf *walletFlags, mode string, target relaybinding.RevokeTarget, lost *party.Fingerprint) error {
	svc, err := r.self(ctx)
	if err != nil {
		return err
	}
	if lost != nil && *lost == svc.Device {
		return relayself.ErrSelf
	}
	if lost != nil && mode != "print" && a.relaySessionBusy() && !a.relaySessionLive() {
		// its revoke is sent at once: not while the TUI's session is logging in,
		// logging out or stuck, and nothing is stored then (SPO-Xmailbox-OUT-120)
		return errSessionBusy
	}
	w := a.d.Out
	var got relayport.Revoke
	switch mode {
	case "key":
		if _, err := r.signing(); err != nil {
			return err
		}
		k, err := r.vaultKey(ctx, wf.key, wf.role)
		if err != nil {
			return err
		}
		if lost != nil {
			rep, err := svc.ForgetLost(ctx, k, *lost)
			return a.reportLost(ctx, r, svc, rep, err)
		}
		if got, err = svc.RevokeWallet(ctx, k, target); err != nil {
			return bindErr(err)
		}
	case "print":
		ext, err := wf.externalWallet()
		if err != nil {
			return err
		}
		if err := a.confirmExternalKey(ctx, svc, ext); err != nil {
			return err
		}
		var p relaybinding.Prepared
		if lost != nil {
			p, err = svc.PrintLost(ctx, ext, *lost)
		} else {
			p, err = svc.PrintRevoke(ctx, ext, target)
		}
		if err != nil {
			return bindErr(err)
		}
		printPrepared(w, p, svc.Device)
		return nil
	case "import":
		s1, key, err := wf.answer()
		if err != nil {
			return err
		}
		if lost != nil {
			if _, err := svc.ImportLost(ctx, *lost, s1, key); err != nil {
				return bindErr(err)
			}
			rep, err := svc.SendPending(ctx)
			return a.reportLost(ctx, r, svc, rep, err)
		}
		if got, err = svc.ImportRevoke(ctx, s1, key); err != nil {
			return bindErr(err)
		}
	}
	until := time.Unix(got.Until, 0).UTC().Format(time.DateTime + " MST")
	if a.relaySessionLive() {
		fmt.Fprintf(w, "Stored the revoke. The relay session sends it within seconds, and again on every connection until %s.\n", until)
		return nil
	}
	// a running login or serve of this workspace follows the store and sends a
	// new revoke at once (SPO-Xmailbox-OUT-111); nothing else dials here
	fmt.Fprintf(w, "Stored the revoke. A relay login or serve running for this workspace sends it within seconds; otherwise it goes at the next relay connection, or now with spo party relay send-revokes. It is sent again on every connection until %s.\n", until)
	return nil
}

// reportLost says what forget --lost did once its revoke is stored: per listed
// relay, whether it recorded every pending revoke (SPO-Xmailbox-OUT-111).
func (a *app) reportLost(ctx context.Context, r *partyRun, svc relayself.Service, rep relayself.SendReport, err error) error {
	w := a.d.Out
	switch {
	case errors.Is(err, relayself.ErrNoSender):
		fmt.Fprintln(w, "Stored the revoke. No relay is configured here: it goes with the next relay connection, on every connection until the revoked binding ends.")
		return nil
	case err != nil && rep.Relays == nil:
		return bindErr(err)
	}
	fmt.Fprintln(w, "Stored and sent. At the relays:")
	return r.reportOwed(ctx, svc, "", rep.Relays)
}

func (a *app) partyRelayForgetCommand() *cobra.Command {
	var (
		wf   walletFlags
		lost string
		yes  bool
		as   string
	)
	cmd := &cobra.Command{
		Use:         "forget [--yes] [--as coordinator|signer] | forget --lost DEVICE (--key NAME [--role R] | --print --wallet HEX | --import --sign1 HEX --cose-key HEX)",
		Annotations: map[string]string{uihint.RelaySession: uihint.RelayForget},
		Short:       "Revoke this device at relays and delete its binding, or revoke a lost device with the wallet key",
		Long: `Without --lost: revoke THIS device with its own key (dated now), keep the revoke
to send to every relay, and delete this device's binding, so a new login needs
a new binding. A relay deletes the queue of a revoked device, so when relays
are listed this logs in first, fetches and handles what waits there (as the
coordinator or the signer of this machine; --as when it is both), then stores
and sends the revoke, logs out, and deletes the binding last. It asks first.

With --lost DEVICE: revoke ANOTHER device of your wallet key (a lost or stolen
one) with the wallet key, and send it from this device without logging in.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if lost == "" {
				if wf.key != "" || wf.print || wf.imp {
					return errors.New("--key, --print and --import go with --lost DEVICE; this device revokes itself with its own key")
				}
				return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
					// it logs in, or dials revoke-only connections: refused before
					// anything is stored while the TUI's session is busy
					// (SPO-Xmailbox-OUT-120; the TUI logs a logged-in session out first)
					if err := a.refuseBusy(); err != nil {
						return err
					}
					ok, err := a.confirm(ctx, "Revoke this device at relays and delete its binding?", yes)
					if err != nil {
						return err
					}
					if !ok {
						return errors.New("nothing was revoked")
					}
					svc, err := r.self(ctx)
					if err != nil {
						return err
					}
					if svc.DeviceRevoke == nil {
						return errors.New("this build cannot sign a revoke with the device key")
					}
					st, err := svc.Load(ctx)
					if err != nil {
						return err
					}
					relays, err := relayself.Relays(ctx, r.s.Store)
					if err != nil {
						return err
					}
					until := func(got relayport.Revoke) string {
						return time.Unix(got.Until, 0).UTC().Format(time.DateTime + " MST")
					}
					if st.Binding != nil && len(relays) > 0 && r.kit().Relay.Connect != nil {
						h, err := r.forgetHandler(ctx, as)
						if err != nil {
							return err
						}
						got, errs, err := r.relayForget(ctx, h)
						if err != nil {
							return bindErr(err)
						}
						fmt.Fprintln(a.d.Out, "Stored this device's revoke, logged out and deleted its binding. At the relays:")
						if err := r.reportOwed(ctx, svc, relayself.ShortID(got), errs); err != nil {
							return err
						}
						fmt.Fprintf(a.d.Out, "Revoked this device at every listed relay. The revoke is sent again on every connection until %s.\n", until(got))
						return nil
					}
					got, err := svc.Forget(ctx)
					if err != nil {
						return bindErr(err)
					}
					if len(relays) == 0 {
						fmt.Fprintf(a.d.Out, "Revoked this device and deleted its binding. No relay is listed: the revoke is sent to every relay on every connection until %s.\n", until(got))
						return nil
					}
					fmt.Fprintln(a.d.Out, "Stored this device's revoke and deleted its binding. At the relays:")
					rep, err := svc.SendPending(ctx)
					if err != nil && !errors.Is(err, relayself.ErrNoSender) {
						fmt.Fprintf(a.d.Err, "sending the revoke: %v\n", err)
					}
					if err := r.reportOwed(ctx, svc, relayself.ShortID(got), rep.Relays); err != nil {
						return err
					}
					fmt.Fprintf(a.d.Out, "Revoked this device at every listed relay. The revoke is sent again on every connection until %s.\n", until(got))
					return nil
				})
			}
			mode, err := wf.mode()
			if err != nil {
				return err
			}
			// the device is named in every mode: --import takes only a prepared
			// revoke of exactly that device
			fp, err := parseDevice(lost)
			if err != nil {
				return err
			}
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				return a.walletRevoke(ctx, r, &wf, mode, relaybinding.RevokeTarget{Device: fp}, &fp)
			})
		},
	}
	wf.add(cmd, false)
	cmd.Flags().StringVar(&lost, "lost", "", "revoke this other device of your wallet key (the eight groups or 40 hex)")
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask")
	cmd.Flags().StringVar(&as, "as", "", "which role handles the relays' queue first, when this machine is both: coordinator or signer")
	return cmd
}

func (a *app) partyRelayPeerCommand() *cobra.Command {
	var (
		file  string
		clear bool
		yes   bool
	)
	cmd := &cobra.Command{
		Use:   "peer NAME (--binding FILE | --clear [--yes])",
		Short: "Record or remove the relay identity (wallet key) of an enrolled party",
		Long: `Record the binding NAME gave you (it bound its device to another wallet key, or
you enrolled it without one). The binding is checked and shown as evidence, and
you type the FIRST FOUR groups of NAME's fingerprint again, read out by its
operator; there is no flag for them. --clear removes the relay identity: NAME
is then reachable by file or a direct connection only.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (file == "") == !clear {
				return errors.New("give exactly one of --binding FILE and --clear")
			}
			var ev *parties.BindingEvidence
			if file != "" {
				var err error
				if ev, err = readBindingFile(file); err != nil {
					return err
				}
			}
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				k := r.kit()
				if k.SetRelay == nil {
					return errors.New("this build cannot record relay identities")
				}
				cur, err := r.byName(ctx, args[0])
				if err != nil {
					return err
				}
				uc := parties.SetPeerRelay{Store: r.s.Store, Registry: k.Registry, SetRelay: k.SetRelay, Clock: r.env.Clock, Relay: r.relayCheck()}
				w := a.d.Out
				if clear {
					ok, err := a.confirm(ctx, fmt.Sprintf("Remove the relay identity of %s?", cur.Name), yes)
					if err != nil {
						return err
					}
					if !ok {
						return errors.New("nothing changed")
					}
					if _, err := uc.Run(ctx, cur.Name, cur.Fingerprint.String()[:19], nil); err != nil {
						return err
					}
					fmt.Fprintf(w, "%s has no relay identity now; it is reachable by file or a direct connection only.\n", cur.Name)
					return nil
				}
				// the evidence is checked and shown before anything is typed
				_, v, err := r.relayCheck().CheckRotationBinding(ctx, r.s.Store, k.Registry, cur.Fingerprint, ev, r.env.Clock.Now())
				if err != nil {
					return err
				}
				fmt.Fprintf(w, "The relay identity of %s\n", strconv.Quote(cur.Name))
				printEvidence(w, v)
				fmt.Fprintf(w, "  last four groups of the fingerprint  %s\n", cur.Fingerprint.Tail())
				typed, err := a.term.ReadLine(ctx, fmt.Sprintf("Type the first %d groups: ", party.ConfirmGroups))
				if errors.Is(err, ErrNoTerminal) {
					return errors.New("no terminal: the first four groups of the fingerprint are typed by the operator, and there is no flag for them. Nothing changed")
				}
				if err != nil {
					return err
				}
				if _, err := uc.Run(ctx, cur.Name, typed, ev); err != nil {
					if errors.Is(err, party.ErrConfirmation) {
						return errors.New("the groups you typed are not the first four groups of that party's fingerprint: nothing changed")
					}
					return err
				}
				fmt.Fprintf(w, "Recorded the wallet key %s for %s.\n", v.WalletKeyHex(), cur.Name)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&file, "binding", "", "the binding file the party gave (spo party export FILE --binding BFILE)")
	cmd.Flags().BoolVar(&clear, "clear", false, "remove the party's relay identity")
	cmd.Flags().BoolVar(&yes, "yes", false, "with --clear: do not ask")
	return cmd
}
