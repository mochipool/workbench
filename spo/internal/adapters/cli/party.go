package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/parties"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// partyRun is what a party command runs in: the open sealed workspace, its
// Env and the stack the composition root built.
type partyRun struct {
	a   *app
	s   *session
	env *Env
	o   WireOptions
	// cleanups run when the command ends (private copies of a snapshot).
	cleanups []func()
	// gateNote is what the passphrase prompt says about the request being
	// approved: its id prefix and its net.
	gateNote string
}

func (r *partyRun) kit() *PartyKit { return r.env.Party }

// vault is the store as the vault that releases the keys. A sealed workspace
// is both.
func (r *partyRun) vault() (ports.NamedVault, error) {
	v, ok := r.s.Store.(ports.NamedVault)
	if !ok {
		return nil, errors.New("this workspace's store cannot release keys to a signer")
	}
	return v, nil
}

// node is the wiring both roles share. Offline mode has no network transport
// (SPO-Xparty-MODE-001).
func (r *partyRun) node() multisig.Node {
	k := r.kit()
	return multisig.Node{Store: r.s.Store, Parties: k.Registry, Replay: k.Replay, Kit: k.Kit, Viewer: r.env.TxViewer, Clock: r.env.Clock,
		Chain: multisig.Chain{Tip: r.env.Tip, Genesis: r.env.Genesis}, Offline: r.o.Mode == ModeOffline}
}

// coordinator is the coordinator role. Complete is left nil on purpose: a
// complete collection is finished by `spo pool register`, which asks the
// operator before the transaction goes out; a response that arrives never
// triggers a prompt or a submission by itself.
func (r *partyRun) coordinator() (multisig.Coordinator, error) {
	magic, err := networkMagic(r.o)
	if err != nil {
		return multisig.Coordinator{}, err
	}
	c := multisig.Coordinator{Node: r.node(), TxIDs: r.env.TxIDs, NetworkMagic: magic}
	idx := labels.NewIndex(r.s.Anchored)
	c.History = func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
		return ports.RoleHistoryOf(ctx, idx, id)
	}
	return c, nil
}

// party runs fn with the sealed workspace open. The needs are checked, and the
// refusal of --upstream-layout made, before the passphrase is asked for.
func (a *app) party(cmd *cobra.Command, cf *chainFlags, needs []Need, fn func(ctx context.Context, r *partyRun) error) error {
	spec := envSpec{flags: cf, sealed: true, needs: append([]Need{CapParty}, needs...)}
	return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, o WireOptions) error {
		r := &partyRun{a: a, s: s, env: env, o: o}
		defer func() {
			for _, c := range r.cleanups {
				c()
			}
		}()
		return fn(ctx, r)
	})
}

func (a *app) partyCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "party",
		Short: "Multi-party signing: identities, enrollment and signing requests",
		Long: `Several people sign one transaction (a pool registration with more than one
owner is the reference case) without passing unauthenticated files around.
Every message is an envelope: encrypted to its recipient and signed by its
sender. Each machine has an identity, and enrolls the others after the
operators compare fingerprints over another channel. See docs/reference/spo-cli.md,
"Multi-party signing".

All of it needs a sealed workspace.`,
	}
	c.AddCommand(a.partyInitCommand(), a.partyShowCommand(), a.partyExportCommand(), a.partyEnrollCommand(), a.partyListCommand(),
		a.partyRevokeCommand(), a.partyScopeCommand(), a.partyEventsCommand(), a.partyRotateCommand(), a.partyRotationCommand(),
		a.partyRequestCommand(), a.partyInboxCommand(), a.partyOutboxCommand(),
		a.partyRequestsCommand(), a.partyReviewCommand(), a.partyApproveCommand(), a.partyRefuseCommand(),
		a.partyServeCommand(), a.partyConnectCommand(), a.partyRelayCommand())
	return c
}

// ---- init, show, export ------------------------------------------------------------

func (a *app) partyInitCommand() *cobra.Command {
	var label string
	var withNode bool
	cmd := &cobra.Command{
		Use:   "init [--label TEXT] [--tailcat]",
		Short: "Create this workspace's party identity",
		Long: `Create the identity this workspace uses to exchange envelopes: an Ed25519 key
that signs and an X25519 key that decrypts, both kept in the sealed store, and
a signed public identity document. Print its fingerprint (eight groups of four
characters). Whoever enrolls you reads the first four groups from you over
another channel.

--tailcat also makes the tailcat node key and publishes its public half in the
identity document, which a coordinator and a signer need to reach each other
over tailcat. The key is a sealed record; it cannot be added later without a
new identity, because the document that carries it is signed.

The label is shown to the parties that enroll you and is not trusted by them.
It cannot be changed: a new label is a new identity.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				if label == "" {
					abs, _ := filepath.Abs(a.workspace)
					label = filepath.Base(abs)
				}
				uc := parties.InitIdentity{Store: r.s.Store, Kit: r.kit().Kit, Clock: r.env.Clock}
				req := parties.InitRequest{Label: label}
				// Refuse before anything is made when an identity exists.
				var have bool
				if err := r.s.Store.View(ctx, func(rd ports.NamedReader) error {
					var err error
					have, err = rd.Exists(ports.NamedRef{Name: "local", Kind: ports.PartyIdentity})
					return err
				}); err != nil {
					return err
				}
				if have {
					return parties.ErrIdentityExists
				}
				if withNode {
					pub, err := r.nodeKey(ctx, true)
					if err != nil {
						return err
					}
					req.Node = &pub
				}
				res, err := uc.Run(ctx, req)
				if err != nil {
					return err
				}
				w := a.d.Out
				fmt.Fprintf(w, "Created the party identity of this workspace.\n  label        %s\n  fingerprint  %s\n", strconv.Quote(label), res.Fingerprint)
				if req.Node != nil {
					fmt.Fprintf(w, "  tailcat node key %x\n", req.Node[:])
				}
				fmt.Fprintln(w, "\nGive the other party your identity with: spo party export FILE")
				fmt.Fprintln(w, "and read them the FIRST FOUR groups of the fingerprint over a separate channel (a call, in person). They type those groups to enroll you; nothing else proves who you are.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "the name peers see for this identity (default: the workspace directory's name)")
	cmd.Flags().BoolVar(&withNode, "tailcat", false, "also make the tailcat node key and publish its public half in the identity, for the tailcat transport")
	return cmd
}

// nodeKey returns the public half of this workspace's tailcat node key,
// making and storing the key first when make is set and there is none.
func (r *partyRun) nodeKey(ctx context.Context, make bool) (party.NodeKey, error) {
	ref := ports.NamedRef{Name: "local", Kind: ports.TailcatNodeKey}
	v, err := r.vault()
	if err != nil {
		return party.NodeKey{}, err
	}
	t := r.kit().Tailcat
	if t.NodePublic == nil {
		return party.NodeKey{}, errors.New("this build has no tailcat transport")
	}
	var have bool
	if err := r.s.Store.View(ctx, func(rd ports.NamedReader) error {
		var err error
		have, err = rd.Exists(ref)
		return err
	}); err != nil {
		return party.NodeKey{}, err
	}
	if !have {
		if !make {
			return party.NodeKey{}, errors.New("this identity has no tailcat node key; it was made without --tailcat and the identity document that carries the key is signed, so it needs a new identity")
		}
		k, err := t.NewNodeKey()
		if err != nil {
			return party.NodeKey{}, err
		}
		defer k.Destroy()
		if err := r.s.Store.Update(ctx, func(w ports.NamedWriter) error { return w.PutSecret(ref, k) }); err != nil {
			return party.NodeKey{}, err
		}
	}
	k, err := v.Open(ctx, ref)
	if err != nil {
		return party.NodeKey{}, err
	}
	defer k.Destroy()
	return t.NodePublic(k)
}

func (a *app) partyShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show this workspace's party identity: label and fingerprint",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.party(cmd, nil, nil, func(ctx context.Context, r *partyRun) error {
				l, err := r.kit().Kit.Local(ctx)
				if err != nil {
					return partyIdentityErr(err)
				}
				defer l.Destroy()
				id := l.Identity()
				w := a.d.Out
				fmt.Fprintf(w, "label        %s\nfingerprint  %s\n", strconv.Quote(id.Label), id.Fingerprint())
				if id.Node != nil {
					fmt.Fprintf(w, "tailcat      node key %x\n", id.Node[:])
				} else {
					fmt.Fprintln(w, "tailcat      none (made without --tailcat)")
				}
				fmt.Fprintf(w, "created      %s\n", id.Created.UTC().Format("2006-01-02 15:04:05 MST"))
				return nil
			})
		},
	}
}

// partyIdentityErr says what to do when the workspace has no identity.
func partyIdentityErr(err error) error {
	if err != nil && strings.Contains(err.Error(), "no party identity") {
		return errors.Join(err, errors.New("create it with: spo party init"))
	}
	return err
}

func (a *app) partyExportCommand() *cobra.Command {
	var (
		overwrite bool
		binding   string
	)
	cmd := &cobra.Command{
		Use:   "export FILE [--binding BFILE] [--overwrite]",
		Short: "Write this workspace's public identity document",
		Long: `Write the signed public identity document (no secret, no address) to FILE, for
another operator to enroll with: spo party enroll FILE. Then read them the
first four groups of the fingerprint over another channel.

--binding also writes this device's relay binding to BFILE (spo party relay
bind makes it), the companion they enroll with: spo party enroll FILE --binding
BFILE. The identity document is the same with or without it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if binding != "" && samePath(args[0], binding) {
				return errors.New("FILE and --binding BFILE are the same file: the binding would overwrite the identity document. Give two paths")
			}
			needs := []Need(nil)
			if binding != "" {
				needs = []Need{CapClock}
			}
			return a.party(cmd, nil, needs, func(ctx context.Context, r *partyRun) error {
				res, err := parties.ExportIdentity{Store: r.s.Store, Kit: r.kit().Kit}.Run(ctx)
				if err != nil {
					return partyIdentityErr(err)
				}
				var bfile []byte
				if binding != "" {
					svc, err := r.self(ctx)
					if err != nil {
						return err
					}
					s, err := svc.Status(ctx)
					if err != nil {
						return err
					}
					// An ended binding is refused: every peer's enrollment check
					// refuses it on its clock (SPO-Xparty-PRE-008), so the file
					// could only fail there.
					if s.Binding != nil && s.Expired {
						return fmt.Errorf("this device's binding ended on %s: a peer cannot enroll with it. Renew it with spo party relay bind, then export again",
							time.Unix(s.Binding.Until, 0).UTC().Format(time.DateTime+" MST"))
					}
					st, err := svc.Load(ctx)
					if err != nil {
						return err
					}
					if bfile, err = st.BindingFile(); err != nil {
						return fmt.Errorf("%w: bind it first with spo party relay bind", err)
					}
					if s.RenewDue {
						fmt.Fprintf(a.d.Err, "WARNING: this device's binding ends in %d day(s); a peer that enrolls with it after that is refused. Renew with spo party relay bind.\n", s.DaysLeft)
					}
				}
				write := func(path string, b []byte) error {
					flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
					if overwrite {
						flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
					}
					f, err := os.OpenFile(path, flags, 0o644)
					if err != nil {
						return fmt.Errorf("%w (use --overwrite to replace it)", err)
					}
					if _, err := f.Write(b); err != nil {
						f.Close()
						return err
					}
					return f.Close()
				}
				if err := write(args[0], res.Document); err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Wrote the public identity to %s.\nfingerprint  %s\n", args[0], res.Fingerprint)
				if bfile != nil {
					if err := write(binding, bfile); err != nil {
						return err
					}
					fmt.Fprintf(a.d.Out, "Wrote this device's relay binding to %s; give it with the identity.\n", binding)
				}
				fmt.Fprintln(a.d.Out, "Read the first four groups to the other operator over a separate channel.")
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace FILE (and BFILE) if it exists")
	cmd.Flags().StringVar(&binding, "binding", "", "also write this device's relay binding to BFILE")
	return cmd
}

// ---- enroll, list, revoke, scope ----------------------------------------------------

// scopeFlags are the flags that name what a coordinator may ask.
type scopeFlags struct {
	keyRoles []string
	pools    []string
	unscoped bool
}

func (f *scopeFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&f.keyRoles, "key-role", nil, "a key role this coordinator may ask for: stake, payment, pool-cold, drep, committee-cold, committee-hot, ... (repeatable)")
	cmd.Flags().StringArrayVar(&f.pools, "pool", nil, "a pool a request may be about, pool1... or 56 hexadecimal characters (repeatable)")
	cmd.Flags().BoolVar(&f.unscoped, "unscoped", false, "also allow the parts of a body that name no pool: withdrawals, stake and vote delegations, DRep and committee certificates, and every payment-key request")
}

// parse checks the names and returns the scope. Pool ids are checked by the
// use case, which stores them in bech32.
func (f *scopeFlags) roles() ([]custody.Role, error) {
	var out []custody.Role
	for _, k := range f.keyRoles {
		r := custody.Role(k)
		if !slices.Contains(custody.Roles(), r) {
			return nil, fmt.Errorf("--key-role %q is not a key role; choose from %s", k, joinRoles(custody.Roles()))
		}
		out = append(out, r)
	}
	return out, nil
}

func joinRoles(rs []custody.Role) string {
	var s []string
	for _, r := range rs {
		s = append(s, string(r))
	}
	return strings.Join(s, ", ")
}

func parseRoles(names []string) ([]party.Role, error) {
	var out []party.Role
	for _, n := range names {
		r := party.Role(n)
		if !r.Valid() {
			return nil, fmt.Errorf("--role %q is not a role; choose coordinator, signer or machine", n)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errors.New("--role is required: coordinator (may send you signing requests), signer (you may send it requests) or machine (your own other machine)")
	}
	return out, nil
}

// unscopedWhy says what Unscoped permits, in the words a confirmation uses.
const unscopedWhy = "UNSCOPED lets this coordinator ask for the parts of a transaction that name no pool: withdrawals of rewards, stake registration and deregistration, vote delegation (choosing a DRep), DRep and committee certificates, votes that are not a pool's, and EVERY payment-key request, whose witness can spend this machine's funds. You will still review each request before it is signed."

func (a *app) partyEnrollCommand() *cobra.Command {
	var (
		name        string
		roles       []string
		sf          scopeFlags
		bindingFile string
	)
	cmd := &cobra.Command{
		Use:   "enroll FILE --as NAME --role ROLE... [--key-role R]... [--pool P]... [--unscoped] [--binding BFILE]",
		Short: "Enroll another party from its identity document",
		Long: `Record another party. The document is verified (it must be signed by the key it
contains), then you are shown its label, the roles you give it and the LAST
FOUR groups of its fingerprint, and you must TYPE the FIRST FOUR groups, which
the other operator reads to you over a separate channel. The groups you must
type are never displayed, so they cannot be copied from the screen. There is
no flag that skips this.

Roles: coordinator (may send you signing requests), signer (you may send it
signing requests), machine (your own other machine). A coordinator is enrolled
with a scope: the key roles it may ask for (--key-role), and the pools its
requests may be about (--pool) and/or --unscoped. There is no default scope;
the scope applies to a coordinator and is checked again at every approval.

Enrollment is not mutual by itself: the other operator enrolls you the same
way.

--binding BFILE is the party's relay binding, given with its document (spo party
export FILE --binding BFILE). It is checked (signature, this party's device,
dates, network, never a cold key) and shown as evidence: the wallet key and the
dates. It does not replace the groups you type. Mail to the party then goes
through a relay under that wallet key.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return errors.New("--as NAME is required: the local name you give this party")
			}
			rs, err := parseRoles(roles)
			if err != nil {
				return err
			}
			krs, err := sf.roles()
			if err != nil {
				return err
			}
			if slices.Contains(rs, party.RoleCoordinator) && (len(krs) == 0 || (len(sf.pools) == 0 && !sf.unscoped)) {
				return errors.New("a coordinator is enrolled with a scope: give --key-role (at least one) and --pool and/or --unscoped. There is no default")
			}
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			var ev *parties.BindingEvidence
			if bindingFile != "" {
				if ev, err = readBindingFile(bindingFile); err != nil {
					return err
				}
			}
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				k := r.kit()
				uc := parties.Enroll{Store: r.s.Store, Kit: k.Kit, Registry: k.Registry, Clock: r.env.Clock, Relay: r.relayCheck()}
				ins, err := uc.Inspect(raw, rs)
				if err != nil {
					return err
				}
				var view parties.BindingView
				if ev != nil {
					// the evidence is checked before anything is shown or typed
					if view, err = uc.InspectBinding(ctx, raw, ev); err != nil {
						return fmt.Errorf("the binding is refused, nothing was enrolled: %w", err)
					}
				}
				w := a.d.Out
				fmt.Fprintf(w, "Enrolling %s\n  label       %s (chosen by its owner; not trusted)\n  roles       %v\n", strconv.Quote(name), strconv.Quote(ins.Label), ins.Roles)
				if ev != nil {
					printEvidence(w, view)
				}
				if slices.Contains(rs, party.RoleCoordinator) {
					fmt.Fprintf(w, "  scope       key roles %v, pools %v, unscoped %v\n", krs, sf.pools, sf.unscoped)
				}
				if sf.unscoped {
					fmt.Fprintln(w, unscopedWhy)
					ok, err := a.askYes(ctx, "Allow an unscoped coordinator?")
					if err != nil {
						return err
					}
					if !ok {
						return errors.New("not enrolled: unscoped was not confirmed")
					}
				}
				fmt.Fprintf(w, "  last four groups of the fingerprint  %s\n", ins.LastGroup)
				fmt.Fprintf(w, "The other operator reads you the FIRST %d groups over a separate channel (not this document, not a message that came with it).\n", party.ConfirmGroups)
				typed, err := a.term.ReadLine(ctx, fmt.Sprintf("Type the first %d groups: ", party.ConfirmGroups))
				if errors.Is(err, ErrNoTerminal) {
					return errors.New("no terminal: the first four groups of the fingerprint are typed by the operator from what the other party reads out, and there is no flag for them")
				}
				if err != nil {
					return err
				}
				p, err := uc.Run(ctx, parties.EnrollRequest{Document: raw, Name: name, Roles: rs, KeyRoles: krs, Pools: sf.pools, Unscoped: sf.unscoped, Confirmation: typed, Binding: ev})
				if err != nil {
					if errors.Is(err, party.ErrConfirmation) {
						return errors.New("the groups you typed are not the first four groups of that identity's fingerprint: nothing was enrolled. If the other operator read them out correctly, this document is not theirs")
					}
					return err
				}
				allowLive(p)
				fmt.Fprintf(w, "Enrolled %s.\n  fingerprint  %s\n", p.Name, p.Fingerprint)
				if p.Relay != nil {
					fmt.Fprintf(w, "  wallet key   %x (mail to it goes through a relay under this key)\n", p.Relay.WalletKey[:])
				}
				if slices.Contains(rs, party.RoleSigner) && p.Identity.Node == nil && p.Relay == nil {
					fmt.Fprintln(w, "note: this party has no tailcat node key; it can exchange files only.")
				}
				fmt.Fprintln(w, "Enrollment is not mutual by itself: the other operator enrolls you too.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "as", "", "the local name for this party (letters, digits, - and _)")
	cmd.Flags().StringArrayVar(&roles, "role", nil, "coordinator, signer or machine (repeatable)")
	cmd.Flags().StringVar(&bindingFile, "binding", "", "the party's relay binding file, given with its document")
	sf.add(cmd)
	return cmd
}

// askYes asks a yes/no question, default No. No flag answers it.
func (a *app) askYes(ctx context.Context, q string) (bool, error) {
	ans, err := a.term.ReadLine(ctx, q+" [y/N] ")
	if errors.Is(err, ErrNoTerminal) {
		return false, errors.New("no terminal to ask on, and no flag answers this question")
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

func (a *app) partyListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the enrolled parties",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.party(cmd, nil, nil, func(ctx context.Context, r *partyRun) error {
				ps, err := parties.List{Store: r.s.Store, Registry: r.kit().Registry}.Run(ctx)
				if err != nil {
					return err
				}
				w := a.d.Out
				if len(ps) == 0 {
					fmt.Fprintln(w, "No party is enrolled. Enroll one with: spo party enroll FILE --as NAME --role ROLE")
					return nil
				}
				for _, p := range ps {
					fmt.Fprintf(w, "%s  %s  roles %v\n  label %s  fingerprint %s\n", p.Name, p.State, p.Roles, strconv.Quote(p.Identity.Label), p.Fingerprint)
					if p.HasRole(party.RoleCoordinator) {
						fmt.Fprintf(w, "  scope: %s\n", scopeText(p.Scope))
					}
					if p.Identity.Node != nil {
						fmt.Fprintf(w, "  tailcat node key %x\n", p.Identity.Node[:])
					}
					if rl := p.Relay; rl != nil {
						fmt.Fprintf(w, "  relay wallet key %x  binding until %s\n", rl.WalletKey[:], time.Unix(rl.Until, 0).UTC().Format(time.DateTime+" MST"))
						if rl.Unverified != "" {
							warnUnverified(a.d.Err, p.Name, rl.Unverified)
						}
					}
				}
				return nil
			})
		},
	}
}

// samePath reports whether two paths name one file: the same cleaned absolute
// path, or, when both exist, the same file (a link).
func samePath(a, b string) bool {
	if aa, err := filepath.Abs(a); err == nil {
		if bb, err := filepath.Abs(b); err == nil && aa == bb {
			return true
		}
	}
	sa, ea := os.Stat(a)
	sb, eb := os.Stat(b)
	return ea == nil && eb == nil && os.SameFile(sa, sb)
}

// warnUnverified tells the operator that a party's stored relay identity no
// longer verifies: it is kept, bytes and all, and is no route until replaced or
// cleared (SPO-Xparty-OUT-007).
func warnUnverified(w io.Writer, name, why string) {
	fmt.Fprintf(w, "WARNING: the relay identity of %s no longer verifies (%s): nothing is sent to it through a relay.\n"+
		"  It is kept as it is. Record a new binding with: spo party relay peer %s --binding BFILE, or remove it with --clear\n",
		strconv.Quote(name), why, name)
}

func scopeText(s party.Scope) string {
	if s.Empty() {
		return "nothing (no key role, or neither a pool nor unscoped)"
	}
	t := fmt.Sprintf("key roles %v, pools %v", s.KeyRoles, s.Pools)
	if s.Unscoped {
		t += ", UNSCOPED"
	}
	return t
}

func (a *app) partyRevokeCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "revoke NAME",
		Short: "Revoke an enrolled party",
		Long: `From the moment this commits, the party's envelopes are refused, including ones
created before. Slots of open witness collections that were assigned to it become
unassigned; witnesses already verified are kept. A tailcat server running in
this process stops serving its node key and closes its connections; a server in
another process does so when it next reads the registry (within seconds).
tailcat itself keeps the key in its allow-list until that server restarts, but
our listener refuses it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.party(cmd, nil, []Need{CapClock, CapTxID, CapTxView}, func(ctx context.Context, r *partyRun) error {
				ok, err := a.confirm(ctx, fmt.Sprintf("Revoke %s?", args[0]), yes)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("not revoked")
				}
				c, err := r.coordinator()
				if err != nil {
					return err
				}
				k := r.kit()
				p, err := parties.Revoke{Store: r.s.Store, Registry: k.Registry, Clock: r.env.Clock,
					Hooks: []func(ports.NamedWriter, party.Party) error{c.OnRevoke, func(_ ports.NamedWriter, p party.Party) error { revokeLive(p); return nil }}}.Run(ctx, args[0])
				if err != nil {
					if errors.Is(err, ports.ErrNotFound) {
						return fmt.Errorf("no party named %q: see spo party list", args[0])
					}
					return err
				}
				fmt.Fprintf(a.d.Out, "Revoked %s (%s). Its envelopes are refused from now on.\n", p.Name, p.Fingerprint)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask")
	return cmd
}

func (a *app) partyScopeCommand() *cobra.Command {
	var sf scopeFlags
	cmd := &cobra.Command{
		Use:   "scope NAME --key-role R... [--pool P]... [--unscoped]",
		Short: "Change what an enrolled coordinator may ask of this machine",
		Long: `Replace the scope recorded for NAME with exactly the key roles, pools and
--unscoped you give. A request already received is checked against the scope as
it is when you approve it, so narrowing a scope stops a request you have not
approved yet. Widening asks a confirmation, and widening to --unscoped says what
that permits. To stop a party entirely use: spo party revoke.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			krs, err := sf.roles()
			if err != nil {
				return err
			}
			if len(krs) == 0 || (len(sf.pools) == 0 && !sf.unscoped) {
				return errors.New("give --key-role (at least one) and --pool and/or --unscoped: a scope that allows nothing is a revocation; use spo party revoke")
			}
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				k := r.kit()
				cur, err := r.byName(ctx, args[0])
				if err != nil {
					return err
				}
				pools, err := canonicalPools(sf.pools)
				if err != nil {
					return err
				}
				next := party.Scope{KeyRoles: krs, Pools: pools, Unscoped: sf.unscoped}
				w := a.d.Out
				fmt.Fprintf(w, "scope of %s\n  now   %s\n  new   %s\n", cur.Name, scopeText(cur.Scope), scopeText(next))
				if scopeWidens(cur.Scope, next) {
					if next.Unscoped && !cur.Scope.Unscoped {
						fmt.Fprintln(w, unscopedWhy)
					}
					ok, err := a.askYes(ctx, "Widen this coordinator's scope?")
					if err != nil {
						return err
					}
					if !ok {
						return errors.New("the scope was not changed")
					}
				}
				var out party.Party
				err = r.s.Store.Update(ctx, func(wr ports.NamedWriter) error {
					var err error
					if out, err = k.SetScope(wr, args[0], next); err != nil {
						return err
					}
					return parties.AppendEvent(wr, parties.Event{At: r.env.Clock.Now(), Kind: "party-scope-changed", Peer: out.Fingerprint.String(),
						Detail: out.Name + ": " + scopeText(next)})
				})
				if err != nil {
					return err
				}
				fmt.Fprintf(w, "The scope of %s is now: %s\n", out.Name, scopeText(out.Scope))
				return nil
			})
		},
	}
	sf.add(cmd)
	return cmd
}

// scopeWidens reports that next allows something old does not.
func scopeWidens(old, next party.Scope) bool {
	for _, r := range next.KeyRoles {
		if !slices.Contains(old.KeyRoles, r) {
			return true
		}
	}
	for _, p := range next.Pools {
		if !slices.Contains(old.Pools, p) {
			return true
		}
	}
	return next.Unscoped && !old.Unscoped
}

func (r *partyRun) byName(ctx context.Context, name string) (party.Party, error) {
	var p party.Party
	err := r.s.Store.View(ctx, func(rd ports.NamedReader) error {
		var err error
		p, err = r.kit().Registry.ByName(rd, name)
		return err
	})
	if errors.Is(err, ports.ErrNotFound) {
		return p, fmt.Errorf("no party named %q: see spo party list", name)
	}
	return p, err
}

func (a *app) partyEventsCommand() *cobra.Command {
	var noise bool
	var limit int
	cmd := &cobra.Command{
		Use:   "events [--noise] [--limit N]",
		Short: "Show the multi-party audit log",
		Long: `Enrollments, revocations, requests sealed, received, reviewed, approved and
refused, responses accepted or refused, collections opened and closed. A request
refused for a reason that depends on what this machine holds (no such key, out
of scope, no input of it) is listed here and never sent to the coordinator.
--noise shows the small ring of refusals that failed before the signature step:
anyone who can reach this machine can make those, and they are never mixed with
the events above.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.party(cmd, nil, nil, func(ctx context.Context, r *partyRun) error {
				var es []parties.Event
				var total uint64
				err := r.s.Store.View(ctx, func(rd ports.NamedReader) error {
					var err error
					if noise {
						es, total, err = multisig.Noise(rd)
						return err
					}
					es, err = multisig.Events(rd)
					return err
				})
				if err != nil {
					return err
				}
				if limit > 0 && len(es) > limit {
					es = es[len(es)-limit:]
				}
				for _, e := range es {
					printEvent(a.d.Out, e)
				}
				if noise {
					fmt.Fprintf(a.d.Out, "%d refusal(s) before the signature step in total; the ring keeps the latest.\n", total)
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&noise, "noise", false, "show the refusals that failed before the signature step")
	cmd.Flags().IntVar(&limit, "limit", 0, "show only the last N events")
	return cmd
}

// printEvent writes one audit event. Every text a peer could have chosen is
// quoted.
func printEvent(w io.Writer, e parties.Event) {
	fmt.Fprintf(w, "%s  %-22s", e.At.UTC().Format("2006-01-02 15:04:05"), safeText(e.Kind))
	if e.Peer != "" {
		fmt.Fprintf(w, " peer %s", safeText(e.Peer))
	}
	if e.Collection != "" {
		fmt.Fprintf(w, " collection %s slot %d", safeText(e.Collection), e.Slot)
	}
	if e.Reason != "" {
		fmt.Fprintf(w, " reason %s", strconv.Quote(e.Reason))
	}
	if e.Detail != "" {
		fmt.Fprintf(w, " detail %s", strconv.Quote(e.Detail))
	}
	if e.Count > 1 {
		fmt.Fprintf(w, " (x%d)", e.Count)
	}
	fmt.Fprintln(w)
}

// canonicalPools turns pool ids, pool1... or 56 hexadecimal characters, into
// the bech32 form a body's pool is compared in (the same rule as enrollment).
func canonicalPools(in []string) ([]string, error) {
	var out []string
	for _, p := range in {
		if id, err := chain.ParsePoolBech32(p); err == nil {
			out = append(out, id.Bech32())
			continue
		}
		if raw, err := hex.DecodeString(strings.ToLower(p)); err == nil && len(p) == 56 {
			var id chain.PoolID
			copy(id[:], raw)
			out = append(out, id.Bech32())
			continue
		}
		return nil, fmt.Errorf("%w: %q", parties.ErrBadPool, p)
	}
	return out, nil
}
