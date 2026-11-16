package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The file transport is a pair of commands and a directory. A coordinator
// writes request envelopes (spo party request export), a signer imports them
// (spo party inbox import), reviews and approves, and exports its response
// (spo party outbox export); the coordinator imports the response the same way.
// Whatever carries the files (a stick, never a synced folder) carries
// ciphertext that is signed: the same checks run as over a network
// (SPO-Xparty-SEC-002).

func (a *app) partyRequestCommand() *cobra.Command {
	c := &cobra.Command{Use: "request", Short: "Ask enrolled signers for signatures (coordinator)"}
	var (
		out     string
		purpose string
		renew   bool
		cf      chainFlags
	)
	exp := &cobra.Command{
		Use:   "export POOL [--out DIR] [--purpose TEXT] [--renew]",
		Short: "Write the signing requests of a pool registration's open collection as files",
		Long: `For the open witness collection of POOL (made by: spo pool register POOL PAYER
--allow-pending), seal one signing request per open slot that belongs to an
enrolled signer, and write each as a file in DIR (default: the party outbox).
A request for the pool cold key may go by file and never over a network. Carry
the files to the signers on a stick; do not use a synced folder.

Only the requests of this pool's collection are written. Anything else waiting
in the outbox (responses, invitations, other collections' requests) stays
queued: spo party outbox export DIR writes everything and says so.

--purpose is shown to the signer as YOUR claim, apart from what the signer
decodes from the body itself. --renew sends a new request for a slot that
already has one outstanding; the old request's answer is then refused as stale.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := poolArg(args[0])
			if err != nil {
				return err
			}
			return a.party(cmd, &cf, append([]Need{CapTxID}, signerNeeds...), func(ctx context.Context, r *partyRun) error {
				c, err := r.coordinator()
				if err != nil {
					return err
				}
				d := r.dirs("", out)
				if out != "" {
					d.outbox = out
				}
				if err := ensureDir(d.outbox); err != nil {
					return err
				}
				bag, err := r.kit().OpenOutput(d.outbox)
				if err != nil {
					return err
				}
				defer bag.Close()
				ob := multisig.Outbox{Store: r.s.Store, Clock: r.env.Clock, Offline: r.o.Mode == ModeOffline}
				bag.SetNamer(outboxNamer(ctx, ob))
				// Only the requests of this pool's collection are written: the
				// outbox may hold responses, invitations and the requests of
				// other collections, for other parties, and none of them is
				// meant for the directory the operator named here. They stay
				// queued.
				cid, err := r.collectionWireID(ctx, name)
				if err != nil {
					return err
				}
				only := onlyCollection{ob: ob, collection: hex.EncodeToString(cid[:])}
				res, err := c.RequestSignatures(ctx, multisig.RequestInput{Ref: multisig.CollectionRef{Kind: multisig.KindPool, Name: name}, Purpose: purpose, Renew: renew}, bag.Transport().Only(only.allow))
				if err != nil {
					return err
				}
				w := a.d.Out
				var requested, refused int
				for _, s := range res {
					fmt.Fprintf(w, "  slot %-28s %-14s %s", s.Name, s.Party, s.Status)
					if s.Err != nil {
						fmt.Fprintf(w, "  %s", safeText(s.Err.Error()))
					}
					fmt.Fprintln(w)
					switch s.Status {
					case multisig.SlotRequested:
						requested++
					case multisig.SlotRefused:
						refused++
					}
				}
				fmt.Fprintf(w, "%d request(s) written to %s.\n", requested, d.outbox)
				if requested > 0 {
					fmt.Fprintln(w, "Carry them to the signers (a stick, not a synced folder); each imports its file with: spo party inbox import FILE")
				}
				if refused > 0 {
					return fmt.Errorf("%d slot(s) were not requested", refused)
				}
				return nil
			})
		},
	}
	exp.Flags().StringVar(&out, "out", "", "directory to write the request files to (default: the party outbox)")
	exp.Flags().StringVar(&purpose, "purpose", "", "what this is for, as you tell the signer (a claim; the signer decodes the body itself)")
	exp.Flags().BoolVar(&renew, "renew", false, "send a new request for a slot that already has one outstanding")
	addChainFlags(exp, &cf, false)
	c.AddCommand(exp)

	var qpurpose string
	var qrenew bool
	var qcf chainFlags
	queue := &cobra.Command{
		Use:   "queue POOL [--purpose TEXT] [--renew]",
		Short: "Seal the signing requests of a pool registration into the outbox, for spo party serve to deliver over tailcat",
		Long: `Like request export, but the requests are only sealed and kept in the outbox:
spo party serve sends each to its signer when that signer connects, and sends
it again, with the same message id, each time the signer reconnects until the
slot is answered. A request for the pool cold key is refused here: it may travel
by file only (request export). Not available in offline mode.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := poolArg(args[0])
			if err != nil {
				return err
			}
			needs := append([]Need{CapTxID, needNetwork{}}, signerNeeds...)
			return a.party(cmd, &qcf, needs, func(ctx context.Context, r *partyRun) error {
				c, err := r.coordinator()
				if err != nil {
					return err
				}
				// A transport with no sender seals and stores; its unknown kind
				// is a network for the cold-key rule.
				res, err := c.RequestSignatures(ctx, multisig.RequestInput{Ref: multisig.CollectionRef{Kind: multisig.KindPool, Name: name}, Purpose: qpurpose, Renew: qrenew}, ports.Transport{})
				if err != nil {
					return err
				}
				var queued, refused int
				for _, s := range res {
					fmt.Fprintf(a.d.Out, "  slot %-28s %-14s %s", s.Name, s.Party, s.Status)
					if s.Err != nil {
						fmt.Fprintf(a.d.Out, "  %s", safeText(s.Err.Error()))
					}
					fmt.Fprintln(a.d.Out)
					switch s.Status {
					case multisig.SlotRequested:
						queued++
					case multisig.SlotRefused:
						refused++
					}
				}
				fmt.Fprintf(a.d.Out, "%d request(s) sealed into the outbox. Deliver them with: spo party serve\n", queued)
				if refused > 0 {
					return fmt.Errorf("%d slot(s) were not requested", refused)
				}
				return nil
			})
		},
	}
	queue.Flags().StringVar(&qpurpose, "purpose", "", "what this is for, as you tell the signer (a claim; the signer decodes the body itself)")
	queue.Flags().BoolVar(&qrenew, "renew", false, "send a new request for a slot that already has one outstanding")
	addChainFlags(queue, &qcf, false)
	c.AddCommand(queue)
	return c
}

// outboxNamer names the files of an export the spec's way,
// <type>-<collection id prefix>-<slot>.spo, by looking the envelope up among
// the outbox's pending items. An item with no collection (an invitation)
// keeps the bag's default name, which carries a hash and cannot collide.
func outboxNamer(ctx context.Context, ob multisig.Outbox) func([]byte) string {
	var items []multisig.OutItem
	load := func() { items, _ = ob.Pending(ctx) }
	find := func(env []byte) string {
		for _, it := range items {
			if bytes.Equal(it.Envelope, env) && it.Collection != "" {
				b, err := hex.DecodeString(it.Collection)
				if err != nil || len(b) != len(party.CollectionID{}) {
					return ""
				}
				return party.FileName(party.Type(it.Type), party.CollectionID(b), party.SlotID(it.Slot))
			}
		}
		return ""
	}
	return func(env []byte) string {
		if n := find(env); n != "" {
			return n
		}
		load()
		return find(env)
	}
}

// onlyCollection is a sender that writes only the signing requests of one
// collection: any other envelope in the outbox gets ErrNoRoute, which Flush
// leaves queued for a later export.
type onlyCollection struct {
	ob         multisig.Outbox
	collection string // hex of the wire id
}

func (o onlyCollection) allow(ctx context.Context, _ party.Fingerprint, env []byte) (bool, error) {
	items, err := o.ob.Pending(ctx)
	if err != nil {
		return false, err
	}
	for _, it := range items {
		if bytes.Equal(it.Envelope, env) && it.Collection == o.collection && it.Type == string(party.TypeSigningRequest) {
			return true, nil
		}
	}
	return false, nil
}

// collectionWireID is the id the requests of a pool's witness collection carry
// on the wire.
func (r *partyRun) collectionWireID(ctx context.Context, poolName string) (party.CollectionID, error) {
	var id party.CollectionID
	err := r.s.Store.View(ctx, func(rd ports.Reader) error {
		raw, err := rd.Get(ports.Ref{Name: poolName, Kind: ports.PoolDescriptor})
		if err != nil {
			return err
		}
		d, err := pool.ParseDescriptor(raw)
		if err != nil {
			return err
		}
		c, err := d.Collection(r.env.TxIDs.TransactionID)
		if err != nil {
			return err
		}
		if c == nil {
			return multisig.ErrNoCollection
		}
		id = multisig.CollectionID(multisig.CollectionRef{Kind: multisig.KindPool, Name: poolName}, *c)
		return nil
	})
	return id, err
}

func (a *app) partyOutboxCommand() *cobra.Command {
	c := &cobra.Command{Use: "outbox", Short: "Envelopes waiting to be carried to another party"}
	var yes bool
	cmd := &cobra.Command{
		Use:   "export DIR [--yes]",
		Short: "Write EVERY waiting envelope as a file in DIR",
		Long: `Write every envelope this machine has sealed and not yet handed to a transport
(a signer's responses and refusals, invitations, closing notices, requests
sealed and not yet carried) as one file each in DIR, then they are done. This
is everything that waits, for every party: the command lists what it will write,
per recipient, before it writes anything. When the envelopes are for more than
one recipient it asks you to confirm, because one directory (a stick) would then
carry another party's files too; --yes answers that for scripts. Carry each file
to the party it is for: the file names say what it is, not who it is for, and
only that party can open it. DIR may be a mounted stick; it is not read as an
inbox.

To write only the requests of one pool's collection, use
spo party request export POOL --out DIR.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				ob := multisig.Outbox{Store: r.s.Store, Clock: r.env.Clock}
				items, err := ob.Pending(ctx)
				if err != nil {
					return err
				}
				w := a.d.Out
				labels, err := r.recipientLabels(ctx)
				if err != nil {
					return err
				}
				type tally struct {
					n     int
					kinds map[string]int
				}
				per := map[string]*tally{}
				for _, it := range items {
					l := labels[it.To]
					if l == "" {
						l = "an unknown recipient " + it.To[:min(8, len(it.To))]
					}
					t := per[l]
					if t == nil {
						t = &tally{kinds: map[string]int{}}
						per[l] = t
					}
					t.n++
					t.kinds[it.Type]++
				}
				names := make([]string, 0, len(per))
				for l := range per {
					names = append(names, l)
				}
				sort.Strings(names)
				if len(items) > 0 {
					fmt.Fprintf(w, "spo party outbox export writes EVERYTHING that waits: %d envelope(s) for %d recipient(s), to %s:\n", len(items), len(per), args[0])
				}
				for _, l := range names {
					var parts []string
					for k, n := range per[l].kinds {
						parts = append(parts, fmt.Sprintf("%d %s", n, k))
					}
					sort.Strings(parts)
					fmt.Fprintf(w, "  for %s  %s\n", safeText(l), strings.Join(parts, ", "))
				}
				if len(per) > 1 && !yes {
					ok, err := a.askYes(ctx, fmt.Sprintf("These are for %d different parties and all go to one directory. Write them all?", len(per)))
					if err != nil {
						return fmt.Errorf("%w (--yes writes them all without asking)", err)
					}
					if !ok {
						fmt.Fprintln(w, "Nothing was written. To write one pool's requests only: spo party request export POOL --out DIR")
						return nil
					}
				}
				if err := ensureDir(args[0]); err != nil {
					return err
				}
				bag, err := r.kit().OpenOutput(args[0])
				if err != nil {
					return err
				}
				defer bag.Close()
				bag.SetNamer(outboxNamer(ctx, ob))
				n, err := ob.Flush(ctx, bag.Transport())
				fmt.Fprintf(w, "%d envelope(s) of %d waiting written to %s.\n", n, len(items), args[0])
				return err
			})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "write the envelopes of several recipients to one directory without asking")
	c.AddCommand(cmd)
	return c
}

// recipientLabels maps a recipient fingerprint (hex) to the local name of the
// party it is enrolled as.
func (r *partyRun) recipientLabels(ctx context.Context) (map[string]string, error) {
	m := map[string]string{}
	err := r.s.Store.View(ctx, func(rd ports.Reader) error {
		ps, err := r.kit().Registry.List(rd)
		for _, p := range ps {
			m[hex.EncodeToString(p.Fingerprint[:])] = p.Name
		}
		return err
	})
	return m, err
}

// ---- inbox ---------------------------------------------------------------------------

var badNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// readEnvelopeFile reads a file the operator named: a regular file (not a
// link, not a device), at most one envelope in size.
func readEnvelopeFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (a symbolic link is refused: name the file itself)", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() == 0 || st.Size() > party.MaxEnvelopeBytes {
		return nil, fmt.Errorf("%s is empty or larger than an envelope may be (%d bytes)", path, party.MaxEnvelopeBytes)
	}
	return io.ReadAll(io.LimitReader(f, party.MaxEnvelopeBytes+1))
}

// importName is the name a file gets in the inbox: its own name made plain,
// and a hash, so two files never share one.
func importName(src string, data []byte) string {
	base := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
	base = badNameChars.ReplaceAllString(base, "_")
	if len(base) > 60 {
		base = base[:60]
	}
	base = strings.TrimLeft(base, "._-")
	if base == "" {
		base = "import"
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%s-%s.spo", base, hex.EncodeToString(sum[:4]))
}

// inboxRole picks the handler of what is imported: a machine that has only
// enrolled coordinators is a signer; one that has only enrolled signers is a
// coordinator; one that is both says which with --as.
func (r *partyRun) inboxRole(ctx context.Context, as string) (string, error) {
	switch as {
	case "coordinator", "signer":
		return as, nil
	case "":
	default:
		return "", fmt.Errorf("--as is coordinator or signer, not %q", as)
	}
	var coord, sign bool
	err := r.s.Store.View(ctx, func(rd ports.Reader) error {
		ps, err := r.kit().Registry.List(rd)
		for _, p := range ps {
			coord = coord || (p.Active() && p.HasRole(party.RoleCoordinator))
			sign = sign || (p.Active() && p.HasRole(party.RoleSigner))
		}
		return err
	})
	switch {
	case err != nil:
		return "", err
	case coord && sign:
		return "", errors.New("this machine is both a coordinator and a signer: say which role is reading the files with --as coordinator (responses, refusals) or --as signer (requests, invitations)")
	case coord:
		return "signer", nil
	case sign:
		return "coordinator", nil
	}
	return "", errors.New("no party is enrolled: enroll the other party first (spo party enroll)")
}

func (a *app) partyInboxCommand() *cobra.Command {
	c := &cobra.Command{Use: "inbox", Short: "Envelopes that arrived by file"}
	var f signerFlags
	var as string
	imp := &cobra.Command{
		Use:   "import FILE|DIR... [--as coordinator|signer]",
		Short: "Read envelope files: requests and invitations (signer), responses (coordinator)",
		Long: `Copy each FILE (or each .spo file of a DIR) into the inbox and read the inbox.
Every file goes through the same checks as a message over a network: it must
decrypt to this machine, come from an enrolled party that is not revoked, carry
a valid signature, not be expired or replayed, and be a message that party's
role may send. A file that fails is refused and recorded; nothing goes back.

A signer's request becomes a pending request: nothing is signed. Read it with
spo party review ID. A coordinator's response fills its slot; when the last slot
is filled, finish the registration with spo pool register POOL PAYER.

The inbox must be a local directory only you can write to (not a link, not
group- or other-writable, not on a network or FUSE file system, and never a
synced folder, whose other copies can feed it files). Files you import are
copied into it, and the files you name are read as regular files only.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.party(cmd, &f.chain, append([]Need{CapTxID}, signerNeeds...), func(ctx context.Context, r *partyRun) error {
				role, err := r.inboxRole(ctx, as)
				if err != nil {
					return err
				}
				d := r.dirs(f.inbox, f.outbox)
				var h multisig.Handler
				switch role {
				case "signer":
					sg, why, err := r.signer(ctx, f.snapshot, d)
					if err != nil {
						return err
					}
					fmt.Fprintf(a.d.Err, "reading as a signer; this machine's own chain view: %s\n", why)
					h = func(ctx context.Context, rcv ports.Received) (multisig.Handled, error) {
						out, err := sg.Handle(ctx, rcv)
						return out, mapSignerErr(err)
					}
				default:
					co, err := r.coordinator()
					if err != nil {
						return err
					}
					h = co.Handle
				}
				if err := ensureDir(d.inbox); err != nil {
					return err
				}
				bag, err := r.kit().OpenInbox(d.inbox)
				if err != nil {
					return err
				}
				defer bag.Close()
				bag.SetPoll(20 * time.Millisecond)
				n, err := a.stageFiles(bag, args)
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "%d file(s) copied into %s.\n", n, d.inbox)
				return a.drainInbox(ctx, bag, h, role)
			})
		},
	}
	imp.Flags().StringVar(&as, "as", "", "which role reads the files, when this machine is both: coordinator or signer")
	f.add(imp)
	c.AddCommand(imp)
	return c
}

// stageFiles copies the files the operator named, or the .spo files of a named
// directory, into the inbox.
func (a *app) stageFiles(bag FileBag, args []string) (int, error) {
	var files []string
	for _, p := range args {
		st, err := os.Lstat(p)
		if err != nil {
			return 0, err
		}
		if st.IsDir() {
			es, err := os.ReadDir(p)
			if err != nil {
				return 0, err
			}
			for _, e := range es {
				if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".spo") {
					files = append(files, filepath.Join(p, e.Name()))
				}
			}
			continue
		}
		files = append(files, p)
	}
	sort.Strings(files)
	n := 0
	for _, p := range files {
		data, err := readEnvelopeFile(p)
		if err != nil {
			return n, err
		}
		if err := bag.Write(importName(p, data), data); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// drainInbox hands every envelope in the inbox to the handler, through the
// bag's own Receive (ADR 0005, obligation 4), acknowledging each once handled.
func (a *app) drainInbox(ctx context.Context, bag FileBag, h multisig.Handler, role string) error {
	w := a.d.Out
	var stored, refused int
	for {
		rctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		rcv, err := bag.Receive(rctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			break // nothing more waits in the inbox
		}
		got, err := h(ctx, rcv)
		if err != nil {
			return err
		}
		if err := bag.Ack(); err != nil {
			return err
		}
		printHandled(w, got)
		if got.Refused {
			refused++
		} else if got.Effect == "stored" {
			stored++
		}
	}
	for _, rj := range bag.Rejected() {
		fmt.Fprintf(w, "refused file %s: %s\n", safeText(rj.Name), safeText(rj.Reason))
	}
	if stored > 0 {
		fmt.Fprintf(w, "%d request(s) are waiting for you: spo party requests\n", stored)
	}
	if refused > 0 {
		fmt.Fprintf(w, "%d envelope(s) were refused and recorded (spo party events); nothing is sent back for a refusal.\n", refused)
	}
	return nil
}

// printHandled writes what one envelope did. Reasons and effects are the
// program's own words, but a refusal's reason can carry a peer's text, so it
// is quoted.
func printHandled(w io.Writer, h multisig.Handled) {
	who := ""
	if h.HasSender {
		who = " from " + h.Sender.String()
	}
	switch {
	case h.Refused:
		fmt.Fprintf(w, "refused %s%s: %s\n", h.Type, who, safeText(h.Reason))
	case h.Effect == "stored":
		fmt.Fprintf(w, "request %x%s is pending. Read it with: spo party review %.8x\n", h.Request[:], who, h.Request[:])
	case h.Effect == "refused":
		fmt.Fprintf(w, "request %x%s was refused: %s (recorded in spo party events%s)\n", h.Request[:], who, safeText(h.Reason), "; not sent when it depends on what this machine holds")
	case h.Complete:
		fmt.Fprintf(w, "%s%s: %s. The collection is complete: finish it with spo pool register POOL PAYER\n", h.Type, who, h.Effect)
	default:
		fmt.Fprintf(w, "%s%s: %s\n", h.Type, who, h.Effect)
	}
}
