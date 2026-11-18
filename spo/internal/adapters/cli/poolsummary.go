package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/hwkeys"
	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// poolConfirmer is the terminal confirmer of the pool commands. A pool
// transaction commits a deposit and a pledge for years, so its summary says
// what the descriptor says about the pool (the cost, the margin, the owners,
// the relays, the metadata) and who holds each signature. It reads the
// descriptor from the store, never a key: only whether a signing file exists.
// The default answer is No and there is no way to skip the question.
type poolConfirmer struct {
	a     *app
	store ports.NamedStore
	ids   ports.TxIDCalculator
	// labels names a co-signer party by its fingerprint for display (nil: the
	// fingerprint is shown). Display only: nothing is routed by a label.
	labels partyLabeler
}

func isPoolKind(kind string) bool {
	return kind == "pool registration" || kind == "pool re-registration" || kind == "pool retirement"
}

func (c poolConfirmer) Confirm(ctx context.Context, sum ports.TxSummary) (bool, error) {
	if !isPoolKind(sum.Kind) {
		return terminalConfirmer{c.a}.Confirm(ctx, sum)
	}
	printPoolSummary(ctx, c.a.d.Out, c.store, c.ids, sum, c.labels)
	q := "Sign and " + routeVerb(sum.Route) + " this transaction? [y/N] "
	if sum.Stage == "body" {
		q = "Build this transaction and collect its witnesses? Nothing is signed or sent yet. [y/N] "
	}
	ans, err := c.a.term.ReadLine(ctx, q)
	if errors.Is(err, ErrNoTerminal) {
		return false, errors.New("no terminal to ask on; this command is always asked and has no --yes")
	}
	if err != nil {
		return false, err
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes", nil
}

// slotInfo is one signature of a pool transaction as the operator sees it.
type slotInfo struct {
	name, role, holder string
	// signed is nil when no collection says.
	signed *bool
	// key is the key the slot demands, resolved from the stored verification key,
	// and storeName the name it is stored under. A slot with a key is described by
	// the signer directory that will sign (partyLabeler.describe), not by which
	// files exist under the name.
	key       custody.KeyRef
	haveKey   bool
	storeName string
}

// withKey records the key the slot demands.
func (s slotInfo) withKey(r ports.NamedReader, role custody.Role, name string) slotInfo {
	if k, err := keyring.Resolve(r, role, name); err == nil {
		s.key, s.haveKey, s.storeName = k, true, name
	}
	return s
}

func hasArtefact(r ports.NamedReader, ref ports.NamedRef) bool {
	ok, err := r.Exists(ref)
	return err == nil && ok
}

// holderText says who signs, from what the store holds. It never reads a key.
func holderText(r ports.NamedReader, name string, skey, hws ports.Kind) string {
	switch {
	case hasArtefact(r, ports.NamedRef{Name: name, Kind: hws}):
		return "hardware wallet"
	case hasArtefact(r, ports.NamedRef{Name: name, Kind: skey}):
		return "this workspace"
	}
	return "NOT in this workspace"
}

// poolSlots lists the signatures of a registration (cold key, payer, every
// owner: SPO-05c-INV-005) or of a retirement (payer, cold key), with who
// holds each.
func poolSlots(r ports.NamedReader, d *pool.Descriptor, poolN, payer string, retire bool, coll *pool.Collection, labels ...partyLabeler) []slotInfo {
	cold := slotInfo{name: poolN + ".node", role: string(custody.RolePoolCold), holder: holderText(r, poolN, ports.NodeSKey, ports.NodeHwsFile)}.withKey(r, custody.RolePoolCold, poolN)
	pay := slotInfo{name: payer, role: string(custody.RolePayment), holder: holderText(r, payer, ports.AddrSKey, ports.AddrHwsFile)}.withKey(r, custody.RolePayment, payer)
	if retire {
		return []slotInfo{pay, cold}
	}
	out := []slotInfo{cold, pay}
	if owners, _, err := d.Owners(); err == nil {
		for _, o := range owners {
			s := slotInfo{name: o.Name + ".staking", role: string(custody.RoleStake)}
			if o.IsLocal() {
				s.holder = holderText(r, o.Name, ports.StakingSKey, ports.StakingHwsFile)
				s = s.withKey(r, custody.RoleStake, o.Name)
			} else {
				s.holder = "signs elsewhere (" + o.Witness + ")"
			}
			out = append(out, s)
		}
	}
	if coll != nil {
		for i := range out {
			if sl, ok := coll.Slot(out[i].name); ok {
				f := sl.Filled()
				out[i].signed = &f
				if sl.Assigned() {
					var lab partyLabeler
					if len(labels) > 0 {
						lab = labels[0]
					}
					out[i].holder = "remote party " + lab.label(r, sl.PartyFingerprint)
				}
			}
		}
	}
	return out
}

func printSlots(w io.Writer, slots []slotInfo) {
	fmt.Fprintln(w, "  signatures")
	for _, s := range slots {
		state := ""
		if s.signed != nil {
			state = "  [missing]"
			if *s.signed {
				state = "  [signed]"
			}
		}
		fmt.Fprintf(w, "    %-28s %-10s %s%s\n", s.name, s.role, s.holder, state)
	}
}

// printPoolSummary writes the summary of a pool registration or retirement.
// It holds names, ids, amounts, URLs and hashes and no key material, and
// never the registration protection key.
func printPoolSummary(ctx context.Context, w io.Writer, store ports.NamedStore, ids ports.TxIDCalculator, s ports.TxSummary, labels ...partyLabeler) {
	title := map[string]string{
		"pool registration":    "Pool registration: first registration (pays the pool deposit)",
		"pool re-registration": "Pool re-registration: an update of a registered pool (no deposit)",
		"pool retirement":      "Pool retirement: retirement certificate only (no deposit moves)",
	}[s.Kind]
	if s.Stage == "body" {
		title += ", before the witnesses are collected"
	}
	fmt.Fprintf(w, "\n%s\n", title)
	fmt.Fprintf(w, "  pool         %s\n", shown(s.Account))
	fmt.Fprintf(w, "  pool id      %s\n", s.Pool)
	var d *pool.Descriptor
	var slots []slotInfo
	if store != nil {
		_ = store.View(ctx, func(r ports.NamedReader) error {
			b, err := r.Get(ports.NamedRef{Name: s.Account, Kind: ports.PoolDescriptor})
			if err != nil {
				return nil
			}
			if d, err = pool.ParseDescriptor(b); err != nil {
				d = nil
				return nil
			}
			var coll *pool.Collection
			if ids != nil {
				coll, _ = d.Collection(ids.TransactionID)
			}
			slots = poolSlots(r, d, s.Account, s.Source, s.Kind == "pool retirement", coll, labels...)
			return nil
		})
		if len(labels) > 0 {
			labels[0].describe(ctx, store, slots) // after the view: the directory reads the store itself
		}
	}
	if s.Kind == "pool retirement" {
		if d != nil {
			fmt.Fprintf(w, "  ticker       %s\n", shown(d.Text(pool.FieldMetaTicker)))
			fmt.Fprintf(w, "  retires at   epoch %s\n", d.Text(pool.FieldDeregEpoch))
		}
	} else {
		fmt.Fprintf(w, "  pledge       %s\n", lovelaceText(s.Pledge))
		if d != nil {
			cost, _ := pool.ParseLovelace(d.Text(pool.FieldCost))
			fmt.Fprintf(w, "  cost         %s per epoch\n", lovelaceText(cost))
			fmt.Fprintf(w, "  margin       %s\n", d.Text(pool.FieldMargin))
			fmt.Fprintf(w, "  reward acct  %s\n", shown(d.Text(pool.FieldRewards)))
			if owners, _, err := d.Owners(); err == nil {
				for _, o := range owners {
					wit := o.Witness
					if o.IsLocal() {
						wit = "local"
					}
					fmt.Fprintf(w, "  owner        %s (%s)\n", o.Name, wit)
				}
			}
			if rels, err := d.Relays(); err == nil {
				for _, r := range rels {
					fmt.Fprintf(w, "  relay        %s %s", r.Type, shown(r.Entry))
					if r.Port != "" {
						fmt.Fprintf(w, ":%s", r.Port)
					}
					fmt.Fprintln(w)
				}
			}
			fmt.Fprintf(w, "  ticker       %s\n", shown(d.Text(pool.FieldMetaTicker)))
			fmt.Fprintf(w, "  metadata     %s\n", shown(d.Text(pool.FieldMetaURL)))
			fmt.Fprintf(w, "  meta hash    %s\n", shown(d.Text(pool.FieldMetaHash)))
		}
		if s.Deposit > 0 {
			fmt.Fprintf(w, "  deposit      %s (paid)\n", lovelaceText(s.Deposit))
		} else {
			fmt.Fprintf(w, "  deposit      none\n")
		}
	}
	if s.Source != "" {
		fmt.Fprintf(w, "  paid by      %s\n", shown(s.Source))
	}
	if len(s.Attachments) > 0 {
		for _, at := range s.Attachments {
			fmt.Fprintf(w, "  attaches     %s\n", shown(at))
		}
	}
	if s.Inputs > 0 {
		fmt.Fprintf(w, "  inputs       %d\n", s.Inputs)
	}
	for i, o := range s.Outputs {
		label := "output"
		if i == len(s.Outputs)-1 {
			label = "change"
		}
		fmt.Fprintf(w, "  %-12s %s  %s\n", label, shown(string(o.Address)), lovelaceText(o.Lovelace))
	}
	if s.Fee > 0 {
		fmt.Fprintf(w, "  fee          %s\n", lovelaceText(s.Fee))
	} else {
		fmt.Fprintf(w, "  fee          (shown with the final transaction)\n")
	}
	if s.TTL > 0 {
		fmt.Fprintf(w, "  valid until  slot %d\n", s.TTL)
	}
	for _, m := range s.Message {
		fmt.Fprintf(w, "  message      %s\n", shown(m))
	}
	if s.TxID != (chain.TxID{}) {
		fmt.Fprintf(w, "  tx id        %s\n", s.TxID)
	}
	if s.Route != "" {
		fmt.Fprintf(w, "  route        %s\n", s.Route)
	}
	if len(slots) > 0 {
		printSlots(w, slots)
	}
	if len(s.Sources) > 0 {
		names := make([]string, len(s.Sources))
		for i, src := range s.Sources {
			names[i] = shown(string(src))
		}
		fmt.Fprintf(w, "  checked via  %s\n", strings.Join(names, ", "))
	}
	if s.SingleSource {
		fmt.Fprintf(w, "  WARNING      the registration state rests on ONE source, acknowledged with --single-source\n")
	}
	if s.Kind != "pool retirement" {
		fmt.Fprintf(w, "  WARNING      the pledge must stay in the owners' delegated stake while the pool is registered, and the deposit comes back only when the pool retires\n")
	}
	for _, u := range s.Unchecked {
		fmt.Fprintf(w, "  NOT CHECKED  %s\n", shown(u))
	}
	for _, n := range s.Notes {
		fmt.Fprintf(w, "  NOTE         %s\n", shown(n))
	}
	fmt.Fprintln(w)
}

// partyLabeler names a party by its fingerprint for display: the label the
// operator gave it in the registry. A fingerprint with no entry (or no
// registry) is shown as the fingerprint. It is display only; a slot is routed
// by the fingerprint, never by a label (ADR 0010 decision 4).
type partyLabeler struct {
	reg     ports.PartyRegistry
	signers ports.SignerDirectory
}

func (l partyLabeler) label(r ports.NamedReader, fp party.Fingerprint) string {
	if l.reg != nil && r != nil {
		if p, err := l.reg.ByFingerprint(r, fp); err == nil && p.Name != "" {
			return safeText(p.Name)
		}
	}
	return fp.String()
}

func labelerOf(env *Env) partyLabeler {
	l := partyLabeler{}
	if env != nil && env.Party != nil {
		l.reg = env.Party.Registry
	}
	if env != nil {
		l.signers = env.Signers
	}
	return l
}

// describe says who signs each slot that has a key, by asking the signer
// directory that will sign: the answer shown to the operator is the plan's. A
// key that answers through another name (one verification key stored under two
// names) says so and names the record that signs. It must be called outside any
// store view.
func (l partyLabeler) describe(ctx context.Context, nstore ports.NamedStore, slots []slotInfo) {
	if l.signers == nil {
		return
	}
	_ = nstore
	for i := range slots {
		s := &slots[i]
		if !s.haveKey || strings.HasPrefix(s.holder, "signs elsewhere") || strings.HasPrefix(s.holder, "remote party") {
			continue
		}
		conn, err := l.signers.Connected(s.key)
		var text string
		switch {
		case err != nil:
			text = "NOT signable here: " + err.Error()
		case len(conn) == 0 && hwkeys.OnDevice(l.signers, s.key):
			text = "hardware wallet (none connected)"
		case len(conn) == 0:
			text = "NOT in this workspace"
		case hwkeys.IsHardware(conn[0].Signer):
			text = "hardware wallet"
		case conn[0].Deferred:
			text = "signs elsewhere (a co-signer)"
		default:
			text = "this workspace"
		}
		// One key is a member of one owner (ADR 0010): the record that signs is the
		// slot's own, so there is no other name to show.
		s.holder = text
	}
}
