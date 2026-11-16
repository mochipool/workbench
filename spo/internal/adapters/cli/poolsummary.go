package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
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
	store ports.Store
	ids   ports.TxIDCalculator
}

func isPoolKind(kind string) bool {
	return kind == "pool registration" || kind == "pool re-registration" || kind == "pool retirement"
}

func (c poolConfirmer) Confirm(ctx context.Context, sum ports.TxSummary) (bool, error) {
	if !isPoolKind(sum.Kind) {
		return terminalConfirmer{c.a}.Confirm(ctx, sum)
	}
	printPoolSummary(ctx, c.a.d.Out, c.store, c.ids, sum)
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
}

func hasArtefact(r ports.Reader, ref ports.Ref) bool {
	ok, err := r.Exists(ref)
	return err == nil && ok
}

// holderText says who signs, from what the store holds. It never reads a key.
func holderText(r ports.Reader, name string, skey, hws ports.Kind) string {
	switch {
	case hasArtefact(r, ports.Ref{Name: name, Kind: hws}):
		return "hardware wallet"
	case hasArtefact(r, ports.Ref{Name: name, Kind: skey}):
		return "this workspace"
	}
	return "NOT in this workspace"
}

// poolSlots lists the signatures of a registration (cold key, payer, every
// owner: SPO-05c-INV-005) or of a retirement (payer, cold key), with who
// holds each.
func poolSlots(r ports.Reader, d *pool.Descriptor, poolN, payer string, retire bool, coll *pool.Collection) []slotInfo {
	cold := slotInfo{name: poolN + ".node", role: string(custody.RolePoolCold), holder: holderText(r, poolN, ports.NodeSKey, ports.NodeHwsFile)}
	pay := slotInfo{name: payer, role: string(custody.RolePayment), holder: holderText(r, payer, ports.AddrSKey, ports.AddrHwsFile)}
	if retire {
		return []slotInfo{pay, cold}
	}
	out := []slotInfo{cold, pay}
	if owners, _, err := d.Owners(); err == nil {
		for _, o := range owners {
			s := slotInfo{name: o.Name + ".staking", role: string(custody.RoleStake)}
			if o.IsLocal() {
				s.holder = holderText(r, o.Name, ports.StakingSKey, ports.StakingHwsFile)
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
				if sl.Holder == custody.HolderRemote && sl.Party != "" {
					out[i].holder = "remote party " + sl.Party
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
func printPoolSummary(ctx context.Context, w io.Writer, store ports.Store, ids ports.TxIDCalculator, s ports.TxSummary) {
	title := map[string]string{
		"pool registration":    "Pool registration: first registration (pays the pool deposit)",
		"pool re-registration": "Pool re-registration: an update of a registered pool (no deposit)",
		"pool retirement":      "Pool retirement: retirement certificate only (no deposit moves)",
	}[s.Kind]
	if s.Stage == "body" {
		title += ", before the witnesses are collected"
	}
	fmt.Fprintf(w, "\n%s\n", title)
	fmt.Fprintf(w, "  pool         %s\n", s.Account)
	fmt.Fprintf(w, "  pool id      %s\n", s.Pool)
	var d *pool.Descriptor
	var slots []slotInfo
	if store != nil {
		_ = store.View(ctx, func(r ports.Reader) error {
			b, err := r.Get(ports.Ref{Name: s.Account, Kind: ports.PoolDescriptor})
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
			slots = poolSlots(r, d, s.Account, s.Source, s.Kind == "pool retirement", coll)
			return nil
		})
	}
	if s.Kind == "pool retirement" {
		if d != nil {
			fmt.Fprintf(w, "  ticker       %s\n", d.Text(pool.FieldMetaTicker))
			fmt.Fprintf(w, "  retires at   epoch %s\n", d.Text(pool.FieldDeregEpoch))
		}
	} else {
		fmt.Fprintf(w, "  pledge       %s\n", lovelaceText(s.Pledge))
		if d != nil {
			cost, _ := pool.ParseLovelace(d.Text(pool.FieldCost))
			fmt.Fprintf(w, "  cost         %s per epoch\n", lovelaceText(cost))
			fmt.Fprintf(w, "  margin       %s\n", d.Text(pool.FieldMargin))
			fmt.Fprintf(w, "  reward acct  %s\n", d.Text(pool.FieldRewards))
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
					fmt.Fprintf(w, "  relay        %s %s", r.Type, r.Entry)
					if r.Port != "" {
						fmt.Fprintf(w, ":%s", r.Port)
					}
					fmt.Fprintln(w)
				}
			}
			fmt.Fprintf(w, "  ticker       %s\n", d.Text(pool.FieldMetaTicker))
			fmt.Fprintf(w, "  metadata     %s\n", d.Text(pool.FieldMetaURL))
			fmt.Fprintf(w, "  meta hash    %s\n", d.Text(pool.FieldMetaHash))
		}
		if s.Deposit > 0 {
			fmt.Fprintf(w, "  deposit      %s (paid)\n", lovelaceText(s.Deposit))
		} else {
			fmt.Fprintf(w, "  deposit      none\n")
		}
	}
	if s.Source != "" {
		fmt.Fprintf(w, "  paid by      %s\n", s.Source)
	}
	if len(s.Attachments) > 0 {
		for _, at := range s.Attachments {
			fmt.Fprintf(w, "  attaches     %s\n", at)
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
		fmt.Fprintf(w, "  %-12s %s  %s\n", label, o.Address, lovelaceText(o.Lovelace))
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
		fmt.Fprintf(w, "  message      %s\n", m)
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
			names[i] = string(src)
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
		fmt.Fprintf(w, "  NOT CHECKED  %s\n", u)
	}
	fmt.Fprintln(w)
}
