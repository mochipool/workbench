package workspace

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Gate B (SPO-Xmulti-INV-007). After the plan and before any write, every pool
// the plan would store is checked against the workspace as the plan would leave
// it: every name its final descriptor carries must be a wallet that exists
// there and holds the very keys of the source owner the layout names. The check
// recomputes from the final artefact sets of the plan and from the source files
// themselves; it does not call the resolver's binding (bindSelected, resolveRef)
// and so does not share a mistake with it. The names a descriptor carries are
// read from its bytes by the domain's own accessors, the ones the pool commands
// use (consumerNames), never by the enumeration the rewrite uses; of the
// resolver it uses only the lexical lookup of the owner a reference names in
// the layout (find).

// consumerNames reads every name a descriptor carries that refers to an owner,
// with the accessors the consumers use: Owners (poolOwner), Text of poolRewards
// and RegistrationNames (regWitness, the reader Collection uses). A descriptor
// the domain cannot read, or whose poolOwner or regWitness the consumers would
// refuse, is an error: it names nothing that can be checked.
func consumerNames(data []byte) ([]nameRef, error) {
	d, err := pool.ParseDescriptor(bytes.TrimPrefix(data, utf8BOM))
	if err != nil {
		return nil, err
	}
	var out []nameRef
	owners, legacy, oerr := d.Owners()
	switch {
	case oerr == nil:
		for i, o := range owners {
			f := "poolOwner[" + strconv.Itoa(i) + "].ownerName"
			if legacy {
				f = "poolOwner"
			}
			out = append(out, nameRef{field: f, name: o.Name})
		}
	}
	// A poolOwner the pool commands cannot read makes the whole descriptor
	// unusable to them (they refuse it), so it binds nothing.
	if rw := d.Text(pool.FieldRewards); rw != "" {
		out = append(out, nameRef{field: "poolRewards", name: rw})
	}
	rn, err := d.RegistrationNames()
	if err != nil {
		return nil, fmt.Errorf("its open registration cannot be read: %w", err)
	}
	if rn.Pay != "" {
		out = append(out, nameRef{field: "regWitness.regPayName", name: rn.Pay})
	}
	slots := append([]string(nil), rn.Slots...)
	sort.Strings(slots)
	for _, k := range slots {
		n, node := k, false
		if c, ok := strings.CutSuffix(n, ".node"); ok {
			n, node = c, true
		} else if c, ok := strings.CutSuffix(n, ".staking"); ok {
			n = c
		}
		out = append(out, nameRef{field: fmt.Sprintf("regWitness.witnesses[%q]", k), name: n, self: node})
	}
	for _, tok := range strings.FieldsFunc(rn.MetadataFiles, func(r rune) bool { return strings.ContainsRune(" ,\"'\t\n", r) }) {
		base := path.Base(strings.ReplaceAll(tok, `\`, "/"))
		for _, suffix := range []string{".metadata.json", ".extended-metadata.json", ".additional-metadata.json"} {
			if n, ok := strings.CutSuffix(base, suffix); ok && n != "" {
				out = append(out, nameRef{field: "regWitness.metadataFilesList", name: n, self: true})
				break
			}
		}
	}
	return out, nil
}

// endOwner is one owner of the workspace after the plan.
type endOwner struct {
	refs map[ports.Ref]bool
	data map[ports.Ref][]byte
}

func (e *endOwner) kind() OwnerKind {
	refs := make([]ports.Ref, 0, len(e.refs))
	for r := range e.refs {
		refs = append(refs, r)
	}
	return kindOfRefs(refs)
}

// endState is the workspace as the plan would leave it: the snapshot, with the
// artefacts of every owner the plan stores laid over it.
func endState(ws *wsSnapshot, order []*found, prep map[*found]*prepared) map[string]*endOwner {
	end := map[string]*endOwner{}
	if ws != nil {
		for n, o := range ws.owners {
			eo := &endOwner{refs: map[ports.Ref]bool{}, data: map[ports.Ref][]byte{}}
			for r := range o.refs {
				eo.refs[r] = true
			}
			for r, b := range o.data {
				eo.data[r] = b
			}
			end[n] = eo
		}
	}
	for _, f := range order {
		p := prep[f]
		if p == nil || p.fixed || !p.ok() {
			continue
		}
		eo := end[f.final]
		if eo == nil {
			eo = &endOwner{refs: map[ports.Ref]bool{}, data: map[ports.Ref][]byte{}}
			end[f.final] = eo
		}
		for _, it := range p.plan {
			eo.refs[it.dst] = true
			if it.sec == nil {
				eo.data[it.dst] = it.data
			}
		}
	}
	return end
}

// checkBinding refuses (sets the refusal of) each planned pool whose final
// descriptor names an owner the end state does not bind to the source owner the
// layout names, and each planned owner that would change a wallet which a pool
// of the workspace's end state, stored by this run or not, names. It repeats
// until a pass refuses nothing new: a refusal changes the end state.
//
// spec: SPO-Xmulti-INV-006, SPO-Xmulti-INV-007, SPO-Xmulti-INV-009
func (u ImportWorkspace) checkBinding(ctx context.Context, res *resolver, ws *wsSnapshot, order []*found, prep map[*found]*prepared) {
	for pass := 0; pass <= len(order); pass++ {
		end := endState(ws, order, prep)
		changed := false
		for _, f := range order {
			p := prep[f]
			if p == nil || p.fixed || !p.ok() || f.kind != KindPool {
				continue
			}
			var final []byte
			for _, it := range p.plan {
				if it.dst.Kind == ports.PoolDescriptor && it.sec == nil {
					final = it.data
				}
			}
			if final == nil {
				continue
			}
			if why := u.bindingFailure(ctx, res, ws, end, f, p, final); why != "" {
				p.refusal = why
				changed = true
			}
		}
		if endPoolsFailure(ws, end, order, prep) {
			changed = true
		}
		if !changed {
			return
		}
	}
}

// endPoolsFailure checks every pool of the end state whose descriptor this run
// does not store: a name it carries that is an owner this run stores must still
// be the wallet the workspace holds now (same stake verification key, same
// payment verification keys). Otherwise the pool would be left naming a wallet
// that is another one, and the planned owner is refused, naming the pools.
func endPoolsFailure(ws *wsSnapshot, end map[string]*endOwner, order []*found, prep map[*found]*prepared) bool {
	touched := map[string]*found{}
	replaced := map[string]bool{}
	for _, f := range order {
		p := prep[f]
		if p == nil || p.fixed || !p.ok() {
			continue
		}
		touched[f.final] = f
		for _, it := range p.plan {
			if it.dst.Kind == ports.PoolDescriptor && it.sec == nil {
				replaced[f.final] = true
			}
		}
	}
	pools := make([]string, 0, len(end))
	for n, eo := range end {
		if !replaced[n] && eo.kind() == KindPool {
			pools = append(pools, n)
		}
	}
	sort.Strings(pools)
	blame := map[*found][]string{}
	var why = map[*found]string{}
	for _, pn := range pools {
		desc, ok := end[pn].data[ports.Ref{Name: pn, Kind: ports.PoolDescriptor}]
		if !ok {
			continue
		}
		names, err := consumerNames(desc)
		if err != nil {
			continue
		}
		for _, nr := range names {
			f := touched[nr.name]
			if nr.self || f == nil {
				continue
			}
			if w := changedWallet(ws, end, nr.name); w != "" {
				blame[f] = append(blame[f], fmt.Sprintf("%s (%s)", pn, nr.field))
				why[f] = w
			}
		}
	}
	changed := false
	for f, ps := range blame {
		prep[f].refusal = fmt.Sprintf("it would change the wallet %q (%s), which the workspace pool(s) %s name and this run does not replace: the pool would be left naming a wallet that is another one; import the wallet under a new name, or import it together with those pools", f.final, why[f], strings.Join(capList(ps, 4), ", "))
		changed = true
	}
	return changed
}

// changedWallet says how the wallet `name` of the end state is no longer the
// wallet the workspace holds now: its stake or payment verification key
// differs, or it is no longer a wallet. A wallet the workspace does not hold
// has no pool naming it that this could break.
func changedWallet(ws *wsSnapshot, end map[string]*endOwner, name string) string {
	wsStake, had := ws.get(ports.Ref{Name: name, Kind: ports.StakingVKey})
	if !had {
		return ""
	}
	own := end[name]
	if own == nil || own.kind() != KindWallet {
		return "it would no longer be a wallet"
	}
	if !bytes.Equal(rawOf(wsStake), rawOf(own.data[ports.Ref{Name: name, Kind: ports.StakingVKey}])) {
		return "its stake verification key would change"
	}
	for _, r := range []ports.Ref{{Name: name + ".payment", Kind: ports.AddrVKey}, {Name: name, Kind: ports.AddrVKey}} {
		if wb, ok := ws.get(r); ok {
			if eb := own.data[r]; eb == nil || !bytes.Equal(rawOf(wb), rawOf(eb)) {
				return "its payment verification key would change"
			}
		}
	}
	return ""
}

func (u ImportWorkspace) bindingFailure(ctx context.Context, res *resolver, ws *wsSnapshot, end map[string]*endOwner, f *found, p *prepared, final []byte) string {
	srcRefs := map[string]string{}
	srcDesc := ports.Ref{Name: f.name, Kind: ports.PoolDescriptor}
	if b, err := u.read(ctx, f.src, srcDesc); err == nil {
		if names, err := consumerNames(b); err == nil {
			for _, nr := range names {
				srcRefs[nr.field] = nr.name
			}
		}
	}
	var note string
	if a := p.results[srcDesc]; a != nil {
		note = a.Note
	}
	names, err := consumerNames(final)
	if err != nil {
		return fmt.Sprintf("refused because the pool commands could not read the descriptor this import would store: %v", err)
	}
	for _, nr := range names {
		fail := func(cond string) string {
			return fmt.Sprintf("refused because %s names %q and the workspace after this import would not bind it to the right wallet: %s", nr.field, nr.name, cond)
		}
		if nr.self {
			if nr.name != f.final {
				return fail("it names another pool than this one")
			}
			continue
		}
		for n := range end {
			if n != nr.name && strings.EqualFold(n, nr.name) {
				return fail(fmt.Sprintf("it differs only by case from the owner %q", n))
			}
		}
		for _, o := range res.all {
			if o.name != nr.name && strings.EqualFold(o.name, nr.name) {
				return fail(fmt.Sprintf("it differs only by case from the source owner %q in %s", o.name, o.dir))
			}
		}
		// 1. an owner of exactly that name will exist, as a wallet with a stake key
		own := end[nr.name]
		if own == nil {
			return fail("no owner of that name will exist")
		}
		if k := own.kind(); k != KindWallet {
			return fail(fmt.Sprintf("the owner of that name will be a %s, not a wallet", k))
		}
		stake := rawOf(own.data[ports.Ref{Name: nr.name, Kind: ports.StakingVKey}])
		if stake == nil {
			return fail("the wallet of that name will have no stake verification key")
		}
		// 2. the source owner the layout names has the very keys
		srcVal, named := srcRefs[nr.field]
		var g *found
		if named {
			if g, _, _, _ = res.find(f, srcVal); g != nil {
				sb, err := u.read(ctx, g.src, ports.Ref{Name: g.name, Kind: ports.StakingVKey})
				srcStake := rawOf(sb)
				if err != nil || srcStake == nil {
					return fail(fmt.Sprintf("the source owner %q in %s has no stake verification key", g.name, g.dir))
				}
				if !bytes.Equal(stake, srcStake) {
					return fail(fmt.Sprintf("the stake verification key of the wallet differs from the one of the source owner %q in %s", g.name, g.dir))
				}
				payRef := ports.Ref{Name: g.name + ".payment", Kind: ports.AddrVKey}
				if hasRef(g.refs, payRef) {
					pb, err := u.read(ctx, g.src, payRef)
					srcPay := rawOf(pb)
					if err != nil {
						return fail(fmt.Sprintf("the payment verification key of the source owner %q in %s cannot be read", g.name, g.dir))
					}
					if ownPay := rawOf(own.data[ports.Ref{Name: nr.name + ".payment", Kind: ports.AddrVKey}]); ownPay != nil && srcPay != nil && !bytes.Equal(ownPay, srcPay) {
						return fail(fmt.Sprintf("the payment verification key of the wallet differs from the one of the source owner %q in %s", g.name, g.dir))
					}
				}
				continue
			}
		}
		// 3. no source owner is named: the wallet is the workspace's own, unchanged
		// by this import, and the note says so
		wsStake := rawOf(func() []byte { b, _ := ws.get(ports.Ref{Name: nr.name, Kind: ports.StakingVKey}); return b }())
		if wsStake == nil || !bytes.Equal(wsStake, stake) {
			return fail("no source owner of that name is named by the layout, and the wallet would not be the one the workspace holds now")
		}
		if !strings.Contains(note, nr.field+" is bound to the existing workspace wallet") {
			return fail("the binding to the workspace's wallet carries no note")
		}
	}
	return ""
}

// staleWitnesses refuses a pool whose witness transfer files
// (`<pool>_<slot>_<id>.witness`) name an owner, or the pool itself, that this
// run stores under another name: the files keep the old name inside the file
// name and the signing name, so they would name an owner that no longer exists
// (SPO-Xmulti-OUT-017).
func (r *resolver) staleWitnesses(f *found) string {
	for _, ref := range f.refs {
		if ref.Kind != ports.PoolWitnessFile {
			continue
		}
		rest := strings.TrimPrefix(ref.Name, f.name+"_")
		if i := strings.LastIndex(rest, "_"); i > 0 {
			rest = rest[:i]
		}
		slot := strings.TrimSuffix(strings.TrimSuffix(rest, ".node"), ".staking")
		if slot == f.name && f.final != f.name {
			return fmt.Sprintf("it holds the witness file %s, which names the pool as %q, and the pool is stored as %q; the file would name a pool that does not exist: finish or discard the registration in the source first, or import without a rename", ref.String(), slot, f.final)
		}
		for _, o := range r.all {
			if o.selected && o.name == slot && o.final != o.name {
				return fmt.Sprintf("it holds the witness file %s, which names the owner %q, and that owner is stored as %q in this run; the file would name an owner that no longer exists under that name: finish or discard the registration in the source first, or import without that rename", ref.String(), slot, o.final)
			}
		}
	}
	return ""
}
