package workspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// wsSnapshot is what the workspace held before an import wrote anything. It is
// taken once, before the first write of a run, and every decision of the run
// (does the workspace hold a wallet of that name, do two wallets have the same
// keys, which artefacts would be replaced) is made from it, never from the
// state the run itself has produced so far. So a dry run and the real run
// decide alike (SPO-Xmulti-INV-003).
type wsSnapshot struct {
	owners map[string]*wsOwner
	fold   map[string][]string
}

// wsOwner is one owner of the workspace: every artefact it has, and the
// content of the non-secret ones for the owners the run names.
type wsOwner struct {
	name string
	refs map[ports.NamedRef]bool
	data map[ports.NamedRef][]byte
}

func (s *wsSnapshot) owner(name string) *wsOwner {
	if s == nil {
		return nil
	}
	return s.owners[name]
}

// sameFolded returns the names of the owners that equal name apart from case
// and are not name itself.
func (s *wsSnapshot) sameFolded(name string) []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, n := range s.fold[strings.ToLower(name)] {
		if n != name {
			out = append(out, n)
		}
	}
	return out
}

func (s *wsSnapshot) has(r ports.NamedRef) bool {
	if s == nil {
		return false
	}
	o := s.owners[OwnerOf(r)]
	return o != nil && o.refs[r]
}

func (s *wsSnapshot) get(r ports.NamedRef) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	o := s.owners[OwnerOf(r)]
	if o == nil {
		return nil, false
	}
	b, ok := o.data[r]
	return b, ok
}

func (s *wsSnapshot) hasWallet(name string) bool {
	return s.has(ports.NamedRef{Name: name, Kind: ports.StakingVKey})
}

// probeRefs are the artefacts looked for, by name, when the destination cannot
// list itself.
func probeRefs(name string) []ports.NamedRef {
	return []ports.NamedRef{
		{Name: name, Kind: ports.StakingVKey}, {Name: name, Kind: ports.StakingSKey}, {Name: name, Kind: ports.StakingAddr},
		{Name: name + ".payment", Kind: ports.AddrVKey}, {Name: name + ".payment", Kind: ports.AddrSKey}, {Name: name + ".payment", Kind: ports.AddrFile},
		{Name: name, Kind: ports.NodeVKey}, {Name: name, Kind: ports.NodeSKey}, {Name: name, Kind: ports.NodeCounter},
		{Name: name, Kind: ports.PoolDescriptor}, {Name: name, Kind: ports.VrfVKey}, {Name: name, Kind: ports.KesCounter},
	}
}

// snapshot reads the destination: which owners it holds, and the content of
// the non-secret artefacts of the owners called `names` (any case). A
// destination that is not a SourceLister is probed for those names only.
func (u ImportWorkspace) snapshot(ctx context.Context, names []string) (*wsSnapshot, error) {
	s := &wsSnapshot{owners: map[string]*wsOwner{}, fold: map[string][]string{}}
	if u.Dest == nil {
		return s, nil
	}
	add := func(r ports.NamedRef) {
		if !ports.IsWorkspaceKind(r.Kind) {
			return
		}
		n := OwnerOf(r)
		o := s.owners[n]
		if o == nil {
			o = &wsOwner{name: n, refs: map[ports.NamedRef]bool{}, data: map[ports.NamedRef][]byte{}}
			s.owners[n] = o
			s.fold[strings.ToLower(n)] = append(s.fold[strings.ToLower(n)], n)
		}
		o.refs[r] = true
	}
	if l, ok := u.Dest.(ports.SourceLister); ok {
		listing, err := l.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, e := range listing.Entries {
			add(e.Ref)
		}
	} else {
		err := u.Dest.View(ctx, func(rd ports.NamedReader) error {
			for _, n := range names {
				for _, r := range probeRefs(n) {
					if r.Validate() != nil {
						continue
					}
					if ok, err := rd.Exists(r); err == nil && ok {
						add(r)
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	for _, o := range s.owners {
		// The verification keys and the stake address identify a wallet, and
		// the descriptor names the wallets a pool depends on; they are read for
		// every owner; the owners the run names are read whole.
		whole := want[strings.ToLower(o.name)]
		refs := make([]ports.NamedRef, 0, len(o.refs))
		for r := range o.refs {
			if r.Kind.Secret() {
				continue
			}
			if whole || r.Kind == ports.StakingVKey || r.Kind == ports.AddrVKey || r.Kind == ports.StakingAddr || r.Kind == ports.PoolDescriptor {
				refs = append(refs, r)
			}
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
		err := u.Dest.View(ctx, func(rd ports.NamedReader) error {
			for _, r := range refs {
				if b, err := rd.Get(r); err == nil {
					o.data[r] = b
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// conflicts reports whether the snapshot holds any artefact of the plan.
func (s *wsSnapshot) conflicts(plan []planned) bool {
	for _, p := range plan {
		if s.has(p.dst) {
			return true
		}
	}
	return false
}

func (o *wsOwner) kind() OwnerKind {
	refs := make([]ports.NamedRef, 0, len(o.refs))
	for r := range o.refs {
		refs = append(refs, r)
	}
	return kindOfRefs(refs)
}

// checkUnion runs the consistency checks over the artefacts the workspace
// already holds under the owner's stored name together with the ones about to
// be stored, so that an owner is never merged into another's artefacts it does
// not belong with (SPO-Xmulti-OUT-011). The incoming artefacts replace existing
// ones of the same reference. It returns the failures of incoming artefacts by
// their source reference, and a reason for a failure of an existing artefact.
func (u ImportWorkspace) checkUnion(ctx context.Context, ws *wsSnapshot, final string, plan []planned) (fails map[ports.NamedRef]string, general string) {
	fails = map[ports.NamedRef]string{}
	o := ws.owner(final)
	if o == nil {
		return fails, ""
	}
	d := ownerData{open: map[ports.NamedRef][]byte{}, skey: map[ports.NamedRef]*ports.Secret{}}
	incoming := map[ports.NamedRef]ports.NamedRef{}
	for _, p := range plan {
		incoming[p.dst] = p.src
	}
	for r, b := range o.data {
		d.open[r] = b
	}
	if v, ok := u.Dest.(ports.NamedVault); ok {
		for r := range o.refs {
			if _, in := incoming[r]; in || !r.Kind.IsSigningKey() {
				continue
			}
			if buf, err := v.Open(ctx, r); err == nil {
				defer buf.Destroy()
				d.skey[r] = buf
			}
		}
	}
	for _, p := range plan {
		switch {
		case p.sec == nil:
			d.open[p.dst] = p.data
		case p.dst.Kind.IsSigningKey():
			d.skey[p.dst] = p.sec
		}
	}
	bad, _ := checker{deriver: u.Deriver, addresses: u.Addresses}.check(ctx, d)
	for r, why := range bad {
		if src, ok := incoming[r]; ok {
			fails[src] = why + " (checked together with the artefacts the workspace already holds under this name)"
		} else if general == "" {
			general = "together with the workspace's existing " + r.String() + ": " + why
		}
	}
	return fails, general
}

// commitRun stores every planned owner of a selective run in one Update, or
// none. The snapshot and the gates were read before it (the store cannot list
// or open secrets from inside an Update, and a decryption is slow work), so the
// Update first re-reads what the decisions rested on and refuses with
// ports.ErrConflict when the workspace is no longer what the snapshot saw: an
// artefact the snapshot held that is gone or changed, or one the run is to
// write, or one of the owners it names, that now exists although it did not
// (SPO-Xmulti-INV-008). The rows of the owners that were to be written say what
// became of them.
func (u ImportWorkspace) commitRun(ctx context.Context, ws *wsSnapshot, names []string, order []*found, prep map[*found]*prepared, outs map[*found]OwnerReport, opts ImportOptions) {
	var plan []planned
	var rows []*found
	for _, f := range order {
		if o := outs[f]; o.Would && !o.Written {
			plan = append(plan, prep[f].plan...)
			rows = append(rows, f)
		}
	}
	if len(rows) == 0 {
		return
	}
	err := u.Dest.Update(ctx, func(w ports.NamedWriter) error {
		if err := verifySnapshot(w, ws, names, plan); err != nil {
			return err
		}
		if !opts.Overwrite {
			for _, p := range plan {
				if ok, err := w.Exists(p.dst); err != nil {
					return err
				} else if ok {
					return errConflict
				}
			}
		}
		for _, p := range plan {
			var err error
			if p.sec != nil {
				err = w.PutSecret(p.dst, p.sec)
			} else {
				err = w.Put(p.dst, p.data)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	for _, f := range rows {
		o, p := outs[f], prep[f]
		o.Would = false
		if err == nil {
			o.Written, p.written = true, true
			for i := range o.Artefacts {
				if o.Artefacts[i].Status == StatusPlanned {
					o.Artefacts[i].Status = StatusDone
				}
			}
		} else {
			o.Reason = "nothing of this run was imported: " + runReason(err)
			p.written = false
			for i := range o.Artefacts {
				if o.Artefacts[i].Status == StatusPlanned {
					o.Artefacts[i].Status, o.Artefacts[i].Reason = StatusSkipped, "the owner was not imported: "+o.Reason
				}
			}
		}
		outs[f] = o
	}
}

func runReason(err error) string {
	switch {
	case errors.Is(err, ports.ErrConflict):
		return "the workspace changed while the import was running (an artefact it had read was changed, or one it would write appeared); run it again"
	case errors.Is(err, errConflict):
		return commitReason(err)
	}
	return "the destination could not be written: " + err.Error()
}

// verifySnapshot re-reads, inside the transaction, what the run decided from.
func verifySnapshot(r ports.NamedReader, ws *wsSnapshot, names []string, plan []planned) error {
	moved := fmt.Errorf("%w", ports.ErrConflict)
	owners := make([]string, 0, len(ws.owners))
	for n := range ws.owners {
		owners = append(owners, n)
	}
	sort.Strings(owners)
	for _, n := range owners {
		o := ws.owners[n]
		refs := make([]ports.NamedRef, 0, len(o.refs))
		for ref := range o.refs {
			refs = append(refs, ref)
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
		for _, ref := range refs {
			ok, err := r.Exists(ref)
			if err != nil {
				return err
			}
			if !ok {
				return moved
			}
			want, read := o.data[ref]
			if !read {
				continue
			}
			got, err := r.Get(ref)
			if errors.Is(err, ports.ErrNotFound) || (err == nil && !bytes.Equal(got, want)) {
				return moved
			}
			if err != nil {
				return err
			}
		}
	}
	// What the snapshot did not hold must still be absent: the artefacts of the
	// plan and the probe set of every name the run looked at.
	var absent []ports.NamedRef
	for _, p := range plan {
		absent = append(absent, p.dst)
	}
	for _, n := range names {
		absent = append(absent, probeRefs(n)...)
	}
	for _, ref := range absent {
		if ref.Validate() != nil || ws.has(ref) {
			continue
		}
		if ok, err := r.Exists(ref); err != nil {
			return err
		} else if ok {
			return moved
		}
	}
	return nil
}
