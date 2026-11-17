package assets

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ApplyChange updates the asset record of a mint or a burn: it creates the
// record when absent, applies the change by the procedure of
// SPO-11a-OUT-002 and rewrites the file (locked at 0400 by the store).
//
// spec: SPO-11a-OUT-002, SPO-11a-OUT-003, SPO-11b-OUT-001, SPO-Pfiles-OUT-033
func ApplyChange(ctx context.Context, store ports.Store, record string, c assets.Change) error {
	ref := ports.Ref{Name: record, Kind: ports.AssetFile}
	return store.Update(ctx, func(w ports.Writer) error {
		return applyIn(w, ref, c)
	})
}

func applyIn(w ports.Writer, ref ports.Ref, c assets.Change) error {
	cur, err := w.Get(ref)
	if err != nil && !errors.Is(err, ports.ErrNotFound) {
		return err
	}
	rec, err := assets.ParseRecord(cur)
	if err != nil {
		return fmt.Errorf("%s: %w", ref, err)
	}
	next, err := rec.Apply(c)
	if err != nil {
		return fmt.Errorf("%s: %w", ref, err)
	}
	return w.Put(ref, next.Marshal())
}

// Applier changes the record a pending update stands for. It runs inside the
// store commit that removes the pending update, so the change and the removal
// are one step: a crash leaves both or neither (exactly once).
type Applier func(w ports.Writer, p assets.Pending, now time.Time) error

// Settle applies and removes pending updates (hazard H9). Asset updates are
// applied here; the other kinds (the pool registration and retirement records)
// are applied by the Appliers the composition hands in, so this package does
// not know the pool descriptor. A kind with no applier is an error, never
// skipped silently.
type Settle struct {
	Store ports.Store
	Clock ports.Clock
	// Appliers maps a pending kind to its applier; the asset kind is built in.
	Appliers map[string]Applier
}

func (s Settle) applier(kind string) (Applier, error) {
	if kind == assets.PendingAsset {
		return applyAsset, nil
	}
	if ap, ok := s.Appliers[kind]; ok && ap != nil {
		return ap, nil
	}
	return nil, fmt.Errorf("no applier for the pending update kind %q", kind)
}

func applyAsset(w ports.Writer, p assets.Pending, now time.Time) error {
	c, err := p.Change(now)
	if err != nil {
		return err
	}
	return applyIn(w, ports.Ref{Name: p.Record, Kind: ports.AssetFile}, c)
}

// pendingRefs are the places a pending update of a transaction can be: the
// current kind, and the first version's.
func pendingRefs(id string) []ports.Ref {
	return []ports.Ref{{Name: id, Kind: ports.PendingUpdate}, {Name: id, Kind: ports.AssetPending}}
}

func getPending(r ports.Reader, id string) (assets.Pending, ports.Ref, bool, error) {
	for _, ref := range pendingRefs(id) {
		b, err := r.Get(ref)
		if errors.Is(err, ports.ErrNotFound) {
			continue
		}
		if err != nil {
			return assets.Pending{}, ref, false, err
		}
		p, err := assets.ParsePending(b)
		if err != nil {
			return assets.Pending{}, ref, false, fmt.Errorf("the pending update of %s: %w", id, err)
		}
		return p, ref, true, nil
	}
	return assets.Pending{}, ports.Ref{}, false, nil
}

// PendingOf reads the pending update of a transaction, whichever version wrote it.
func PendingOf(ctx context.Context, store ports.Store, id chain.TxID) (assets.Pending, bool, error) {
	var p assets.Pending
	var found bool
	err := store.View(ctx, func(r ports.Reader) error {
		var err error
		p, _, found, err = getPending(r, id.String())
		return err
	})
	return p, found, err
}

// ListPending reads every pending update of the workspace, oldest name first.
// It needs the workspace's lister; without one it returns nothing and false.
func ListPending(ctx context.Context, store ports.Store, lister ports.SourceLister) ([]assets.Pending, bool, error) {
	if lister == nil {
		return nil, false, nil
	}
	l, err := lister.List(ctx)
	if err != nil {
		return nil, true, err
	}
	seen := map[string]bool{}
	var ids []string
	for _, e := range l.Entries {
		if (e.Ref.Kind == ports.PendingUpdate || e.Ref.Kind == ports.AssetPending) && !seen[e.Ref.Name] {
			seen[e.Ref.Name] = true
			ids = append(ids, e.Ref.Name)
		}
	}
	sort.Strings(ids)
	var out []assets.Pending
	err = store.View(ctx, func(r ports.Reader) error {
		for _, id := range ids {
			p, _, ok, err := getPending(r, id)
			if err != nil {
				return err
			}
			if ok {
				out = append(out, p)
			}
		}
		return nil
	})
	return out, true, err
}

// Apply applies and removes the pending update of the transaction, in one
// commit, and says whether there was one. A second call finds none and changes
// nothing. A transaction with no pending update is not an error.
func (s Settle) Apply(ctx context.Context, id chain.TxID) (assets.Pending, bool, error) {
	var got assets.Pending
	var found bool
	err := s.Store.Update(ctx, func(w ports.Writer) error {
		p, ref, ok, err := getPending(w, id.String())
		if err != nil || !ok {
			return err
		}
		ap, err := s.applier(p.KindOrAsset())
		if err != nil {
			return err
		}
		if err := ap(w, p, s.Clock.Now()); err != nil {
			return err
		}
		got, found = p, true
		return w.Delete(ref)
	})
	return got, found, err
}

// Discard removes the pending update of the transaction without applying it.
func (s Settle) Discard(ctx context.Context, id chain.TxID) (assets.Pending, bool, error) {
	var got assets.Pending
	var found bool
	err := s.Store.Update(ctx, func(w ports.Writer) error {
		p, ref, ok, err := getPending(w, id.String())
		if err != nil || !ok {
			return err
		}
		got, found = p, true
		return w.Delete(ref)
	})
	return got, found, err
}

// UpdateHook implements ports.ConfirmedUpdateHook for the machine that runs
// `offline execute`, called when the transaction is confirmed. When the
// workspace holds the pending update of the transaction (the queuing and the
// executing machine are one) it applies that through Settle. Otherwise, when
// it holds the asset record the update names (a copy of the record on the
// online machine), it applies the update the queue entry carried. A workspace
// with neither does nothing.
//
// The queue entry's field is the file writer's claim, so the fallback applies
// it only after checking it against the confirmed transaction itself: Tx is
// that transaction's signed bytes; the update's txid must be the id computed
// from them, and the update's asset (policy and name, and the name in the
// record's own name) and amount must be what the transaction's own mint field
// says. Without Tx, TxIDs and Viewer the fallback refuses.
type UpdateHook struct {
	Store    ports.Store
	Clock    ports.Clock
	Appliers map[string]Applier
	Tx       []byte
	TxIDs    ports.TxIDCalculator
	Viewer   ports.TxViewer
}

// ErrCarriedUpdateRefused: the update a queue entry carries is not what the
// confirmed transaction does, so it is not applied.
var ErrCarriedUpdateRefused = errors.New("the update the queue entry carries is not applied")

// checkCarried checks a carried asset update against the transaction.
func (h UpdateHook) checkCarried(id chain.TxID, p assets.Pending) error {
	refuse := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrCarriedUpdateRefused, fmt.Sprintf(format, a...))
	}
	if p.TxID != id.String() {
		return refuse("it names transaction %s, not the confirmed %s", shownID(p.TxID), id)
	}
	if h.TxIDs == nil || h.Viewer == nil || len(h.Tx) == 0 {
		return refuse("it cannot be checked against the transaction here")
	}
	if local, err := h.TxIDs.TransactionID(h.Tx); err != nil || local != id {
		return refuse("the transaction it came with is not transaction %s", id)
	}
	body, err := h.Viewer.BodyOf(h.Tx)
	if err != nil {
		return refuse("the transaction cannot be read: %v", err)
	}
	v, err := h.Viewer.View(body)
	if err != nil {
		return refuse("the transaction cannot be read: %v", err)
	}
	c, err := p.Change(h.Clock.Now())
	if err != nil {
		return refuse("%v", err)
	}
	var minted int64
	var n int
	for _, m := range v.Mint {
		if m.Policy == c.Asset.Policy && bytes.Equal(m.Name, c.Asset.Name) {
			minted += m.Quantity
			n++
		}
	}
	if n != 1 || minted != c.Delta {
		return refuse("the transaction does not mint or burn %d of that asset", c.Delta)
	}
	_, asset, _ := strings.Cut(p.Record, ".")
	if asset != string(c.Asset.Name) && asset != "hex-"+hex.EncodeToString(c.Asset.Name) {
		return refuse("the record %s is not the record of that asset name", shownID(p.Record))
	}
	return nil
}

// shownID bounds a value from the file for a message.
func shownID(s string) string {
	if len(s) > 80 {
		s = s[:80]
	}
	return strconv.QuoteToASCII(s)
}

// OnConfirmedUpdate implements ports.ConfirmedUpdateHook.
func (h UpdateHook) OnConfirmedUpdate(ctx context.Context, id chain.TxID, update string) error {
	if _, found, err := (Settle{Store: h.Store, Clock: h.Clock, Appliers: h.Appliers}).Apply(ctx, id); err != nil || found {
		return err
	}
	p, err := assets.ParsePending([]byte(update))
	if err != nil {
		return err
	}
	if p.KindOrAsset() != assets.PendingAsset {
		return nil
	}
	c, err := p.Change(h.Clock.Now())
	if err != nil {
		return err
	}
	ref := ports.Ref{Name: p.Record, Kind: ports.AssetFile}
	return h.Store.Update(ctx, func(w ports.Writer) error {
		ok, err := w.Exists(ref)
		if err != nil || !ok {
			return err
		}
		if err := h.checkCarried(id, p); err != nil {
			return err
		}
		return applyIn(w, ref, c)
	})
}

var _ ports.ConfirmedUpdateHook = UpdateHook{}
