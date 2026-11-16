package assets

import (
	"context"
	"errors"
	"fmt"

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

// Settle applies the asset-record updates that wait for a queued mint or burn
// to be submitted (hazard H9). It implements ports.PostSubmitHook: the
// executor of the offline queue calls it with the id of the transaction it
// submitted. A transaction with no pending update is not an error.
type Settle struct {
	Store ports.Store
	Clock ports.Clock
}

// OnSubmitted applies and removes the pending update of the transaction.
//
// spec: SPO-11a-MODE-002, SPO-11b-MODE-002
func (s Settle) OnSubmitted(ctx context.Context, id chain.TxID) error {
	pref := ports.Ref{Name: id.String(), Kind: ports.AssetPending}
	return s.Store.Update(ctx, func(w ports.Writer) error {
		b, err := w.Get(pref)
		if errors.Is(err, ports.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		p, err := assets.ParsePending(b)
		if err != nil {
			return err
		}
		c, err := p.Change(s.Clock.Now())
		if err != nil {
			return err
		}
		if err := applyIn(w, ports.Ref{Name: p.Record, Kind: ports.AssetFile}, c); err != nil {
			return err
		}
		return w.Delete(pref)
	})
}

// SettlingSubmitter wraps the submitter of the executor of the offline queue:
// after the inner submitter accepts a transaction it calls the hook with the
// transaction's id. The executor (airgap.ExecuteTx) has no hook of its own, so
// the composition hands it this submitter in place of the plain one. A hook
// failure never fails the submission (the transaction is on its way to the
// chain, and the executor would otherwise think it was not): it is passed to
// OnError for the operator to see, and the pending update stays for a retry.
type SettlingSubmitter struct {
	Inner   ports.TxSubmitter
	Hook    ports.PostSubmitHook
	OnError func(id chain.TxID, err error)
}

// Source implements ports.ChainSource.
func (s SettlingSubmitter) Source() chain.Source { return s.Inner.Source() }

// Submit implements ports.TxSubmitter.
func (s SettlingSubmitter) Submit(ctx context.Context, tx []byte) (chain.TxID, error) {
	id, err := s.Inner.Submit(ctx, tx)
	if err != nil {
		return id, err
	}
	if s.Hook != nil {
		if herr := s.Hook.OnSubmitted(ctx, id); herr != nil && s.OnError != nil {
			s.OnError(id, herr)
		}
	}
	return id, nil
}

var (
	_ ports.PostSubmitHook = Settle{}
	_ ports.TxSubmitter    = SettlingSubmitter{}
)
