package poolops

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrNotSigned: the transfer file carries no witness.
var ErrNotSigned = errors.New("the witness transfer file has not been signed")

// ErrNoCollection: the pool has no open witness collection.
var ErrNoCollection = errors.New("the pool has no witness collection")

// ImportWitness takes a signed witness transfer file into the pool's
// collection (upstream 05d `add`; the sign side is not in scope). Unlike
// upstream, which compares text and trusts the witness (SPO-05d-INV-006), the
// witness is verified: the signature over the stored body hash and the key
// hash of the slot (Collection.Fill), the same path a remote response and a
// local signer take. The slot records that the witness arrived without an
// authenticated party (SPO-Xparty-IF-007).
type ImportWitness struct {
	Store ports.Store
	Tip   ports.TipReader
	TxIDs ports.TxIDCalculator
}

// ImportRequest carries the transfer file's content.
type ImportRequest struct {
	Pool string
	File []byte
	// Overwrite replaces a witness already in the slot (SPO-05d-PR-002).
	Overwrite bool
}

// ImportResult is the collection after the import.
type ImportResult struct {
	Slot            string
	State           pool.CollectionState
	Missing         []string
	Unauthenticated bool
}

// Run imports the witness. The read, the verification and the write are one
// store transaction, so two imports at once cannot lose an update
// (SPO-Xparty-INV-014).
//
// spec: SPO-05d-IF-004, SPO-05d-PRE-007, SPO-05d-PRE-008, SPO-05d-PRE-009, SPO-05d-PRE-010, SPO-05d-PRE-011,
// spec: SPO-05d-PR-002, SPO-05d-OUT-003, SPO-05d-INV-005, SPO-05d-INV-006, SPO-05d-SEC-003, SPO-05d-INV-004
func (uc ImportWitness) Run(ctx context.Context, req ImportRequest) (ImportResult, error) {
	name, err := poolName(req.Pool)
	if err != nil {
		return ImportResult{}, err
	}
	tf, err := pool.ParseTransferFile(req.File)
	if err != nil {
		return ImportResult{}, err
	}
	tip, err := uc.Tip.Tip(ctx)
	if err != nil {
		return ImportResult{}, fmt.Errorf("current slot: %w", err)
	}
	var out ImportResult
	err = uc.Store.Update(ctx, func(w ports.Writer) error {
		d, err := readDescriptor(w, name)
		if err != nil {
			return err
		}
		coll, err := d.Collection(uc.TxIDs.TransactionID)
		if err != nil {
			return err
		}
		if coll == nil {
			return ErrNoCollection
		}
		if !tf.Signed() {
			return ErrNotSigned
		}
		if tf.PoolMetaTicker != d.Text(pool.FieldMetaTicker) {
			return fmt.Errorf("%w: ticker %q, the descriptor has %q", pool.ErrCollectionMismatch, tf.PoolMetaTicker, d.Text(pool.FieldMetaTicker))
		}
		if err := tf.Matches(*coll); err != nil {
			return err
		}
		if err := bindFromStore(w, name, coll); err != nil {
			return err
		}
		wit, err := pool.ParseWitnessEnvelope(tf.SignedWitness)
		if err != nil {
			return err
		}
		next, err := coll.Fill(pool.Fill{Slot: tf.SigningName, Witness: wit, ExpectVersion: coll.Version, Overwrite: req.Overwrite, Unauthenticated: true}, tip.Slot)
		if err != nil {
			return err
		}
		d.SetCollection(next)
		if err := w.Put(ports.Ref{Name: name, Kind: ports.PoolDescriptor}, d.Render()); err != nil {
			return err
		}
		// The request file goes once the witness is stored (SPO-05d-INV-004).
		ref := ports.Ref{Name: tf.Name(), Kind: ports.PoolWitnessFile}
		if ok, err := w.Exists(ref); err != nil {
			return err
		} else if ok {
			if err := w.Delete(ref); err != nil {
				return err
			}
		}
		out = ImportResult{Slot: tf.SigningName, State: next.State(tip.Slot), Missing: next.Missing(), Unauthenticated: true}
		return nil
	})
	return out, err
}

// bindFromStore gives every slot of a collection read from a descriptor its
// key hash from the verification key in the store, so a collection made by
// the upstream script (which stores none) can verify. A hash that is stored
// and differs from the store's is an error.
func bindFromStore(r ports.Reader, poolN string, c *pool.Collection) error {
	for i, s := range c.Slots {
		var ref ports.Ref
		switch {
		case s.Name == poolN+".node":
			ref = ports.Ref{Name: poolN, Kind: ports.NodeVKey}
		case len(s.Name) > len(".staking") && s.Name[len(s.Name)-len(".staking"):] == ".staking":
			ref = ports.Ref{Name: s.Name[:len(s.Name)-len(".staking")], Kind: ports.StakingVKey}
		default:
			ref = ports.Ref{Name: s.Name, Kind: ports.AddrVKey}
		}
		env, err := r.Get(ref)
		if err != nil {
			if s.KeyHash != (txbuild.KeyHash{}) {
				continue // bound already; the key file is not on this machine
			}
			return fmt.Errorf("the key of slot %q: %w", s.Name, err)
		}
		_, h, err := keyOf(env)
		if err != nil {
			return fmt.Errorf("the key of slot %q: %w", s.Name, err)
		}
		if s.KeyHash == (txbuild.KeyHash{}) {
			c.Slots[i].KeyHash = h
		} else if s.KeyHash != h {
			return fmt.Errorf("%w: slot %q is bound to another key than the one in the store", pool.ErrBadCollection, s.Name)
		}
	}
	return nil
}
