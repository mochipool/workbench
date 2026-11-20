package relayregistry

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// Operations whose outcome storage did not confirm (ADR 0015, "Changes after
// the review of the store client"). A store that is not a directory can lose
// the answer to a write, and a directory can rename a file and then fail to
// sync it. The adapter then cannot tell whether storage holds the effect. It
// calls ApplyUnknown: memory takes the stricter state (a tombstone written is
// enforced, a binding deleted is not served) and remembers the operation as
// unconfirmed. Every reader then enforces it as it enforces any tombstone.
//
// An unconfirmed operation is settled in three ways:
//
//   - a later write of the same thing is confirmed (Apply), or a refresh reads a
//     value at least as high from storage (LoadTombstone, MergeTombstones);
//   - a replayed revoke plans the unconfirmed tombstone again (PlanRevoke, with
//     Op.Retry), so the client's re-sent revoke writes it;
//   - the adapter's sweep and tombstone refresh read each one back (Unconfirmed,
//     Settle) and send again what storage does not show yet.
//
// One that stays unconfirmed for UnconfirmedSeconds is a conflict: Settle and
// Overdue return ErrUnconfirmed, which the adapter wraps with
// relayport.ErrAuthorityLost, and the relay stops. Storage may still apply the
// lost write for as long as its request is valid, so the writer never writes
// other content in its place; it sends the same operation again or stops.

// ReadBack is what an adapter's read of storage showed of an unconfirmed
// operation. An object-store adapter maps the result of its client's read-back
// to it; a directory adapter, whose rename is visible and whose sync is what is
// in doubt, maps a sync that succeeds to ReadBackApplied and one that fails to
// ReadBackCannotTell.
type ReadBack uint8

const (
	// ReadBackApplied: storage holds the operation's effect.
	ReadBackApplied ReadBack = iota + 1
	// ReadBackNotYet: storage shows the state before the operation; the
	// operation is sent again (the same bytes).
	ReadBackNotYet
	// ReadBackCannotTell: the read did not answer.
	ReadBackCannotTell
)

// Unconfirmed is one operation applied to memory whose outcome storage has not
// confirmed, and the relay time it was first applied at.
type Unconfirmed struct {
	Op    Op
	Since int64
}

// unconfKey is what an unconfirmed operation changes: a tombstone written (by
// its scope key) or a binding deleted (by its device).
type unconfKey struct {
	kind OpKind
	tomb TombKey
	dev  party.Fingerprint
}

func putKey(k TombKey) unconfKey               { return unconfKey{kind: OpPutTombstone, tomb: k} }
func delKey(d party.Fingerprint) unconfKey     { return unconfKey{kind: OpDeleteBinding, dev: d} }
func (c *Core) unconfirmedTomb(k TombKey) bool { _, ok := c.unconfirmed[putKey(k)]; return ok }

// ApplyUnknown applies an operation whose outcome storage could not confirm,
// when that is the stricter state (a tombstone written, a binding deleted), and
// remembers it as unconfirmed; it reports whether it applied it. Any other
// operation (a binding written, a tombstone dropped) is not applied: memory
// then serves less than storage may hold, never more, and the next load finds
// what storage holds. An operation already unconfirmed keeps the time it was
// first applied, so sending it again does not extend its bound.
func (c *Core) ApplyUnknown(op Op) bool {
	if !applyWhenUnknown(op) {
		return false
	}
	k := delKey(op.Device)
	if op.Kind == OpPutTombstone {
		k = putKey(op.Tomb)
	}
	since := op.Now
	if u, ok := c.unconfirmed[k]; ok {
		since = min(since, u.Since)
	}
	c.apply(op)
	op.Retry = false
	c.unconfirmed[k] = Unconfirmed{Op: op, Since: since}
	return true
}

// confirmBy drops the unconfirmed write that a confirmed op supersedes.
func (c *Core) confirmBy(op Op) {
	switch op.Kind {
	case OpPutTombstone, OpDeleteTombstone:
		delete(c.unconfirmed, putKey(op.Tomb))
	case OpDeleteBinding:
		delete(c.unconfirmed, delKey(op.Device))
	case OpPutBinding:
		if op.Persist {
			delete(c.unconfirmed, delKey(op.Rec.Device))
		}
	}
}

// Unconfirmed lists the unconfirmed operations in a stable order: tombstones by
// scope key, then binding deletes by device.
func (c *Core) Unconfirmed() []Unconfirmed {
	out := make([]Unconfirmed, 0, len(c.unconfirmed))
	for _, u := range c.unconfirmed {
		out = append(out, u)
	}
	slices.SortFunc(out, func(a, b Unconfirmed) int {
		if a.Op.Kind != b.Op.Kind {
			return int(b.Op.Kind) - int(a.Op.Kind) // OpPutTombstone (3) before OpDeleteBinding (2)
		}
		if a.Op.Tomb.Scope != b.Op.Tomb.Scope {
			return int(a.Op.Tomb.Scope) - int(b.Op.Tomb.Scope)
		}
		if x := bytes.Compare(a.Op.Tomb.Key[:], b.Op.Tomb.Key[:]); x != 0 {
			return x
		}
		if x := bytes.Compare(a.Op.Tomb.Device[:], b.Op.Tomb.Device[:]); x != 0 {
			return x
		}
		return bytes.Compare(a.Op.Device[:], b.Op.Device[:])
	})
	return out
}

// Settle records what a read-back of the unconfirmed operation u showed at now.
// ReadBackApplied confirms it. ReadBackNotYet returns the operation to send
// again (the same operation, Retry set, Now now) with send true; the adapter
// then calls Apply when storage takes it and ApplyUnknown when the answer is
// lost again. ReadBackCannotTell keeps it. Either of the last two returns
// ErrUnconfirmed instead once the operation has been unconfirmed for
// UnconfirmedSeconds. An operation that is no longer unconfirmed is ignored.
func (c *Core) Settle(u Unconfirmed, rb ReadBack, now int64) (again Op, send bool, err error) {
	k := delKey(u.Op.Device)
	if u.Op.Kind == OpPutTombstone {
		k = putKey(u.Op.Tomb)
	}
	cur, ok := c.unconfirmed[k]
	if !ok {
		return Op{}, false, nil
	}
	if rb == ReadBackApplied {
		delete(c.unconfirmed, k)
		return Op{}, false, nil
	}
	if now-cur.Since >= UnconfirmedSeconds {
		return Op{}, false, fmt.Errorf("%w: unconfirmed for %d s", ErrUnconfirmed, now-cur.Since)
	}
	if rb != ReadBackNotYet {
		return Op{}, false, nil
	}
	again = cur.Op
	again.Retry, again.Now, again.Charge = true, now, false
	return again, true, nil
}

// Overdue returns ErrUnconfirmed when any operation has been unconfirmed for
// UnconfirmedSeconds at now.
func (c *Core) Overdue(now int64) error {
	for _, u := range c.unconfirmed {
		if now-u.Since >= UnconfirmedSeconds {
			return fmt.Errorf("%w: unconfirmed for %d s", ErrUnconfirmed, now-u.Since)
		}
	}
	return nil
}

// ---- the rate buckets across restarts (ADR 0015 work package 4) ----

// RateState is one rate bucket as a store keeps it: Units of tokenUnits per
// token (RateUnitsPerToken), as of the relay time At.
type RateState struct {
	Units int64
	At    int64
}

// RateUnitsPerToken is the unit of RateState.Units: one token is this many.
const RateUnitsPerToken = tokenUnits

// RateSnapshot is the two relay-wide caps: new bindings and revokes that
// invalidate nothing.
type RateSnapshot struct {
	NewBindings, Revokes RateState
}

// Rates is the two buckets at now, for an adapter to store (at most once a
// minute and at a planned stop, ADR 0015 decision 2).
func (c *Core) Rates(now int64) RateSnapshot {
	return RateSnapshot{NewBindings: c.rate.state(now), Revokes: c.revRate.state(now)}
}

// RestoreRates loads the buckets a store kept, at now. Each value is checked
// first: Units 0 to the largest burst any configuration may have
// (mailbox.NewBindingBurst and RevokeBurst tokens) and At 0 to
// relaybind.MaxTime; one outside is refused with ErrRateState and nothing
// changes. A level above THIS configuration's burst (the operator tightened
// it) is not an error: the rule below caps it.
//
// THE RULE. A restore can only take tokens away. Each bucket becomes the lower
// of what it holds now and the stored level refilled at this configuration's
// rate from At to now, capped at this burst. A bucket starts full, so a store
// can give back at most the burst, which is what a restart without stored state
// gives anyway: a store cannot hand out a token the caps do not allow. A stored
// At in the future gains no refill and freezes none: the bucket counts from now.
func (c *Core) RestoreRates(s RateSnapshot, now int64) error {
	if err := checkRate(s.NewBindings, int64(mailbox.NewBindingBurst)*tokenUnits); err != nil {
		return fmt.Errorf("new bindings: %w", err)
	}
	if err := checkRate(s.Revokes, int64(RevokeBurst)*tokenUnits); err != nil {
		return fmt.Errorf("revokes: %w", err)
	}
	c.rate.restore(s.NewBindings, now)
	c.revRate.restore(s.Revokes, now)
	return nil
}

func (b *bucket) state(now int64) RateState {
	at := now
	if b.started && b.last > at {
		at = b.last
	}
	return RateState{Units: b.at(now), At: at}
}

func checkRate(s RateState, ceiling int64) error {
	if s.Units < 0 || s.Units > ceiling || s.At < 0 || s.At > relaybind.MaxTime {
		return fmt.Errorf("%w: %d units at %d, a bucket holds 0 to %d", ErrRateState, s.Units, s.At, ceiling)
	}
	return nil
}

func (b *bucket) restore(s RateState, now int64) {
	stored := bucket{perHour: b.perHour, cap: b.cap, tokens: s.Units, last: s.At, started: true}
	level := stored.at(now) // a future At refills nothing
	b.tokens = min(b.at(now), level)
	if !b.started || now > b.last {
		b.last = now
	}
	b.started = true
}
