package relayregistry

import (
	"bytes"
	"fmt"
	"slices"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// held reports whether a stored binding still holds its device: it has not
// expired and no stored tombstone invalidates it. (A binding that waits for the
// clock to reach its from is held: it was valid when stored.)
func (c *Core) held(r *Record, now int64) bool {
	return c.live(r, now) && !relaybind.Invalidated(r.Binding, c.Tombstones(r.Key, r.Device))
}

// PlanRegister decides the registration of a presented binding. In this order:
//
//  1. relaybind.Admit with the three stored tombstones: a binding not yet valid,
//     expired, or blocked by a tombstone is refused with relaybind's error, and
//     nothing is stored (a binding is never stored before it is valid);
//  2. the lifetime against THIS registry's policy (`until - from` at most
//     Policy.MaxLifetime): a statement verified under a looser policy, or none,
//     is refused with relaybind.ErrLifetimePolicy and never stored, so a load at
//     the next start never has to drop it. This is the one place the registry
//     checks the lifetime: a Presented can reach storage only through this plan;
//  3. the allow-list, after Admit, so a presenter of a binding that does not
//     verify learns nothing about the list (ErrNotAllowed);
//  4. the same statement again, by StatementID (never the full hash, which holds
//     the signature): Renewed. Only the last authentication moves. It uses no
//     new-binding token, no cap and no eviction: it is not a new binding;
//  5. a binding of the same wallet key and device with an EARLIER `from` than the
//     stored one is refused (ErrOlderBinding): an older valid statement must not
//     replace a newer one;
//  6. the cap of live devices per wallet key, not counting this device, so that a
//     replacement does not count itself and a device moved to another key frees
//     a place under the old one (ErrKeyDeviceLimit);
//  7. what the registration costs. A device that has NO held binding is a new
//     binding: one token of the relay-wide cap (ErrNewBindingRate). A device that
//     has one, bound again under the SAME key (the renewal every 90 days, a longer
//     `until`), costs nothing. Bound under ANOTHER key it draws on the device's
//     own budget of KeyChangesPerDevice in KeyChangeWindowSeconds
//     (ErrKeyChangeRate), so cycling keys is not free (it was a lever of the flood
//     of tombstones). The old binding's expected-sender list goes with the old key;
//  8. the registry cap: when the device is new, victims are chosen so that the
//     newcomer fits. Expired and invalidated bindings go first, oldest until
//     first, whatever the guard says (they are dead and the store keeps the mail);
//     then the live bindings the guard allows, the least recently authenticated
//     first, equal times by device bytes. The guard is asked at most
//     EvictionProbes times besides one ask per binding that must go, so a refused
//     registration costs a bounded number of calls however many bindings there
//     are; the consequence is that when the oldest EvictionProbes bindings are all
//     busy a registration is refused (ErrRegistryFull) though a younger one is
//     idle. The device that registers is never a victim. If the victims are too
//     few the newcomer is refused and nothing changes.
func (c *Core) PlanRegister(p Presented, now int64) (Plan[RegisterResult], error) {
	var none Plan[RegisterResult]
	if p.IsZero() {
		return none, relaybind.ErrUnverified
	}
	vb := p.vb
	b := vb.Binding()
	key, dev := vb.Key(), b.Device
	if err := relaybind.Admit(vb, c.Tombstones(key, dev), now, c.cfg.Policy); err != nil {
		return none, err
	}
	if d := b.Until - b.From; d > c.cfg.Policy.MaxLifetime {
		return none, fmt.Errorf("%w: %w: %d seconds, this registry's maximum is %d", relaybind.ErrLifetimePolicy, relaybind.ErrLifetime, d, c.cfg.Policy.MaxLifetime)
	}
	if !c.cfg.allows(key) {
		return none, ErrNotAllowed
	}
	old := c.dev[dev]
	if old != nil && old.StatementID == vb.StatementID() {
		rec := old.clone()
		rec.LastAuth = max(old.LastAuth, now)
		op := Op{Kind: OpPutBinding, Rec: rec, Persist: rec.LastAuth-old.persistedAuth >= PersistGranularity, Now: now}
		return Plan[RegisterResult]{Ops: []Op{op}, Result: RegisterResult{Outcome: Renewed, Entry: rec.Entry()}}, nil
	}
	oldHeld := old != nil && c.held(old, now)
	if oldHeld && old.Key == key && b.From < old.Binding.From {
		return none, ErrOlderBinding
	}
	devices := 0
	for d := range c.byKey[key] {
		if r := c.dev[d]; d != dev && r != nil && c.held(r, now) {
			devices++
		}
	}
	if devices >= c.cfg.MaxDevicesPerKey {
		return none, ErrKeyDeviceLimit
	}
	fresh := !oldHeld
	var changes []int64
	switch {
	case fresh:
		if !c.rate.has(now) {
			return none, ErrNewBindingRate
		}
	case old.Key == key:
		changes = old.keyChanges
	default:
		var ok bool
		if changes, ok = nextKeyChanges(old.keyChanges, now); !ok {
			return none, ErrKeyChangeRate
		}
	}
	var ops []Op
	var evicted []Entry
	if old == nil {
		victims, err := c.victims(now)
		if err != nil {
			return none, err
		}
		for _, v := range victims {
			ops = append(ops, Op{Kind: OpDeleteBinding, Device: v.Device, Reason: ReasonEvicted, Now: now})
			evicted = append(evicted, v.Entry())
		}
	}
	rec := Record{
		Device: dev, Key: key, Binding: b, StatementID: vb.StatementID(), FullHash: vb.FullHash(),
		Sign1: bytes.Clone(p.sign1), COSEKey: bytes.Clone(p.key), LastAuth: now,
		keyChanges: slices.Clone(changes),
	}
	res := RegisterResult{Outcome: Registered, Evicted: evicted}
	if oldHeld {
		if old.Key == key {
			rec.Senders = slices.Clone(old.Senders) // the same wallet key: the device keeps its list
		}
		prev := old.Entry()
		res.Outcome, res.Previous = Replaced, &prev
	}
	ops = append(ops, Op{Kind: OpPutBinding, Rec: rec, Persist: true, Fresh: fresh, Now: now})
	res.Entry = rec.Entry()
	return Plan[RegisterResult]{Ops: ops, Result: res}, nil
}

// nextKeyChanges is the list of key-change times after one at now, or false when
// the device has used its budget: KeyChangesPerDevice changes, the oldest within
// KeyChangeWindowSeconds. A clock that steps back gains nothing.
func nextKeyChanges(prev []int64, now int64) ([]int64, bool) {
	if len(prev) >= KeyChangesPerDevice && now-prev[0] < KeyChangeWindowSeconds {
		return nil, false
	}
	out := append(slices.Clone(prev), now)
	if len(out) > KeyChangesPerDevice {
		out = out[len(out)-KeyChangesPerDevice:]
	}
	return out, true
}

// victims are the bindings to drop so that one more fits under the cap.
func (c *Core) victims(now int64) ([]*Record, error) {
	need := len(c.dev) - c.cfg.MaxBoundDevices + 1
	if need <= 0 {
		return nil, nil
	}
	var dead, live []*Record
	for _, r := range c.dev {
		if c.held(r, now) {
			live = append(live, r)
		} else {
			dead = append(dead, r)
		}
	}
	slices.SortFunc(dead, func(a, b *Record) int {
		if a.Binding.Until != b.Binding.Until {
			return cmp64(a.Binding.Until, b.Binding.Until)
		}
		return bytes.Compare(a.Device[:], b.Device[:])
	})
	slices.SortFunc(live, func(a, b *Record) int {
		if a.LastAuth != b.LastAuth {
			return cmp64(a.LastAuth, b.LastAuth)
		}
		return bytes.Compare(a.Device[:], b.Device[:])
	})
	var out []*Record
	for _, r := range dead {
		if len(out) == need {
			break
		}
		out = append(out, r)
	}
	probes := EvictionProbes + need
	for _, r := range live {
		if len(out) == need || probes == 0 || c.cfg.Evictable == nil {
			break
		}
		probes--
		if c.cfg.Evictable(r.Device) {
			out = append(out, r)
		}
	}
	if len(out) < need {
		return nil, ErrRegistryFull
	}
	return out, nil
}

func cmp64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// PlanRevoke decides the recording of a verified revoke (ADR 0014 decisions 7
// and 8). The binding is deleted ONLY when relaybind.Invalidated says the merged
// tombstones invalidate it, so a re-sent or replayed old revoke cannot wipe a
// newer binding:
//
//   - scope pair: the binding of the device, if it is bound under that key;
//   - scope all: every binding of the key;
//   - scope device (device-signed): the binding of the device, whatever its key.
//
// The tombstone is written before the bindings are deleted, so a crash between
// the two leaves a binding that the next load drops.
//
// TWO KINDS OF REVOKE. A revoke is INVALIDATING when it invalidates at least one
// binding that is held here and was not already invalidated; every other revoke
// (of a device that is not bound here, of a key with nothing bound, with a
// not-before below every held `from`) is a note against a later presentation and
// nothing more. The first kind must never be refused for want of room: a revoke
// is how the owner takes a stolen or lost device out. The second kind is the
// lever of a flood, because anyone can make it with a throwaway key before
// authenticating.
//
//   - A non-invalidating revoke that raises a stored tombstone needs no room. One
//     that would add a tombstone may use only the lower half of MaxTombstones
//     (ErrTombstoneFull otherwise) and takes a token of the relay-wide revoke cap
//     (ErrRevokeRate). A replay records nothing and costs nothing.
//   - An invalidating revoke is never refused and never rate limited. Its
//     tombstone goes into the table up to MaxTombstones, then into the headroom
//     above it (Config.TombstoneHeadroom). When the headroom is spent too, the
//     bindings are STILL deleted and the tombstone is not recorded: the plan has
//     Warn = ErrTombstoneUnrecorded and Result.TombstoneUnrecorded. That is weaker
//     (the revoked binding could be presented again) but strictly better than
//     refusing and leaving it live.
//
// ROOM IS PLANNED ON ITS OWN (ADR 0015 decision 3, "The registry core"). The
// plan of a revoke holds no drop: an expired tombstone (past not-before + the
// maximum lifetime + the skew) that must go to make room is planned by PlanRoom,
// which the adapter calls and carries out first, each drop on its own. A drop
// that storage refuses is held back (Hold) and the revoke is then planned with
// the room that is really there, so a refused drop never fails a revoke and is
// never the reason a revoked binding stays live. A live tombstone is never
// dropped to make room.
func (c *Core) PlanRevoke(r RevokeRecord, now int64) (Plan[RevokeResult], error) {
	var none Plan[RevokeResult]
	sh, err := c.shape(r, now)
	if err != nil {
		return none, err
	}
	unconf := c.unconfirmedTomb(sh.tk)
	res := RevokeResult{Recorded: sh.have, NotBefore: sh.cur, hadStored: sh.have, hadUnconfirmed: unconf, before: sh.cur}
	var ops []Op
	var warn error
	reason := ReasonInvalidated
	put := Op{Kind: OpPutTombstone, Tomb: sh.tk, NotBefore: sh.merged, Now: now, Replaces: sh.have, Retry: unconf}
	if sh.have {
		put.Prev = sh.cur
	}
	if !sh.raised && unconf {
		// the stored value is memory's, not yet storage's: a replay writes it
		// again, so the client's re-sent revoke is what confirms it (it costs no
		// token: it was charged when it was first planned)
		u := c.unconfirmed[putKey(sh.tk)].Op
		u.Retry, u.Now, u.Charge = true, now, false
		ops = append(ops, u)
	}
	if sh.raised {
		switch {
		case sh.have:
			if !sh.invalidating && !c.revRate.has(now) {
				return none, ErrRevokeRate
			}
			put.Charge = !sh.invalidating
			ops = append(ops, put)
		case sh.invalidating:
			if c.tombCount() >= c.hardSize() {
				warn, reason = ErrTombstoneUnrecorded, ReasonInvalidatedUnrecorded
				res.TombstoneUnrecorded = true
				break
			}
			ops = append(ops, put)
		default:
			if c.tombCount() >= c.cfg.MaxTombstones/2 {
				return none, ErrTombstoneFull
			}
			if !c.revRate.has(now) {
				return none, ErrRevokeRate
			}
			put.Charge = true
			ops = append(ops, put)
		}
		if !res.TombstoneUnrecorded {
			res.Recorded, res.Raised, res.NotBefore = true, true, sh.merged
		}
	}
	res.Invalidated = []Entry{}
	for _, rec := range sh.inv {
		ops = append(ops, Op{Kind: OpDeleteBinding, Device: rec.Device, Reason: reason, Now: now})
		res.Invalidated = append(res.Invalidated, rec.Entry())
	}
	return Plan[RevokeResult]{Ops: ops, Result: res, Warn: warn}, nil
}

// PlanRoom is the first step of a revoke: the drops of expired tombstones that
// make room for the new tombstone r would add, in a stable order, or none. It is
// a plan of its own (ADR 0015 decision 3): the adapter carries out each drop and
// applies it, holds back (Hold) one that storage refuses, and only then calls
// PlanRevoke, which decides with the room that is really there. It plans the
// drops when r adds a tombstone (it raises none that is stored) and the table is
// at the limit that applies, and only when they would make room:
//
//   - an invalidating revoke may use the whole bound and then the headroom: the
//     expired tombstones go whenever the table is at the bound, to keep the
//     headroom for later, as long as dropping them leaves room under the hard
//     size;
//   - a revoke of nothing may use only the lower half: the expired ones go when
//     that is full, when dropping them leaves room in it, and when the revoke cap
//     has a token (a revoke that will be refused drops nothing).
//
// A held tombstone is not expired for this until its hold ends. PlanRoom
// changes nothing.
func (c *Core) PlanRoom(r RevokeRecord, now int64) []Op {
	sh, err := c.shape(r, now)
	if err != nil || !sh.raised || sh.have {
		return nil
	}
	total := c.tombCount()
	if sh.invalidating {
		if total < c.cfg.MaxTombstones {
			return nil
		}
		drop := c.expiredTombstones(now)
		if total-len(drop) >= c.hardSize() {
			return nil
		}
		return drop
	}
	limit := c.cfg.MaxTombstones / 2
	if total < limit || !c.revRate.has(now) {
		return nil
	}
	drop := c.expiredTombstones(now)
	if total-len(drop) >= limit {
		return nil
	}
	return drop
}

// hardSize is the bound of the table with its headroom.
func (c *Core) hardSize() int { return c.cfg.MaxTombstones + c.cfg.TombstoneHeadroom() }

// revokeShape is what a revoke would do to the state now: its tombstone (stored
// or not, and the value after the merge) and the stored bindings it invalidates.
type revokeShape struct {
	tk           TombKey
	have         bool
	cur, merged  int64
	raised       bool
	inv          []*Record
	invalidating bool // it invalidates a held binding
}

func (c *Core) shape(r RevokeRecord, now int64) (revokeShape, error) {
	if !r.valid() {
		return revokeShape{}, relaybind.ErrUnverified
	}
	if r.notBefore < 0 || r.notBefore > relaybind.MaxTime {
		return revokeShape{}, relaybind.ErrRange
	}
	sh := revokeShape{tk: r.tombKey(), cur: relaybind.NoTombstone}
	if v, ok := c.getTomb(sh.tk); ok {
		sh.have, sh.cur = true, v
	}
	sh.merged = relaybind.MergeTombstone(sh.cur, r.notBefore)
	sh.raised = sh.merged > sh.cur
	cand := c.named(sh.tk)
	slices.SortFunc(cand, func(a, b *Record) int { return bytes.Compare(a.Device[:], b.Device[:]) })
	for _, rec := range cand {
		if !relaybind.Invalidated(rec.Binding, c.Tombstones(rec.Key, rec.Device).Merge(r.scope, r.notBefore)) {
			continue
		}
		sh.inv = append(sh.inv, rec)
		if c.held(rec, now) {
			sh.invalidating = true
		}
	}
	return sh, nil
}

// tombExpired is relaybind.TombstoneExpired with a margin of the skew: a clock
// that runs a little ahead must not drop a live tombstone.
func (c *Core) tombExpired(notBefore, now int64) bool {
	return relaybind.TombstoneExpired(notBefore, now-c.cfg.Policy.Skew)
}

// mayHaveExpired reports whether any stored tombstone can be expired at now,
// from the least day of the stored not-before values: false skips the scan of the
// table (a revoke at a full table, and a sweep, cost nothing when nothing can
// have expired).
func (c *Core) mayHaveExpired(now int64) bool {
	for day := range c.tombDays {
		first := day * secondsPerDay
		if day < 0 {
			first = -1
		}
		if c.tombExpired(first, now) {
			return true
		}
	}
	return false
}

func (c *Core) expiredTombstones(now int64) []Op {
	if !c.mayHaveExpired(now) {
		return nil
	}
	var ops []Op
	add := func(k TombKey, v int64) {
		if c.tombExpired(v, now) && !c.isHeld(k, now) {
			ops = append(ops, Op{Kind: OpDeleteTombstone, Tomb: k, NotBefore: v, Now: now})
		}
	}
	for k, v := range c.pair {
		add(TombKey{Scope: relaybind.ScopePair, Key: k.key, Device: k.dev}, v)
	}
	for k, v := range c.all {
		add(TombKey{Scope: relaybind.ScopeAll, Key: k}, v)
	}
	for d, v := range c.dtomb {
		add(TombKey{Scope: relaybind.ScopeDevice, Device: d}, v)
	}
	slices.SortFunc(ops, func(a, b Op) int {
		if a.Tomb.Scope != b.Tomb.Scope {
			return int(a.Tomb.Scope) - int(b.Tomb.Scope)
		}
		if x := bytes.Compare(a.Tomb.Key[:], b.Tomb.Key[:]); x != 0 {
			return x
		}
		return bytes.Compare(a.Tomb.Device[:], b.Tomb.Device[:])
	})
	return ops
}

// PlanSweep decides what has expired: the bindings past their until (whatever
// their queue holds: the mailbox store keeps the mail until retention and serves
// it again if a fresh binding arrives), the bindings still stored that a stored
// tombstone invalidates (a delete that failed earlier), the live bindings that
// have not authenticated for IdleDrop (now - last >= IdleDrop) and that the guard
// allows to drop (empty queue, not connected; with no guard none is dropped), and
// the tombstones that are expired by a margin of the skew. The tombstones are
// dropped only here and to make room, never at load: a start-up clock that is
// ahead must not drop live ones. The guard is asked once per idle binding.
func (c *Core) PlanSweep(now int64) Plan[SweepResult] {
	idle := int64(c.cfg.IdleDrop / time.Second)
	recs := make([]*Record, 0, len(c.dev))
	for _, r := range c.dev {
		recs = append(recs, r)
	}
	slices.SortFunc(recs, func(a, b *Record) int { return bytes.Compare(a.Device[:], b.Device[:]) })
	res := SweepResult{Expired: []Entry{}, Idle: []Entry{}, Invalidated: []Entry{}}
	var ops []Op
	for _, r := range recs {
		switch {
		case !c.live(r, now):
			ops = append(ops, Op{Kind: OpDeleteBinding, Device: r.Device, Reason: ReasonExpired, Now: now})
			res.Expired = append(res.Expired, r.Entry())
		case relaybind.Invalidated(r.Binding, c.Tombstones(r.Key, r.Device)):
			ops = append(ops, Op{Kind: OpDeleteBinding, Device: r.Device, Reason: ReasonInvalidated, Now: now})
			res.Invalidated = append(res.Invalidated, r.Entry())
		case now-r.LastAuth >= idle && c.cfg.Evictable != nil && c.cfg.Evictable(r.Device):
			ops = append(ops, Op{Kind: OpDeleteBinding, Device: r.Device, Reason: ReasonIdle, Now: now})
			res.Idle = append(res.Idle, r.Entry())
		}
	}
	tombs := c.expiredTombstones(now)
	res.Tombstones = len(tombs)
	ops = append(ops, tombs...)
	return Plan[SweepResult]{Ops: ops, Result: res}
}

// PlanSetSenders decides the replacement of a device's expected-sender list. The
// device must have a served binding (ErrNotBound) and the list must be canonical
// (ErrBadSenders): strictly ascending, at most mailbox.MaxSenders. A list equal
// to the stored one changes nothing. The session calls it on every successful
// login, with the list of that login, an empty one included: the list is then
// always the latest login's.
func (c *Core) PlanSetSenders(d party.Fingerprint, senders []mailbox.WalletKey, now int64) (Plan[struct{}], error) {
	var none Plan[struct{}]
	rec := c.dev[d]
	if rec == nil || !c.serves(rec, now) {
		return none, ErrNotBound
	}
	canon, err := mailbox.CanonicalSenders(senders)
	if err != nil || !slices.Equal(canon, senders) {
		return none, ErrBadSenders
	}
	if slices.Equal(rec.Senders, senders) {
		return none, nil
	}
	nr := rec.clone()
	nr.Senders = slices.Clone(senders)
	return Plan[struct{}]{Ops: []Op{{Kind: OpPutBinding, Rec: nr, Persist: true, Now: now}}}, nil
}

// PartialRevoke is the result of a revoke whose operations did not all succeed:
// applied lists the operations that took effect (an operation whose effect is
// visible, as the adapter defines it). It tells the caller what happened, because
// an error alone loses it (the session must still close the sessions of what was
// revoked, and drop its mail). The tombstone decides: when it is stored (written
// now, already there, or none was needed) every binding the plan named is
// invalidated and no reader serves it, deleted or not; when it was to be written
// and was not, nothing is. A revoke that could not record a tombstone (headroom
// spent) has nothing to filter by, so only the bindings actually deleted count.
//
// unknown lists the operations whose outcome storage did not confirm and that
// the adapter applied with Core.ApplyUnknown. A tombstone among them is enforced
// by memory, so the bindings it invalidates are not served and count as
// invalidated; but it is not recorded: Recorded is false and Unconfirmed true,
// and the caller answers `refused` so that the client sends the revoke again
// (SPO-Xmailbox-OUT-128). A revoke whose tombstone was already unconfirmed and
// whose write again failed is not recorded either.
func PartialRevoke(plan Plan[RevokeResult], applied, unknown []Op) RevokeResult {
	res := plan.Result
	wrote, planned, enforced := false, false, false
	deleted := map[party.Fingerprint]bool{}
	for _, op := range plan.Ops {
		if op.Kind == OpPutTombstone {
			planned = true
		}
	}
	for _, op := range applied {
		switch op.Kind {
		case OpPutTombstone:
			wrote = true
		case OpDeleteBinding:
			deleted[op.Device] = true
		}
	}
	for _, op := range unknown {
		switch op.Kind {
		case OpPutTombstone:
			enforced = true
		case OpDeleteBinding:
			deleted[op.Device] = true
		}
	}
	if planned && !wrote {
		res.Recorded, res.Raised = plan.Result.hadStored && !plan.Result.hadUnconfirmed, false
		res.NotBefore = plan.Result.before
		res.Unconfirmed = enforced || plan.Result.hadUnconfirmed
	}
	var inv []Entry
	for _, e := range plan.Result.Invalidated {
		switch {
		case plan.Result.TombstoneUnrecorded:
			if deleted[e.Device] {
				inv = append(inv, e)
			}
		case !planned || wrote || enforced || plan.Result.hadUnconfirmed:
			inv = append(inv, e)
		}
	}
	res.Invalidated = inv
	if res.Invalidated == nil {
		res.Invalidated = []Entry{}
	}
	return res
}
