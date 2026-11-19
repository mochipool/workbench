package relaybind

import "fmt"

// Scope is what a tombstone applies to (ADR 0014 decisions 7 and 8, revised
// after the package review). A relay keeps three tombstone tables:
//
//   - ScopePair: one device of one wallet key, from a wallet-signed revoke that
//     names a device; keyed by (K, device).
//   - ScopeAll: every device of one wallet key, from a wallet-signed revoke of
//     "all"; keyed by K.
//   - ScopeDevice: one device whatever key it is bound to, from a device-signed
//     revoke. That revoke carries no wallet key, so it cannot be stored under
//     (K, device): the device may not be bound where it arrives, and its old
//     binding could otherwise be presented again. Keyed by device alone.
type Scope uint8

const (
	ScopePair Scope = iota + 1
	ScopeAll
	ScopeDevice
)

// Tombstones are the three not-before values that apply to one binding: the
// one for its (K, device) pair, the one for (K, all) and the one for the device
// under any key. NoTombstone where there is none. The zero value is NOT "no
// tombstones": 0 is a valid not-before, so it blocks a from of 0 or less (it
// fails closed); use NoTombstones().
type Tombstones struct {
	Pair   int64
	All    int64
	Device int64
}

// NoTombstones is the value with no tombstone of any scope.
func NoTombstones() Tombstones {
	return Tombstones{Pair: NoTombstone, All: NoTombstone, Device: NoTombstone}
}

// Merge is the tombstones after a revoke of the given scope with the given
// not-before: that scope keeps the maximum ever seen, the others are unchanged.
// Recording the tombstone is ALWAYS done for a verified revoke, whether or not
// anything is bound, and whether or not the binding in the registry is
// invalidated (Invalidated).
func (t Tombstones) Merge(scope Scope, notBefore int64) Tombstones {
	switch scope {
	case ScopePair:
		t.Pair = MergeTombstone(t.Pair, notBefore)
	case ScopeAll:
		t.All = MergeTombstone(t.All, notBefore)
	case ScopeDevice:
		t.Device = MergeTombstone(t.Device, notBefore)
	}
	return t
}

// blocks reports whether a binding with this from is at or before any of the
// three tombstones.
func (t Tombstones) blocks(from int64) bool {
	for _, n := range [3]int64{t.Pair, t.All, t.Device} {
		if n != NoTombstone && from <= n {
			return true
		}
	}
	return false
}

// Invalidated is the predicate of the relay on a verified revoke (ADR 0014
// decision 7, revised): given the binding STORED for a device and the merged
// tombstones, it reports whether the stored binding is invalidated, that is
// whether its from is not later than some applicable tombstone. The relay
// deletes the binding, closes the device's sessions and deletes its queued mail
// ONLY when it is. A revoke that is older than the stored binding (a replay, or
// the client re-sending a pending revoke after a later re-login with from =
// not-before + 1) changes nothing but the tombstone. Revokes name no relay, so
// anyone can replay one; this is what stops a replay from wiping a newer
// binding and its mail.
func Invalidated(stored Binding, t Tombstones) bool { return t.blocks(stored.From) }

// MergeTombstone is the stored tombstone after a verified revoke: the maximum
// not-before ever seen, never lowered.
func MergeTombstone(current, incoming int64) int64 {
	if incoming > current {
		return incoming
	}
	return current
}

// TombstoneExpired reports whether a tombstone may be dropped. It is kept
// while some binding it could block might still verify. Such a binding has
// from <= notBefore (the tombstone refuses a from at or before it) and so
// until <= from + MaxLifetimeSeconds <= notBefore + MaxLifetimeSeconds, and a
// binding verifies at now == until (VerifyBinding: now <= until). The
// tombstone is therefore kept THROUGH now == notBefore + MaxLifetimeSeconds and
// expires strictly after it. NoTombstone (and any negative value) has nothing
// to keep; a value beyond MaxTime is never reached by a valid revoke and is
// kept. notBefore is at most MaxTime here, so the sum cannot overflow.
func TombstoneExpired(notBefore, now int64) bool {
	if notBefore < 0 {
		return true
	}
	if notBefore > MaxTime {
		return false
	}
	return now > notBefore+MaxLifetimeSeconds
}

// ChooseFrom is the client's rule for the from of a new binding:
// max(now - 60 s, last not-before + 1 s), where last is the latest tombstone
// time the client holds for the device (NoTombstone if none), so that a rebind
// after a revoke is always later than the tombstone and a slightly fast client
// clock still binds. It never goes below 0, and it refuses a now or tombstone
// outside the time range and a from with no room left for the shortest
// binding. The result is never below 0: the tombstone term is at least 0.
func ChooseFrom(now, lastNotBefore int64) (int64, error) {
	if now < 0 || now > MaxTime {
		return 0, fmt.Errorf("%w: now %d is not 0 to %d", ErrRange, now, MaxTime)
	}
	if lastNotBefore < NoTombstone || lastNotBefore > MaxTime {
		return 0, fmt.Errorf("%w: tombstone %d is not %d to %d", ErrRange, lastNotBefore, NoTombstone, MaxTime)
	}
	from := now - FromBackdateSeconds
	if after := lastNotBefore + 1; after > from {
		from = after
	}
	if from > MaxTime-MinLifetimeSeconds {
		return 0, fmt.Errorf("%w: from %d leaves no room for a binding", ErrRange, from)
	}
	return from, nil
}

// PlanFrom is the client's whole waiting rule. From is ChooseFrom. A relay
// refuses a binding whose from is later than relay time plus the skew
// (ErrNotYetValid), and a revoke's not-before may itself be as late as relay
// time plus the skew, so from = last + 1 can be beyond what the relay accepts
// yet. WaitSeconds is how long to wait before presenting: it is
// max(0, from - skew - now), that is, wait exactly when last + 1 - skew > now.
// The client waits (and shows why); it does not ask the wallet to sign a later
// binding, because the wait is at most skew + 1 seconds.
//
// On a binding refusal that this rule does not explain (the client has waited,
// its from is later than its tombstone, its clock is within the skew, and the
// relay still answers `binding`), the client backs off, with a growing delay
// and a small limit on tries, and tells the operator. It does NOT ask the
// wallet to sign again: each wallet touch is a human action, and a relay that
// refuses for a reason the client cannot see (a tombstone the client does not
// know, a tightened policy, a clock far off) will refuse the next signature too.
// skew is the relay's, 0 to SkewSeconds.
func PlanFrom(now, lastNotBefore, skew int64) (from, waitSeconds int64, err error) {
	if skew < 0 || skew > SkewSeconds {
		return 0, 0, fmt.Errorf("%w: skew %d is not 0 to %d", ErrRange, skew, SkewSeconds)
	}
	from, err = ChooseFrom(now, lastNotBefore)
	if err != nil {
		return 0, 0, err
	}
	// from <= MaxTime and skew <= 300, now >= 0: no overflow.
	if wait := from - skew - now; wait > 0 {
		return from, wait, nil
	}
	return from, 0, nil
}
