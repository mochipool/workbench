package chain

import "fmt"

// DescribePoolStatus is a pool's status in words, for a message that must
// show the field two sources differ on.
func DescribePoolStatus(s PoolState) string {
	switch s.Status {
	case PoolRetiring:
		return fmt.Sprintf("retiring at epoch %d", s.RetiringEpoch)
	case PoolRetired:
		return "retired"
	case PoolStatusUnstated:
		return "status not stated"
	}
	return "registered, no retirement pending"
}

// DescribePool is a pool reading in words: whether it is registered.
func DescribePool(r Reading[PoolState]) string {
	if r.IsUnknown() || r.IsNone() {
		return DescribePoolDetailed(r)
	}
	return "registered"
}

// DescribePoolFor is a reading in words for a message about the field diff
// (from DiffPoolReadings): the plain answer when the sources differ on
// registration itself, otherwise the answer with the status it states.
func DescribePoolFor(r Reading[PoolState], diff string) string {
	if diff == "registration" {
		return DescribePool(r)
	}
	return DescribePoolDetailed(r)
}

// DescribePoolDetailed is DescribePool with, for a registered pool, where it
// is in its life as the source states it.
func DescribePoolDetailed(r Reading[PoolState]) string {
	switch {
	case r.IsUnknown():
		return "unknown (" + r.Why() + ")"
	case r.IsNone():
		return "not registered"
	}
	st, _ := r.Get()
	if st.Status == PoolStatusUnstated {
		return "registered (status not stated)"
	}
	return "registered (" + DescribePoolStatus(st) + ")"
}

// DiffPoolReadings compares two non-Unknown readings of one pool's
// registration and returns "" when they agree, otherwise the fields that
// actually differ. Registration is always compared. The status and the
// retiring epoch are compared only when both sources state them: a source
// that does not state a status (PoolStatusUnstated) is not a different answer.
func DiffPoolReadings(a, b Reading[PoolState]) string {
	if a.IsNone() || b.IsNone() {
		if a.IsNone() && b.IsNone() {
			return ""
		}
		return "registration"
	}
	av, _ := a.Get()
	bv, _ := b.Get()
	if av.Status == PoolStatusUnstated || bv.Status == PoolStatusUnstated {
		return ""
	}
	var d []string
	if av.Status != bv.Status {
		d = append(d, "status")
	} else if av.Status == PoolRetiring && av.RetiringEpoch != bv.RetiringEpoch {
		d = append(d, "retiring epoch")
	}
	if len(d) == 0 {
		return ""
	}
	return d[0]
}
