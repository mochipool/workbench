package mailbox

// Retention is counted in whole unix seconds, the unit of the arrival time in
// an entry name and of the AuthOK message.

// ClampRetention takes a configured retention: zero is refused and anything
// above MaxRetentionSeconds is cut to it.
func ClampRetention(seconds uint64) (uint64, error) {
	if seconds == 0 {
		return 0, bad(ErrRange, "retention is zero")
	}
	return min(seconds, MaxRetentionSeconds), nil
}

// ExpiresAt is the time an entry that arrived at arrival is swept. An arrival
// outside 0 to MaxTime is refused, so the sum cannot overflow and agrees with
// Expired for every arrival that is not in the future.
func ExpiresAt(arrival int64, retentionSeconds uint64) (int64, error) {
	r, err := ClampRetention(retentionSeconds)
	if err != nil {
		return 0, err
	}
	if arrival < 0 || arrival > MaxTime {
		return 0, bad(ErrRange, "arrival time %d is not 0 to %d", arrival, int64(MaxTime))
	}
	return arrival + int64(r), nil // MaxTime + 30 days does not overflow
}

// Expired reports whether an entry that arrived at arrival is due for
// deletion at now: its age has reached the retention, clamped to the maximum.
// It fails closed: a negative arrival time, an arrival above MaxTime or a zero
// retention is expired. An arrival in the future is expired once it is more
// than MaxRetentionSeconds ahead of now, because no clock that was merely set
// back for a while produced it and it would otherwise hold quota for ever; a
// nearer one (the clock went back) is not.
func Expired(arrival, now int64, retentionSeconds uint64) bool {
	r, err := ClampRetention(retentionSeconds)
	if err != nil || arrival < 0 || arrival > MaxTime {
		return true
	}
	if arrival > now {
		// arrival > now: the unsigned difference is exact, also when now is negative
		return uint64(arrival)-uint64(now) > MaxRetentionSeconds
	}
	return uint64(now)-uint64(arrival) >= r // now >= arrival >= 0, so no overflow
}
