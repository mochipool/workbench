package mailbox

// DefaultQuota is the bounds table of ADR 0013 decision 2. A server may only
// tighten it.
func DefaultQuota() Quota {
	return Quota{
		MailboxEntries: MaxMailboxEntries,
		MailboxBytes:   MaxMailboxBytes,
		PairEntries:    MaxPairEntries,
		PairBytes:      MaxPairBytes,
		SenderBytes:    MaxSenderBytes,
		GlobalBytes:    DefaultGlobalBytes,
	}
}

// fits reports whether used+add <= max without computing the sum, which could
// wrap.
func fits(used, add, max uint64) bool { return add <= max && used <= max-add }

// ValidQuota is a Quota that passed Validate. It can only be made by
// Quota.Validated, so nothing that decides a put works from a quota that was
// not checked; the zero value is the unvalidated one and admits nothing.
type ValidQuota struct {
	q  Quota
	ok bool
}

// Validated is Validate that returns the checked quota.
func (q Quota) Validated(parties int) (ValidQuota, error) {
	if err := q.Validate(parties); err != nil {
		return ValidQuota{}, err
	}
	return ValidQuota{q: q, ok: true}, nil
}

// IsZero reports whether v is the zero value, which was never validated.
func (v ValidQuota) IsZero() bool { return !v.ok }

// Quota returns the checked figures (the zero Quota for the zero value).
func (v ValidQuota) Quota() Quota { return v.q }

// Admit decides whether one more envelope of size bytes may be stored, given
// the usage before it: StatusTooLarge for a size outside 1..MaxEnvelopeBytes,
// StatusFull for any bound that would be passed, else StatusStored. A put of an
// entry that already exists (duplicate) is decided by the store before this
// and costs no quota. On the zero ValidQuota it answers StatusFull for every
// size (it fails closed); callers refuse a zero ValidQuota before this.
func (v ValidQuota) Admit(u Usage, size uint64) Status {
	if !v.ok {
		return StatusFull
	}
	q := v.q
	if size == 0 || size > MaxEnvelopeBytes {
		return StatusTooLarge
	}
	if u.MailboxEntries >= q.MailboxEntries || u.PairEntries >= q.PairEntries {
		return StatusFull
	}
	if !fits(u.MailboxBytes, size, q.MailboxBytes) ||
		!fits(u.PairBytes, size, q.PairBytes) ||
		!fits(u.SenderBytes, size, q.SenderBytes) ||
		!fits(u.GlobalBytes, size, q.GlobalBytes) {
		return StatusFull
	}
	return StatusStored
}

// Validate is the configuration-load rule: every bound is set and no looser
// than the table, the access list has 1 to MaxAccessListParties parties, and
// the global quota covers the per-sender totals of all of them.
func (q Quota) Validate(parties int) error {
	if parties < 1 || parties > MaxAccessListParties {
		return bad(ErrQuota, "%d parties; the access list has 1 to %d", parties, MaxAccessListParties)
	}
	if err := q.checkBounds(); err != nil {
		return err
	}
	// A global quota of zero fails the cover rule, as parties >= 1 and
	// SenderBytes >= 1. parties <= 1024 and SenderBytes <= 64 MiB, so the product cannot wrap.
	if need := uint64(parties) * q.SenderBytes; q.GlobalBytes < need {
		return bad(ErrQuota, "the global quota %d does not cover %d parties at %d bytes each (%d)", q.GlobalBytes, parties, q.SenderBytes, need)
	}
	return nil
}

// checkBounds is the part of the load rule that is the same in both versions:
// every bound is set and no looser than the table.
func (q Quota) checkBounds() error {
	for _, c := range []struct {
		name     string
		v, limit uint64
	}{
		{"mailbox entries", q.MailboxEntries, MaxMailboxEntries},
		{"mailbox bytes", q.MailboxBytes, MaxMailboxBytes},
		{"pair entries", q.PairEntries, MaxPairEntries},
		{"pair bytes", q.PairBytes, MaxPairBytes},
		{"sender bytes", q.SenderBytes, MaxSenderBytes},
	} {
		if c.v == 0 || c.v > c.limit {
			return bad(ErrQuota, "%s is %d; it must be 1 to %d", c.name, c.v, c.limit)
		}
	}
	return nil
}
