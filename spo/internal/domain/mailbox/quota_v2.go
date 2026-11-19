package mailbox

import "math/bits"

// OpenQuota is the configuration of a relay in open mode (ADR 0014 decision
// 5): the quota of ADR 0013, the registry size, and the allowance that senders
// not on a recipient's expected-sender list share. Zero values are invalid;
// start from DefaultOpenQuota, tighten, and call Validated: only a
// ValidOpenQuota admits a put.
type OpenQuota struct {
	Quota           Quota
	MaxBoundDevices uint64
	StrangerEntries uint64
	StrangerBytes   uint64
}

// DefaultOpenQuota is the default of open mode (ADR 0014 decision 5): 1024
// bound devices; per device a queue of 256 entries and 4 MiB; per sender and
// device 64 entries and 2 MiB; 16 entries and 1 MiB for the strangers of a
// recipient; 64 MiB per wallet key as a sender; and a global quota of 4 GiB,
// which is exactly 1024 queues of 4 MiB. The queue bounds of ADR 0013 (64 MiB,
// 8 MiB) are ceilings, not defaults: 1024 devices at 64 MiB would need 256 GiB
// (ReservedBytes). An operator who wants 4096 devices sets a global quota of
// 16 GiB.
func DefaultOpenQuota() OpenQuota {
	return OpenQuota{
		Quota: Quota{
			MailboxEntries: MaxMailboxEntries,
			MailboxBytes:   OpenMailboxBytes,
			PairEntries:    MaxPairEntries,
			PairBytes:      OpenPairBytes,
			SenderBytes:    MaxSenderBytes,
			GlobalBytes:    DefaultGlobalBytes,
		},
		MaxBoundDevices: DefaultBoundDevices,
		StrangerEntries: StrangerEntries,
		StrangerBytes:   StrangerBytes,
	}
}

// OpenUsage is what the store and the registry report before a put in open
// mode: the usage of ADR 0013 and what the recipient's strangers hold. The
// sender figure of Usage is counted per wallet key (ADR 0014 decision 5): the
// caller sums a key's devices.
type OpenUsage struct {
	Usage
	StrangerEntries uint64
	StrangerBytes   uint64
}

// ValidOpenQuota is an OpenQuota that passed Validate. It can only be made by
// OpenQuota.Validated; the zero value is the unvalidated one and admits
// nothing.
type ValidOpenQuota struct {
	q  OpenQuota
	ok bool
}

// ReservedBytes is the room the global quota must reserve: perDevice times
// devices. ok is false when the product does not fit in a uint64, in which case
// no global quota covers it.
func ReservedBytes(perDevice, devices uint64) (need uint64, ok bool) {
	hi, lo := bits.Mul64(perDevice, devices)
	if hi != 0 {
		return 0, false
	}
	return lo, true
}

// Validate is the configuration-load rule of open mode: every bound of ADR 0013
// is set and no looser than the table; there are 1 to MaxBoundDevices bound
// devices; the stranger allowance is 1 to 16 entries and 1 to 1 MiB and sits
// inside the queue bound; and the global quota is at least the per-device queue
// bound times the maximum number of bound devices, because the quota reserves
// room per bound device, not per sender (ADR 0014 decision 5).
//
// The allowance sits strictly inside the queue bound, so that strangers can
// never fill a victim's queue: it has fewer entries than the queue, and the
// bytes the queue has beyond the allowance are at least those of one envelope
// of the largest size, so a listed sender can always store one once the
// strangers hold everything they may.
func (q OpenQuota) Validate() error {
	if err := q.Quota.checkBounds(); err != nil {
		return err
	}
	if q.MaxBoundDevices < 1 || q.MaxBoundDevices > MaxBoundDevices {
		return bad(ErrQuota, "max bound devices is %d; it must be 1 to %d", q.MaxBoundDevices, MaxBoundDevices)
	}
	if q.StrangerEntries < 1 || q.StrangerEntries > StrangerEntries {
		return bad(ErrQuota, "stranger entries is %d; it must be 1 to %d", q.StrangerEntries, StrangerEntries)
	}
	if q.StrangerBytes < 1 || q.StrangerBytes > StrangerBytes {
		return bad(ErrQuota, "stranger bytes is %d; it must be 1 to %d", q.StrangerBytes, StrangerBytes)
	}
	if q.StrangerEntries >= q.Quota.MailboxEntries {
		return bad(ErrQuota, "the stranger allowance of %d entries is not below the queue bound of %d", q.StrangerEntries, q.Quota.MailboxEntries)
	}
	if q.StrangerBytes > q.Quota.MailboxBytes || q.Quota.MailboxBytes-q.StrangerBytes < MaxEnvelopeBytes {
		return bad(ErrQuota, "the queue bound of %d bytes does not leave %d bytes beyond the stranger allowance of %d bytes",
			q.Quota.MailboxBytes, MaxEnvelopeBytes, q.StrangerBytes)
	}
	need, ok := ReservedBytes(q.Quota.MailboxBytes, q.MaxBoundDevices)
	if !ok || q.Quota.GlobalBytes < need {
		return bad(ErrQuota, "the global quota %d does not cover %d bound devices at %d bytes each", q.Quota.GlobalBytes, q.MaxBoundDevices, q.Quota.MailboxBytes)
	}
	return nil
}

// Validated runs Validate and returns the checked quota.
func (q OpenQuota) Validated() (ValidOpenQuota, error) {
	if err := q.Validate(); err != nil {
		return ValidOpenQuota{}, err
	}
	return ValidOpenQuota{q: q, ok: true}, nil
}

// IsZero reports whether v was never validated.
func (v ValidOpenQuota) IsZero() bool { return !v.ok }

// Quota returns the checked figures (the zero OpenQuota for the zero value).
func (v ValidOpenQuota) Quota() OpenQuota { return v.q }

// Admit decides one put in open mode, from the usage before it. listed says
// whether the sender's wallet key is on the recipient's expected-sender list.
// Every sender is held to the bounds of ADR 0013 (ValidQuota.Admit: too_large
// for a size outside 1 to MaxEnvelopeBytes, full for any bound the put would
// pass). A sender that is not listed also shares the stranger allowance of its
// recipient: full if the strangers already hold the allowance's entries, or if
// the put would pass its bytes. The strangers' pool is a sub-budget of the
// queue: strangers never hold more than their allowance, and a listed sender
// may use all the rest, which Validate keeps at no less than one envelope of the
// largest size. A stranger can therefore never fill a victim's queue. The zero
// ValidOpenQuota answers StatusFull (it fails closed).
func (v ValidOpenQuota) Admit(u OpenUsage, size uint64, listed bool) Status {
	if !v.ok {
		return StatusFull
	}
	if st := (ValidQuota{q: v.q.Quota, ok: true}).Admit(u.Usage, size); st != StatusStored {
		return st
	}
	if listed {
		return StatusStored
	}
	if u.StrangerEntries >= v.q.StrangerEntries || !fits(u.StrangerBytes, size, v.q.StrangerBytes) {
		return StatusFull
	}
	return StatusStored
}
