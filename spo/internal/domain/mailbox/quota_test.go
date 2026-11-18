package mailbox_test

import (
	"errors"
	"math"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

func quota() mailbox.Quota { return mailbox.DefaultQuota() }

func valid(t *testing.T, q mailbox.Quota) mailbox.ValidQuota {
	t.Helper()
	v, err := q.Validated(1)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// spec: SPO-Xmailbox-OUT-009, SPO-Xmailbox-OUT-008
func TestDefaultQuotaIsTheBoundsTable(t *testing.T) {
	q := quota()
	want := mailbox.Quota{
		MailboxEntries: 256, MailboxBytes: 64 << 20,
		PairEntries: 64, PairBytes: 8 << 20,
		SenderBytes: 64 << 20, GlobalBytes: 4 << 30,
	}
	if q != want {
		t.Errorf("%+v", q)
	}
	if mailbox.MaxEnvelopeBytes != 1<<20 || mailbox.MaxHeaderFrame != 4096 || mailbox.MaxAckHashes != 64 ||
		mailbox.MaxItemsPerFetch != 16 || mailbox.MaxFetchWaitSeconds != 20 || mailbox.MaxAccessListParties != 1024 ||
		mailbox.MaxConnections != 64 || mailbox.MaxConnsPerKey != 2 || mailbox.MaxNewConnsPerKeyPerMinute != 6 ||
		mailbox.MaxRequestsPerConn != 256 || mailbox.MaxBytesPerConn != 64<<20 || mailbox.MaxBytesSentPerConn != 256<<20 || mailbox.MaxPutsPerPartyPerMinute != 120 ||
		mailbox.MaxInFlight != 8 || mailbox.MaxCBORDepth != 4 || mailbox.MaxCBORArray != 64 || mailbox.MaxCBORMapPairs != 8 {
		t.Error("a bound differs from the table of ADR 0013")
	}
	if mailbox.ConnLifetime.Minutes() != 10 || mailbox.IdleTimeout.Seconds() != 30 || mailbox.HandshakeTimeout.Seconds() != 10 || mailbox.ClockSkewWarning.Minutes() != 5 {
		t.Error("a timer differs from the table of ADR 0013")
	}
	if mailbox.DefaultRetentionSeconds != 7*86400 || mailbox.MaxRetentionSeconds != 30*86400 {
		t.Error("retention")
	}
}

// Each dimension: just under, at and just over.
//
// spec: SPO-Xmailbox-OUT-009
func TestAdmitUnderAtOver(t *testing.T) {
	q := quota()
	size := uint64(1000)
	type dim struct {
		name string
		set  func(*mailbox.Usage, uint64)
		max  uint64
		unit uint64 // what one put adds to this dimension
	}
	dims := []dim{
		{"mailbox bytes", func(u *mailbox.Usage, v uint64) { u.MailboxBytes = v }, q.MailboxBytes, size},
		{"pair bytes", func(u *mailbox.Usage, v uint64) { u.PairBytes = v }, q.PairBytes, size},
		{"sender bytes", func(u *mailbox.Usage, v uint64) { u.SenderBytes = v }, q.SenderBytes, size},
		{"global bytes", func(u *mailbox.Usage, v uint64) { u.GlobalBytes = v }, q.GlobalBytes, size},
		{"mailbox entries", func(u *mailbox.Usage, v uint64) { u.MailboxEntries = v }, q.MailboxEntries, 1},
		{"pair entries", func(u *mailbox.Usage, v uint64) { u.PairEntries = v }, q.PairEntries, 1},
	}
	for _, d := range dims {
		var u mailbox.Usage
		d.set(&u, d.max-d.unit-1)
		if st := valid(t, q).Admit(u, size); st != mailbox.StatusStored {
			t.Errorf("%s under: %d", d.name, st)
		}
		d.set(&u, d.max-d.unit)
		if st := valid(t, q).Admit(u, size); st != mailbox.StatusStored {
			t.Errorf("%s at: %d", d.name, st)
		}
		d.set(&u, d.max-d.unit+1)
		if st := valid(t, q).Admit(u, size); st != mailbox.StatusFull {
			t.Errorf("%s over: %d", d.name, st)
		}
		d.set(&u, d.max)
		if st := valid(t, q).Admit(u, size); st != mailbox.StatusFull {
			t.Errorf("%s full: %d", d.name, st)
		}
		d.set(&u, d.max+5)
		if st := valid(t, q).Admit(u, size); st != mailbox.StatusFull {
			t.Errorf("%s past full: %d", d.name, st)
		}
	}
	if st := valid(t, q).Admit(mailbox.Usage{}, 1); st != mailbox.StatusStored {
		t.Errorf("empty: %d", st)
	}
}

// spec: SPO-Xmailbox-OUT-009, SPO-Xmailbox-PRE-005
func TestAdmitSizeBounds(t *testing.T) {
	q := quota()
	for _, s := range []uint64{0, mailbox.MaxEnvelopeBytes + 1, 1 << 32, math.MaxUint64} {
		if st := valid(t, q).Admit(mailbox.Usage{}, s); st != mailbox.StatusTooLarge {
			t.Errorf("size %d: %d", s, st)
		}
	}
	for _, s := range []uint64{1, mailbox.MaxEnvelopeBytes} {
		if st := valid(t, q).Admit(mailbox.Usage{}, s); st != mailbox.StatusStored {
			t.Errorf("size %d: %d", s, st)
		}
	}
	// Too large wins over full.
	if st := valid(t, q).Admit(mailbox.Usage{MailboxEntries: 256}, 0); st != mailbox.StatusTooLarge {
		t.Errorf("%d", st)
	}
}

// Usage plus size must not wrap: a figure near the top of uint64 is full, not
// stored.
//
// spec: SPO-Xmailbox-SEC-004
func TestAdmitDoesNotOverflow(t *testing.T) {
	huge := mailbox.Quota{
		MailboxEntries: math.MaxUint64, MailboxBytes: math.MaxUint64,
		PairEntries: math.MaxUint64, PairBytes: math.MaxUint64,
		SenderBytes: math.MaxUint64, GlobalBytes: math.MaxUint64,
	}
	near := uint64(math.MaxUint64 - 5)
	for name, u := range map[string]mailbox.Usage{
		"mailbox bytes":   {MailboxBytes: near},
		"pair bytes":      {PairBytes: near},
		"sender bytes":    {SenderBytes: near},
		"global bytes":    {GlobalBytes: near},
		"mailbox entries": {MailboxEntries: math.MaxUint64},
		"pair entries":    {PairEntries: math.MaxUint64},
	} {
		if st := mailbox.UncheckedValid(huge).Admit(u, 10); st != mailbox.StatusFull {
			t.Errorf("%s: %d", name, st)
		}
	}
	if st := mailbox.UncheckedValid(huge).Admit(mailbox.Usage{MailboxBytes: math.MaxUint64 - 10}, 10); st != mailbox.StatusStored {
		t.Errorf("an exact fit at the top: %d", st)
	}
}

// spec: SPO-Xmailbox-OUT-009
func TestValidateTheGlobalQuotaCoversTheSenders(t *testing.T) {
	q := quota()
	if err := q.Validate(64); err != nil {
		t.Errorf("64 parties at the default: %v", err)
	}
	if err := q.Validate(65); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("65 parties at the default: %v", err)
	}
	q.GlobalBytes = 3 * q.SenderBytes
	if err := q.Validate(3); err != nil {
		t.Errorf("exact cover: %v", err)
	}
	q.GlobalBytes--
	if err := q.Validate(3); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("one byte short: %v", err)
	}
	q = quota()
	q.GlobalBytes = 1024 * q.SenderBytes
	if err := q.Validate(1024); err != nil {
		t.Errorf("1024 parties: %v", err)
	}
	if err := q.Validate(1025); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("1025 parties: %v", err)
	}
	for _, n := range []int{0, -1} {
		if err := q.Validate(n); !errors.Is(err, mailbox.ErrQuota) {
			t.Errorf("%d parties: %v", n, err)
		}
	}
	// A tighter sender total needs less.
	q = quota()
	q.SenderBytes = 1 << 20
	q.GlobalBytes = 10 << 20
	if err := q.Validate(10); err != nil {
		t.Errorf("tight: %v", err)
	}
	if err := q.Validate(11); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("tight, one more: %v", err)
	}
}

// A server may only tighten the bounds.
//
// spec: SPO-Xmailbox-OUT-009, SPO-Xmailbox-OUT-008
func TestValidateRefusesZeroAndLooseBounds(t *testing.T) {
	muts := map[string]func(*mailbox.Quota){
		"zero mailbox entries": func(q *mailbox.Quota) { q.MailboxEntries = 0 },
		"zero mailbox bytes":   func(q *mailbox.Quota) { q.MailboxBytes = 0 },
		"zero pair entries":    func(q *mailbox.Quota) { q.PairEntries = 0 },
		"zero pair bytes":      func(q *mailbox.Quota) { q.PairBytes = 0 },
		"zero sender bytes":    func(q *mailbox.Quota) { q.SenderBytes = 0 },
		"zero global bytes":    func(q *mailbox.Quota) { q.GlobalBytes = 0 },
		"mailbox entries 257":  func(q *mailbox.Quota) { q.MailboxEntries = 257 },
		"mailbox bytes +1":     func(q *mailbox.Quota) { q.MailboxBytes = 64<<20 + 1 },
		"pair entries 65":      func(q *mailbox.Quota) { q.PairEntries = 65 },
		"pair bytes +1":        func(q *mailbox.Quota) { q.PairBytes = 8<<20 + 1 },
		"sender bytes +1":      func(q *mailbox.Quota) { q.SenderBytes = 64<<20 + 1 },
	}
	for name, mut := range muts {
		q := quota()
		q.GlobalBytes = 1 << 40 // so the cover rule is not what refuses
		mut(&q)
		if err := q.Validate(1); !errors.Is(err, mailbox.ErrQuota) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Tightened values are accepted.
	q := quota()
	q.MailboxEntries, q.PairEntries, q.MailboxBytes, q.PairBytes, q.SenderBytes = 1, 1, 1, 1, 1
	q.GlobalBytes = 1
	if err := q.Validate(1); err != nil {
		t.Errorf("tight: %v", err)
	}
}

// A bound tighter than the envelope never lets one through: the test is
// size <= max, not a subtraction that could wrap.
//
// spec: SPO-Xmailbox-SEC-004, SPO-Xmailbox-OUT-009
func TestAdmitWithBoundsSmallerThanTheEnvelope(t *testing.T) {
	for name, set := range map[string]func(*mailbox.Quota){
		"mailbox bytes": func(q *mailbox.Quota) { q.MailboxBytes = 500 },
		"pair bytes":    func(q *mailbox.Quota) { q.PairBytes = 500 },
		"sender bytes":  func(q *mailbox.Quota) { q.SenderBytes = 500 },
		"global bytes":  func(q *mailbox.Quota) { q.GlobalBytes = 500 },
	} {
		q := quota()
		set(&q)
		v := mailbox.UncheckedValid(q) // a global quota of 500 does not pass Validate; this is the arithmetic
		if st := v.Admit(mailbox.Usage{}, 1000); st != mailbox.StatusFull {
			t.Errorf("%s: %d", name, st)
		}
		if st := v.Admit(mailbox.Usage{}, 500); st != mailbox.StatusStored {
			t.Errorf("%s, exact: %d", name, st)
		}
	}
}

// The party count is bounded on its own, not only through the cover rule.
//
// spec: SPO-Xmailbox-OUT-009
func TestValidatePartyCountWithAnUnboundedGlobalQuota(t *testing.T) {
	q := quota()
	q.GlobalBytes = 1 << 50
	if err := q.Validate(1024); err != nil {
		t.Errorf("1024: %v", err)
	}
	if err := q.Validate(1025); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("1025: %v", err)
	}
}

// Only a quota that passed Validate decides a put. The zero ValidQuota, the
// only other value there is, fails closed for every size and usage; Validated
// refuses what Validate refuses and returns the figures it checked.
//
// spec: SPO-Xmailbox-OUT-009, SPO-Xmailbox-SEC-014
func TestAdmitNeedsAValidatedQuota(t *testing.T) {
	var zero mailbox.ValidQuota
	if !zero.IsZero() {
		t.Error("the zero value is not zero")
	}
	for _, size := range []uint64{0, 1, 1000, mailbox.MaxEnvelopeBytes, mailbox.MaxEnvelopeBytes + 1} {
		if st := zero.Admit(mailbox.Usage{}, size); st != mailbox.StatusFull {
			t.Errorf("zero quota, size %d: %d", size, st)
		}
	}
	v, err := quota().Validated(4)
	if err != nil {
		t.Fatal(err)
	}
	if v.IsZero() || v.Quota() != quota() {
		t.Error("a validated quota lost its figures or is zero")
	}
	if st := v.Admit(mailbox.Usage{}, 1); st != mailbox.StatusStored {
		t.Errorf("validated: %d", st)
	}
	loose := quota()
	loose.MailboxEntries++
	for name, bad := range map[string]mailbox.Quota{"zero": {}, "loose": loose} {
		got, err := bad.Validated(1)
		if !errors.Is(err, mailbox.ErrQuota) || !got.IsZero() || got.Quota() != (mailbox.Quota{}) {
			t.Errorf("%s: %v, %+v", name, err, got)
		}
	}
	if got, err := quota().Validated(0); !errors.Is(err, mailbox.ErrQuota) || !got.IsZero() {
		t.Errorf("no parties: %v", err)
	}
}

// A list the protocol allows is never refused by the structural bound of the
// CBOR array.
//
// spec: SPO-Xmailbox-OUT-008
func TestListLimitsFitTheCBORArray(t *testing.T) {
	const _ = uint(mailbox.MaxCBORArray - mailbox.MaxAckHashes)     // compile time: MaxAckHashes <= MaxCBORArray
	const _ = uint(mailbox.MaxCBORArray - mailbox.MaxItemsPerFetch) // compile time: MaxItemsPerFetch <= MaxCBORArray
	if mailbox.MaxAckHashes > mailbox.MaxCBORArray || mailbox.MaxItemsPerFetch > mailbox.MaxCBORArray {
		t.Error("a list the protocol allows would be refused by the structural bound")
	}
	// The same figures through the codec: the largest legal Ack and Items
	// encode and decode.
	mids := make([]mailbox.Hash, mailbox.MaxAckHashes)
	for i := range mids {
		mids[i] = hash(byte(i))
		mids[i][31] = byte(i)
	}
	if _, err := mailbox.DecodeFromClient(mustEncode(t, mailbox.Ack{RequestID: 1, Mids: mids})); err != nil {
		t.Errorf("the largest Ack: %v", err)
	}
	entries := make([]mailbox.Item, mailbox.MaxItemsPerFetch)
	for i := range entries {
		entries[i] = mailbox.Item{Mid: hash(byte(i)), Size: 1}
		entries[i].Mid[31] = byte(i)
	}
	if _, err := mailbox.DecodeFromRelay(mustEncode(t, mailbox.Items{RequestID: 1, Entries: entries})); err != nil {
		t.Errorf("the largest Items: %v", err)
	}
}
