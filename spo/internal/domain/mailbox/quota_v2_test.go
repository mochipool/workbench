package mailbox_test

import (
	"errors"
	"math"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// spec: SPO-Xmailbox-OUT-056, SPO-Xmailbox-SEC-042
func TestReservedBytesDoesNotWrap(t *testing.T) {
	for _, c := range []struct {
		per, n, want uint64
		ok           bool
	}{
		{64 << 20, 4096, 256 << 30, true},
		{64 << 20, 64, 4 << 30, true},
		{0, 1 << 40, 0, true},
		{1 << 40, 0, 0, true},
		{1, 1, 1, true},
		{1 << 32, 1 << 31, 1 << 63, true},
		{1 << 32, 1 << 32, 0, false},
		{1 << 63, 2, 0, false},
		{math.MaxUint64, 2, 0, false},
		{math.MaxUint64, 1, math.MaxUint64, true},
		{2, math.MaxUint64, 0, false},
		{math.MaxUint64, math.MaxUint64, 0, false},
		{1<<32 + 1, 1 << 32, 0, false},
	} {
		got, ok := mailbox.ReservedBytes(c.per, c.n)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("ReservedBytes(%d, %d) = %d, %v; want %d, %v", c.per, c.n, got, ok, c.want, c.ok)
		}
	}
}

func openTable() mailbox.OpenQuota {
	q := mailbox.DefaultOpenQuota()
	return q
}

// The defaults of open mode are inside the ceilings of ADR 0013 and the
// constants that name them are the figures of the decision (the figures
// themselves are pinned by TestDefaultOpenQuotaValues).
//
// spec: SPO-Xmailbox-OUT-056
func TestDefaultOpenQuotaIsInsideTheTable(t *testing.T) {
	q := mailbox.DefaultOpenQuota()
	if q.Quota.MailboxEntries > mailbox.MaxMailboxEntries || q.Quota.MailboxBytes > mailbox.MaxMailboxBytes ||
		q.Quota.PairEntries > mailbox.MaxPairEntries || q.Quota.PairBytes > mailbox.MaxPairBytes ||
		q.Quota.SenderBytes > mailbox.MaxSenderBytes || q.Quota.GlobalBytes != mailbox.DefaultGlobalBytes {
		t.Errorf("%+v", q.Quota)
	}
	if q.StrangerEntries != 16 || q.StrangerBytes != 1<<20 || mailbox.StrangerEntries != 16 || mailbox.StrangerBytes != 1<<20 {
		t.Errorf("stranger allowance %d, %d", q.StrangerEntries, q.StrangerBytes)
	}
	if mailbox.MaxBoundDevices != 4096 || mailbox.DefaultBoundDevices != 1024 || mailbox.OpenMailboxBytes != 4<<20 || mailbox.OpenPairBytes != 2<<20 {
		t.Error("the registry size or the open-mode queue bounds")
	}
	if q.MaxBoundDevices != mailbox.DefaultBoundDevices || q.Quota.MailboxBytes != mailbox.OpenMailboxBytes || q.Quota.PairBytes != mailbox.OpenPairBytes {
		t.Errorf("the default is not made of the named constants: %+v", q)
	}
	if _, err := q.Validated(); err != nil {
		t.Errorf("the default: %v", err)
	}
}

// The configuration-load rule: the global quota is at least the per-device
// queue bound times the maximum number of bound devices.
//
// spec: SPO-Xmailbox-PRE-031
func TestOpenQuotaConfigRule(t *testing.T) {
	q := openTable()
	q.Quota.MailboxBytes = mailbox.MaxMailboxBytes // the ceiling: 64 MiB
	q.Quota.PairBytes = mailbox.MaxPairBytes
	q.MaxBoundDevices = mailbox.MaxBoundDevices // 4096
	need, _ := mailbox.ReservedBytes(q.Quota.MailboxBytes, q.MaxBoundDevices)
	if need != 256<<30 {
		t.Fatalf("need %d", need)
	}
	q.Quota.GlobalBytes = need - 1
	if err := q.Validate(); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("one byte short: %v", err)
	}
	q.Quota.GlobalBytes = need
	if err := q.Validate(); err != nil {
		t.Errorf("exactly enough: %v", err)
	}
	q.Quota.GlobalBytes = need + 1
	if err := q.Validate(); err != nil {
		t.Errorf("one byte more: %v", err)
	}
	// The operator keeps the ceiling queue bound and lowers max_bound_devices:
	// the default 4 GiB covers 64.
	q = openTable()
	q.Quota.MailboxBytes = mailbox.MaxMailboxBytes
	q.MaxBoundDevices = 64
	if err := q.Validate(); err != nil {
		t.Errorf("64 devices on 4 GiB: %v", err)
	}
	q.MaxBoundDevices = 65
	if err := q.Validate(); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("65 devices on 4 GiB: %v", err)
	}
	// The per-device bound is the queue's own, as tightened (2 MiB is the least
	// that holds the 1 MiB of strangers and one more envelope).
	q = openTable()
	q.Quota.MailboxBytes = 2 << 20
	q.MaxBoundDevices = 4096
	q.Quota.GlobalBytes = 8 << 30
	if err := q.Validate(); err != nil {
		t.Errorf("a tighter queue bound covers 4096 devices on 8 GiB: %v", err)
	}
	q.Quota.GlobalBytes = 8<<30 - 1
	if err := q.Validate(); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("4 GiB less one: %v", err)
	}
	// The default registry of 1024 devices at 4 MiB is exactly 4 GiB.
	q = openTable()
	if need, ok := mailbox.ReservedBytes(q.Quota.MailboxBytes, q.MaxBoundDevices); !ok || need != q.Quota.GlobalBytes {
		t.Errorf("the default reserves %d of %d", need, q.Quota.GlobalBytes)
	}
	// A global quota of zero never covers.
	q = openTable()
	q.Quota.GlobalBytes = 0
	if err := q.Validate(); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("zero global quota: %v", err)
	}
}

// spec: SPO-Xmailbox-PRE-031
func TestOpenQuotaBounds(t *testing.T) {
	big := func(q *mailbox.OpenQuota) { q.Quota.GlobalBytes = 1 << 50 }
	for name, mut := range map[string]func(*mailbox.OpenQuota){
		"mailbox entries 0":               func(q *mailbox.OpenQuota) { q.Quota.MailboxEntries = 0 },
		"mailbox entries 257":             func(q *mailbox.OpenQuota) { q.Quota.MailboxEntries = 257 },
		"mailbox bytes 0":                 func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = 0 },
		"mailbox bytes 64MiB+1":           func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = mailbox.MaxMailboxBytes + 1 },
		"pair entries 0":                  func(q *mailbox.OpenQuota) { q.Quota.PairEntries = 0 },
		"pair entries 65":                 func(q *mailbox.OpenQuota) { q.Quota.PairEntries = 65 },
		"pair bytes 0":                    func(q *mailbox.OpenQuota) { q.Quota.PairBytes = 0 },
		"pair bytes 8MiB+1":               func(q *mailbox.OpenQuota) { q.Quota.PairBytes = mailbox.MaxPairBytes + 1 },
		"sender bytes 0":                  func(q *mailbox.OpenQuota) { q.Quota.SenderBytes = 0 },
		"sender bytes 64MiB+1":            func(q *mailbox.OpenQuota) { q.Quota.SenderBytes = mailbox.MaxSenderBytes + 1 },
		"devices 0":                       func(q *mailbox.OpenQuota) { q.MaxBoundDevices = 0 },
		"devices 4097":                    func(q *mailbox.OpenQuota) { q.MaxBoundDevices = 4097; big(q) },
		"devices 2^63":                    func(q *mailbox.OpenQuota) { q.MaxBoundDevices = 1 << 63; big(q) },
		"stranger entries 0":              func(q *mailbox.OpenQuota) { q.StrangerEntries = 0 },
		"stranger entries 17":             func(q *mailbox.OpenQuota) { q.StrangerEntries = 17 },
		"stranger bytes 0":                func(q *mailbox.OpenQuota) { q.StrangerBytes = 0 },
		"stranger bytes 1MiB+1":           func(q *mailbox.OpenQuota) { q.StrangerBytes = 1<<20 + 1 },
		"stranger entries over the queue": func(q *mailbox.OpenQuota) { q.Quota.MailboxEntries = 8 },
		"stranger bytes over the queue":   func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = 1<<20 - 1 },
		"zero":                            func(q *mailbox.OpenQuota) { *q = mailbox.OpenQuota{} },
	} {
		q := openTable()
		mut(&q)
		if err := q.Validate(); !errors.Is(err, mailbox.ErrQuota) {
			t.Errorf("%s: %v", name, err)
		}
		if v, err := q.Validated(); err == nil || !v.IsZero() {
			t.Errorf("%s: Validated gave %v, %v", name, v, err)
		}
	}
	for name, mut := range map[string]func(*mailbox.OpenQuota){
		"mailbox entries 2":   func(q *mailbox.OpenQuota) { q.Quota.MailboxEntries = 2; q.StrangerEntries = 1 },
		"mailbox entries 256": func(q *mailbox.OpenQuota) { q.Quota.MailboxEntries = 256 },
		"mailbox bytes 2MiB":  func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = 2 << 20 },
		"stranger entries 16": func(q *mailbox.OpenQuota) { q.StrangerEntries = 16 },
		"stranger entries 1":  func(q *mailbox.OpenQuota) { q.StrangerEntries = 1 },
		"stranger bytes 1":    func(q *mailbox.OpenQuota) { q.StrangerBytes = 1 },
		"stranger bytes 1MiB": func(q *mailbox.OpenQuota) { q.StrangerBytes = 1 << 20 },
		"devices 1":           func(q *mailbox.OpenQuota) { q.MaxBoundDevices = 1 },
		"devices 4096":        func(q *mailbox.OpenQuota) { q.MaxBoundDevices = 4096; q.Quota.GlobalBytes = 16 << 30 },
		"pair 8MiB":           func(q *mailbox.OpenQuota) { q.Quota.PairBytes = mailbox.MaxPairBytes },
	} {
		q := openTable()
		mut(&q)
		if err := q.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if v, err := q.Validated(); err != nil || v.IsZero() || v.Quota() != q {
			t.Errorf("%s: Validated gave %v, %v", name, v, err)
		}
	}
	if !(mailbox.ValidOpenQuota{}).IsZero() {
		t.Error("the zero value is validated")
	}
}

func validOpen(t *testing.T) mailbox.ValidOpenQuota {
	t.Helper()
	v, err := openTable().Validated()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A sender on the recipient's list has the bounds of ADR 0013; any other sender
// also shares the stranger allowance of 16 entries and 1 MiB per recipient.
//
// spec: SPO-Xmailbox-OUT-056, SPO-Xmailbox-SEC-042
func TestStrangerAllowance(t *testing.T) {
	v := validOpen(t)
	const mib = 1 << 20
	for _, c := range []struct {
		name   string
		u      mailbox.OpenUsage
		size   uint64
		listed bool
		want   mailbox.Status
	}{
		{"stranger, empty", mailbox.OpenUsage{}, 1000, false, mailbox.StatusStored},
		{"stranger, 15 entries", mailbox.OpenUsage{StrangerEntries: 15}, 1000, false, mailbox.StatusStored},
		{"stranger, 16 entries", mailbox.OpenUsage{StrangerEntries: 16}, 1000, false, mailbox.StatusFull},
		{"stranger, 17 entries", mailbox.OpenUsage{StrangerEntries: 17}, 1000, false, mailbox.StatusFull},
		{"stranger, bytes just fit", mailbox.OpenUsage{StrangerBytes: mib - 1000}, 1000, false, mailbox.StatusStored},
		{"stranger, bytes one over", mailbox.OpenUsage{StrangerBytes: mib - 999}, 1000, false, mailbox.StatusFull},
		{"stranger, 1 MiB at once", mailbox.OpenUsage{}, mib, false, mailbox.StatusStored},
		{"stranger, 1 MiB after 1 byte", mailbox.OpenUsage{StrangerBytes: 1}, mib, false, mailbox.StatusFull},
		{"stranger, bytes full", mailbox.OpenUsage{StrangerBytes: mib}, 1, false, mailbox.StatusFull},
		{"stranger, bytes near the top of uint64", mailbox.OpenUsage{StrangerBytes: math.MaxUint64}, 1, false, mailbox.StatusFull},
		{"stranger, bytes top-1", mailbox.OpenUsage{StrangerBytes: math.MaxUint64 - 1}, 2, false, mailbox.StatusFull},
		{"stranger, entries at the top", mailbox.OpenUsage{StrangerEntries: math.MaxUint64}, 1, false, mailbox.StatusFull},
		// A listed sender is not held to the allowance, even when strangers
		// have used all of it.
		{"listed, strangers full by entries", mailbox.OpenUsage{StrangerEntries: 16}, 1000, true, mailbox.StatusStored},
		{"listed, strangers full by bytes", mailbox.OpenUsage{StrangerBytes: mib}, 1000, true, mailbox.StatusStored},
		{"listed, a 1 MiB envelope", mailbox.OpenUsage{StrangerBytes: mib, StrangerEntries: 16}, mib, true, mailbox.StatusStored},
		// Both are held to the bounds of ADR 0013.
		{"stranger, queue entries full", mailbox.OpenUsage{Usage: mailbox.Usage{MailboxEntries: 256}}, 1000, false, mailbox.StatusFull},
		{"listed, queue entries full", mailbox.OpenUsage{Usage: mailbox.Usage{MailboxEntries: 256}}, 1000, true, mailbox.StatusFull},
		{"listed, queue entries 255", mailbox.OpenUsage{Usage: mailbox.Usage{MailboxEntries: 255}}, 1000, true, mailbox.StatusStored},
		{"stranger, queue bytes full", mailbox.OpenUsage{Usage: mailbox.Usage{MailboxBytes: 4<<20 - 999}}, 1000, false, mailbox.StatusFull},
		{"listed, queue bytes full", mailbox.OpenUsage{Usage: mailbox.Usage{MailboxBytes: 4<<20 - 999}}, 1000, true, mailbox.StatusFull},
		{"listed, queue bytes fit", mailbox.OpenUsage{Usage: mailbox.Usage{MailboxBytes: 4<<20 - 1000}}, 1000, true, mailbox.StatusStored},
		{"listed, pair entries full", mailbox.OpenUsage{Usage: mailbox.Usage{PairEntries: 64}}, 1000, true, mailbox.StatusFull},
		{"listed, pair bytes full", mailbox.OpenUsage{Usage: mailbox.Usage{PairBytes: 2<<20 - 999}}, 1000, true, mailbox.StatusFull},
		{"listed, pair bytes fit", mailbox.OpenUsage{Usage: mailbox.Usage{PairBytes: 2<<20 - 1000}}, 1000, true, mailbox.StatusStored},
		{"listed, sender bytes full", mailbox.OpenUsage{Usage: mailbox.Usage{SenderBytes: 64<<20 - 999}}, 1000, true, mailbox.StatusFull},
		{"listed, global full", mailbox.OpenUsage{Usage: mailbox.Usage{GlobalBytes: 4<<30 - 999}}, 1000, true, mailbox.StatusFull},
		{"stranger, global full", mailbox.OpenUsage{Usage: mailbox.Usage{GlobalBytes: 4<<30 - 999}}, 1000, false, mailbox.StatusFull},
		// Sizes.
		{"size 0, listed", mailbox.OpenUsage{}, 0, true, mailbox.StatusTooLarge},
		{"size 0, stranger", mailbox.OpenUsage{}, 0, false, mailbox.StatusTooLarge},
		{"size 1 MiB + 1, listed", mailbox.OpenUsage{}, mib + 1, true, mailbox.StatusTooLarge},
		{"size 1 MiB + 1, stranger", mailbox.OpenUsage{}, mib + 1, false, mailbox.StatusTooLarge},
		{"size max uint64", mailbox.OpenUsage{}, math.MaxUint64, false, mailbox.StatusTooLarge},
	} {
		if got := v.Admit(c.u, c.size, c.listed); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	// A relay that tightened the allowance holds strangers to it.
	q := openTable()
	q.StrangerEntries, q.StrangerBytes = 2, 5000
	tv, err := q.Validated()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		u    mailbox.OpenUsage
		size uint64
		want mailbox.Status
	}{
		{mailbox.OpenUsage{StrangerEntries: 1}, 5000, mailbox.StatusStored},
		{mailbox.OpenUsage{StrangerEntries: 2}, 1, mailbox.StatusFull},
		{mailbox.OpenUsage{StrangerBytes: 1}, 5000, mailbox.StatusFull},
		{mailbox.OpenUsage{StrangerBytes: 4999}, 1, mailbox.StatusStored},
		{mailbox.OpenUsage{StrangerBytes: 5000}, 1, mailbox.StatusFull},
	} {
		if got := tv.Admit(c.u, c.size, false); got != c.want {
			t.Errorf("tightened %+v size %d: %d, want %d", c.u, c.size, got, c.want)
		}
	}
	// The zero ValidOpenQuota admits nothing.
	for _, listed := range []bool{true, false} {
		if got := (mailbox.ValidOpenQuota{}).Admit(mailbox.OpenUsage{}, 1, listed); got != mailbox.StatusFull {
			t.Errorf("zero quota, listed=%v: %d", listed, got)
		}
	}
}

// Adding up never wraps: for any usage near the top of uint64 the answer is
// full, never stored.
//
// spec: SPO-Xmailbox-SEC-042
func TestOpenAdmitDoesNotWrap(t *testing.T) {
	v := validOpen(t)
	top := uint64(math.MaxUint64)
	for _, u := range []mailbox.OpenUsage{{StrangerBytes: top}, {StrangerBytes: top - 1}, {StrangerEntries: top}} {
		if got := v.Admit(u, 2, false); got != mailbox.StatusFull {
			t.Errorf("%+v, a stranger: %d", u, got)
		}
		if got := v.Admit(u, 2, true); got != mailbox.StatusStored {
			t.Errorf("%+v, a listed sender: %d", u, got)
		}
	}
	for _, u := range []mailbox.OpenUsage{
		{Usage: mailbox.Usage{MailboxBytes: top}}, {Usage: mailbox.Usage{PairBytes: top}},
		{Usage: mailbox.Usage{SenderBytes: top}}, {Usage: mailbox.Usage{GlobalBytes: top}},
		{Usage: mailbox.Usage{MailboxEntries: top}}, {Usage: mailbox.Usage{PairEntries: top}},
	} {
		for _, listed := range []bool{true, false} {
			if got := v.Admit(u, 2, listed); got != mailbox.StatusFull {
				t.Errorf("%+v listed=%v: %d", u, listed, got)
			}
		}
	}
}
