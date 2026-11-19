package mailbox_test

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// M2. The stranger allowance is strictly inside the queue bound, and the rest
// of the queue holds at least one envelope of the largest size, so a listed
// sender always has room once the strangers are full.
//
// spec: SPO-Xmailbox-PRE-031, SPO-Xmailbox-OUT-056
func TestStrangerAllowanceIsStrictlyInsideTheQueue(t *testing.T) {
	const mib = 1 << 20
	for name, c := range map[string]struct {
		mut func(*mailbox.OpenQuota)
		ok  bool
	}{
		"entries equal":             {func(q *mailbox.OpenQuota) { q.Quota.MailboxEntries = 16; q.StrangerEntries = 16 }, false},
		"entries one inside":        {func(q *mailbox.OpenQuota) { q.Quota.MailboxEntries = 17; q.StrangerEntries = 16 }, true},
		"entries 1 and 1":           {func(q *mailbox.OpenQuota) { q.Quota.MailboxEntries = 1; q.StrangerEntries = 1 }, false},
		"entries 2 and 1":           {func(q *mailbox.OpenQuota) { q.Quota.MailboxEntries = 2; q.StrangerEntries = 1 }, true},
		"entries below":             {func(q *mailbox.OpenQuota) { q.Quota.MailboxEntries = 15; q.StrangerEntries = 16 }, false},
		"bytes equal":               {func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = mib; q.StrangerBytes = mib }, false},
		"bytes room one short":      {func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = 2*mib - 1; q.StrangerBytes = mib }, false},
		"bytes room exactly":        {func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = 2 * mib; q.StrangerBytes = mib }, true},
		"bytes room one more":       {func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = 2*mib + 1; q.StrangerBytes = mib }, true},
		"small allowance, one room": {func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = mib + 1; q.StrangerBytes = 1 }, true},
		"small allowance, short":    {func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = mib; q.StrangerBytes = 1 }, false},
		"queue bytes of one letter": {func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = 1000; q.StrangerBytes = 1 }, false},
		"queue below the allowance": {func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = 1000; q.StrangerBytes = 2000 }, false},
		"the 16 entries and 1 MiB":  {func(q *mailbox.OpenQuota) { q.Quota.MailboxEntries = 16; q.Quota.MailboxBytes = mib }, false},
		"max room with a big queue": {func(q *mailbox.OpenQuota) { q.Quota.MailboxBytes = 64 * mib; q.Quota.GlobalBytes = 64 << 30 }, true},
	} {
		q := openTable()
		c.mut(&q)
		err := q.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !c.ok && !errors.Is(err, mailbox.ErrQuota) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// For every quota that validates, once the strangers hold their whole allowance
// a stranger is refused and a listed sender still stores an envelope of the
// largest size: the stranger pool is a sub-budget of the queue.
//
// spec: SPO-Xmailbox-OUT-056, SPO-Xmailbox-PRE-031
func TestListedSenderAlwaysHasRoomWhenStrangersAreFull(t *testing.T) {
	const mib = 1 << 20
	valid := 0
	for _, entries := range []uint64{1, 2, 16, 17, 32, 256} {
		for _, bytes := range []uint64{mib, mib + 1, 2*mib - 1, 2 * mib, 3 * mib, 4 * mib, 64 * mib} {
			for _, sE := range []uint64{1, 2, 15, 16} {
				for _, sB := range []uint64{1, 1000, mib - 1, mib} {
					q := openTable()
					q.Quota.MailboxEntries, q.Quota.MailboxBytes = entries, bytes
					q.Quota.GlobalBytes = 1 << 40 // covers the registry at any queue bound
					q.StrangerEntries, q.StrangerBytes = sE, sB
					v, err := q.Validated()
					if err != nil {
						continue
					}
					valid++
					full := mailbox.OpenUsage{
						Usage:           mailbox.Usage{MailboxEntries: sE, MailboxBytes: sB},
						StrangerEntries: sE, StrangerBytes: sB,
					}
					if got := v.Admit(full, 1, false); got != mailbox.StatusFull {
						t.Errorf("%+v: a stranger after the allowance: %d", q, got)
					}
					if got := v.Admit(full, mailbox.MaxEnvelopeBytes, true); got != mailbox.StatusStored {
						t.Errorf("entries %d bytes %d, strangers %d and %d: a listed sender with strangers full: %d", entries, bytes, sE, sB, got)
					}
					// Strangers never go beyond the allowance, whatever the queue holds.
					for _, size := range []uint64{1, 1000, mib} {
						beyond := mailbox.OpenUsage{Usage: mailbox.Usage{MailboxEntries: sE - 1, MailboxBytes: sB - 1}, StrangerEntries: sE - 1, StrangerBytes: sB - 1}
						if want := sB-1+size <= sB; (v.Admit(beyond, size, false) == mailbox.StatusStored) != want && sE-1 < sE {
							t.Errorf("entries %d bytes %d, strangers %d and %d, size %d: one below the allowance", entries, bytes, sE, sB, size)
						}
					}
				}
			}
		}
	}
	if valid < 20 {
		t.Fatalf("only %d valid quotas in the grid", valid)
	}
}

// The defaults of open mode (ADR 0014 decision 5): 1024 bound devices, 4 MiB
// and 256 entries of queue per device, 2 MiB per pair, 16 entries and 1 MiB of
// strangers, 64 MiB per sender and a global quota of 4 GiB, which is exactly
// the queue bound times the devices.
//
// spec: SPO-Xmailbox-OUT-056, SPO-Xmailbox-PRE-031
func TestDefaultOpenQuotaValues(t *testing.T) {
	q := mailbox.DefaultOpenQuota()
	if q.MaxBoundDevices != 1024 {
		t.Errorf("max bound devices %d", q.MaxBoundDevices)
	}
	if q.Quota.MailboxEntries != 256 || q.Quota.MailboxBytes != 4<<20 {
		t.Errorf("queue %d entries, %d bytes", q.Quota.MailboxEntries, q.Quota.MailboxBytes)
	}
	if q.Quota.PairBytes != 2<<20 || q.Quota.PairEntries != mailbox.MaxPairEntries {
		t.Errorf("pair %d entries, %d bytes", q.Quota.PairEntries, q.Quota.PairBytes)
	}
	if q.Quota.SenderBytes != 64<<20 || q.Quota.GlobalBytes != 4<<30 {
		t.Errorf("sender %d, global %d", q.Quota.SenderBytes, q.Quota.GlobalBytes)
	}
	if q.StrangerEntries != 16 || q.StrangerBytes != 1<<20 {
		t.Errorf("strangers %d entries, %d bytes", q.StrangerEntries, q.StrangerBytes)
	}
	need, ok := mailbox.ReservedBytes(q.Quota.MailboxBytes, q.MaxBoundDevices)
	if !ok || need != q.Quota.GlobalBytes || need != 4<<30 {
		t.Errorf("the default reserves %d (ok %v) of %d", need, ok, q.Quota.GlobalBytes)
	}
	if err := q.Validate(); err != nil {
		t.Errorf("the default: %v", err)
	}
	// The default is on the edge of the rule: a byte less is refused, one more
	// device is refused.
	short := q
	short.Quota.GlobalBytes--
	if err := short.Validate(); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("a byte short: %v", err)
	}
	more := q
	more.MaxBoundDevices++
	if err := more.Validate(); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("1025 devices on 4 GiB: %v", err)
	}
	// An operator who wants 4096 devices sets 16 GiB; 4097 is never allowed.
	big := q
	big.MaxBoundDevices = 4096
	big.Quota.GlobalBytes = 16 << 30
	if err := big.Validate(); err != nil {
		t.Errorf("4096 devices on 16 GiB: %v", err)
	}
	big.Quota.GlobalBytes--
	if err := big.Validate(); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("4096 devices on 16 GiB less a byte: %v", err)
	}
	big.MaxBoundDevices, big.Quota.GlobalBytes = 4097, 1<<40
	if err := big.Validate(); !errors.Is(err, mailbox.ErrQuota) {
		t.Errorf("4097 devices: %v", err)
	}
}

// The AuthOK of version 2 carries the `until` of a recorded binding, which is a
// time: 1 to MaxTime. A zero is a binding that never was valid.
//
// spec: SPO-Xmailbox-PRE-028, SPO-Xmailbox-OUT-049
func TestAuthOKV2UntilIsATime(t *testing.T) {
	ok := func(until int64) mailbox.AuthOKV2 {
		return mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1, Until: until}
	}
	for _, until := range []int64{0, -1, mailbox.MaxTime + 1, -mailbox.MaxTime} {
		if _, err := mailbox.EncodeV(2, ok(until)); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("encode until %d: %v", until, err)
		}
		frame := cbor(t, 2, 2, 1, 1, 1, 1, uint64(until))
		if until >= 0 {
			if _, err := mailbox.DecodeFromRelayIn(mailbox.StageV2PreAuth, frame); !errors.Is(err, mailbox.ErrRange) {
				t.Errorf("decode until %d: %v", until, err)
			}
		}
	}
	for _, until := range []int64{1, 1707776000, mailbox.MaxTime} {
		b, err := mailbox.EncodeV(2, ok(until))
		if err != nil {
			t.Errorf("encode until %d: %v", until, err)
			continue
		}
		m, err := mailbox.DecodeFromRelayIn(mailbox.StageV2PreAuth, b)
		if err != nil || m.(mailbox.AuthOKV2).Until != until {
			t.Errorf("decode until %d: %v, %v", until, m, err)
		}
	}
}

// ErrAuthWeakKey names its package like its siblings.
//
// spec: SPO-Xmailbox-SEC-041
func TestErrAuthWeakKeyHasThePackagePrefix(t *testing.T) {
	if !strings.HasPrefix(mailbox.ErrAuthWeakKey.Error(), "mailbox: ") {
		t.Errorf("%q", mailbox.ErrAuthWeakKey)
	}
	for _, e := range []error{mailbox.ErrStage, mailbox.ErrAuth, mailbox.ErrVersion, mailbox.ErrRange} {
		if !strings.HasPrefix(e.Error(), "mailbox: ") {
			t.Errorf("%q", e)
		}
	}
}

// A client configured for version 2 only refuses a Challenge that offers only
// version 1, and chooses version 2 from any range that holds it. There is no
// floor and no way to remember one: the protection is that the client speaks
// version 2 only.
//
// spec: SPO-Xmailbox-OUT-050, SPO-Xmailbox-SEC-036
func TestClientOfVersion2RefusesAnOfferOfVersion1(t *testing.T) {
	for _, r := range [][2]uint{{1, 1}} {
		if _, err := mailbox.V2.Choose(r[0], r[1]); !errors.Is(err, mailbox.ErrVersion) {
			t.Errorf("version 2 only, offered %v: %v", r, err)
		}
	}
	for _, r := range [][2]uint{{1, 2}, {2, 2}, {2, 65535}, {1, 65535}} {
		if n, err := mailbox.V2.Choose(r[0], r[1]); err != nil || n != 2 {
			t.Errorf("version 2 only, offered %v: %d, %v", r, n, err)
		}
	}
	// The relay that offers only version 2 announces [2, 2], which the same
	// client takes.
	lo, hi := mailbox.V2.Range()
	if lo != 2 || hi != 2 {
		t.Errorf("range %d..%d", lo, hi)
	}
	if n, err := mailbox.V2.Choose(lo, hi); err != nil || n != 2 {
		t.Errorf("%d, %v", n, err)
	}
}

// The frames of the retired version 1 are refused by every decoder at every stage
// and from either side, whatever their fields: an Auth of version 1, an Auth
// with the old arity, a Put and an AuthOK of the old shapes. The committed
// vectors of the shared frames still decode, each as one message of its own side.
//
// spec: SPO-Xmailbox-OUT-052, SPO-Xmailbox-PRE-029, SPO-Xmailbox-OUT-011
func TestTheFramesOfTheRetiredVersionAreRefused(t *testing.T) {
	retired := [][]byte{
		cbor(t, 1, 1, fpb(1), sigb(1)),         // the Auth of version 1
		cbor(t, 1, 2, fpb(1), sigb(1)),         // the old arity under version 2
		cbor(t, 2, 1, 10, 11, 12, 13),          // the AuthOK of version 1
		cbor(t, 2, 2, 10, 11, 12, 13),          // the old arity under version 2
		cbor(t, 3, 7, fpb(4), hashb(5), 99),    // the Put of version 1
		cbor(t, 3, 7, fpb(4), hashb(5), 99, 0), // one field more
	}
	for _, st := range []mailbox.Stage{mailbox.StageV2PreAuth, mailbox.StageV2Authed} {
		for i, c := range retired {
			if m, err := mailbox.DecodeFromClientIn(st, c); err == nil {
				t.Errorf("retired frame %d decoded from the client at %v as %T", i, st, m)
			}
			if m, err := mailbox.DecodeFromRelayIn(st, c); err == nil {
				t.Errorf("retired frame %d decoded from the relay at %v as %T", i, st, m)
			}
		}
	}
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	for _, v := range vf.Frames {
		c := unhex(t, v.CBORHex)
		okSides := 0
		for _, w := range []where{{mailbox.StageV2PreAuth, true}, {mailbox.StageV2Authed, true}, {mailbox.StageV2PreAuth, false}, {mailbox.StageV2Authed, false}} {
			if _, err := decodeIn(w, c); err == nil {
				okSides++
			}
		}
		if okSides == 0 {
			t.Errorf("the shared frame %s decodes nowhere", v.Name)
		}
	}
}
