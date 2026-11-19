package mailbox_test

import (
	"bytes"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// Whatever the stage decoders accept re-encodes to the same bytes, at every
// stage and from either side, and nothing panics. The seeds are small (the
// largest Auth is not a seed).
//
// spec: SPO-Xmailbox-INV-030, SPO-Xmailbox-INV-029
func FuzzDecodeIn(f *testing.F) {
	for _, s := range samplesV2() {
		f.Add(mustEncodeV(f, 2, s.m), uint8(s.w.stage), s.w.client)
	}
	for _, m := range samples() {
		f.Add(mustEncode(f, m), uint8(mailbox.StageV1), true)
		f.Add(mustEncode(f, m), uint8(mailbox.StageV1), false)
	}
	f.Add([]byte{}, uint8(0), true)
	f.Add([]byte{0x9f, 0xff}, uint8(3), false)
	f.Add([]byte{0x86, 0x01, 0x02, 0x5a, 0xff, 0xff, 0xff, 0xff}, uint8(3), true)
	f.Add([]byte{0x85, 0x0a, 0x01, 0x01, 0x5a, 0xff, 0xff, 0xff, 0xff}, uint8(3), true)
	f.Fuzz(func(t *testing.T, data []byte, stage uint8, client bool) {
		if len(data) > fuzzCap {
			t.Skip()
		}
		m, err := decodeIn(where{mailbox.Stage(stage), client}, data)
		if err != nil {
			if m != nil {
				t.Fatalf("an error and a message %T", m)
			}
			return
		}
		again, err := reencode(m)
		if err != nil {
			t.Fatalf("accepted %x at stage %d but cannot re-encode: %v", data, stage, err)
		}
		if !bytes.Equal(again, data) {
			t.Fatalf("accepted %x at stage %d, re-encodes to %x", data, stage, again)
		}
	})
}

// CanonicalSenders always returns a list that SendersHash accepts and that it
// returns unchanged, or an error for a list over the bound once repeats are
// dropped; no input panics.
//
// spec: SPO-Xmailbox-INV-030, SPO-Xmailbox-OUT-054
func FuzzCanonicalSenders(f *testing.F) {
	f.Add(bs(28, 1))
	f.Add(append(bs(28, 9), bs(28, 1)...))
	f.Add(append(bs(28, 1), bs(28, 1)...))
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 28*70 {
			t.Skip()
		}
		var keys []mailbox.WalletKey
		for i := 0; i+28 <= len(data); i += 28 {
			var k mailbox.WalletKey
			copy(k[:], data[i:i+28])
			keys = append(keys, k)
		}
		c, err := mailbox.CanonicalSenders(keys)
		if err != nil {
			return
		}
		if len(c) > mailbox.MaxSenders {
			t.Fatalf("%d senders", len(c))
		}
		for i := 1; i < len(c); i++ {
			if bytes.Compare(c[i-1][:], c[i][:]) >= 0 {
				t.Fatalf("not ascending at %d", i)
			}
		}
		if _, err := mailbox.SendersHash(c); err != nil {
			t.Fatalf("the hash of a canonical list: %v", err)
		}
		if again, err := mailbox.CanonicalSenders(c); err != nil || len(again) != len(c) {
			t.Fatalf("not idempotent: %v", err)
		}
		// Every input key is in the output.
		for _, k := range keys {
			found := false
			for _, o := range c {
				found = found || o == k
			}
			if !found {
				t.Fatalf("a key was lost")
			}
		}
	})
}

// A put is stored only if every bound still holds after it, and nothing wraps.
//
// spec: SPO-Xmailbox-INV-030, SPO-Xmailbox-SEC-042
func FuzzOpenAdmit(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint64(0), uint64(0), uint64(1000), true)
	f.Add(uint64(15), uint64(1<<20-1000), uint64(255), uint64(1<<26-1000), uint64(1000), false)
	f.Add(^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), uint64(1), false)
	v, err := mailbox.DefaultOpenQuota().Validated()
	if err != nil {
		f.Fatal(err)
	}
	q := v.Quota()
	f.Fuzz(func(t *testing.T, sEntries, sBytes, mEntries, mBytes, size uint64, listed bool) {
		u := mailbox.OpenUsage{Usage: mailbox.Usage{MailboxEntries: mEntries, MailboxBytes: mBytes}, StrangerEntries: sEntries, StrangerBytes: sBytes}
		if v.Admit(u, size, listed) != mailbox.StatusStored {
			return
		}
		if size == 0 || size > mailbox.MaxEnvelopeBytes || mEntries >= q.Quota.MailboxEntries || mBytes > q.Quota.MailboxBytes-size {
			t.Fatalf("stored against the queue bound: %+v size %d", u, size)
		}
		if !listed && (sEntries >= q.StrangerEntries || sBytes > q.StrangerBytes-size) {
			t.Fatalf("a stranger stored beyond the allowance: %+v size %d", u, size)
		}
	})
}
