package mailbox_test

import (
	"io"
	"runtime"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

func fp(b byte) (f party.Fingerprint) {
	for i := range f {
		f[i] = b + byte(i)
	}
	return
}

func hash(b byte) (h mailbox.Hash) {
	for i := range h {
		h[i] = b + byte(i)
	}
	return
}

func nk(b byte) (k party.NodeKey) {
	for i := range k {
		k[i] = b + byte(i)
	}
	return
}

func nonce(b byte) (n [32]byte) {
	for i := range n {
		n[i] = b + byte(i)
	}
	return
}

func sig(b byte) (s [64]byte) {
	for i := range s {
		s[i] = b + byte(i)
	}
	return
}

// samples is one valid message of every type (two for fetch and items).
func samples() []mailbox.Message {
	h := hash(9)
	return []mailbox.Message{
		mailbox.Challenge{Min: 1, Max: 1, Nonce: nonce(1), RelayKey: nk(2), RelayTime: 1700000000},
		mailbox.Auth{Version: 1, Fingerprint: fp(3), Signature: sig(4)},
		mailbox.AuthOK{Version: 1, MaxEnvelope: mailbox.MaxEnvelopeBytes, MaxEntries: 256, MaxBytes: 64 << 20, RetentionSeconds: mailbox.DefaultRetentionSeconds},
		mailbox.Put{RequestID: 7, To: fp(4), Mid: hash(5), Size: 1234},
		mailbox.PutResult{RequestID: 7, Status: mailbox.StatusStored},
		mailbox.Fetch{RequestID: 8, MaxItems: 16, WaitSeconds: 20},
		mailbox.Fetch{RequestID: 9, After: &h, MaxItems: 1, WaitSeconds: 0},
		mailbox.Items{RequestID: 8, Entries: []mailbox.Item{{Mid: hash(1), Size: 10}, {Mid: hash(2), Size: 20}}, More: true},
		mailbox.Items{RequestID: 8},
		mailbox.Ack{RequestID: 9, Mids: []mailbox.Hash{hash(1), hash(2)}},
		mailbox.AckResult{RequestID: 9, Deleted: 2},
		mailbox.Error{Code: mailbox.CodeAuth},
	}
}

func mustEncode(t testing.TB, m mailbox.Message) []byte {
	t.Helper()
	b, err := mailbox.Encode(m)
	if err != nil {
		t.Fatalf("Encode(%#v): %v", m, err)
	}
	return b
}

// cbor encodes an array of items canonically, for building hostile frames.
func cbor(t testing.TB, items ...any) []byte {
	t.Helper()
	b, err := identity.EncodeCanonical(items)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bs(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

type countReader struct {
	r io.Reader
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// endless serves zero bytes until limit, then fails. It stands for a hostile
// peer; no test reads more than the stated figure.
type endless struct{ left int }

func (e *endless) Read(p []byte) (int, error) {
	if e.left <= 0 {
		return 0, io.ErrNoProgress
	}
	if len(p) > e.left {
		p = p[:e.left]
	}
	e.left -= len(p)
	return len(p), nil
}

func allocated(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

func fpb(b byte) []byte    { v := fp(b); return v[:] }
func nkb(b byte) []byte    { v := nk(b); return v[:] }
func nonceb(b byte) []byte { v := nonce(b); return v[:] }
func sigb(b byte) []byte   { v := sig(b); return v[:] }
func hashb(b byte) []byte  { v := hash(b); return v[:] }
