package objmailbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

const t0 = 1_700_000_000

var (
	rcptA, rcptC = fp(0xA1), fp(0xC3)
	sendB, sendD = fp(0xB2), fp(0xD4)
)

func fp(b byte) party.Fingerprint {
	var f party.Fingerprint
	for i := range f {
		f[i] = b
	}
	return f
}

func body(n int, tag byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*13) ^ tag
	}
	if n > 0 {
		b[0] = tag
	}
	return b
}

func quota(t *testing.T) mailbox.ValidQuota {
	t.Helper()
	q, err := mailbox.DefaultQuota().Validated(1)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func putOf(rcpt, sender party.Fingerprint, b []byte, q mailbox.ValidQuota) relayport.MailboxPut {
	return relayport.MailboxPut{Recipient: rcpt, Sender: sender, Mid: mailbox.HashOf(b), Size: uint32(len(b)), Quota: q}
}

func doPut(t *testing.T, s *Store, rcpt, sender party.Fingerprint, b []byte) (relayport.MailboxOutcome, error) {
	t.Helper()
	return s.Put(context.Background(), putOf(rcpt, sender, b, quota(t)), bytes.NewReader(b))
}

func mustStore(t *testing.T, s *Store, rcpt, sender party.Fingerprint, b []byte) {
	t.Helper()
	if o, err := doPut(t, s, rcpt, sender, b); err != nil || o != relayport.MailboxStored {
		t.Fatalf("Put = %v, %v; want stored", o, err)
	}
}

func list(t *testing.T, s *Store, rcpt party.Fingerprint) []relayport.MailboxEntry {
	t.Helper()
	es, more, err := s.List(context.Background(), rcpt, nil, mailbox.MaxMailboxEntries)
	if err != nil || more {
		t.Fatalf("List = %d, %v, %v", len(es), more, err)
	}
	return es
}

func use(t *testing.T, s *Store, rcpt, sender party.Fingerprint) mailbox.Usage {
	t.Helper()
	u, err := s.Usage(context.Background(), rcpt, sender)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func readEntry(t *testing.T, s *Store, rcpt party.Fingerprint, mid mailbox.Hash) ([]byte, error) {
	t.Helper()
	rc, err := s.Open(context.Background(), rcpt, mid)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// keyOf is the object key of an entry of b from sender to rcpt at arrival
// with the nonce 0: what an operator or another writer puts by hand. A put of
// the store draws its own nonce (objectOf finds its key).
func keyOf(rcpt, sender party.Fingerprint, arrival int64, b []byte) string {
	return entryKey(mailboxPrefix(testNode), rcpt, arrival, mailbox.HashOf(b), sender, 0)
}

// objectOf is the key under which the bucket holds an entry of b from sender
// to rcpt, and its bytes; "" when the bucket holds none. With several, the
// first in key order.
func (e *env) objectOf(t *testing.T, rcpt, sender party.Fingerprint, b []byte) (string, []byte) {
	t.Helper()
	for _, k := range e.objectKeys(t) {
		r, _, m, x, _, err := parseKey(mailboxPrefix(testNode), k)
		if err == nil && r == rcpt && x == sender && m == mailbox.HashOf(b) {
			data, _ := e.stored(k)
			return k, data
		}
	}
	return "", nil
}

// adminPut writes body at key outside any store (another writer, or the
// store's operator), create-only.
func (e *env) adminPut(t *testing.T, key string, b []byte) {
	t.Helper()
	if _, err := e.client.Put(ctxFor(t, 5*time.Second), s3client.PutInput{Key: key, Body: b, IfNoneMatch: true, Checksum: true}); err != nil {
		t.Fatalf("admin put %s: %v", key, err)
	}
}

// stored is the bytes the bucket holds at key, read outside any store.
func (e *env) stored(key string) ([]byte, bool) { return e.srv.Current(workBucket, key) }

func newStore(t *testing.T) (*env, *Store, *relayporttest.ManualClock) {
	t.Helper()
	clk := relayporttest.NewManualClock(t0)
	e := newEnv(t, clk)
	s := e.open(t)
	t.Cleanup(func() { e.noUnconditional(t) })
	return e, s, clk
}

// reopen opens a second store on the env's bucket under a new lease (the
// first one released): a restart, or a taker.
func (e *env) reopen(t *testing.T, old *Store) *Store {
	t.Helper()
	old.Close()
	if err := e.lease.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.lease = e.newLease(t)
	return e.open(t)
}

func isLost(err error) bool { return errors.Is(err, relayport.ErrAuthorityLost) }

func isUnknown(err error) bool { return errors.Is(err, relayport.ErrOutcomeUnknown) }

// gatedReader blocks its first Read until gate is closed, and closes started
// when it is reached.
type gatedReader struct {
	r       io.Reader
	gate    chan struct{}
	started chan struct{}
	once    sync.Once
}

func newGated(b []byte) *gatedReader {
	return &gatedReader{r: bytes.NewReader(b), gate: make(chan struct{}), started: make(chan struct{})}
}

func (g *gatedReader) Read(p []byte) (int, error) {
	g.once.Do(func() { close(g.started); <-g.gate })
	return g.r.Read(p)
}

// countingReader counts the bytes read from it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}
